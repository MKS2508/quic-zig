// MoQ Transport draft-17 browser demo server.
//
// Runs a WebTransport server that speaks MoQ Transport:
//  - Accepts WT sessions on path "/"
//  - Exchanges MoQ SETUP on control uni streams
//  - Handles SUBSCRIBE requests on bidi streams
//  - Publishes a synthetic clock track ("moq/demo" → "clock") that emits
//    one object per second with an incrementing counter

const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;
const tls13 = quic.tls13;
const connection = quic.connection;

const moq_wire = @import("quic").moq.wire;
const moq_msg = @import("quic").moq.message;
const moq_codes = @import("quic").moq.message_codes;
const moq_obj = @import("quic").moq.object;
const moq_version = @import("quic").moq.version;

pub const std_options: std.Options = .{
    .log_level = .err,
};

const StreamRole = enum { control, request, data, unknown };

const MAX_SUBSCRIBERS: usize = 16;

const Subscriber = struct {
    session_id: u64,
    bidi_stream_id: u64,
    track_alias: u64,
    active: bool = true,
};

const MoqHandler = struct {
    pub const protocol: event_loop.Protocol = .webtransport;

    // Per-session state — only one session supported for demo.
    wt_session_id: ?u64 = null,
    control_stream_out: ?u64 = null,
    peer_control_stream: ?u64 = null,
    setup_sent: bool = false,
    setup_received: bool = false,
    subscribers: [MAX_SUBSCRIBERS]Subscriber = undefined,
    subscriber_count: usize = 0,
    group_id: u64 = 0,
    object_id: u64 = 0,
    last_tick_ns: i128 = 0,
    stream_roles: [256]StreamRole = [_]StreamRole{.unknown} ** 256,

    fn streamIdx(stream_id: u64) ?u8 {
        if (stream_id >= 256) return null;
        return @intCast(stream_id);
    }

    fn setStreamRole(self: *MoqHandler, stream_id: u64, role: StreamRole) void {
        if (streamIdx(stream_id)) |idx| self.stream_roles[idx] = role;
    }

    fn getStreamRole(self: *MoqHandler, stream_id: u64) StreamRole {
        if (streamIdx(stream_id)) |idx| return self.stream_roles[idx];
        return .unknown;
    }

    pub fn onConnectRequest(self: *MoqHandler, session: *event_loop.Session, session_id: u64, _: []const u8) void {
        session.acceptSession(session_id) catch return;
        self.wt_session_id = session_id;

        // Open our control uni stream and send SETUP.
        const ctrl_id = session.openUniStream(session_id, 0) catch return;
        self.control_stream_out = ctrl_id;

        var buf: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        moq_msg.writeSetup(fbs.writer(), .{
            .implementation = "quic-zig/moq",
        }) catch return;
        session.sendStreamData(ctrl_id, buf[0..fbs.pos]) catch return;
        self.setup_sent = true;
        std.debug.print("[MoQ] Sent SETUP on uni stream {d}\n", .{ctrl_id});
    }

    pub fn onUniStream(self: *MoqHandler, _: *event_loop.Session, _: u64, stream_id: u64) void {
        // Peer-opened uni stream. Could be control (SETUP) or data.
        // We'll classify on first data.
        self.setStreamRole(stream_id, .unknown);
        std.debug.print("[MoQ] Peer opened uni stream {d}\n", .{stream_id});
    }

    pub fn onBidiStream(self: *MoqHandler, _: *event_loop.Session, _: u64, stream_id: u64) void {
        self.setStreamRole(stream_id, .request);
        std.debug.print("[MoQ] Peer opened bidi stream {d}\n", .{stream_id});
    }

    pub fn onStreamData(self: *MoqHandler, session: *event_loop.Session, stream_id: u64, data: []const u8, _: bool) void {
        if (data.len == 0) return;

        const role = self.getStreamRole(stream_id);
        switch (role) {
            .unknown => {
                // First data on a peer uni stream — try to parse as control (SETUP).
                self.handleFirstUniData(session, stream_id, data);
            },
            .control => self.handleControlData(data),
            .request => self.handleRequestData(session, stream_id, data),
            .data => {},
        }
    }

    fn handleFirstUniData(self: *MoqHandler, session: *event_loop.Session, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        if (parsed.env.type == moq_codes.MSG_SETUP) {
            self.peer_control_stream = stream_id;
            self.setStreamRole(stream_id, .control);
            const opts = moq_msg.decodeSetupPayload(parsed.env.payload) catch return;
            self.setup_received = true;
            std.debug.print("[MoQ] Received SETUP", .{});
            if (opts.implementation) |impl| std.debug.print(" impl=\"{s}\"", .{impl});
            std.debug.print("\n", .{});

            if (self.setup_sent and self.setup_received) {
                std.debug.print("[MoQ] Handshake complete\n", .{});
                // Publish an initial tick immediately.
                self.publishTick(session);
            }
        }
    }

    fn handleControlData(self: *MoqHandler, data: []const u8) void {
        // Control messages after SETUP (e.g., GOAWAY).
        const parsed = moq_msg.parseEnvelope(data) catch return;
        std.debug.print("[MoQ] Control msg type=0x{x} len={d}\n", .{ parsed.env.type, parsed.env.payload.len });
        _ = self;
    }

    fn handleRequestData(self: *MoqHandler, session: *event_loop.Session, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        switch (parsed.env.type) {
            moq_codes.MSG_SUBSCRIBE => self.handleSubscribe(session, stream_id, parsed.env.payload),
            else => std.debug.print("[MoQ] Unhandled request type=0x{x} on stream {d}\n", .{ parsed.env.type, stream_id }),
        }
    }

    fn handleSubscribe(self: *MoqHandler, session: *event_loop.Session, stream_id: u64, payload: []const u8) void {
        const sub = moq_msg.decodeSubscribe(payload) catch return;
        std.debug.print("[MoQ] SUBSCRIBE ns_parts={d} name=\"{s}\" pri={d}\n", .{
            sub.track_namespace.len, sub.track_name, sub.subscriber_priority,
        });

        const alias: u64 = self.subscriber_count + 1;

        // Send SUBSCRIBE_OK on the same bidi stream.
        var buf: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        moq_msg.writeSubscribeOk(fbs.writer(), .{
            .track_alias = alias,
        }) catch return;
        session.sendStreamData(stream_id, buf[0..fbs.pos]) catch return;

        if (self.subscriber_count < MAX_SUBSCRIBERS) {
            const sid = self.wt_session_id orelse return;
            self.subscribers[self.subscriber_count] = .{
                .session_id = sid,
                .bidi_stream_id = stream_id,
                .track_alias = alias,
            };
            self.subscriber_count += 1;
        }

        std.debug.print("[MoQ] Sent SUBSCRIBE_OK alias={d}, subscribers={d}\n", .{ alias, self.subscriber_count });
    }

    pub fn onDatagram(_: *MoqHandler, _: *event_loop.Session, _: u64, _: []const u8) void {}

    pub fn onSessionDraining(self: *MoqHandler, _: *event_loop.Session, _: u64) void {
        self.subscriber_count = 0;
        self.wt_session_id = null;
        self.setup_sent = false;
        self.setup_received = false;
        std.debug.print("[MoQ] Session draining\n", .{});
    }

    pub fn onPollComplete(self: *MoqHandler, session: *event_loop.Session) void {
        if (!self.setup_sent or !self.setup_received) return;
        if (self.subscriber_count == 0) return;

        const now = std.time.nanoTimestamp();
        if (self.last_tick_ns == 0) self.last_tick_ns = now;

        const elapsed_ns = now - self.last_tick_ns;
        if (elapsed_ns < 1_000_000_000) return; // 1 second
        self.last_tick_ns = now;

        self.publishTick(session);
    }

    fn publishTick(self: *MoqHandler, session: *event_loop.Session) void {
        const sid = self.wt_session_id orelse return;

        // Build the payload: "tick N (group G, obj 0)"
        var payload_buf: [128]u8 = undefined;
        const payload = std.fmt.bufPrint(&payload_buf, "tick {d} (group {d}, obj 0)", .{ self.group_id, self.group_id }) catch return;

        // For each subscriber, open a uni stream and send a subgroup header + object.
        for (self.subscribers[0..self.subscriber_count]) |*sub| {
            if (!sub.active) continue;

            // Open a uni stream for this subgroup.
            const data_stream = session.openUniStream(sid, null) catch continue;

            var buf: [256]u8 = undefined;
            var fbs = std.io.fixedBufferStream(&buf);
            const w = fbs.writer();

            // Write subgroup header.
            moq_obj.writeSubgroupHeader(w, .{
                .track_alias = sub.track_alias,
                .group = self.group_id,
                .subgroup = 0,
                .publisher_priority = 128,
                .end_of_group = true,
                .per_object_properties = false,
            }) catch continue;

            // Write object header: object_id (varint) + payload_len (varint) + payload.
            moq_wire.writeVarInt(w, 0) catch continue; // object_id
            moq_wire.writeVarInt(w, payload.len) catch continue; // payload len
            w.writeAll(payload) catch continue;

            session.sendStreamData(data_stream, buf[0..fbs.pos]) catch continue;
            session.closeStream(data_stream);
        }

        std.debug.print("[MoQ] Published group {d}, payload: {s}\n", .{ self.group_id, payload });
        self.group_id += 1;
        self.object_id = 0;
    }
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var port: u16 = 4433;
    var cert_path: []const u8 = "interop/browser/certs/server.crt";
    var key_path: []const u8 = "interop/browser/certs/server.key";

    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--port")) {
            if (args.next()) |v| port = std.fmt.parseInt(u16, v, 10) catch 4433;
        } else if (std.mem.eql(u8, arg, "--cert")) {
            if (args.next()) |v| cert_path = v;
        } else if (std.mem.eql(u8, arg, "--key")) {
            if (args.next()) |v| key_path = v;
        }
    }

    // Print certificate SHA-256 hash for browser pinning.
    const server_cert_pem = try std.fs.cwd().readFileAlloc(alloc, cert_path, 8192);
    var cert_der_buf: [4096]u8 = undefined;
    const cert_der = try tls13.parsePemCert(server_cert_pem, &cert_der_buf);

    var cert_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert_der, &cert_hash, .{});
    std.debug.print("\n=== MoQ Transport Browser Demo Server (draft-17) ===\n", .{});
    std.debug.print("ALPN: {s}\n", .{moq_version.ALPN});
    std.debug.print("Certificate SHA-256: ", .{});
    for (cert_hash) |byte| std.debug.print("{x:0>2}", .{byte});
    std.debug.print("\n", .{});

    std.debug.print("JS hash: new Uint8Array([", .{});
    for (cert_hash, 0..) |byte, idx| {
        if (idx > 0) std.debug.print(", ", .{});
        std.debug.print("{d}", .{byte});
    }
    std.debug.print("])\n\n", .{});

    var handler = MoqHandler{};
    var server = try event_loop.Server(MoqHandler).init(alloc, &handler, .{
        .address = "0.0.0.0",
        .port = port,
        .cert_path = cert_path,
        .key_path = key_path,
        .conn_config = .{ .max_datagram_frame_size = 65536 },
        .http1 = .{ .static_dir = "interop/browser" },
    });
    defer server.deinit();

    std.debug.print("Listening on https://0.0.0.0:{d} (MoQ/WebTransport)\n", .{port});
    std.debug.print("Open https://localhost:{d}/moq.html in Chrome\n\n", .{port});
    try server.run();
}
