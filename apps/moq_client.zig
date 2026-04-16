// MoQ Transport draft-17 client over raw QUIC.
//
// Connects to a MoQ relay/server, exchanges SETUP, sends SUBSCRIBE
// for a given track, and prints received objects. For interop testing
// against moq-rs.
//
// Usage:
//   zig-out/bin/moq-client --addr localhost:4443 --ns moq-clock --track seconds

const std = @import("std");
const quic = @import("quic");
const event_loop = quic.event_loop;

const moq_wire = quic.moq.wire;
const moq_msg = quic.moq.message;
const moq_codes = quic.moq.message_codes;
const moq_obj = quic.moq.object;
const moq_version = quic.moq.version;

pub const std_options: std.Options = .{ .log_level = .err };

const StreamRole = enum { control, request, data, unknown };

const MoqClientHandler = struct {
    pub const protocol: event_loop.Protocol = .quic;

    ns_parts: []const []const u8,
    track_name: []const u8,

    control_out: ?u64 = null,
    peer_control: ?u64 = null,
    subscribe_bidi: ?u64 = null,
    setup_sent: bool = false,
    setup_received: bool = false,
    subscribed: bool = false,
    objects_received: u64 = 0,

    stream_roles: [256]StreamRole = [_]StreamRole{.unknown} ** 256,

    fn setRole(self: *MoqClientHandler, sid: u64, role: StreamRole) void {
        if (sid < 256) self.stream_roles[@intCast(sid)] = role;
    }
    fn getRole(self: *MoqClientHandler, sid: u64) StreamRole {
        if (sid < 256) return self.stream_roles[@intCast(sid)];
        return .unknown;
    }

    pub fn onConnected(self: *MoqClientHandler, session: *event_loop.ClientSession) void {
        std.debug.print("[MoQ] QUIC connected, sending SETUP...\n", .{});

        // Open control uni stream and send SETUP.
        const ctrl = session.openQuicUniStream() catch |e| {
            std.debug.print("[MoQ] Failed to open uni stream: {}\n", .{e});
            return;
        };
        self.control_out = ctrl;
        self.setRole(ctrl, .control);

        var buf: [256]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        moq_msg.writeSetup(fbs.writer(), .{
            .implementation = "quic-zig/moq",
        }) catch return;
        session.writeStream(ctrl, buf[0..fbs.pos]) catch return;
        self.setup_sent = true;
        std.debug.print("[MoQ] Sent SETUP on stream {d}\n", .{ctrl});
    }

    pub fn onStreamData(self: *MoqClientHandler, session: *event_loop.ClientSession, stream_id: u64, data: []const u8, _: bool) void {
        if (data.len == 0) return;

        const role = self.getRole(stream_id);
        switch (role) {
            .unknown => self.handleNewStream(session, stream_id, data),
            .control => self.handleControl(stream_id, data),
            .request => self.handleRequest(stream_id, data),
            .data => self.handleDataStream(stream_id, data),
        }
    }

    fn handleNewStream(self: *MoqClientHandler, session: *event_loop.ClientSession, stream_id: u64, data: []const u8) void {
        // Try to parse as control message (SETUP from server).
        const parsed = moq_msg.parseEnvelope(data) catch {
            // Could be a data stream (subgroup header).
            self.setRole(stream_id, .data);
            self.handleDataStream(stream_id, data);
            return;
        };

        if (parsed.env.type == moq_codes.MSG_SETUP) {
            self.peer_control = stream_id;
            self.setRole(stream_id, .control);
            self.setup_received = true;
            const opts = moq_msg.decodeSetupPayload(parsed.env.payload) catch return;
            std.debug.print("[MoQ] Received SETUP", .{});
            if (opts.implementation) |impl| std.debug.print(" impl=\"{s}\"", .{impl});
            std.debug.print("\n", .{});

            if (self.setup_sent and self.setup_received and !self.subscribed) {
                self.sendSubscribe(session);
            }
        } else {
            // Some other message on a new stream — probably a bidi request response.
            self.setRole(stream_id, .request);
            self.handleRequest(stream_id, data);
        }
    }

    fn handleControl(self: *MoqClientHandler, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        std.debug.print("[MoQ] Control msg type=0x{x} on stream {d}\n", .{ parsed.env.type, stream_id });
        _ = self;
    }

    fn handleRequest(self: *MoqClientHandler, stream_id: u64, data: []const u8) void {
        const parsed = moq_msg.parseEnvelope(data) catch return;
        switch (parsed.env.type) {
            moq_codes.MSG_SUBSCRIBE_OK => {
                const ok = moq_msg.decodeSubscribeOk(parsed.env.payload) catch return;
                std.debug.print("[MoQ] SUBSCRIBE_OK alias={d}\n", .{ok.track_alias});
            },
            moq_codes.MSG_REQUEST_OK => {
                std.debug.print("[MoQ] REQUEST_OK on stream {d}\n", .{stream_id});
            },
            moq_codes.MSG_REQUEST_ERROR => {
                const err = moq_msg.decodeRequestError(parsed.env.payload) catch return;
                std.debug.print("[MoQ] REQUEST_ERROR code={d} reason=\"{s}\"\n", .{ err.error_code, err.reason });
            },
            else => {
                std.debug.print("[MoQ] Response type=0x{x} on stream {d}\n", .{ parsed.env.type, stream_id });
            },
        }
        _ = self;
    }

    fn handleDataStream(self: *MoqClientHandler, stream_id: u64, data: []const u8) void {
        var fbs = std.io.fixedBufferStream(data);
        const parsed = moq_obj.readSubgroupHeader(&fbs) catch {
            std.debug.print("[MoQ] Data stream {d}: {d} bytes (parse deferred)\n", .{ stream_id, data.len });
            return;
        };
        const h = parsed.header;
        std.debug.print("[MoQ] Subgroup: alias={d} group={d} sub={?d} eog={}\n", .{
            h.track_alias, h.group, h.subgroup, h.end_of_group,
        });

        // Read objects from remainder.
        const rest = data[fbs.pos..];
        var off: usize = 0;
        while (off < rest.len) {
            var obj_fbs = std.io.fixedBufferStream(rest[off..]);
            const obj_reader = obj_fbs.reader();
            const obj_id = moq_wire.readVarInt(obj_reader) catch break;
            const payload_len = moq_wire.readVarInt(obj_reader) catch break;
            const plen: usize = @intCast(payload_len);
            const hdr_len = obj_fbs.pos;
            if (off + hdr_len + plen > rest.len) break;
            const payload = rest[off + hdr_len .. off + hdr_len + plen];
            std.debug.print("[MoQ] Object: group={d} obj={d} payload=\"{s}\"\n", .{ h.group, obj_id, payload });
            self.objects_received += 1;
            off += hdr_len + plen;
        }
    }

    fn sendSubscribe(self: *MoqClientHandler, session: *event_loop.ClientSession) void {
        // Open a bidi stream for the SUBSCRIBE request.
        const bidi = session.openStream() catch |e| {
            std.debug.print("[MoQ] Failed to open bidi stream: {}\n", .{e});
            return;
        };
        self.subscribe_bidi = bidi;
        self.setRole(bidi, .request);
        self.subscribed = true;

        var buf: [512]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        moq_msg.writeSubscribe(fbs.writer(), .{
            .track_namespace = self.ns_parts,
            .track_name = self.track_name,
            .subscriber_priority = 128,
            .group_order = .ascending,
            .filter_type = .latest_object,
        }) catch return;
        session.writeStream(bidi, buf[0..fbs.pos]) catch return;
        std.debug.print("[MoQ] Sent SUBSCRIBE on bidi stream {d}\n", .{bidi});
    }

    pub fn onPollComplete(_: *MoqClientHandler, _: *event_loop.ClientSession) void {}
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    var address: []const u8 = "127.0.0.1";
    var port: u16 = 4443;
    var server_name: []const u8 = "localhost";
    var ns_str: []const u8 = "moq-clock";
    var track_name: []const u8 = "seconds";

    var args = std.process.args();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--addr")) {
            if (args.next()) |v| {
                // Parse "host:port".
                if (std.mem.lastIndexOf(u8, v, ":")) |colon| {
                    address = v[0..colon];
                    port = std.fmt.parseInt(u16, v[colon + 1 ..], 10) catch 4443;
                } else {
                    address = v;
                }
            }
        } else if (std.mem.eql(u8, arg, "--ns")) {
            if (args.next()) |v| ns_str = v;
        } else if (std.mem.eql(u8, arg, "--track")) {
            if (args.next()) |v| track_name = v;
        } else if (std.mem.eql(u8, arg, "--server-name")) {
            if (args.next()) |v| server_name = v;
        }
    }

    // Parse namespace: "moq-clock" → ["moq-clock"], "a,b" → ["a","b"]
    var ns_list = std.ArrayList([]const u8){ .items = &.{}, .capacity = 0 };
    var ns_it = std.mem.splitScalar(u8, ns_str, ',');
    while (ns_it.next()) |part| {
        if (part.len > 0) try ns_list.append(alloc, part);
    }

    std.debug.print("\n=== MoQ Client (draft-17, raw QUIC) ===\n", .{});
    std.debug.print("Target: {s}:{d}  ALPN: {s}\n", .{ address, port, moq_version.ALPN });
    std.debug.print("Track: [", .{});
    for (ns_list.items, 0..) |p, i| {
        if (i > 0) std.debug.print(",", .{});
        std.debug.print("{s}", .{p});
    }
    std.debug.print("] / {s}\n\n", .{track_name});

    var handler = MoqClientHandler{
        .ns_parts = ns_list.items,
        .track_name = track_name,
    };

    var client = try event_loop.Client(MoqClientHandler).init(alloc, &handler, .{
        .address = address,
        .port = port,
        .server_name = server_name,
        .alpn = moq_version.ALPN,
        .skip_cert_verify = true,
    });
    defer client.deinit();
    try client.run();
}
