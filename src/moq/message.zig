// Control-message codec for MoQ Transport draft-17.
//
// Framing (§9): every control message on the uni control stream is
//   Type (moq-varint) | Length (u16 big-endian) | Payload (Length bytes)
//
// This module implements the envelope plus payload codecs for the
// messages needed to reach a working pub/sub flow. Other messages
// (FETCH, TRACK_STATUS, NAMESPACE streams, PUBLISH_BLOCKED) are added
// as later phases exercise them.

const std = @import("std");
const io = std.io;
const testing = std.testing;

const wire = @import("wire.zig");
const codes = @import("message_codes.zig");
const track = @import("track.zig");

pub const MAX_PAYLOAD_LEN: usize = std.math.maxInt(u16);

pub const Error = error{
    UnknownMessageType,
    ReservedLegacyMessage,
    PayloadTooLarge,
    MalformedMessage,
} || wire.Error;

// Envelope I/O -------------------------------------------------------------

pub const Envelope = struct {
    type: u64,
    payload: []const u8,
};

pub fn writeEnvelope(writer: anytype, msg_type: u64, payload: []const u8) !void {
    if (payload.len > MAX_PAYLOAD_LEN) return Error.PayloadTooLarge;
    try wire.writeVarInt(writer, msg_type);
    var len_be: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_be, @as(u16, @intCast(payload.len)), .big);
    try writer.writeAll(&len_be);
    try writer.writeAll(payload);
}

// Parses one envelope from the front of `data`. Returns the envelope
// plus total bytes consumed. Caller should slice `data` forward.
pub fn parseEnvelope(data: []const u8) !struct { env: Envelope, consumed: usize } {
    var fbs = io.fixedBufferStream(data);
    const t = try wire.readVarInt(fbs.reader());
    if (codes.isReservedLegacyMessageType(t)) return Error.ReservedLegacyMessage;
    if (fbs.pos + 2 > data.len) return Error.BufferTooShort;
    const len = std.mem.readInt(u16, data[fbs.pos..][0..2], .big);
    const payload_start = fbs.pos + 2;
    const payload_end = payload_start + len;
    if (payload_end > data.len) return Error.BufferTooShort;
    return .{
        .env = .{ .type = t, .payload = data[payload_start..payload_end] },
        .consumed = payload_end,
    };
}

// SETUP (0x2F00, §9.4) -----------------------------------------------------

pub const SetupOptions = struct {
    path: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    implementation: ?[]const u8 = null,
    max_auth_token_cache_size: ?u64 = null,
    // AUTHORIZATION_TOKEN (0x03) is decoded at wire level but not
    // surfaced here in the first pass; see auth.zig (TBD).
};

pub fn encodeSetupPayload(writer: anytype, opts: SetupOptions) !void {
    // Build a KV list sorted by key.
    var kvs: [8]wire.KvEntry = undefined;
    var n: usize = 0;
    if (opts.path) |p| {
        kvs[n] = .{ .key = codes.OPT_PATH, .value = .{ .bytes = p } };
        n += 1;
    }
    if (opts.max_auth_token_cache_size) |v| {
        kvs[n] = .{ .key = codes.OPT_MAX_AUTH_TOKEN_CACHE_SIZE, .value = .{ .varint = v } };
        n += 1;
    }
    if (opts.authority) |a| {
        kvs[n] = .{ .key = codes.OPT_AUTHORITY, .value = .{ .bytes = a } };
        n += 1;
    }
    if (opts.implementation) |i| {
        kvs[n] = .{ .key = codes.OPT_MOQT_IMPLEMENTATION, .value = .{ .bytes = i } };
        n += 1;
    }
    try wire.encodeKvList(writer, kvs[0..n]);
}

pub fn decodeSetupPayload(payload: []const u8) !SetupOptions {
    var opts = SetupOptions{};
    var it = wire.KvIterator.init(payload);
    while (try it.next()) |e| {
        switch (e.key) {
            codes.OPT_PATH => opts.path = e.value.bytes,
            codes.OPT_AUTHORIZATION_TOKEN => {}, // ignored in first pass
            codes.OPT_MAX_AUTH_TOKEN_CACHE_SIZE => opts.max_auth_token_cache_size = e.value.varint,
            codes.OPT_AUTHORITY => opts.authority = e.value.bytes,
            codes.OPT_MOQT_IMPLEMENTATION => opts.implementation = e.value.bytes,
            else => {}, // unknown keys: ignore per draft
        }
    }
    return opts;
}

pub fn writeSetup(writer: anytype, opts: SetupOptions) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try encodeSetupPayload(fbs.writer(), opts);
    try writeEnvelope(writer, codes.MSG_SETUP, scratch[0..fbs.pos]);
}

// GOAWAY (0x10, §9.5) ------------------------------------------------------

pub const Goaway = struct { new_uri: []const u8 };

pub fn writeGoaway(writer: anytype, g: Goaway) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarBytes(fbs.writer(), g.new_uri);
    try writeEnvelope(writer, codes.MSG_GOAWAY, scratch[0..fbs.pos]);
}

pub fn decodeGoaway(payload: []const u8) !Goaway {
    var fbs = io.fixedBufferStream(payload);
    return .{ .new_uri = try wire.readVarBytesZc(&fbs) };
}

// REQUEST_OK / REQUEST_ERROR (§9.6, §9.7) ----------------------------------
//
// These travel on the per-request bidi stream. In draft-17 they carry
// no request_id on the wire (the stream is the identifier).

pub const RequestOk = struct {
    // An empty trailing KV list of status parameters.
    parameters: []const wire.KvEntry = &.{},
};

pub fn writeRequestOk(writer: anytype, r: RequestOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.encodeKvList(fbs.writer(), r.parameters);
    try writeEnvelope(writer, codes.MSG_REQUEST_OK, scratch[0..fbs.pos]);
}

pub const RequestError = struct {
    error_code: u64,
    reason: []const u8,
};

pub fn writeRequestError(writer: anytype, e: RequestError) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(fbs.writer(), e.error_code);
    try wire.writeVarBytes(fbs.writer(), e.reason);
    try writeEnvelope(writer, codes.MSG_REQUEST_ERROR, scratch[0..fbs.pos]);
}

pub fn decodeRequestError(payload: []const u8) !RequestError {
    var fbs = io.fixedBufferStream(payload);
    const code = try wire.readVarInt(fbs.reader());
    const reason = try wire.readVarBytesZc(&fbs);
    return .{ .error_code = code, .reason = reason };
}

// SUBSCRIBE (0x03, §9.8) — sent on a bidi request stream.

pub const Subscribe = struct {
    track_namespace: []const []const u8,
    track_name: []const u8,
    subscriber_priority: track.Priority,
    group_order: track.GroupOrder,
    filter_type: track.FilterType,
    start: ?track.Location = null, // for absolute_start/absolute_range
    end: ?track.Location = null, // for absolute_range only
};

pub fn writeSubscribe(writer: anytype, s: Subscribe) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = fbs.writer();
    try wire.writeTuple(w, s.track_namespace);
    try wire.writeVarBytes(w, s.track_name);
    try w.writeByte(s.subscriber_priority);
    try w.writeByte(@intFromEnum(s.group_order));
    try wire.writeVarInt(w, @intFromEnum(s.filter_type));
    if (s.start) |loc| {
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    if (s.end) |loc| {
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    try writeEnvelope(writer, codes.MSG_SUBSCRIBE, scratch[0..fbs.pos]);
}

pub fn decodeSubscribe(payload: []const u8) !Subscribe {
    var fbs = io.fixedBufferStream(payload);
    const reader = fbs.reader();

    const count = try wire.readVarInt(reader);
    if (count > wire.MAX_TUPLE_PARTS) return Error.MalformedMessage;
    var ns_parts: [wire.MAX_TUPLE_PARTS][]const u8 = undefined;
    for (0..@as(usize, @intCast(count))) |i| {
        ns_parts[i] = try wire.readVarBytesZc(&fbs);
    }
    const name = try wire.readVarBytesZc(&fbs);
    const pri = reader.readByte() catch return wire.Error.BufferTooShort;
    const go_raw = reader.readByte() catch return wire.Error.BufferTooShort;
    const ft_raw = try wire.readVarInt(reader);
    const ft = track.FilterType.fromInt(ft_raw) orelse return Error.MalformedMessage;

    var start: ?track.Location = null;
    var end: ?track.Location = null;
    if (ft == .absolute_start or ft == .absolute_range) {
        start = .{
            .group = try wire.readVarInt(reader),
            .object = try wire.readVarInt(reader),
        };
    }
    if (ft == .absolute_range) {
        end = .{
            .group = try wire.readVarInt(reader),
            .object = try wire.readVarInt(reader),
        };
    }

    return .{
        .track_namespace = ns_parts[0..@as(usize, @intCast(count))],
        .track_name = name,
        .subscriber_priority = pri,
        .group_order = @enumFromInt(go_raw),
        .filter_type = ft,
        .start = start,
        .end = end,
    };
}

// SUBSCRIBE_OK (0x04, §9.9)

pub const SubscribeOk = struct {
    track_alias: track.TrackAlias,
    content_exists: bool = true,
    largest: ?track.Location = null,
};

pub fn writeSubscribeOk(writer: anytype, s: SubscribeOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = fbs.writer();
    try wire.writeVarInt(w, s.track_alias);
    try w.writeByte(if (s.content_exists) 1 else 0);
    if (s.largest) |loc| {
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    try writeEnvelope(writer, codes.MSG_SUBSCRIBE_OK, scratch[0..fbs.pos]);
}

pub fn decodeSubscribeOk(payload: []const u8) !SubscribeOk {
    var fbs = io.fixedBufferStream(payload);
    const reader = fbs.reader();
    const alias = try wire.readVarInt(reader);
    const ce = reader.readByte() catch return wire.Error.BufferTooShort;
    var largest: ?track.Location = null;
    if (fbs.pos < payload.len) {
        largest = .{
            .group = try wire.readVarInt(reader),
            .object = try wire.readVarInt(reader),
        };
    }
    return .{
        .track_alias = alias,
        .content_exists = ce != 0,
        .largest = largest,
    };
}

// REQUEST_UPDATE (0x02, §9.10) — update an existing subscribe

pub const RequestUpdate = struct {
    subscriber_priority: track.Priority,
    group_order: track.GroupOrder,
    end: ?track.Location = null,
};

pub fn writeRequestUpdate(writer: anytype, u: RequestUpdate) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = fbs.writer();
    try w.writeByte(u.subscriber_priority);
    try w.writeByte(@intFromEnum(u.group_order));
    if (u.end) |loc| {
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    try writeEnvelope(writer, codes.MSG_REQUEST_UPDATE, scratch[0..fbs.pos]);
}

// PUBLISH (0x1D, §9.11) — sent on bidi request stream to announce intent

pub const Publish = struct {
    track_namespace: []const []const u8,
    track_name: []const u8,
    track_alias: track.TrackAlias,
    publisher_priority: track.Priority,
};

pub fn writePublish(writer: anytype, p: Publish) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = fbs.writer();
    try wire.writeTuple(w, p.track_namespace);
    try wire.writeVarBytes(w, p.track_name);
    try wire.writeVarInt(w, p.track_alias);
    try w.writeByte(p.publisher_priority);
    try writeEnvelope(writer, codes.MSG_PUBLISH, scratch[0..fbs.pos]);
}

pub fn decodePublish(payload: []const u8) !Publish {
    var fbs = io.fixedBufferStream(payload);
    const reader = fbs.reader();
    const count = try wire.readVarInt(reader);
    if (count > wire.MAX_TUPLE_PARTS) return Error.MalformedMessage;
    var ns_parts: [wire.MAX_TUPLE_PARTS][]const u8 = undefined;
    for (0..@as(usize, @intCast(count))) |i| {
        ns_parts[i] = try wire.readVarBytesZc(&fbs);
    }
    const name = try wire.readVarBytesZc(&fbs);
    const alias = try wire.readVarInt(reader);
    const pri = reader.readByte() catch return wire.Error.BufferTooShort;
    return .{
        .track_namespace = ns_parts[0..@as(usize, @intCast(count))],
        .track_name = name,
        .track_alias = alias,
        .publisher_priority = pri,
    };
}

// PUBLISH_OK (0x1E, §9.12)

pub const PublishOk = struct {
    content_exists: bool = true,
    largest: ?track.Location = null,
};

pub fn writePublishOk(writer: anytype, p: PublishOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = fbs.writer();
    try w.writeByte(if (p.content_exists) 1 else 0);
    if (p.largest) |loc| {
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    try writeEnvelope(writer, codes.MSG_PUBLISH_OK, scratch[0..fbs.pos]);
}

// PUBLISH_DONE (0x0B, §9.13)

pub const PublishDone = struct {
    final_group: ?track.GroupId = null,
    final_object: ?track.ObjectId = null,
    status_code: u64 = 0,
    reason: []const u8 = "",
};

pub fn writePublishDone(writer: anytype, p: PublishDone) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = fbs.writer();
    try wire.writeVarInt(w, p.status_code);
    try wire.writeVarBytes(w, p.reason);
    if (p.final_group) |g| {
        try wire.writeVarInt(w, g);
        if (p.final_object) |o| try wire.writeVarInt(w, o);
    }
    try writeEnvelope(writer, codes.MSG_PUBLISH_DONE, scratch[0..fbs.pos]);
}

// PUBLISH_NAMESPACE (0x06, §9.17)

pub const PublishNamespace = struct {
    track_namespace_prefix: []const []const u8,
};

pub fn writePublishNamespace(writer: anytype, p: PublishNamespace) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(fbs.writer(), p.track_namespace_prefix);
    try writeEnvelope(writer, codes.MSG_PUBLISH_NAMESPACE, scratch[0..fbs.pos]);
}

// SUBSCRIBE_NAMESPACE (0x11, §9.20)

pub const SubscribeNamespace = struct {
    track_namespace_prefix: []const []const u8,
};

pub fn writeSubscribeNamespace(writer: anytype, s: SubscribeNamespace) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(fbs.writer(), s.track_namespace_prefix);
    try writeEnvelope(writer, codes.MSG_SUBSCRIBE_NAMESPACE, scratch[0..fbs.pos]);
}

// NAMESPACE (0x08, §9.18)

pub const Namespace = struct {
    track_namespace: []const []const u8,
};

pub fn writeNamespace(writer: anytype, n: Namespace) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeTuple(fbs.writer(), n.track_namespace);
    try writeEnvelope(writer, codes.MSG_NAMESPACE, scratch[0..fbs.pos]);
}

// NAMESPACE_DONE (0x0E, §9.19)

pub fn writeNamespaceDone(writer: anytype) !void {
    try writeEnvelope(writer, codes.MSG_NAMESPACE_DONE, &.{});
}

// FETCH (0x16, §9.14)

pub const Fetch = struct {
    track_namespace: []const []const u8,
    track_name: []const u8,
    subscriber_priority: track.Priority,
    group_order: track.GroupOrder,
    start: track.Location,
    end: track.Location,
};

pub fn writeFetch(writer: anytype, f: Fetch) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = fbs.writer();
    try wire.writeTuple(w, f.track_namespace);
    try wire.writeVarBytes(w, f.track_name);
    try w.writeByte(f.subscriber_priority);
    try w.writeByte(@intFromEnum(f.group_order));
    try wire.writeVarInt(w, f.start.group);
    try wire.writeVarInt(w, f.start.object);
    try wire.writeVarInt(w, f.end.group);
    try wire.writeVarInt(w, f.end.object);
    try writeEnvelope(writer, codes.MSG_FETCH, scratch[0..fbs.pos]);
}

// FETCH_OK (0x18, §9.15)

pub const FetchOk = struct {
    track_alias: track.TrackAlias,
};

pub fn writeFetchOk(writer: anytype, f: FetchOk) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(fbs.writer(), f.track_alias);
    try writeEnvelope(writer, codes.MSG_FETCH_OK, scratch[0..fbs.pos]);
}

// TRACK_STATUS (0x0D, §9.16)

pub const TrackStatus = struct {
    track_namespace: []const []const u8,
    track_name: []const u8,
    status_code: u64,
    largest: ?track.Location = null,
};

pub fn writeTrackStatus(writer: anytype, t: TrackStatus) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    const w = fbs.writer();
    try wire.writeTuple(w, t.track_namespace);
    try wire.writeVarBytes(w, t.track_name);
    try wire.writeVarInt(w, t.status_code);
    if (t.largest) |loc| {
        try wire.writeVarInt(w, loc.group);
        try wire.writeVarInt(w, loc.object);
    }
    try writeEnvelope(writer, codes.MSG_TRACK_STATUS, scratch[0..fbs.pos]);
}

// PUBLISH_BLOCKED (0x0F, §9.21)

pub const PublishBlocked = struct {
    track_alias: track.TrackAlias,
};

pub fn writePublishBlocked(writer: anytype, p: PublishBlocked) !void {
    var scratch: [MAX_PAYLOAD_LEN]u8 = undefined;
    var fbs = io.fixedBufferStream(&scratch);
    try wire.writeVarInt(fbs.writer(), p.track_alias);
    try writeEnvelope(writer, codes.MSG_PUBLISH_BLOCKED, scratch[0..fbs.pos]);
}

// Tests

test "envelope round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeEnvelope(fbs.writer(), codes.MSG_GOAWAY, "hello");
    const parsed = try parseEnvelope(buf[0..fbs.pos]);
    try testing.expectEqual(codes.MSG_GOAWAY, parsed.env.type);
    try testing.expectEqualStrings("hello", parsed.env.payload);
    try testing.expectEqual(fbs.pos, parsed.consumed);
}

test "envelope rejects legacy setup codes" {
    // Code 0x20 is a legacy CLIENT_SETUP from pre-v17.
    var buf = [_]u8{ 0x20, 0x00, 0x00 };
    try testing.expectError(Error.ReservedLegacyMessage, parseEnvelope(&buf));
}

test "SETUP round-trip with path + implementation" {
    var buf: [128]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSetup(fbs.writer(), .{
        .path = "/moq",
        .implementation = "quic-zig/moq/0",
        .max_auth_token_cache_size = 256,
    });
    const p = try parseEnvelope(buf[0..fbs.pos]);
    try testing.expectEqual(codes.MSG_SETUP, p.env.type);
    const opts = try decodeSetupPayload(p.env.payload);
    try testing.expectEqualStrings("/moq", opts.path.?);
    try testing.expectEqualStrings("quic-zig/moq/0", opts.implementation.?);
    try testing.expectEqual(@as(?u64, 256), opts.max_auth_token_cache_size);
    try testing.expectEqual(@as(?[]const u8, null), opts.authority);
}

test "GOAWAY round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeGoaway(fbs.writer(), .{ .new_uri = "https://other.example/moq" });
    const p = try parseEnvelope(buf[0..fbs.pos]);
    try testing.expectEqual(codes.MSG_GOAWAY, p.env.type);
    const g = try decodeGoaway(p.env.payload);
    try testing.expectEqualStrings("https://other.example/moq", g.new_uri);
}

test "REQUEST_ERROR round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeRequestError(fbs.writer(), .{
        .error_code = codes.ERR_UNAUTHORIZED,
        .reason = "no token",
    });
    const p = try parseEnvelope(buf[0..fbs.pos]);
    const e = try decodeRequestError(p.env.payload);
    try testing.expectEqual(codes.ERR_UNAUTHORIZED, e.error_code);
    try testing.expectEqualStrings("no token", e.reason);
}

test "SUBSCRIBE round-trip" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq", "demo" };
    try writeSubscribe(fbs.writer(), .{
        .track_namespace = &ns,
        .track_name = "video",
        .subscriber_priority = 128,
        .group_order = .ascending,
        .filter_type = .latest_object,
    });
    const p = try parseEnvelope(buf[0..fbs.pos]);
    try testing.expectEqual(codes.MSG_SUBSCRIBE, p.env.type);
    const s = try decodeSubscribe(p.env.payload);
    try testing.expectEqual(@as(usize, 2), s.track_namespace.len);
    try testing.expectEqualStrings("video", s.track_name);
    try testing.expectEqual(@as(u8, 128), s.subscriber_priority);
    try testing.expectEqual(track.FilterType.latest_object, s.filter_type);
}

test "SUBSCRIBE_OK round-trip" {
    var buf: [64]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    try writeSubscribeOk(fbs.writer(), .{
        .track_alias = 42,
        .content_exists = true,
        .largest = .{ .group = 10, .object = 5 },
    });
    const p = try parseEnvelope(buf[0..fbs.pos]);
    try testing.expectEqual(codes.MSG_SUBSCRIBE_OK, p.env.type);
    const s = try decodeSubscribeOk(p.env.payload);
    try testing.expectEqual(@as(u64, 42), s.track_alias);
    try testing.expect(s.content_exists);
    try testing.expectEqual(@as(u64, 10), s.largest.?.group);
}

test "PUBLISH round-trip" {
    var buf: [256]u8 = undefined;
    var fbs = io.fixedBufferStream(&buf);
    const ns = [_][]const u8{ "moq", "demo" };
    try writePublish(fbs.writer(), .{
        .track_namespace = &ns,
        .track_name = "video",
        .track_alias = 7,
        .publisher_priority = 200,
    });
    const p = try parseEnvelope(buf[0..fbs.pos]);
    try testing.expectEqual(codes.MSG_PUBLISH, p.env.type);
    const pub_ = try decodePublish(p.env.payload);
    try testing.expectEqual(@as(usize, 2), pub_.track_namespace.len);
    try testing.expectEqualStrings("video", pub_.track_name);
    try testing.expectEqual(@as(u64, 7), pub_.track_alias);
    try testing.expectEqual(@as(u8, 200), pub_.publisher_priority);
}
