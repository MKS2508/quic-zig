//! Zig 0.15-style `fixedBufferStream` over a fixed []u8 buffer.
//! The 0.16 stdlib dropped `std.io.fixedBufferStream` in favor of
//! `std.Io.Reader.fixed` / `std.Io.Writer.fixed`, which expose a
//! different method naming convention (`take*` / `peek*` on Reader).
//! Our codebase has 200+ call sites that use the 0.15 shape, so we
//! keep a thin compat struct that matches the old API exactly —
//! hand-rolled against `[]u8` with a running position.
//!
//! The returned Reader/Writer are *concrete* wrapper types (not
//! interfaces): method calls inline directly into pointer arithmetic,
//! no vtable hop. This matches the 0.15 perf characteristics.

const std = @import("std");
const mem = std.mem;
const builtin = std.builtin;

pub fn FixedBufferStream(comptime Buffer: type) type {
    comptime std.debug.assert(@typeInfo(Buffer) == .pointer);
    const is_const_buf = @typeInfo(Buffer).pointer.is_const;
    // Normalize to a slice type regardless of whether the caller passed
    // `[]u8`, `[]const u8`, `*[N]u8`, etc.
    const Slice = if (is_const_buf) []const u8 else []u8;

    return struct {
        buffer: Slice,
        pos: usize,

        const Self = @This();
        const is_const = is_const_buf;

        pub const ReadError = error{};
        pub const WriteError = error{NoSpaceLeft};

        pub const Reader = struct {
            context: *Self,

            pub fn readAll(r: Reader, dest: []u8) ReadError!usize {
                const s = r.context;
                const n = @min(dest.len, s.buffer.len - s.pos);
                @memcpy(dest[0..n], s.buffer[s.pos..][0..n]);
                s.pos += n;
                return n;
            }

            pub fn readNoEof(r: Reader, dest: []u8) error{EndOfStream}!void {
                const n = readAll(r, dest) catch unreachable;
                if (n != dest.len) return error.EndOfStream;
            }

            pub fn readByte(r: Reader) error{EndOfStream}!u8 {
                const s = r.context;
                if (s.pos >= s.buffer.len) return error.EndOfStream;
                const b = s.buffer[s.pos];
                s.pos += 1;
                return b;
            }

            pub fn readBytesNoEof(r: Reader, comptime n: usize) error{EndOfStream}![n]u8 {
                var buf: [n]u8 = undefined;
                try readNoEof(r, &buf);
                return buf;
            }

            pub fn readInt(r: Reader, comptime T: type, endian: std.builtin.Endian) error{EndOfStream}!T {
                const n = @divExact(@typeInfo(T).int.bits, 8);
                const bytes = try readBytesNoEof(r, n);
                return mem.readInt(T, &bytes, endian);
            }
        };

        pub const Writer = if (is_const) struct {} else struct {
            context: *Self,

            pub fn writeAll(w: Writer, bytes: []const u8) WriteError!void {
                const s = w.context;
                if (bytes.len > s.buffer.len - s.pos) return error.NoSpaceLeft;
                @memcpy(s.buffer[s.pos..][0..bytes.len], bytes);
                s.pos += bytes.len;
            }

            pub fn writeByte(w: Writer, byte: u8) WriteError!void {
                const s = w.context;
                if (s.pos >= s.buffer.len) return error.NoSpaceLeft;
                s.buffer[s.pos] = byte;
                s.pos += 1;
            }

            pub fn writeInt(w: Writer, comptime T: type, value: T, endian: std.builtin.Endian) WriteError!void {
                const n = @divExact(@typeInfo(T).int.bits, 8);
                var buf: [n]u8 = undefined;
                mem.writeInt(T, &buf, value, endian);
                try writeAll(w, &buf);
            }
        };

        pub fn reader(self: *Self) Reader {
            return .{ .context = self };
        }

        pub fn writer(self: *Self) Writer {
            if (is_const) @compileError("writer() unavailable on const-buffered FixedBufferStream");
            return .{ .context = self };
        }

        pub fn getWritten(self: *const Self) Slice {
            return self.buffer[0..self.pos];
        }

        pub fn getPos(self: *const Self) usize {
            return self.pos;
        }

        pub fn seekTo(self: *Self, new_pos: usize) void {
            self.pos = @min(new_pos, self.buffer.len);
        }

        pub fn seekBy(self: *Self, offset: usize) error{NoSpaceLeft}!void {
            if (offset > self.buffer.len - self.pos) return error.NoSpaceLeft;
            self.pos += offset;
        }

        pub fn getEndPos(self: *const Self) usize {
            return self.buffer.len;
        }
    };
}

pub fn fixedBufferStream(buffer: anytype) FixedBufferStream(@TypeOf(buffer)) {
    // Normalize pointer-to-array → slice via `[0..]` so the stored buffer
    // is always a slice; the generic Buffer parameter is only used for
    // const-ness detection.
    return .{ .buffer = buffer[0..], .pos = 0 };
}
