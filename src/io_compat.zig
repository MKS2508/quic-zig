//! Zig 0.15-style `fixedBufferStream` over a fixed []u8 buffer.
//!
//! The 0.16 stdlib dropped `std.io.fixedBufferStream` in favor of
//! `std.Io.Reader.fixed` / `std.Io.Writer.fixed`. This shim bridges the
//! remaining call sites while the migration is in progress. The FBS
//! struct itself exposes the `*std.Io.Reader`-compatible surface
//! (field names `seek`/`buffer`, methods `takeByte`/`takeInt`/
//! `readSliceAll`/`takeArray`/`writeByte`/`writeAll`/`writeInt`/
//! `buffered`) so migrating a call site is literally replacing
//! `var fbs = io.fixedBufferStream(...)` with
//! `var reader: std.Io.Reader = .fixed(...)` — the surrounding method
//! calls stay the same.
//!
//! Legacy helpers (`.reader()`, `.writer()`, `.pos` as `getPos()`,
//! `.getWritten()`, `.seekBy()`, `.readByte`, `.readInt`, `.readNoEof`,
//! `.readBytesNoEof`, `.readAll`) remain during the transition.

const std = @import("std");
const mem = std.mem;
const builtin = std.builtin;

pub fn FixedBufferStream(comptime Buffer: type) type {
    comptime std.debug.assert(@typeInfo(Buffer) == .pointer);
    const is_const_buf = @typeInfo(Buffer).pointer.is_const;
    const Slice = if (is_const_buf) []const u8 else []u8;

    return struct {
        buffer: Slice,
        seek: usize,

        const Self = @This();
        const is_const = is_const_buf;

        pub const ReadError = error{};
        pub const WriteError = error{NoSpaceLeft};

        // --- std.Io.Reader-compatible (takes *Self) -------------------------

        pub fn takeByte(self: *Self) error{EndOfStream}!u8 {
            if (self.seek >= self.buffer.len) return error.EndOfStream;
            const b = self.buffer[self.seek];
            self.seek += 1;
            return b;
        }

        pub fn takeInt(self: *Self, comptime T: type, endian: std.builtin.Endian) error{EndOfStream}!T {
            const n = @divExact(@typeInfo(T).int.bits, 8);
            if (self.buffer.len - self.seek < n) return error.EndOfStream;
            const slice = self.buffer[self.seek..][0..n];
            self.seek += n;
            return mem.readInt(T, slice, endian);
        }

        pub fn readSliceAll(self: *Self, dest: []u8) error{EndOfStream}!void {
            if (self.buffer.len - self.seek < dest.len) return error.EndOfStream;
            @memcpy(dest, self.buffer[self.seek..][0..dest.len]);
            self.seek += dest.len;
        }

        pub fn readSliceShort(self: *Self, dest: []u8) ReadError!usize {
            const n = @min(dest.len, self.buffer.len - self.seek);
            @memcpy(dest[0..n], self.buffer[self.seek..][0..n]);
            self.seek += n;
            return n;
        }

        pub fn takeArray(self: *Self, comptime n: usize) error{EndOfStream}!*[n]u8 {
            if (self.buffer.len - self.seek < n) return error.EndOfStream;
            const ptr: *[n]u8 = @ptrCast(self.buffer[self.seek..][0..n].ptr);
            self.seek += n;
            return ptr;
        }

        // --- std.Io.Writer-compatible forwarders (mutable buffer only) ------

        pub fn writeAll(self: *Self, bytes: []const u8) WriteError!void {
            if (comptime is_const) return;
            if (bytes.len > self.buffer.len - self.seek) return error.NoSpaceLeft;
            @memcpy(self.buffer[self.seek..][0..bytes.len], bytes);
            self.seek += bytes.len;
        }

        pub fn writeByte(self: *Self, byte: u8) WriteError!void {
            if (comptime is_const) return;
            if (self.seek >= self.buffer.len) return error.NoSpaceLeft;
            self.buffer[self.seek] = byte;
            self.seek += 1;
        }

        pub fn writeInt(self: *Self, comptime T: type, value: T, endian: std.builtin.Endian) WriteError!void {
            if (comptime is_const) return;
            const n = @divExact(@typeInfo(T).int.bits, 8);
            if (self.buffer.len - self.seek < n) return error.NoSpaceLeft;
            mem.writeInt(T, self.buffer[self.seek..][0..n], value, endian);
            self.seek += n;
        }

        pub fn buffered(self: *const Self) Slice {
            return self.buffer[0..self.seek];
        }

        // --- Inner Reader / Writer wrappers (legacy 0.15 API) ---------------
        // Retained so `const reader = fbs.reader();` call sites keep working.
        // Methods dispatch through the stored *Self pointer; fields `.seek`
        // and `.buffer` are NOT exposed here — access those via the
        // FBS itself.

        pub const Reader = struct {
            fbs: *Self,

            pub fn takeByte(self: Reader) error{EndOfStream}!u8 {
                return self.fbs.takeByte();
            }
            pub fn takeInt(self: Reader, comptime T: type, endian: std.builtin.Endian) error{EndOfStream}!T {
                return self.fbs.takeInt(T, endian);
            }
            pub fn readSliceAll(self: Reader, dest: []u8) error{EndOfStream}!void {
                return self.fbs.readSliceAll(dest);
            }
            pub fn readSliceShort(self: Reader, dest: []u8) ReadError!usize {
                return self.fbs.readSliceShort(dest);
            }
            pub fn takeArray(self: Reader, comptime n: usize) error{EndOfStream}!*[n]u8 {
                return self.fbs.takeArray(n);
            }
            // 0.15 aliases
            pub fn readByte(self: Reader) error{EndOfStream}!u8 {
                return self.fbs.takeByte();
            }
            pub fn readInt(self: Reader, comptime T: type, endian: std.builtin.Endian) error{EndOfStream}!T {
                return self.fbs.takeInt(T, endian);
            }
            pub fn readNoEof(self: Reader, dest: []u8) error{EndOfStream}!void {
                return self.fbs.readSliceAll(dest);
            }
            pub fn readBytesNoEof(self: Reader, comptime n: usize) error{EndOfStream}![n]u8 {
                var buf: [n]u8 = undefined;
                try self.fbs.readSliceAll(&buf);
                return buf;
            }
            pub fn readAll(self: Reader, dest: []u8) ReadError!usize {
                return self.fbs.readSliceShort(dest);
            }
        };

        pub const Writer = struct {
            fbs: *Self,

            pub fn writeAll(self: Writer, bytes: []const u8) WriteError!void {
                return self.fbs.writeAll(bytes);
            }
            pub fn writeByte(self: Writer, byte: u8) WriteError!void {
                return self.fbs.writeByte(byte);
            }
            pub fn writeInt(self: Writer, comptime T: type, value: T, endian: std.builtin.Endian) WriteError!void {
                return self.fbs.writeInt(T, value, endian);
            }
        };

        pub fn reader(self: *Self) Reader {
            return .{ .fbs = self };
        }

        pub fn writer(self: *Self) Writer {
            return .{ .fbs = self };
        }

        pub fn getWritten(self: *const Self) Slice {
            return self.buffered();
        }

        pub fn getPos(self: *const Self) usize {
            return self.seek;
        }

        pub fn seekTo(self: *Self, new_seek: usize) void {
            self.seek = @min(new_seek, self.buffer.len);
        }

        pub fn seekBy(self: *Self, offset: usize) error{NoSpaceLeft}!void {
            if (offset > self.buffer.len - self.seek) return error.NoSpaceLeft;
            self.seek += offset;
        }

        pub fn getEndPos(self: *const Self) usize {
            return self.buffer.len;
        }

        // Legacy 0.15 method-name forwarders on FBS itself.
        pub fn readByte(self: *Self) error{EndOfStream}!u8 {
            return takeByte(self);
        }
        pub fn readInt(self: *Self, comptime T: type, endian: std.builtin.Endian) error{EndOfStream}!T {
            return takeInt(self, T, endian);
        }
        pub fn readNoEof(self: *Self, dest: []u8) error{EndOfStream}!void {
            return readSliceAll(self, dest);
        }
        pub fn readBytesNoEof(self: *Self, comptime n: usize) error{EndOfStream}![n]u8 {
            var buf: [n]u8 = undefined;
            try readSliceAll(self, &buf);
            return buf;
        }
        pub fn readAll(self: *Self, dest: []u8) ReadError!usize {
            return readSliceShort(self, dest);
        }
    };
}

pub fn fixedBufferStream(buffer: anytype) FixedBufferStream(@TypeOf(buffer)) {
    return .{ .buffer = buffer[0..], .seek = 0 };
}
