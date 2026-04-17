//! Thin POSIX syscall wrappers replacing the 0.15 `std.posix.*` helpers
//! that Zig 0.16 removed. Structured for cross-platform with `@compileError`
//! branches for unimplemented platforms — we only claim to work where we
//! actually test. Currently: Linux, macOS, FreeBSD.
//!
//! Naming mirrors the old `std.posix.X` so migration at call sites is
//! a one-word swap (`posix.socket` → `sys.socket`). Constants
//! (`AF`, `SOCK`, `IPPROTO`, `SOL`, `SO`) still live on `std.posix`.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const c = std.c;

// BSD/Darwin-only. 0.16 std.c drops the declaration; declare locally.
extern "c" fn arc4random_buf(buf: [*]u8, nbytes: usize) void;
const c_arc4random_buf = arc4random_buf;

pub const socket_t = posix.socket_t;
pub const fd_t = posix.fd_t;
pub const sockaddr = posix.sockaddr;
pub const socklen_t = posix.socklen_t;
pub const timespec = posix.timespec;

/// setsockopt survived in std.posix on POSIX targets; re-export so callers
/// only need one namespace.
pub const setsockopt = posix.setsockopt;

// --- errors ---

pub const SocketError = error{
    AddressFamilyNotSupported,
    ProtocolFamilyNotSupported,
    ProtocolNotSupported,
    SystemFdQuotaExceeded,
    ProcessFdQuotaExceeded,
    SystemResources,
    PermissionDenied,
    Unexpected,
};

pub const BindError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    AddressFamilyNotSupported,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    NotDir,
    ReadOnlyFileSystem,
    NetworkSubsystemFailed,
    FileDescriptorNotASocket,
    AlreadyBound,
    Unexpected,
};

pub const SendToError = error{
    WouldBlock,
    ConnectionResetByPeer,
    MessageTooBig,
    SystemResources,
    BrokenPipe,
    NetworkUnreachable,
    HostUnreachable,
    AccessDenied,
    NetworkSubsystemFailed,
    FileDescriptorNotASocket,
    AddressFamilyNotSupported,
    Unexpected,
};

pub const RecvFromError = error{
    WouldBlock,
    SystemResources,
    ConnectionRefused,
    ConnectionResetByPeer,
    NetworkSubsystemFailed,
    SocketNotConnected,
    Unexpected,
};

pub const GetSockNameError = error{
    SystemResources,
    NetworkSubsystemFailed,
    NotSocket,
    SocketNotBound,
    Unexpected,
};

pub const ClockGetTimeError = error{
    UnsupportedClock,
    Unexpected,
};

pub const GetRandomError = error{
    Unexpected,
};

// --- functions ---

pub fn socket(domain: u32, sock_type: u32, protocol: u32) SocketError!socket_t {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.socket: Windows support pending"),
        else => @compileError("sys.socket: unsupported OS"),
    }
    // On Darwin, SOCK.NONBLOCK / SOCK.CLOEXEC are not accepted by socket(2)
    // and must be applied via fcntl after creation.
    const darwin_family = switch (builtin.os.tag) {
        .macos, .ios, .watchos, .tvos, .visionos => true,
        else => false,
    };
    const filtered_type: u32 = if (darwin_family)
        sock_type & ~@as(u32, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC)
    else
        sock_type;
    const rc = c.socket(@intCast(domain), @intCast(filtered_type), @intCast(protocol));
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .ACCES => return error.PermissionDenied,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .INVAL => return error.ProtocolFamilyNotSupported,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolNotSupported,
        else => |err| return unexpected(err),
    }
    const fd: socket_t = @intCast(rc);
    if (darwin_family and (sock_type & posix.SOCK.NONBLOCK) != 0) {
        const nonblock: c_int = @bitCast(posix.O{ .NONBLOCK = true });
        _ = c.fcntl(fd, posix.F.SETFL, nonblock);
    }
    if (darwin_family and (sock_type & posix.SOCK.CLOEXEC) != 0) {
        const cloexec: c_int = posix.FD_CLOEXEC;
        _ = c.fcntl(fd, posix.F.SETFD, cloexec);
    }
    return fd;
}

pub fn close(fd: fd_t) void {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.close: Windows support pending"),
        else => @compileError("sys.close: unsupported OS"),
    }
    // close(2) failures are unrecoverable from userspace (EINTR/EIO on some systems),
    // and retrying EINTR close is itself an anti-pattern on Linux — follow libc practice.
    _ = c.close(fd);
}

pub fn bind(sock: socket_t, addr: *const sockaddr, len: socklen_t) BindError!void {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.bind: Windows support pending"),
        else => @compileError("sys.bind: unsupported OS"),
    }
    const rc = c.bind(sock, addr, len);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .BADF => unreachable, // always a race condition
        .INVAL => return error.AlreadyBound,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .FAULT => unreachable,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .ROFS => return error.ReadOnlyFileSystem,
        else => |err| return unexpected(err),
    }
}

pub fn sendto(
    sock: socket_t,
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const sockaddr,
    addrlen: socklen_t,
) SendToError!usize {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.sendto: Windows support pending"),
        else => @compileError("sys.sendto: unsupported OS"),
    }
    const rc = c.sendto(sock, buf.ptr, buf.len, flags, dest_addr, addrlen);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .AGAIN => return error.WouldBlock,
        .ALREADY => return error.WouldBlock,
        .BADF => unreachable, // always a race condition
        .CONNRESET => return error.ConnectionResetByPeer,
        .DESTADDRREQ => unreachable, // non-null dest_addr required
        .FAULT => unreachable,
        .INTR => return error.Unexpected,
        .INVAL => unreachable,
        .ISCONN => unreachable,
        .MSGSIZE => return error.MessageTooBig,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .OPNOTSUPP => unreachable,
        .PIPE => return error.BrokenPipe,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .LOOP => return error.Unexpected,
        .NAMETOOLONG => return error.Unexpected,
        .NOENT => return error.Unexpected,
        .NOTDIR => return error.Unexpected,
        .HOSTUNREACH => return error.HostUnreachable,
        .NETUNREACH => return error.NetworkUnreachable,
        .NOTCONN => return error.Unexpected,
        .NETDOWN => return error.NetworkSubsystemFailed,
        else => |err| return unexpected(err),
    }
}

pub fn recvfrom(
    sock: socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*sockaddr,
    addrlen: ?*socklen_t,
) RecvFromError!usize {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.recvfrom: Windows support pending"),
        else => @compileError("sys.recvfrom: unsupported OS"),
    }
    const rc = c.recvfrom(sock, buf.ptr, buf.len, flags, src_addr, addrlen);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .BADF => unreachable, // always a race condition
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .FAULT => unreachable,
        .INTR => return error.Unexpected,
        .INVAL => unreachable,
        .NOMEM => return error.SystemResources,
        .NOTCONN => return error.SocketNotConnected,
        .NOTSOCK => unreachable,
        .NETDOWN => return error.NetworkSubsystemFailed,
        else => |err| return unexpected(err),
    }
}

/// Raw write(2) — replaces `posix.write` for TCP streams etc.
pub fn write(fd: fd_t, bytes: []const u8) WriteError!usize {
    while (true) {
        const rc = c.write(fd, bytes.ptr, bytes.len);
        if (rc < 0) switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => return 0,
            .DQUOT => return error.DiskQuota,
            .NOSPC => return error.NoSpaceLeft,
            .PIPE => return error.BrokenPipe,
            .IO => return error.InputOutput,
            .CONNRESET => return error.ConnectionResetByPeer,
            .ACCES, .PERM => return error.AccessDenied,
            else => |err| return unexpected(err),
        };
        return @intCast(rc);
    }
}

/// Raw read(2) — replaces `posix.read` for TCP streams etc.
pub fn read(fd: fd_t, dest: []u8) ReadError!usize {
    while (true) {
        const rc = c.read(fd, dest.ptr, dest.len);
        if (rc < 0) switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => return 0,
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .ACCES, .PERM => return error.AccessDenied,
            else => |err| return unexpected(err),
        };
        return @intCast(rc);
    }
}

pub const ListenError = error{
    AddressInUse,
    FileDescriptorNotASocket,
    SystemResources,
    OperationNotSupported,
    Unexpected,
};

pub fn listen(sock: socket_t, backlog: u31) ListenError!void {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.listen: Windows support pending"),
        else => @compileError("sys.listen: unsupported OS"),
    }
    const rc = c.listen(sock, @intCast(backlog));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ADDRINUSE => return error.AddressInUse,
        .BADF => unreachable,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .OPNOTSUPP => return error.OperationNotSupported,
        else => |err| return unexpected(err),
    }
}

pub const AcceptError = error{
    WouldBlock,
    ConnectionAborted,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    ProtocolFailure,
    Unexpected,
};

pub fn accept(sock: socket_t) AcceptError!socket_t {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.accept: Windows support pending"),
        else => @compileError("sys.accept: unsupported OS"),
    }
    const rc = c.accept(sock, null, null);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .BADF => unreachable,
        .CONNABORTED => return error.ConnectionAborted,
        .FAULT => unreachable,
        .INTR => return error.WouldBlock,
        .INVAL => unreachable,
        .NOTSOCK => unreachable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .OPNOTSUPP => unreachable,
        .PROTO => return error.ProtocolFailure,
        else => |err| return unexpected(err),
    }
}

pub fn getsockname(sock: socket_t, addr: *sockaddr, addrlen: *socklen_t) GetSockNameError!void {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.getsockname: Windows support pending"),
        else => @compileError("sys.getsockname: unsupported OS"),
    }
    const rc = c.getsockname(sock, addr, addrlen);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .BADF => unreachable,
        .FAULT => unreachable,
        .INVAL => return error.SocketNotBound,
        .NOBUFS => return error.SystemResources,
        .NOTSOCK => return error.NotSocket,
        .NETDOWN => return error.NetworkSubsystemFailed,
        else => |err| return unexpected(err),
    }
}

/// Sleep for the given number of nanoseconds. Replaces `std.Thread.sleep`
/// which was removed in Zig 0.16.
pub fn sleepNs(ns: u64) void {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.sleepNs: Windows support pending (use SleepEx)"),
        else => @compileError("sys.sleepNs: unsupported OS"),
    }
    var req: timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: timespec = undefined;
    while (c.nanosleep(&req, &rem) == -1) {
        switch (posix.errno(@as(c_int, -1))) {
            .INTR => {
                req = rem;
                continue;
            },
            else => return,
        }
    }
}

/// Monotonic clock timestamp in nanoseconds (replaces `std.time.nanoTimestamp`).
pub fn nanoTimestamp() i64 {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.nanoTimestamp: Windows support pending (use QueryPerformanceCounter)"),
        else => @compileError("sys.nanoTimestamp: unsupported OS"),
    }
    var ts: timespec = undefined;
    const rc = c.clock_gettime(posix.CLOCK.MONOTONIC, &ts);
    if (rc != 0) return 0; // monotonic clock should never fail; fall back to 0.
    return @as(i64, ts.sec) * std.time.ns_per_s + @as(i64, ts.nsec);
}

/// Return a single random integer of the given type (replaces
/// `std.crypto.random.int(T)` for small integer types).
pub fn randomInt(comptime T: type) T {
    var bytes: [@sizeOf(T)]u8 = undefined;
    randomBytes(&bytes);
    return std.mem.readInt(T, &bytes, .little);
}

/// Read cryptographic randomness into buf (replaces `std.crypto.random.bytes`).
/// Uses arc4random_buf on macOS/BSD and getrandom on Linux.
pub fn randomBytes(buf: []u8) void {
    switch (builtin.os.tag) {
        .linux => {
            var off: usize = 0;
            while (off < buf.len) {
                const rc = std.os.linux.getrandom(buf[off..].ptr, buf.len - off, 0);
                switch (posix.errno(@as(isize, @bitCast(rc)))) {
                    .SUCCESS => off += rc,
                    .INTR => continue,
                    else => @panic("getrandom failed"),
                }
            }
        },
        .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .openbsd => {
            // arc4random_buf is always available and never fails on BSD/Darwin.
            c_arc4random_buf(buf.ptr, buf.len);
        },
        .windows => @compileError("sys.randomBytes: Windows support pending (use BCryptGenRandom)"),
        else => @compileError("sys.randomBytes: unsupported OS"),
    }
}

/// getenv: look up an environment variable. Returns null if not set.
/// On POSIX this is a direct libc getenv() call; the returned slice
/// points into libc-managed static storage and must not be freed.
pub fn getenv(name: [*:0]const u8) ?[:0]const u8 {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.getenv: Windows support pending (use GetEnvironmentVariableW)"),
        else => @compileError("sys.getenv: unsupported OS"),
    }
    const raw = c.getenv(name) orelse return null;
    return std.mem.span(raw);
}

fn unexpected(err: posix.E) error{Unexpected} {
    if (builtin.mode == .Debug) {
        std.log.warn("sys: unexpected errno: {t}", .{err});
    }
    return error.Unexpected;
}

// --- file I/O ---

pub const OpenError = error{
    FileNotFound,
    AccessDenied,
    IsDir,
    NameTooLong,
    SystemResources,
    NoSpaceLeft,
    PathAlreadyExists,
    SystemFdQuotaExceeded,
    ProcessFdQuotaExceeded,
    PathTooLong,
    Unexpected,
};

pub const WriteError = error{
    DiskQuota,
    NoSpaceLeft,
    BrokenPipe,
    InputOutput,
    ConnectionResetByPeer,
    AccessDenied,
    Unexpected,
};

pub const ReadError = error{
    InputOutput,
    AccessDenied,
    IsDir,
    Unexpected,
};

/// A minimal file handle with close/writeAll/readAll, replacing the
/// 0.15 `std.fs.File` for the narrow ways we use it.
pub const File = struct {
    fd: fd_t,

    pub fn close(self: File) void {
        closeFd(self.fd);
    }

    pub fn writeAll(self: File, bytes: []const u8) WriteError!void {
        var written: usize = 0;
        while (written < bytes.len) {
            const rc = c.write(self.fd, bytes[written..].ptr, bytes.len - written);
            if (rc < 0) {
                switch (posix.errno(rc)) {
                    .INTR => continue,
                    .AGAIN => continue,
                    .DQUOT => return error.DiskQuota,
                    .NOSPC => return error.NoSpaceLeft,
                    .PIPE => return error.BrokenPipe,
                    .IO => return error.InputOutput,
                    .CONNRESET => return error.ConnectionResetByPeer,
                    .ACCES, .PERM => return error.AccessDenied,
                    else => |err| return unexpected(err),
                }
            }
            written += @intCast(rc);
        }
    }

    pub fn read(self: File, dest: []u8) ReadError!usize {
        while (true) {
            const rc = c.read(self.fd, dest.ptr, dest.len);
            if (rc < 0) {
                switch (posix.errno(rc)) {
                    .INTR => continue,
                    .AGAIN => return 0,
                    .IO => return error.InputOutput,
                    .ISDIR => return error.IsDir,
                    .ACCES, .PERM => return error.AccessDenied,
                    else => |err| return unexpected(err),
                }
            }
            return @intCast(rc);
        }
    }

    pub const Stat = struct { size: u64 };

    pub fn stat(self: File) !Stat {
        var st: posix.Stat = undefined;
        const rc = c.fstat(self.fd, &st);
        if (rc != 0) switch (posix.errno(rc)) {
            else => |err| return unexpected(err),
        };
        return .{ .size = @intCast(st.size) };
    }
};

fn closeFd(fd: fd_t) void {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.closeFd: Windows support pending"),
        else => @compileError("sys.closeFd: unsupported OS"),
    }
    _ = c.close(fd);
}

/// Null-terminate a path onto a stack buffer. Errors if the path would
/// overflow PATH_MAX.
fn pathZ(path: []const u8, buf: *[std.fs.max_path_bytes]u8) OpenError![:0]const u8 {
    if (path.len >= buf.len) return error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

/// Open an existing file for reading. Replaces `std.fs.cwd().openFile`.
pub fn openFileRead(path: []const u8) OpenError!File {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.openFileRead: Windows support pending"),
        else => @compileError("sys.openFileRead: unsupported OS"),
    }
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathZ(path, &path_buf);
    const flags: posix.O = .{ .ACCMODE = .RDONLY };
    const rc = c.open(z.ptr, flags, @as(posix.mode_t, 0));
    switch (posix.errno(rc)) {
        .SUCCESS => return .{ .fd = @intCast(rc) },
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .ISDIR => return error.IsDir,
        .NAMETOOLONG => return error.NameTooLong,
        .NOMEM => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => |err| return unexpected(err),
    }
}

/// Create/truncate a file for writing (mode 0644 on POSIX). Replaces
/// the `std.fs.cwd().createFile(path, .{})` pattern.
pub fn createFile(path: []const u8) OpenError!File {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.createFile: Windows support pending"),
        else => @compileError("sys.createFile: unsupported OS"),
    }
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathZ(path, &path_buf);
    const flags: posix.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true };
    const rc = c.open(z.ptr, flags, @as(posix.mode_t, 0o644));
    switch (posix.errno(rc)) {
        .SUCCESS => return .{ .fd = @intCast(rc) },
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .ISDIR => return error.IsDir,
        .NAMETOOLONG => return error.NameTooLong,
        .NOMEM => return error.SystemResources,
        .NOSPC => return error.NoSpaceLeft,
        .EXIST => return error.PathAlreadyExists,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => |err| return unexpected(err),
    }
}

pub const MakeDirError = error{
    PathAlreadyExists,
    AccessDenied,
    FileNotFound,
    NoSpaceLeft,
    NotDir,
    PathTooLong,
    Unexpected,
};

/// Create a directory (mode 0755). Returns `PathAlreadyExists` if it
/// already exists — callers can catch that and treat as success.
pub fn makeDir(path: []const u8) MakeDirError!void {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.makeDir: Windows support pending"),
        else => @compileError("sys.makeDir: unsupported OS"),
    }
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathZBad(path, &path_buf);
    const rc = c.mkdir(z.ptr, @as(posix.mode_t, 0o755));
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .EXIST => return error.PathAlreadyExists,
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .NOSPC => return error.NoSpaceLeft,
        .NOTDIR => return error.NotDir,
        .NAMETOOLONG => return error.PathTooLong,
        else => |err| return unexpected(err),
    }
}

fn pathZBad(path: []const u8, buf: *[std.fs.max_path_bytes]u8) MakeDirError![:0]const u8 {
    if (path.len >= buf.len) return error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

/// Read the entire contents of `path` into a newly-allocated buffer.
/// Replaces the `std.fs.cwd().readFileAlloc(gpa, path, max)` pattern.
pub fn readFileAlloc(
    gpa: std.mem.Allocator,
    path: []const u8,
    max_bytes: usize,
) ![]u8 {
    switch (builtin.os.tag) {
        .linux, .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => {},
        .windows => @compileError("sys.readFileAlloc: Windows support pending"),
        else => @compileError("sys.readFileAlloc: unsupported OS"),
    }
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const z = try pathZ(path, &path_buf);
    const flags: posix.O = .{ .ACCMODE = .RDONLY };
    const fd_rc = c.open(z.ptr, flags, @as(posix.mode_t, 0));
    if (fd_rc < 0) switch (posix.errno(fd_rc)) {
        .ACCES, .PERM => return error.AccessDenied,
        .NOENT => return error.FileNotFound,
        .ISDIR => return error.IsDir,
        .NAMETOOLONG => return error.NameTooLong,
        .NOMEM => return error.SystemResources,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        else => |err| return unexpected(err),
    };
    const fd: fd_t = @intCast(fd_rc);
    defer closeFd(fd);

    // Read in chunks; grow the buffer as needed up to max_bytes.
    var buf = try gpa.alloc(u8, 4096);
    errdefer gpa.free(buf);
    var len: usize = 0;
    while (true) {
        if (len == buf.len) {
            if (len >= max_bytes) return error.StreamTooLong;
            const new_size = @min(buf.len * 2, max_bytes);
            buf = try gpa.realloc(buf, new_size);
        }
        const rc = c.read(fd, buf[len..].ptr, buf.len - len);
        if (rc < 0) switch (posix.errno(rc)) {
            .INTR => continue,
            .AGAIN => continue,
            .IO => return error.InputOutput,
            .ISDIR => return error.IsDir,
            .ACCES, .PERM => return error.AccessDenied,
            else => |err| return unexpected(err),
        };
        if (rc == 0) break; // EOF
        len += @intCast(rc);
    }
    return gpa.realloc(buf, len);
}
