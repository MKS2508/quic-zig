const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

/// Linux sendmmsg batches multiple datagrams into one syscall.
/// Compile-time gate; on other platforms the portable sendmsg loop is used.
const use_sendmmsg = builtin.os.tag == .linux;
const linux = std.os.linux;

/// Runtime kill switch. Set QUIC_ZIG_NO_SENDMMSG=1 to force the sendmsg loop
/// on Linux (useful for bisecting regressions without rebuilding).
const sendmmsg_env_var = "QUIC_ZIG_NO_SENDMMSG";

/// UDP Generic Segmentation Offload (UDP_SEGMENT) is **opt-in**. Set
/// `QUIC_ZIG_ENABLE_GSO=1` to turn it on; it requires sendmmsg and a Linux
/// 4.18+ kernel. Opt-in because GSO currently regresses one interop combo
/// (zig-client → neqo-server bulk transfer over the ns-3 veth simulator;
/// root cause not yet pinpointed). sendmmsg remains default-on since it has
/// no known regressions.
const gso_env_var = "QUIC_ZIG_ENABLE_GSO";

/// Linux UDP GSO socket-level constants (not exposed by std.os.linux).
const SOL_UDP: i32 = 17;
const UDP_SEGMENT: i32 = 103;
/// Linux UDP_MAX_SEGMENTS as of 5.x — matches our MAX_BATCH so one entry can
/// hold a whole run.
const UDP_MAX_SEGMENTS: usize = 64;

/// Linux SO_TXTIME / SCM_TXTIME — kernel-scheduled packet transmission.
/// Payload is a u64 CLOCK_MONOTONIC nanosecond timestamp.
const SOL_SOCKET_LEVEL: i32 = 1;
const SO_TXTIME: i32 = 61;
const SCM_TXTIME: i32 = 61;
const CLOCK_MONOTONIC_ID: i32 = 1;

/// `sock_txtime` passed to setsockopt(SO_TXTIME).
const SockTxtime = extern struct {
    clockid: i32,
    flags: u32,
};

/// Runtime opt-in for SO_TXTIME kernel pacing. Requires a Linux kernel with
/// SO_TXTIME (≥4.19) and an fq qdisc on the egress interface for the kernel
/// to actually honor timestamps. On non-fq paths setsockopt succeeds but the
/// timestamps are ignored — same behavior as today.
const txtime_env_var = "QUIC_ZIG_ENABLE_TXTIME";

// Platform-specific constants for ECN socket options (IPv4).
const IPPROTO_IP: u32 = 0;

const IP_TOS: u32 = switch (builtin.os.tag) {
    .macos => 3,
    .linux => 1,
    .windows => 3, // unused — ECN not supported on Windows
    else => @compileError("unsupported OS for ECN"),
};

const IP_RECVTOS: u32 = switch (builtin.os.tag) {
    .macos => 27,
    .linux => 13,
    .windows => 0, // unused — ECN not supported on Windows
    else => @compileError("unsupported OS for ECN"),
};

// IPv6 ECN constants
const IPV6_TCLASS: u32 = switch (builtin.os.tag) {
    .macos => 36,
    .linux => 67,
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

const IPV6_RECVTCLASS: u32 = switch (builtin.os.tag) {
    .macos => 35,
    .linux => 66,
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

// cmsg_type returned by recvmsg for TOS/ECN ancillary data.
// On macOS, the kernel returns IP_RECVTOS as the cmsg_type.
// On Linux, the kernel returns IP_TOS as the cmsg_type.
const CMSG_TYPE_TOS: u32 = switch (builtin.os.tag) {
    .macos => 27, // IP_RECVTOS
    .linux => 1, // IP_TOS
    .windows => 0,
    else => @compileError("unsupported OS for ECN"),
};

// cmsg header — Zig std doesn't expose this on macOS.
// Not used on Windows.
const CmsgHdr = extern struct {
    cmsg_len: switch (builtin.os.tag) {
        .macos => u32,
        .windows => u32,
        else => usize,
    },
    cmsg_level: i32,
    cmsg_type: i32,
};

const CMSG_HDR_SIZE = @sizeOf(CmsgHdr);

// Aligned cmsg buffer size (header + 4 bytes data, padded to alignment).
const CMSG_SPACE = (CMSG_HDR_SIZE + 4 + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);
const CMSG_BUF_SIZE = CMSG_SPACE * 2; // room for at least 2 cmsgs

/// Per-entry cmsg buffer for UDP_SEGMENT (u16 gso_size payload).
const CMSG_SPACE_U16 = (CMSG_HDR_SIZE + 2 + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);

/// Per-entry cmsg buffer for SCM_TXTIME (u64 ns timestamp).
const CMSG_SPACE_U64 = (CMSG_HDR_SIZE + 8 + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);

/// Combined buffer when both UDP_SEGMENT and SCM_TXTIME apply to an entry.
/// Layout: [UDP_SEGMENT cmsg][SCM_TXTIME cmsg]
const CMSG_SPACE_COMBINED = CMSG_SPACE_U16 + CMSG_SPACE_U64;

/// Raw setsockopt that doesn't panic on EINVAL (needed for trying IPv6 opts on IPv4 sockets).
fn rawSetsockopt(sockfd: posix.socket_t, level: i32, optname: u32, optval: []const u8) void {
    _ = std.c.setsockopt(sockfd, level, @intCast(optname), optval.ptr, @intCast(optval.len));
}

/// Enable receiving ECN/TOS info on incoming packets.
/// No-op on Windows (ECN ancillary data not supported).
pub fn enableEcnRecv(sockfd: posix.socket_t) !void {
    if (comptime is_windows) return;
    const val: u32 = 1;
    const val_bytes = std.mem.asBytes(&val);
    // Enable for IPv4 (may fail on IPv6-only sockets — that's OK)
    rawSetsockopt(sockfd, IPPROTO_IP, IP_RECVTOS, val_bytes);
    // Enable for IPv6 (may fail on IPv4-only sockets — that's OK)
    rawSetsockopt(sockfd, @intCast(posix.IPPROTO.IPV6), IPV6_RECVTCLASS, val_bytes);
}

/// Set the ECN codepoint for outgoing packets (low 2 bits of IP TOS).
/// No-op on Windows.
pub fn setEcnMark(sockfd: posix.socket_t, ecn_mark: u2) !void {
    if (comptime is_windows) return;
    const tos: u32 = @as(u32, ecn_mark);
    const tos_bytes = std.mem.asBytes(&tos);
    // Try both IPv4 and IPv6 — one will fail silently depending on socket family
    rawSetsockopt(sockfd, IPPROTO_IP, IP_TOS, tos_bytes);
    rawSetsockopt(sockfd, @intCast(posix.IPPROTO.IPV6), IPV6_TCLASS, tos_bytes);
}

pub const RecvResult = struct {
    bytes_read: usize,
    from_addr: posix.sockaddr.storage,
    addr_len: posix.socklen_t,
    ecn: u2,
};

/// Receive a UDP datagram and extract the ECN codepoint from ancillary data.
/// On Windows, falls back to recvfrom with ecn=0 (no ancillary data support).
pub fn recvmsgEcn(sockfd: posix.socket_t, buf: []u8) !RecvResult {
    if (comptime is_windows) {
        // Windows fallback: plain recvfrom, no ECN info.
        var from_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
        const bytes_read = try posix.recvfrom(sockfd, buf, 0, @ptrCast(&from_addr), &addr_len);
        return .{
            .bytes_read = bytes_read,
            .from_addr = from_addr,
            .addr_len = addr_len,
            .ecn = 0,
        };
    }

    var iov = [1]posix.iovec{
        .{
            .base = buf.ptr,
            .len = buf.len,
        },
    };

    var cmsg_buf: [CMSG_BUF_SIZE]u8 align(@alignOf(CmsgHdr)) = .{0} ** CMSG_BUF_SIZE;
    var from_addr: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);

    var msg = std.c.msghdr{
        .name = @ptrCast(&from_addr),
        .namelen = addr_len,
        .iov = &iov,
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = CMSG_BUF_SIZE,
        .flags = 0,
    };

    const rc = std.c.recvmsg(sockfd, &msg, 0);
    if (rc < 0) {
        const err = std.posix.errno(rc);
        return switch (err) {
            .AGAIN => error.WouldBlock,
            .CONNREFUSED => error.ConnectionRefused,
            .NOTCONN => error.SocketNotConnected,
            else => posix.unexpectedErrno(err),
        };
    }

    const bytes_read: usize = @intCast(rc);
    addr_len = msg.namelen;

    // Parse cmsg for IP_TOS
    var ecn: u2 = 0;
    var offset: usize = 0;
    while (offset + CMSG_HDR_SIZE <= msg.controllen) {
        const hdr: *const CmsgHdr = @ptrCast(@alignCast(&cmsg_buf[offset]));
        const data_offset = offset + CMSG_HDR_SIZE;
        const data_len = @as(usize, hdr.cmsg_len) -| CMSG_HDR_SIZE;
        const is_ipv4_tos = hdr.cmsg_level == @as(i32, @intCast(IPPROTO_IP)) and
            hdr.cmsg_type == @as(i32, @intCast(CMSG_TYPE_TOS));
        const is_ipv6_tclass = hdr.cmsg_level == @as(i32, @intCast(posix.IPPROTO.IPV6)) and
            hdr.cmsg_type == @as(i32, @intCast(IPV6_TCLASS));
        if ((is_ipv4_tos or is_ipv6_tclass) and
            data_len >= 1 and data_offset < CMSG_BUF_SIZE)
        {
            ecn = @truncate(cmsg_buf[data_offset] & 0x03);
            break;
        }
        // Advance to next cmsg (aligned)
        const total = (CMSG_HDR_SIZE + data_len + @alignOf(CmsgHdr) - 1) & ~@as(usize, @alignOf(CmsgHdr) - 1);
        if (total == 0) break;
        offset += total;
    }

    return .{
        .bytes_read = bytes_read,
        .from_addr = from_addr,
        .addr_len = addr_len,
        .ecn = ecn,
    };
}

/// Convert an AF_INET sockaddr to IPv4-mapped AF_INET6 (::ffff:a.b.c.d) in-place.
/// No-op if already AF_INET6. Useful for dual-stack IPv6 sockets that need to sendto IPv4 addresses.
pub fn mapV4ToV6(storage: *posix.sockaddr.storage) void {
    if (storage.family != posix.AF.INET) return;
    const in_addr: *const posix.sockaddr.in = @ptrCast(@alignCast(storage));
    const v4_bytes: [4]u8 = @bitCast(in_addr.addr);
    const port = in_addr.port;
    var result: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    result.family = posix.AF.INET6;
    const in6: *posix.sockaddr.in6 = @ptrCast(@alignCast(&result));
    in6.addr[10] = 0xff;
    in6.addr[11] = 0xff;
    @memcpy(in6.addr[12..16], &v4_bytes);
    in6.port = port;
    storage.* = result;
}

/// Batch sender that collects outgoing packets and flushes them together.
/// Reduces syscall overhead by batching sendto calls and caching ECN marks.
/// On Linux, flush uses sendmmsg to send many packets per syscall
/// (grouped by ECN mark so the cached IP_TOS stays valid). On other platforms
/// it falls back to a per-packet sendmsg loop.
pub const SendBatch = struct {
    const MAX_BATCH: usize = 64;

    /// Warn every N dropped packets so a stuck send path is visible without
    /// flooding the log when ENOBUFS briefly spikes.
    const DROP_WARN_INTERVAL: u64 = 1024;

    sockfd: posix.socket_t,
    count: usize = 0,
    current_ecn: u2 = 0,

    /// Total packets the kernel refused to accept from this batcher.
    /// UDP is lossy and QUIC loss detection recovers; we just surface a metric.
    dropped_packets: u64 = 0,

    /// Runtime kill switch — resolved once at init, so flush() never touches env.
    use_mmsg: bool = false,

    /// Whether UDP GSO (UDP_SEGMENT) is available and enabled.
    /// Implies use_mmsg; ignored when use_mmsg is false.
    use_gso: bool = false,

    /// Whether SO_TXTIME kernel pacing is available and enabled.
    /// Implies use_mmsg; ignored when use_mmsg is false.
    use_txtime: bool = false,

    // Per-packet data
    addrs: [MAX_BATCH]posix.sockaddr.storage = undefined,
    addr_lens: [MAX_BATCH]posix.socklen_t = undefined,
    offsets: [MAX_BATCH]u32 = undefined, // offset into data_buf
    lengths: [MAX_BATCH]u32 = undefined, // length of each packet
    ecn_marks: [MAX_BATCH]u2 = undefined,
    /// Kernel target transmission time per packet (CLOCK_MONOTONIC ns).
    /// Zero means "send now" (no SCM_TXTIME cmsg attached).
    txtimes: [MAX_BATCH]u64 = undefined,

    // Contiguous buffer holding all packet data
    data_buf: [MAX_BATCH * 1500]u8 = undefined,
    data_len: usize = 0,

    pub fn init(sockfd: posix.socket_t) SendBatch {
        const mmsg_on = use_sendmmsg and !envFlagSet(sendmmsg_env_var);
        // GSO is opt-in: only enabled when QUIC_ZIG_ENABLE_GSO=1 is set.
        const gso_on = mmsg_on and envFlagSet(gso_env_var) and probeGsoSupport(sockfd);
        // SO_TXTIME is opt-in: requires QUIC_ZIG_ENABLE_TXTIME=1 and kernel support.
        const txtime_on = mmsg_on and envFlagSet(txtime_env_var) and probeTxtimeSupport(sockfd);
        return .{
            .sockfd = sockfd,
            .use_mmsg = mmsg_on,
            .use_gso = gso_on,
            .use_txtime = txtime_on,
        };
    }

    /// Add a packet to the batch — sends as soon as the kernel will accept it.
    /// Auto-flushes when full.
    pub fn add(self: *SendBatch, data: []const u8, addr: *const posix.sockaddr, addr_len: posix.socklen_t, ecn: u2) void {
        self.addTxtime(data, addr, addr_len, ecn, 0);
    }

    /// Add a packet with a CLOCK_MONOTONIC target transmission time. The
    /// kernel releases the packet at `txtime_ns` if SO_TXTIME is honored on
    /// the egress qdisc; otherwise behaves like `add`. Pass 0 to opt out
    /// per-packet without disabling TXTIME for the whole socket.
    pub fn addTxtime(
        self: *SendBatch,
        data: []const u8,
        addr: *const posix.sockaddr,
        addr_len: posix.socklen_t,
        ecn: u2,
        txtime_ns: u64,
    ) void {
        if (self.count >= MAX_BATCH or self.data_len + data.len > self.data_buf.len) {
            self.flush();
        }
        const idx = self.count;
        self.offsets[idx] = @intCast(self.data_len);
        self.lengths[idx] = @intCast(data.len);
        @memcpy(self.data_buf[self.data_len..][0..data.len], data);
        self.data_len += data.len;
        self.addrs[idx] = @as(*const posix.sockaddr.storage, @ptrCast(@alignCast(addr))).*;
        self.addr_lens[idx] = addr_len;
        self.ecn_marks[idx] = ecn;
        self.txtimes[idx] = txtime_ns;
        self.count += 1;
    }

    /// Send all queued packets. Dispatches to the fastest available path.
    pub fn flush(self: *SendBatch) void {
        if (self.count == 0) return;
        defer {
            self.count = 0;
            self.data_len = 0;
        }

        if (comptime use_sendmmsg) {
            if (self.use_mmsg) {
                self.flushLinux();
                return;
            }
        }
        self.flushPortable();
    }

    /// Per-packet sendmsg loop — used on macOS/Windows and as the kill-switch fallback.
    fn flushPortable(self: *SendBatch) void {
        for (0..self.count) |i| {
            self.applyEcn(self.ecn_marks[i]);
            const data = self.data_buf[self.offsets[i]..][0..self.lengths[i]];
            var iov = [1]posix.iovec_const{.{
                .base = data.ptr,
                .len = data.len,
            }};
            const msg = std.c.msghdr_const{
                .name = @ptrCast(&self.addrs[i]),
                .namelen = self.addr_lens[i],
                .iov = &iov,
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
            if (std.c.sendmsg(self.sockfd, &msg, 0) < 0) {
                self.recordDrop(1);
            }
        }
    }

    /// Linux sendmmsg path: walks runs of same ECN mark. When GSO is enabled,
    /// each run is further sub-grouped into GSO super-buffers (same peer, same
    /// packet size except possibly the last segment, contiguous in data_buf);
    /// each sub-group becomes one mmsghdr entry carrying a single iovec over
    /// the concatenated segments and a per-entry UDP_SEGMENT cmsg. When TXTIME
    /// is enabled and a packet has a non-zero target timestamp, an SCM_TXTIME
    /// cmsg is stacked alongside; per-packet timestamps within a GSO group must
    /// match (one timestamp applies to the whole super-buffer).
    fn flushLinux(self: *SendBatch) void {
        if (comptime !use_sendmmsg) unreachable;

        // Scratch arrays live on the stack — sized for MAX_BATCH.
        var iovs: [MAX_BATCH]posix.iovec_const = undefined;
        var msgvec: [MAX_BATCH]linux.mmsghdr_const = undefined;
        // Per-entry cmsg buffer sized to fit UDP_SEGMENT + SCM_TXTIME stacked.
        // Unused when both GSO and TXTIME are off and the entry carries one packet.
        var cmsg_bufs: [MAX_BATCH][CMSG_SPACE_COMBINED]u8 align(@alignOf(CmsgHdr)) = undefined;
        // Segment count per mmsghdr entry — used to translate entry-level drops
        // reported by the kernel back into packet counts.
        var seg_counts: [MAX_BATCH]u32 = undefined;

        var start: usize = 0;
        while (start < self.count) {
            // Extend the run while the ECN mark matches the one at `start`.
            const run_ecn = self.ecn_marks[start];
            var end = start + 1;
            while (end < self.count and self.ecn_marks[end] == run_ecn) : (end += 1) {}

            self.applyEcn(run_ecn);

            // Sub-group this ECN run into mmsghdr entries (GSO groups when possible).
            var entries: u32 = 0;
            var g0 = start;
            while (g0 < end) {
                const g1 = if (self.use_gso) self.findGsoGroupEnd(g0, end) else g0 + 1;
                self.fillEntry(entries, g0, g1, &iovs, &msgvec, &cmsg_bufs);
                seg_counts[entries] = @intCast(g1 - g0);
                entries += 1;
                g0 = g1;
            }

            const sent = sendmmsgRun(self.sockfd, &msgvec, entries);
            if (sent < entries) {
                var dropped: u32 = 0;
                for (sent..entries) |i| dropped += seg_counts[i];
                self.recordDrop(dropped);
            }
            start = end;
        }
    }

    /// Return the exclusive end of the maximal GSO group starting at `g0`
    /// within ECN-run `[g0..end)`. Members must share peer address, be
    /// contiguous in data_buf, and have identical size (only the last may be
    /// shorter). When TXTIME is active they must also share the same target
    /// timestamp, since one cmsg applies to the whole super-buffer. Capped at
    /// UDP_MAX_SEGMENTS.
    fn findGsoGroupEnd(self: *const SendBatch, g0: usize, end: usize) usize {
        const gso_size = self.lengths[g0];
        const cap = @min(end, g0 + UDP_MAX_SEGMENTS);
        var g1 = g0 + 1;
        while (g1 < cap) : (g1 += 1) {
            // Prior segment must have been full-size; addresses must match;
            // offsets must be contiguous; current size ≤ gso_size.
            if (self.lengths[g1 - 1] != gso_size) break;
            if (!sameSockaddr(&self.addrs[g1], &self.addrs[g0])) break;
            if (self.addr_lens[g1] != self.addr_lens[g0]) break;
            if (self.offsets[g1] != self.offsets[g1 - 1] + self.lengths[g1 - 1]) break;
            if (self.lengths[g1] > gso_size) break;
            if (self.use_txtime and self.txtimes[g1] != self.txtimes[g0]) break;
        }
        return g1;
    }

    /// Populate one mmsghdr slot covering packets `[g0..g1)`. Stacks
    /// UDP_SEGMENT (when the group has more than one segment) and SCM_TXTIME
    /// (when TXTIME is active and the group's target timestamp is non-zero).
    fn fillEntry(
        self: *SendBatch,
        entry_idx: u32,
        g0: usize,
        g1: usize,
        iovs: *[MAX_BATCH]posix.iovec_const,
        msgvec: *[MAX_BATCH]linux.mmsghdr_const,
        cmsg_bufs: *[MAX_BATCH][CMSG_SPACE_COMBINED]u8,
    ) void {
        const first_off = self.offsets[g0];
        const last_end = self.offsets[g1 - 1] + self.lengths[g1 - 1];
        const total_bytes = last_end - first_off;

        iovs[entry_idx] = .{
            .base = self.data_buf[first_off..].ptr,
            .len = total_bytes,
        };

        // Compose cmsgs into the per-entry buffer, in fixed order:
        // UDP_SEGMENT first (offset 0), then SCM_TXTIME (offset CMSG_SPACE_U16).
        var control_ptr: ?*const anyopaque = null;
        var control_len: usize = 0;
        // Each entry slot is CMSG_SPACE_COMBINED bytes; the outer array's
        // alignment guarantees the start of every slot is CmsgHdr-aligned
        // because CMSG_SPACE_COMBINED is a multiple of @alignOf(CmsgHdr).
        const buf_ptr: [*]align(@alignOf(CmsgHdr)) u8 = @ptrCast(@alignCast(&cmsg_bufs[entry_idx]));
        if (g1 - g0 > 1) {
            writeUdpSegmentCmsg(buf_ptr, @intCast(self.lengths[g0]));
            control_ptr = @ptrCast(buf_ptr);
            control_len = CMSG_SPACE_U16;
        }
        if (self.use_txtime and self.txtimes[g0] != 0) {
            writeTxtimeCmsg(@alignCast(buf_ptr + control_len), self.txtimes[g0]);
            if (control_ptr == null) control_ptr = @ptrCast(buf_ptr);
            control_len += CMSG_SPACE_U64;
        }

        msgvec[entry_idx] = .{
            .hdr = .{
                .name = @ptrCast(&self.addrs[g0]),
                .namelen = self.addr_lens[g0],
                .iov = @ptrCast(&iovs[entry_idx]),
                .iovlen = 1,
                .control = control_ptr,
                .controllen = control_len,
                .flags = 0,
            },
            .len = 0,
        };
    }

    /// Issue one sendmmsg syscall for `n` packets starting at `msgvec`.
    /// Retries once on EINTR when no packets have been sent yet.
    /// Returns the number of packets the kernel accepted.
    fn sendmmsgRun(sockfd: posix.socket_t, msgvec: [*]linux.mmsghdr_const, n: u32) u32 {
        var attempts: u2 = 0;
        while (true) : (attempts += 1) {
            const rc = linux.sendmmsg(sockfd, msgvec, n, 0);
            switch (linux.E.init(rc)) {
                .SUCCESS => return @intCast(rc),
                .INTR => if (attempts == 0) continue else return 0,
                else => return 0,
            }
        }
    }

    /// Update the socket ECN mark via setsockopt, skipping the syscall when
    /// the mark hasn't changed since the last send.
    fn applyEcn(self: *SendBatch, ecn: u2) void {
        if (ecn == self.current_ecn) return;
        self.current_ecn = ecn;
        setEcnMark(self.sockfd, ecn) catch {};
    }

    fn recordDrop(self: *SendBatch, n: u32) void {
        const before = self.dropped_packets;
        self.dropped_packets += n;
        // Log only when we cross a DROP_WARN_INTERVAL boundary.
        const crossed = (before / DROP_WARN_INTERVAL) != (self.dropped_packets / DROP_WARN_INTERVAL);
        if (crossed) {
            std.log.warn("ecn_socket: {d} outgoing UDP packets dropped so far", .{self.dropped_packets});
        }
    }
};

/// Compare two sockaddr_storage values for equality on the address bytes
/// actually used by the current family. Avoids false-negatives from padding.
fn sameSockaddr(a: *const posix.sockaddr.storage, b: *const posix.sockaddr.storage) bool {
    if (a.family != b.family) return false;
    return switch (a.family) {
        posix.AF.INET => blk: {
            const a4: *const posix.sockaddr.in = @ptrCast(@alignCast(a));
            const b4: *const posix.sockaddr.in = @ptrCast(@alignCast(b));
            break :blk a4.port == b4.port and a4.addr == b4.addr;
        },
        posix.AF.INET6 => blk: {
            const a6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(a));
            const b6: *const posix.sockaddr.in6 = @ptrCast(@alignCast(b));
            break :blk a6.port == b6.port and
                a6.flowinfo == b6.flowinfo and
                a6.scope_id == b6.scope_id and
                std.mem.eql(u8, &a6.addr, &b6.addr);
        },
        else => std.mem.eql(u8, std.mem.asBytes(a), std.mem.asBytes(b)),
    };
}

/// Encode a UDP_SEGMENT cmsg (u16 gso_size) into the caller-provided buffer.
fn writeUdpSegmentCmsg(buf: [*]align(@alignOf(CmsgHdr)) u8, gso_size: u16) void {
    const hdr: *CmsgHdr = @ptrCast(@alignCast(buf));
    hdr.cmsg_len = CMSG_HDR_SIZE + @sizeOf(u16);
    hdr.cmsg_level = SOL_UDP;
    hdr.cmsg_type = UDP_SEGMENT;
    std.mem.writeInt(u16, buf[CMSG_HDR_SIZE..][0..@sizeOf(u16)], gso_size, builtin.cpu.arch.endian());
}

/// Encode a SCM_TXTIME cmsg (u64 ns timestamp) into the caller-provided buffer.
fn writeTxtimeCmsg(buf: [*]align(@alignOf(CmsgHdr)) u8, txtime_ns: u64) void {
    const hdr: *CmsgHdr = @ptrCast(@alignCast(buf));
    hdr.cmsg_len = CMSG_HDR_SIZE + @sizeOf(u64);
    hdr.cmsg_level = SOL_SOCKET_LEVEL;
    hdr.cmsg_type = SCM_TXTIME;
    std.mem.writeInt(u64, buf[CMSG_HDR_SIZE..][0..@sizeOf(u64)], txtime_ns, builtin.cpu.arch.endian());
}

/// Treats an env var as a boolean flag: unset, empty, or "0" → false; anything else → true.
fn envFlagSet(name: [:0]const u8) bool {
    if (comptime is_windows) return false;
    const value = std.posix.getenv(name) orelse return false;
    return !(value.len == 0 or std.mem.eql(u8, value, "0"));
}

/// Probe UDP_SEGMENT support at init so flush() never fails on unsupported kernels.
/// Setting gso_size=0 is a no-op that simply validates the kernel recognises the
/// option; Linux 4.18+ returns 0, older kernels return ENOPROTOOPT.
fn probeGsoSupport(sockfd: posix.socket_t) bool {
    if (comptime !use_sendmmsg) return false;
    const zero: u16 = 0;
    const rc = std.c.setsockopt(
        sockfd,
        SOL_UDP,
        UDP_SEGMENT,
        std.mem.asBytes(&zero).ptr,
        @sizeOf(u16),
    );
    return rc == 0;
}

/// Enable SO_TXTIME on `sockfd` and return whether the kernel accepted it.
/// On non-fq egress paths the kernel still accepts the sockopt but ignores
/// per-packet timestamps — same observable behavior as no-TXTIME, no error
/// path needed in flush(). Older kernels (<4.19) return ENOPROTOOPT.
fn probeTxtimeSupport(sockfd: posix.socket_t) bool {
    if (comptime !use_sendmmsg) return false;
    const cfg: SockTxtime = .{ .clockid = CLOCK_MONOTONIC_ID, .flags = 0 };
    const rc = std.c.setsockopt(
        sockfd,
        SOL_SOCKET_LEVEL,
        SO_TXTIME,
        std.mem.asBytes(&cfg).ptr,
        @sizeOf(SockTxtime),
    );
    return rc == 0;
}

/// Send a single packet directly from the caller's buffer (zero-copy send path).
/// Avoids the batch memcpy overhead for single-packet sends — the common case
/// for latency-sensitive echo/datagram workloads.
pub fn sendDirect(sockfd: posix.socket_t, data: []const u8, addr: *const posix.sockaddr.storage, addr_len: posix.socklen_t, ecn: u2, current_ecn: *u2) void {
    if (ecn != current_ecn.*) {
        current_ecn.* = ecn;
        setEcnMark(sockfd, ecn) catch {};
    }
    var iov = [1]posix.iovec_const{.{
        .base = data.ptr,
        .len = data.len,
    }};
    const msg = std.c.msghdr_const{
        .name = @ptrCast(addr),
        .namelen = addr_len,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    _ = std.c.sendmsg(sockfd, &msg, 0);
}

// Tests — ECN ancillary data tests only run on POSIX platforms.
test "enableEcnRecv on a real socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());

    try enableEcnRecv(sockfd);
}

test "setEcnMark on a real socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());

    // ECT(0) = 0b10 = 2
    try setEcnMark(sockfd, 0b10);
    // Not-ECT = 0b00 = 0
    try setEcnMark(sockfd, 0b00);
}

test "SendBatch delivers mixed-ECN packets in order" {
    if (comptime is_windows) return error.SkipZigTest;

    const rx = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(rx);
    const tx = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer posix.close(tx);

    const bind_addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(rx, &bind_addr.any, bind_addr.getOsSockLen());
    try enableEcnRecv(rx);

    var peer: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    var peer_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try posix.getsockname(rx, @ptrCast(&peer), &peer_len);

    var batch = SendBatch.init(tx);
    // Alternate ECN marks to exercise the run-segmentation logic.
    const payloads = [_][]const u8{ "aa", "bb", "cc", "dd", "ee" };
    const marks = [_]u2{ 0, 0b10, 0b10, 0, 0b01 };
    for (payloads, marks) |p, m| {
        batch.add(p, @ptrCast(&peer), peer_len, m);
    }
    batch.flush();
    try std.testing.expectEqual(@as(u64, 0), batch.dropped_packets);

    // Drain the receiver — order should match the send order on loopback.
    var buf: [64]u8 = undefined;
    // Give the kernel a moment to queue everything (loopback is fast but not sync).
    var received: usize = 0;
    const deadline = std.time.milliTimestamp() + 200;
    while (received < payloads.len and std.time.milliTimestamp() < deadline) {
        const r = recvmsgEcn(rx, &buf) catch |err| switch (err) {
            error.WouldBlock => {
                std.Thread.sleep(1 * std.time.ns_per_ms);
                continue;
            },
            else => return err,
        };
        try std.testing.expectEqualSlices(u8, payloads[received], buf[0..r.bytes_read]);
        received += 1;
    }
    try std.testing.expectEqual(payloads.len, received);
}

test "findGsoGroupEnd groups uniform same-peer runs" {
    // Grouping logic is OS-agnostic — exercise it on all platforms.
    var batch: SendBatch = .{ .sockfd = -1 };
    const peer = std.mem.zeroes(posix.sockaddr.storage);
    // 5 identical-size same-peer packets, contiguous.
    for (0..5) |i| {
        batch.addrs[i] = peer;
        batch.addr_lens[i] = @sizeOf(posix.sockaddr.storage);
        batch.offsets[i] = @intCast(i * 1200);
        batch.lengths[i] = 1200;
        batch.ecn_marks[i] = 0;
    }
    batch.count = 5;
    try std.testing.expectEqual(@as(usize, 5), batch.findGsoGroupEnd(0, 5));
}

test "findGsoGroupEnd splits on address change" {
    var batch: SendBatch = .{ .sockfd = -1 };
    var peer_a: posix.sockaddr.storage = std.mem.zeroes(posix.sockaddr.storage);
    peer_a.family = posix.AF.INET;
    const a4: *posix.sockaddr.in = @ptrCast(@alignCast(&peer_a));
    a4.port = 1111;
    a4.addr = 0x01010101;
    var peer_b = peer_a;
    const b4: *posix.sockaddr.in = @ptrCast(@alignCast(&peer_b));
    b4.addr = 0x02020202;
    batch.addrs[0] = peer_a;
    batch.addrs[1] = peer_a;
    batch.addrs[2] = peer_b;
    for (0..3) |i| {
        batch.addr_lens[i] = @sizeOf(posix.sockaddr.in);
        batch.offsets[i] = @intCast(i * 1200);
        batch.lengths[i] = 1200;
        batch.ecn_marks[i] = 0;
    }
    batch.count = 3;
    // Group ends where peer changes (index 2).
    try std.testing.expectEqual(@as(usize, 2), batch.findGsoGroupEnd(0, 3));
    try std.testing.expectEqual(@as(usize, 3), batch.findGsoGroupEnd(2, 3));
}

test "findGsoGroupEnd allows only the last segment to be shorter" {
    var batch: SendBatch = .{ .sockfd = -1 };
    const peer = std.mem.zeroes(posix.sockaddr.storage);
    const sizes = [_]u32{ 1200, 1200, 900, 1200 };
    var off: u32 = 0;
    for (sizes, 0..) |s, i| {
        batch.addrs[i] = peer;
        batch.addr_lens[i] = @sizeOf(posix.sockaddr.storage);
        batch.offsets[i] = off;
        batch.lengths[i] = s;
        batch.ecn_marks[i] = 0;
        off += s;
    }
    batch.count = 4;
    // [0..3) = two full + one short tail (OK).
    try std.testing.expectEqual(@as(usize, 3), batch.findGsoGroupEnd(0, 4));
    // [2..4) = short then full — the full packet after a short breaks the run.
    try std.testing.expectEqual(@as(usize, 3), batch.findGsoGroupEnd(2, 4));
}

test "findGsoGroupEnd caps at UDP_MAX_SEGMENTS" {
    var batch: SendBatch = .{ .sockfd = -1 };
    const peer = std.mem.zeroes(posix.sockaddr.storage);
    for (0..SendBatch.MAX_BATCH) |i| {
        batch.addrs[i] = peer;
        batch.addr_lens[i] = @sizeOf(posix.sockaddr.storage);
        batch.offsets[i] = @intCast(i * 1200);
        batch.lengths[i] = 1200;
        batch.ecn_marks[i] = 0;
    }
    batch.count = SendBatch.MAX_BATCH;
    try std.testing.expectEqual(UDP_MAX_SEGMENTS, batch.findGsoGroupEnd(0, SendBatch.MAX_BATCH));
}

test "recvmsgEcn returns WouldBlock on empty socket" {
    if (comptime is_windows) return error.SkipZigTest;
    const sockfd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
    defer posix.close(sockfd);

    const addr = try std.net.Address.parseIp4("127.0.0.1", 0);
    try posix.bind(sockfd, &addr.any, addr.getOsSockLen());
    try enableEcnRecv(sockfd);

    var buf: [1500]u8 = undefined;
    const result = recvmsgEcn(sockfd, &buf);
    try std.testing.expectError(error.WouldBlock, result);
}
