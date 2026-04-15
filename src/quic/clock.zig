const std = @import("std");
const builtin = @import("builtin");

/// Read `CLOCK_MONOTONIC` in nanoseconds.
///
/// The Pacer uses this clock so its `last_sent_time` values can be handed to
/// the Linux kernel as `SO_TXTIME`/`SCM_TXTIME` timestamps, which require a
/// monotonic source. Loss detection, PTO, and idle-timeout code paths continue
/// to use `std.time.nanoTimestamp()` (REALTIME) — those only consume durations
/// within a single clock, so the split is safe.
pub fn monoNanos() i64 {
    // On Windows there is no POSIX CLOCK_MONOTONIC; fall back to the default
    // `nanoTimestamp()` so the pacer still works. Non-issue for SO_TXTIME,
    // which is Linux-only anyway.
    if (comptime builtin.os.tag == .windows) {
        return @intCast(std.time.nanoTimestamp());
    }
    const ts = std.posix.clock_gettime(.MONOTONIC) catch {
        return @intCast(std.time.nanoTimestamp());
    };
    return @as(i64, ts.sec) * std.time.ns_per_s + @as(i64, ts.nsec);
}

test "monoNanos is non-decreasing" {
    const a = monoNanos();
    const b = monoNanos();
    try std.testing.expect(b >= a);
}
