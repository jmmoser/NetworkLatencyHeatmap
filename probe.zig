// TCP connect probing shared by mesh mode: measure RTT to a host as the
// time from SYN to the first response — a SYN-ACK if the port is open, or
// an RST if it is closed. Either way the target's network stack answered,
// so both are valid latency samples; `refused` records which one it was.
//
// A completed handshake is torn down with SO_LINGER {on, 0s}, which makes
// close() send an RST (with a zero window) instead of a graceful FIN
// exchange: no TIME_WAIT piles up on either side, and the accepting
// application (if any) sees an abort rather than a phantom client.
//
// This works against hosts that aren't running this tool at all — anything
// with a known TCP port (a router's web UI, an SSH server, a printer)
// answers a SYN with either SYN-ACK or RST.
const std = @import("std");
const posix = std.posix;
const c = std.c;
const common = @import("common.zig");

// Cap on --tcp-ping targets and on one probe batch (peers + extras)
pub const max_targets = 16;
pub const max_batch = 64;

// Rolling window of RTT samples per probed target
pub const stats_window = 8;

pub const TcpTarget = struct {
    ip: [4]u8,
    port: u16,
};

// Parse "a.b.c.d:port"; null on anything malformed or port 0
pub fn parseTcpTarget(arg: []const u8) ?TcpTarget {
    const colon = std.mem.lastIndexOfScalar(u8, arg, ':') orelse return null;
    const port = std.fmt.parseInt(u16, arg[colon + 1 ..], 10) catch return null;
    if (port == 0) return null;

    var ip: [4]u8 = undefined;
    var octets = std.mem.splitScalar(u8, arg[0..colon], '.');
    var i: usize = 0;
    while (octets.next()) |octet| : (i += 1) {
        if (i >= 4) return null;
        ip[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
    }
    if (i != 4) return null;
    return .{ .ip = ip, .port = port };
}

pub const Outcome = struct {
    rtt_us: ?u32, // null = no response within the timeout
    refused: bool, // response was an RST (closed port) rather than a SYN-ACK
};

// Per-target rolling RTT stats fed by repeated probe rounds. A miss (no
// response) doesn't pollute the samples but is counted, so a target that
// stopped answering ages out of the display instead of showing stale numbers.
pub const ProbeStats = struct {
    samples: [stats_window]u32 = undefined,
    count: u8 = 0,
    idx: u8 = 0,
    refused: bool = false, // whether the newest sample came from an RST
    misses: u8 = 0, // consecutive probes with no response

    pub fn record(self: *ProbeStats, outcome: Outcome) void {
        if (outcome.rtt_us) |rtt| {
            self.samples[self.idx] = rtt;
            self.idx = (self.idx + 1) % stats_window;
            if (self.count < stats_window) self.count += 1;
            self.refused = outcome.refused;
            self.misses = 0;
        } else if (self.misses < std.math.maxInt(u8)) {
            self.misses += 1;
        }
    }

    pub fn avg(self: *const ProbeStats) ?u64 {
        if (self.count == 0) return null;
        var total: u64 = 0;
        for (self.samples[0..self.count]) |s| total += s;
        return total / self.count;
    }

    pub fn last(self: *const ProbeStats) ?u64 {
        if (self.count == 0) return null;
        return self.samples[(self.idx + stats_window - 1) % stats_window];
    }

    // False once several probes in a row went unanswered — the stored
    // samples are then history, not the current state of the target
    pub fn alive(self: *const ProbeStats) bool {
        return self.count > 0 and self.misses < 3;
    }
};

fn setNonblocking(fd: posix.fd_t) bool {
    const flags = c.fcntl(fd, posix.F.GETFL, @as(c_int, 0));
    if (flags < 0) return false;
    const FlagsInt = std.meta.Int(.unsigned, @bitSizeOf(posix.O));
    const o_nonblock: FlagsInt = @bitCast(posix.O{ .NONBLOCK = true });
    return c.fcntl(fd, posix.F.SETFL, flags | @as(c_int, o_nonblock)) >= 0;
}

// Abortive close: RST with a zero window instead of FIN/ACK teardown
fn rstClose(fd: posix.fd_t) void {
    const lo = c.linger{ .onoff = 1, .linger = 0 };
    _ = c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.LINGER, &lo, @sizeOf(c.linger));
    _ = c.close(fd);
}

fn clampRtt(delta_us: i64) u32 {
    return @intCast(std.math.clamp(delta_us, 0, std.math.maxInt(u32)));
}

// Probe every address concurrently: fire all the SYNs, then poll the whole
// set until each socket resolves or the deadline passes. Concurrency keeps
// one dead target from serializing the batch behind its timeout, and RTTs
// are taken at poll wakeup, so they aren't quantized by any caller's loop.
//
// Blocks up to timeout_ms; run it off the latency-critical path (mesh mode
// runs it on a dedicated thread).
pub fn tcpProbeBatch(addrs: []const posix.sockaddr.in, results: []Outcome, timeout_ms: u32) void {
    std.debug.assert(addrs.len == results.len);
    std.debug.assert(addrs.len <= max_batch);

    var fds: [max_batch]posix.fd_t = undefined;
    var t0: [max_batch]i64 = undefined;
    var pending: [max_batch]bool = @splat(false);

    for (addrs, 0..) |*addr, i| {
        results[i] = .{ .rtt_us = null, .refused = false };
        const fd_c = c.socket(posix.AF.INET, c.SOCK.STREAM, 0);
        if (fd_c < 0) continue;
        const fd: posix.fd_t = @intCast(fd_c);
        if (!setNonblocking(fd)) {
            _ = c.close(fd);
            continue;
        }
        t0[i] = common.monotonicMicros();
        const rc = c.connect(fd, @ptrCast(addr), @sizeOf(posix.sockaddr.in));
        if (rc == 0) {
            // Connected synchronously (loopback / same host)
            results[i] = .{ .rtt_us = clampRtt(common.monotonicMicros() - t0[i]), .refused = false };
            rstClose(fd);
            continue;
        }
        if (std.c._errno().* != @intFromEnum(posix.E.INPROGRESS)) {
            // No route, no buffers, ... — not a latency signal
            _ = c.close(fd);
            continue;
        }
        fds[i] = fd;
        pending[i] = true;
    }

    const deadline = common.monotonicMicros() + @as(i64, timeout_ms) * std.time.us_per_ms;
    while (true) {
        var pfds: [max_batch]posix.pollfd = undefined;
        var map: [max_batch]usize = undefined;
        var n: usize = 0;
        for (pending, 0..) |p, i| {
            if (!p) continue;
            pfds[n] = .{ .fd = fds[i], .events = posix.POLL.OUT, .revents = 0 };
            map[n] = i;
            n += 1;
        }
        if (n == 0) break;

        const now = common.monotonicMicros();
        if (now >= deadline) break;
        const wait_ms: c_int = @intCast(@min(
            @divFloor(deadline - now, std.time.us_per_ms) + 1,
            @as(i64, timeout_ms),
        ));
        const rc = c.poll(&pfds, @intCast(n), wait_ms);
        if (rc < 0) {
            if (std.c._errno().* == @intFromEnum(posix.E.INTR)) continue;
            break;
        }
        if (rc == 0) break; // timed out

        const t1 = common.monotonicMicros();
        for (pfds[0..n], 0..) |*p, k| {
            if (p.revents == 0) continue;
            const i = map[k];
            // POLLOUT with SO_ERROR 0 is a completed handshake (SYN-ACK
            // arrived); POLLERR/POLLHUP resolve through SO_ERROR too
            var soerr: c_int = 0;
            var len: posix.socklen_t = @sizeOf(c_int);
            _ = c.getsockopt(fds[i], posix.SOL.SOCKET, posix.SO.ERROR, &soerr, &len);
            const rtt = clampRtt(t1 - t0[i]);
            if (soerr == 0) {
                results[i] = .{ .rtt_us = rtt, .refused = false };
                rstClose(fds[i]);
            } else if (soerr == @intFromEnum(posix.E.CONNREFUSED) or
                soerr == @intFromEnum(posix.E.CONNRESET))
            {
                // The RST came from the target's stack: RTT is still real
                results[i] = .{ .rtt_us = rtt, .refused = true };
                _ = c.close(fds[i]);
            } else {
                // Unreachable / timed out in the stack: no sample
                _ = c.close(fds[i]);
            }
            pending[i] = false;
        }
    }

    // Whatever never resolved: closing aborts the kernel's SYN retries
    for (pending, 0..) |p, i| {
        if (p) _ = c.close(fds[i]);
    }
}

const testing = std.testing;

test "parseTcpTarget accepts ip:port and rejects malformed input" {
    const t = parseTcpTarget("192.168.1.1:443").?;
    try testing.expectEqual([4]u8{ 192, 168, 1, 1 }, t.ip);
    try testing.expectEqual(@as(u16, 443), t.port);

    try testing.expect(parseTcpTarget("192.168.1.1") == null); // no port
    try testing.expect(parseTcpTarget("192.168.1:80") == null); // 3 octets
    try testing.expect(parseTcpTarget("192.168.1.1.5:80") == null); // 5 octets
    try testing.expect(parseTcpTarget("192.168.1.256:80") == null); // bad octet
    try testing.expect(parseTcpTarget("192.168.1.1:0") == null); // port 0
    try testing.expect(parseTcpTarget("192.168.1.1:99999") == null); // port range
    try testing.expect(parseTcpTarget("host:80") == null); // not an IP
}

test "ProbeStats rolls a window and tracks misses" {
    var s = ProbeStats{};
    try testing.expectEqual(@as(?u64, null), s.avg());
    try testing.expect(!s.alive());

    s.record(.{ .rtt_us = 100, .refused = false });
    s.record(.{ .rtt_us = 300, .refused = true });
    try testing.expectEqual(@as(?u64, 200), s.avg());
    try testing.expectEqual(@as(?u64, 300), s.last());
    try testing.expect(s.refused);
    try testing.expect(s.alive());

    // Misses don't change samples but eventually mark the target dead
    s.record(.{ .rtt_us = null, .refused = false });
    s.record(.{ .rtt_us = null, .refused = false });
    try testing.expect(s.alive());
    s.record(.{ .rtt_us = null, .refused = false });
    try testing.expect(!s.alive());
    try testing.expectEqual(@as(?u64, 200), s.avg());

    // A fresh response revives it
    s.record(.{ .rtt_us = 200, .refused = false });
    try testing.expect(s.alive());
    try testing.expectEqual(@as(?u64, 200), s.last());

    // Window caps at stats_window samples
    for (0..stats_window * 2) |_| s.record(.{ .rtt_us = 50, .refused = false });
    try testing.expectEqual(@as(u8, stats_window), s.count);
    try testing.expectEqual(@as(?u64, 50), s.avg());
}

test "tcpProbeBatch measures open and closed loopback ports" {
    const loopback = [4]u8{ 127, 0, 0, 1 };

    // Listener on an ephemeral port: probing it must yield a non-refused RTT
    const lfd_c = c.socket(posix.AF.INET, c.SOCK.STREAM, 0);
    try testing.expect(lfd_c >= 0);
    const lfd: posix.fd_t = @intCast(lfd_c);
    defer _ = c.close(lfd);
    var laddr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.bytesToValue(u32, &loopback),
    };
    try testing.expect(c.bind(lfd, @ptrCast(&laddr), @sizeOf(posix.sockaddr.in)) == 0);
    try testing.expect(c.listen(lfd, 4) == 0);
    var llen: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    try testing.expect(c.getsockname(lfd, @ptrCast(&laddr), &llen) == 0);

    // A port that was just free: probing it must yield a refused RTT
    var closed_addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.bytesToValue(u32, &loopback),
    };
    {
        const tmp_c = c.socket(posix.AF.INET, c.SOCK.STREAM, 0);
        try testing.expect(tmp_c >= 0);
        const tmp: posix.fd_t = @intCast(tmp_c);
        try testing.expect(c.bind(tmp, @ptrCast(&closed_addr), @sizeOf(posix.sockaddr.in)) == 0);
        var clen: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        try testing.expect(c.getsockname(tmp, @ptrCast(&closed_addr), &clen) == 0);
        _ = c.close(tmp);
    }

    const addrs = [2]posix.sockaddr.in{ laddr, closed_addr };
    var results: [2]Outcome = undefined;
    tcpProbeBatch(&addrs, &results, 1000);

    try testing.expect(results[0].rtt_us != null);
    try testing.expect(!results[0].refused);
    try testing.expect(results[1].rtt_us != null);
    try testing.expect(results[1].refused);
}
