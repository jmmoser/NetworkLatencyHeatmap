// Helpers shared between the scanner (main.zig) and mesh mode (mesh.zig):
// clocks, IP math, latency formatting/colors, and the socket poller.
const std = @import("std");
const posix = std.posix;
const c = std.c;
const builtin = @import("builtin");

// Writer interface type for Zig 0.16
pub const StdoutWriter = *std.Io.Writer;

// Terminal capabilities, set once at startup by initTerm. Color and the
// \r-rewriting progress lines are only emitted when stdout is a TTY (and
// color can be disabled explicitly via --no-color or the NO_COLOR env var,
// see https://no-color.org).
pub var stdout_is_tty: bool = false;
pub var color_enabled: bool = false;

extern "c" fn isatty(fd: c_int) c_int;

pub fn initTerm(no_color_flag: bool) void {
    stdout_is_tty = isatty(posix.STDOUT_FILENO) == 1;
    // Per https://no-color.org, NO_COLOR disables color when set to any
    // non-empty value
    const no_color_env = c.getenv("NO_COLOR");
    const no_color_set = no_color_env != null and no_color_env.?[0] != 0;
    color_enabled = stdout_is_tty and !no_color_flag and !no_color_set;
}

// Gate an ANSI SGR escape on color support: returns the code unchanged when
// color is enabled, "" otherwise. Call sites format with {s} so disabled
// colors collapse to nothing.
pub fn sgr(code: []const u8) []const u8 {
    return if (color_enabled) code else "";
}

// Carriage-return prefix for lines that overwrite an in-place progress
// line: "\r" on a TTY, "" when output is piped (no progress lines then)
pub fn cr() []const u8 {
    return if (stdout_is_tty) "\r" else "";
}

pub const PingResult = struct {
    ip: [4]u8,
    latency_us: ?u64, // microseconds, null if timeout (min latency)
    latency_avg: ?u64, // average latency
    latency_max: ?u64, // max latency
};

// Platform-agnostic event poller for socket readiness
pub const SocketPoller = struct {
    // Use kqueue on macOS/BSD, epoll on Linux
    pub const is_darwin = builtin.os.tag == .macos or builtin.os.tag == .ios or
        builtin.os.tag == .watchos or builtin.os.tag == .tvos or
        builtin.os.tag == .freebsd or builtin.os.tag == .netbsd or
        builtin.os.tag == .openbsd or builtin.os.tag == .dragonfly;

    pub const is_linux = builtin.os.tag == .linux;

    fd: posix.fd_t,
    sock: posix.fd_t,

    pub fn init(sock: posix.fd_t) !SocketPoller {
        if (is_darwin) {
            const kq = c.kqueue();
            if (kq < 0) return error.PollerInitFailed;
            // Register socket for read events
            const changelist = [_]c.Kevent{.{
                .ident = @intCast(sock),
                .filter = c.EVFILT.READ,
                .flags = c.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            var events: [1]c.Kevent = undefined;
            if (c.kevent(kq, &changelist, changelist.len, &events, 0, null) < 0)
                return error.PollerInitFailed;
            return .{ .fd = kq, .sock = sock };
        } else if (is_linux) {
            const epfd = c.epoll_create1(0);
            if (epfd < 0) return error.PollerInitFailed;
            var ev = std.os.linux.epoll_event{
                .events = std.os.linux.EPOLL.IN,
                .data = .{ .fd = sock },
            };
            if (c.epoll_ctl(epfd, std.os.linux.EPOLL.CTL_ADD, sock, &ev) < 0)
                return error.PollerInitFailed;
            return .{ .fd = epfd, .sock = sock };
        } else {
            // Fallback: no event fd, will use polling
            return .{ .fd = -1, .sock = sock };
        }
    }

    pub fn deinit(self: *SocketPoller) void {
        if (self.fd >= 0) {
            _ = c.close(self.fd);
        }
    }

    // Wait for socket to be readable, returns true if data available, false on timeout
    // timeout_ms: max time to wait in milliseconds
    pub fn wait(self: *SocketPoller, timeout_ms: u32) bool {
        if (is_darwin) {
            const timeout = c.timespec{
                .sec = @intCast(timeout_ms / 1000),
                .nsec = @intCast((timeout_ms % 1000) * 1_000_000),
            };
            var events: [1]c.Kevent = undefined;
            const n = c.kevent(self.fd, &[_]c.Kevent{}, 0, &events, events.len, &timeout);
            return n > 0;
        } else if (is_linux) {
            var events: [1]std.os.linux.epoll_event = undefined;
            const n = c.epoll_wait(self.fd, &events, events.len, @intCast(timeout_ms));
            return n > 0;
        } else {
            // Fallback: block in poll(2) until the socket is readable or the
            // timeout elapses.
            var fds = [_]posix.pollfd{.{ .fd = self.sock, .events = posix.POLL.IN, .revents = 0 }};
            const n = posix.poll(&fds, @intCast(timeout_ms)) catch return false;
            return n > 0;
        }
    }

    // Non-blocking check if data is available (timeout = 0)
    pub fn poll(self: *SocketPoller) bool {
        return self.wait(0);
    }
};

pub fn ipToU32(ip: [4]u8) u32 {
    return @as(u32, ip[0]) << 24 | @as(u32, ip[1]) << 16 | @as(u32, ip[2]) << 8 | @as(u32, ip[3]);
}

pub fn u32ToIp(val: u32) [4]u8 {
    return .{
        @truncate(val >> 24),
        @truncate(val >> 16),
        @truncate(val >> 8),
        @truncate(val),
    };
}

// Monotonic clock in µs: immune to NTP steps and slews of the wall clock.
// Used for all pacing/timeouts and as the step-safe RTT measurement; the
// wall clock is only consulted to compare against kernel receive stamps.
pub fn clockMicros(clk: c.clockid_t) i64 {
    var ts: c.timespec = undefined;
    if (c.clock_gettime(clk, &ts) != 0) return 0;
    return @as(i64, @intCast(ts.sec)) * std.time.us_per_s + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_us);
}

pub fn monotonicMicros() i64 {
    return clockMicros(.MONOTONIC);
}

// Wall clock in µs since the Unix epoch, the same clock domain as the
// kernel's SO_TIMESTAMP receive stamps.
pub fn wallMicros() i64 {
    return clockMicros(.REALTIME);
}

pub fn sleepNanos(ns: u64) void {
    var req: c.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = c.nanosleep(&req, null);
}

pub fn ipToString(ip: [4]u8, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "";
}

pub fn latencyToColor(latency_us: ?u64) []const u8 {
    if (!color_enabled) return "";
    if (latency_us == null) return "\x1b[90m"; // Gray - offline

    const lat = latency_us.?;
    if (lat < 1000) return "\x1b[92m"; // Bright green - excellent (<1ms)
    if (lat < 5000) return "\x1b[32m"; // Green - good (<5ms)
    if (lat < 20000) return "\x1b[93m"; // Yellow - okay (<20ms)
    if (lat < 100000) return "\x1b[33m"; // Orange - slow (<100ms)
    return "\x1b[91m"; // Red - very slow
}

pub fn latencyToBlock(latency_us: ?u64) []const u8 {
    if (latency_us == null) return "·";

    const lat = latency_us.?;
    if (lat < 1000) return "█";
    if (lat < 5000) return "▓";
    if (lat < 20000) return "▒";
    if (lat < 100000) return "░";
    return "▪";
}

pub fn formatLatency(latency_us: ?u64, buf: []u8) []const u8 {
    if (latency_us == null) return "---";

    const lat = latency_us.?;
    if (lat < 1000) {
        return std.fmt.bufPrint(buf, "{d}µs", .{lat}) catch "???";
    } else if (lat < 1000000) {
        return std.fmt.bufPrint(buf, "{d:.1}ms", .{@as(f64, @floatFromInt(lat)) / 1000.0}) catch "???";
    } else {
        return std.fmt.bufPrint(buf, "{d:.1}s", .{@as(f64, @floatFromInt(lat)) / 1000000.0}) catch "???";
    }
}

pub fn displayWidth(s: []const u8) usize {
    // Count display width, accounting for multi-byte UTF-8 and ANSI escape sequences
    var width: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const byte = s[i];
        // Skip ANSI escape sequences (e.g., \x1b[32m)
        if (byte == 0x1b and i + 1 < s.len and s[i + 1] == '[') {
            i += 2;
            // Skip until we hit the final byte of the sequence (letter)
            while (i < s.len and (s[i] < 0x40 or s[i] > 0x7E)) : (i += 1) {}
            if (i < s.len) i += 1; // Skip the final letter
            continue;
        }
        if (byte < 0x80) {
            // ASCII
            width += 1;
            i += 1;
        } else if (byte < 0xE0) {
            // 2-byte UTF-8 (includes µ)
            width += 1;
            i += 2;
        } else if (byte < 0xF0) {
            // 3-byte UTF-8
            width += 1;
            i += 3;
        } else {
            // 4-byte UTF-8
            width += 1;
            i += 4;
        }
    }
    return width;
}

const testing = std.testing;

test "ipToU32 and u32ToIp round-trip" {
    const ip = [4]u8{ 192, 168, 1, 42 };
    try testing.expectEqual(@as(u32, 0xC0A8012A), ipToU32(ip));
    try testing.expectEqual(ip, u32ToIp(ipToU32(ip)));
}

test "displayWidth ignores ANSI escapes and counts multi-byte chars once" {
    try testing.expectEqual(@as(usize, 3), displayWidth("abc"));
    try testing.expectEqual(@as(usize, 5), displayWidth("\x1b[92m1.2ms\x1b[0m"));
    try testing.expectEqual(@as(usize, 5), displayWidth("123µs"));
}

test "sgr and latencyToColor collapse to nothing when color is disabled" {
    const saved = color_enabled;
    defer color_enabled = saved;

    color_enabled = false;
    try testing.expectEqualStrings("", sgr("\x1b[92m"));
    try testing.expectEqualStrings("", latencyToColor(500));
    try testing.expectEqualStrings("", latencyToColor(null));

    color_enabled = true;
    try testing.expectEqualStrings("\x1b[92m", sgr("\x1b[92m"));
    try testing.expectEqualStrings("\x1b[92m", latencyToColor(500));
    try testing.expectEqualStrings("\x1b[90m", latencyToColor(null));
}

test "monotonicMicros is nondecreasing" {
    const a = monotonicMicros();
    const b = monotonicMicros();
    try testing.expect(b >= a);
    try testing.expect(a > 0);
}
