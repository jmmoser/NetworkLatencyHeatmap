// Helpers shared between the scanner (main.zig) and mesh mode (mesh.zig):
// clocks, IP math, latency formatting/colors, and the socket poller.
const std = @import("std");
const posix = std.posix;
const c = std.c;
const builtin = @import("builtin");
const plat = @import("plat.zig");

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
    if (plat.is_windows) {
        // Also enables ANSI escape processing and UTF-8 output on the
        // console, so the colors and block characters render
        stdout_is_tty = plat.windowsSetupConsole();
    } else {
        stdout_is_tty = isatty(posix.STDOUT_FILENO) == 1;
    }
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
    stddev_us: ?u64 = null, // jitter: standard deviation of the samples
    sent: u8 = 0, // latency-phase pings sent
    received: u8 = 0, // latency-phase replies received
    // False for hosts found only in the neighbor (ARP) table: present on
    // the segment but not answering ICMP echo, so no latency samples
    icmp: bool = true,

    // Latency-phase packet loss in percent, null when nothing was sent
    pub fn lossPct(self: PingResult) ?f64 {
        if (self.sent == 0) return null;
        const lost: f64 = @floatFromInt(self.sent - @min(self.received, self.sent));
        return lost / @as(f64, @floatFromInt(self.sent)) * 100.0;
    }
};

// Platform-agnostic event poller for socket readiness
pub const SocketPoller = struct {
    // Use kqueue on macOS/BSD, epoll on Linux, WSAPoll on Windows
    pub const is_darwin = builtin.os.tag == .macos or builtin.os.tag == .ios or
        builtin.os.tag == .watchos or builtin.os.tag == .tvos or
        builtin.os.tag == .freebsd or builtin.os.tag == .netbsd or
        builtin.os.tag == .openbsd or builtin.os.tag == .dragonfly;

    pub const is_linux = builtin.os.tag == .linux;
    pub const is_windows = builtin.os.tag == .windows;

    // The event fd only exists for kqueue/epoll; Windows polls the socket
    // directly (posix.fd_t is not an integer type there)
    const EventFd = if (is_windows) i32 else posix.fd_t;

    fd: EventFd,
    sock: plat.Socket,

    pub fn init(sock: plat.Socket) !SocketPoller {
        if (is_windows) {
            return .{ .fd = -1, .sock = sock };
        } else if (is_darwin) {
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
        if (is_windows) return;
        if (self.fd >= 0) {
            _ = c.close(self.fd);
        }
    }

    // Wait for socket to be readable, returns true if data available, false on timeout
    // timeout_ms: max time to wait in milliseconds
    pub fn wait(self: *SocketPoller, timeout_ms: u32) bool {
        if (is_windows) {
            return plat.pollOne(self.sock, plat.POLL_IN, @intCast(timeout_ms));
        } else if (is_darwin) {
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
    if (plat.is_windows) {
        return plat.windowsMonotonicMicros();
    } else {
        return clockMicros(.MONOTONIC);
    }
}

// Wall clock in µs since the Unix epoch, the same clock domain as the
// kernel's SO_TIMESTAMP receive stamps.
pub fn wallMicros() i64 {
    if (plat.is_windows) {
        return plat.windowsWallMicros();
    } else {
        return clockMicros(.REALTIME);
    }
}

pub fn sleepNanos(ns: u64) void {
    if (plat.is_windows) {
        plat.windowsSleepNanos(ns);
    } else {
        var req: c.timespec = .{
            .sec = @intCast(ns / std.time.ns_per_s),
            .nsec = @intCast(ns % std.time.ns_per_s),
        };
        _ = c.nanosleep(&req, null);
    }
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

// In-place frame overwrite for live TTY views. Clear-then-redraw
// (\x1b[2J followed by many small writes) lets the terminal repaint while
// the screen is blank or half-drawn, which the user sees as flicker.
// Instead, the previous frame is overwritten where it stands: home the
// cursor, rewrite every line erasing only its stale tail (EL), then erase
// whatever rows the previous frame had below this one (ED). No cell is
// ever blanked before its new content is written, so there is no blank
// state to flash — even on terminals that ignore the synchronized-output
// wrap (DEC private mode 2026) asking capable ones to commit the frame
// atomically. The cursor is hidden while it jumps; hide and show travel
// inside the same frame, so it never visibly blinks out. The caller
// emits the encoded frame as a single write.
//
// Overwriting in place only works while the frame fits the window: a
// line wider than the terminal wraps onto a second row and a frame taller
// than it scrolls, after which homing the cursor no longer lands on the
// frame's first line and every redraw leaves a stale copy behind. Given
// the terminal size, lines are clipped to cols-1 columns and the frame to
// rows-1 lines (the final newline must not scroll), with a note in place
// of the cut-off tail.
pub fn encodeFrame(out: *std.Io.Writer, body: []const u8, size: ?plat.TermSize) !void {
    try out.writeAll("\x1b[?2026h\x1b[?25l\x1b[H");

    const max_cols: usize = if (size) |sz| @max(@as(usize, sz.cols), 2) - 1 else std.math.maxInt(usize);
    const max_lines: usize = if (size) |sz| @max(@as(usize, sz.rows), 2) - 1 else std.math.maxInt(usize);
    const total_lines = std.mem.count(u8, body, "\n") + @intFromBool(body.len > 0 and body[body.len - 1] != '\n');
    const keep_lines = if (total_lines > max_lines) max_lines - 1 else total_lines;

    var rest = body;
    var line_no: usize = 0;
    while (std.mem.indexOfScalar(u8, rest, '\n')) |nl| : (line_no += 1) {
        if (line_no >= keep_lines) break;
        try writeClipped(out, rest[0..nl], max_cols);
        try out.writeAll("\x1b[K\n");
        rest = rest[nl + 1 ..];
    } else {
        if (line_no < keep_lines) try writeClipped(out, rest, max_cols);
    }
    if (total_lines > keep_lines) {
        var note_buf: [96]u8 = undefined;
        const note = std.fmt.bufPrint(&note_buf, "{s}  ... {d} more lines; enlarge the terminal to see them{s}", .{
            sgr("\x1b[90m"), total_lines - keep_lines, sgr("\x1b[0m"),
        }) catch "";
        try writeClipped(out, note, max_cols);
        try out.writeAll("\x1b[K\n");
    }
    try out.writeAll("\x1b[0J\x1b[?25h\x1b[?2026l");
}

// Byte length of the UTF-8 sequence starting with `byte` (1 for ASCII and
// stray continuation bytes)
fn utf8Len(byte: u8) usize {
    if (byte < 0xC0) return 1;
    if (byte < 0xE0) return 2;
    if (byte < 0xF0) return 3;
    return 4;
}

// Byte length of the ANSI CSI sequence at s[i..] (0 if there is none)
fn csiLen(s: []const u8, i: usize) usize {
    if (s[i] != 0x1b or i + 1 >= s.len or s[i + 1] != '[') return 0;
    var j = i + 2;
    // Skip until the final byte of the sequence (letter)
    while (j < s.len and (s[j] < 0x40 or s[j] > 0x7E)) : (j += 1) {}
    if (j < s.len) j += 1;
    return j - i;
}

// Write `line` showing at most max_cols visible columns. Escape sequences
// past the cut are still written, so a trailing color reset still applies.
fn writeClipped(out: *std.Io.Writer, line: []const u8, max_cols: usize) !void {
    if (displayWidth(line) <= max_cols) return out.writeAll(line);
    var width: usize = 0;
    var i: usize = 0;
    while (i < line.len) {
        const esc = csiLen(line, i);
        if (esc > 0) {
            try out.writeAll(line[i..][0..esc]);
            i += esc;
            continue;
        }
        const n = @min(utf8Len(line[i]), line.len - i);
        if (width < max_cols) try out.writeAll(line[i..][0..n]);
        width += 1;
        i += n;
    }
}

pub fn displayWidth(s: []const u8) usize {
    // Count display width, accounting for multi-byte UTF-8 and ANSI escape
    // sequences (every character used here is one column wide)
    var width: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const esc = csiLen(s, i);
        if (esc > 0) {
            i += esc;
            continue;
        }
        width += 1;
        i += utf8Len(s[i]);
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

test "encodeFrame overwrites in place: sync wrap, EL per line, ED at end" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try encodeFrame(&w, "ab\ncd\n", null);
    try testing.expectEqualStrings(
        "\x1b[?2026h\x1b[?25l\x1b[H" ++ "ab\x1b[K\ncd\x1b[K\n" ++ "\x1b[0J\x1b[?25h\x1b[?2026l",
        w.buffered(),
    );
    // The frame must never blank the screen before redrawing
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\x1b[2J") == null);
}

test "encodeFrame handles a body without a trailing newline" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try encodeFrame(&w, "tail", null);
    try testing.expectEqualStrings(
        "\x1b[?2026h\x1b[?25l\x1b[H" ++ "tail" ++ "\x1b[0J\x1b[?25h\x1b[?2026l",
        w.buffered(),
    );
}

test "encodeFrame clips wide lines but keeps their escape sequences" {
    var buf: [256]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try encodeFrame(&w, "\x1b[92mabcdef\x1b[0m\nxy\n", .{ .rows = 10, .cols = 4 });
    try testing.expectEqualStrings(
        "\x1b[?2026h\x1b[?25l\x1b[H" ++ "\x1b[92mabc\x1b[0m\x1b[K\nxy\x1b[K\n" ++ "\x1b[0J\x1b[?25h\x1b[?2026l",
        w.buffered(),
    );
}

test "encodeFrame cuts a frame taller than the terminal, leaving a note" {
    const saved = color_enabled;
    defer color_enabled = saved;
    color_enabled = false;

    var buf: [512]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    // 5 lines into a 4-row terminal: 3 rows of frame (2 lines + note), so
    // the final newline never scrolls
    try encodeFrame(&w, "1\n2\n3\n4\n5\n", .{ .rows = 4, .cols = 80 });
    const got = w.buffered();
    try testing.expect(std.mem.startsWith(u8, got, "\x1b[?2026h\x1b[?25l\x1b[H1\x1b[K\n2\x1b[K\n  ... 3 more lines"));
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, got, "\n"));
    try testing.expect(std.mem.endsWith(u8, got, "\x1b[K\n\x1b[0J\x1b[?25h\x1b[?2026l"));
}

test "PingResult.lossPct" {
    var r = PingResult{ .ip = .{ 1, 2, 3, 4 }, .latency_us = null, .latency_avg = null, .latency_max = null };
    try testing.expectEqual(@as(?f64, null), r.lossPct());
    r.sent = 4;
    r.received = 3;
    try testing.expectEqual(@as(?f64, 25.0), r.lossPct());
}

test "monotonicMicros is nondecreasing" {
    const a = monotonicMicros();
    const b = monotonicMicros();
    try testing.expect(b >= a);
    try testing.expect(a > 0);
}
