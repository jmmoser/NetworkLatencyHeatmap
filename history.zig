// The time axis: a rolling per-host record of the last `max_scans` scans,
// so the heatmap can show *when* a host went bad, not just that it is bad
// right now. One History is kept per vantage point (our own scans, and in
// mesh mode one per peer, fed from its gossiped results).
//
// Each scan contributes one Cell per tracked host. A host that was not
// discovered in a scan gets an `absent` cell (sent = 0), so the columns of
// every host line up in time and an intermittent host shows as a broken
// strip rather than silently shrinking. Cells are colored by the worse of
// two dimensions — latency tier and packet loss — so a host answering 2 of
// 5 probes at 1ms is not painted healthy green just because the replies
// that did arrive were fast.
const std = @import("std");
const common = @import("common.zig");

pub const StdoutWriter = common.StdoutWriter;

// Scans remembered per host (columns of history). Display width is chosen
// from the terminal at render time, never more than this.
pub const max_scans = 120;

// Sentinel: host was discovered but produced no latency sample
pub const no_data: u32 = 0xFFFF_FFFF;

// One host in one scan
pub const Cell = struct {
    avg_us: u32 = no_data,
    sent: u8 = 0, // probes sent in the latency phase; 0 = not discovered
    received: u8 = 0,

    pub const absent = Cell{};

    pub fn lossPct(self: Cell) u8 {
        if (self.sent == 0) return 0;
        const lost: u32 = self.sent - @min(self.sent, self.received);
        return @intCast(lost * 100 / self.sent);
    }

    pub fn avg(self: Cell) ?u64 {
        return if (self.avg_us == no_data or self.received == 0) null else self.avg_us;
    }
};

// Severity of a cell, ordered so `max` picks the worse of two dimensions
pub const Tier = enum(u3) {
    excellent, // < 1ms, no loss
    good, // < 5ms
    okay, // < 20ms, or loss ≤ 20%
    slow, // < 100ms, or loss ≤ 50%
    bad, // ≥ 100ms, or loss > 50%
    dead, // discovered, but no probe answered
    absent, // not discovered in this scan

    pub fn glyph(self: Tier) []const u8 {
        return switch (self) {
            .excellent => "█",
            .good => "▓",
            .okay => "▒",
            .slow => "░",
            .bad => "▪",
            .dead => "×",
            .absent => "·",
        };
    }

    pub fn color(self: Tier) []const u8 {
        return common.sgr(switch (self) {
            .excellent => "\x1b[92m",
            .good => "\x1b[32m",
            .okay => "\x1b[93m",
            .slow => "\x1b[33m",
            .bad, .dead => "\x1b[91m",
            .absent => "\x1b[90m",
        });
    }
};

pub fn latencyTier(avg_us: u64) Tier {
    if (avg_us < 1_000) return .excellent;
    if (avg_us < 5_000) return .good;
    if (avg_us < 20_000) return .okay;
    if (avg_us < 100_000) return .slow;
    return .bad;
}

pub fn lossTier(loss_pct: u8) Tier {
    if (loss_pct == 0) return .excellent;
    if (loss_pct <= 20) return .okay;
    if (loss_pct <= 50) return .slow;
    return .bad;
}

pub fn cellTier(cell: Cell) Tier {
    if (cell.sent == 0) return .absent;
    const avg = cell.avg() orelse return .dead;
    const lat = latencyTier(avg);
    const loss = lossTier(cell.lossPct());
    return @enumFromInt(@max(@intFromEnum(lat), @intFromEnum(loss)));
}

// "Much slower than baseline": 3x AND more than jitter noise apart. Shared
// with the mesh view's cross-observer spread check.
pub fn muchSlower(baseline_us: u64, current_us: u64) bool {
    return current_us >= baseline_us * 3 and (current_us - baseline_us) > 2000;
}

// A cell is bad relative to a baseline when the host vanished, dropped
// probes, or answered much slower than it usually does
fn cellIsBad(cell: Cell, baseline_us: u64) bool {
    const avg = cell.avg() orelse return true; // absent or dead
    return cell.lossPct() >= 20 or muchSlower(baseline_us, avg);
}

pub const HostHistory = struct {
    cells: [max_scans]Cell = undefined,
    head: u16 = 0, // next write slot
    len: u16 = 0,
    seen_scan: u64 = 0, // History.scan_count when last present, for eviction
    touched: u64 = 0, // History.scan_count of the scan currently being recorded

    fn push(self: *HostHistory, cell: Cell) void {
        self.cells[self.head] = cell;
        self.head = (self.head + 1) % max_scans;
        if (self.len < max_scans) self.len += 1;
    }

    // Cell `age` scans back (0 = newest); null beyond what is recorded
    pub fn at(self: *const HostHistory, age: usize) ?Cell {
        if (age >= self.len) return null;
        const idx = (@as(usize, self.head) + max_scans - 1 - age) % max_scans;
        return self.cells[idx];
    }

    pub fn latest(self: *const HostHistory) ?Cell {
        return self.at(0);
    }

    // Aggregates over the whole recorded window
    pub const Window = struct {
        samples: usize = 0, // cells with a latency sample
        avg_us: ?u64 = null, // mean of per-scan averages
        worst_us: ?u64 = null,
        sent: u32 = 0,
        received: u32 = 0,
        absent: usize = 0, // scans the host was not discovered in

        pub fn lossPct(self: Window) u8 {
            if (self.sent == 0) return 0;
            const lost = self.sent - @min(self.sent, self.received);
            return @intCast(lost * 100 / self.sent);
        }
    };

    pub fn window(self: *const HostHistory) Window {
        var w = Window{};
        var total: u64 = 0;
        var age: usize = 0;
        while (self.at(age)) |cell| : (age += 1) {
            if (cell.sent == 0) {
                w.absent += 1;
                continue;
            }
            w.sent += cell.sent;
            w.received += cell.received;
            if (cell.avg()) |a| {
                w.samples += 1;
                total += a;
                w.worst_us = @max(w.worst_us orelse 0, a);
            }
        }
        if (w.samples > 0) w.avg_us = total / w.samples;
        return w;
    }

    // Median of per-scan averages over ages [from, len), or null with fewer
    // than `min_samples` data points — the host's "usual" latency
    fn baseline(self: *const HostHistory, from: usize, min_samples: usize) ?u64 {
        var avgs: [max_scans]u64 = undefined;
        var n: usize = 0;
        var age = from;
        while (self.at(age)) |cell| : (age += 1) {
            if (cell.avg()) |a| {
                avgs[n] = a;
                n += 1;
            }
        }
        if (n < min_samples) return null;
        std.mem.sort(u64, avgs[0..n], {}, std.sort.asc(u64));
        return avgs[n / 2];
    }
};

pub const ChangeKind = enum {
    offline, // vanished or stopped answering
    lossy, // answering, but dropping probes
    degraded, // answering, but much slower than its baseline
    appeared, // a host not seen before

    fn severity(self: ChangeKind) u8 {
        return switch (self) {
            .offline => 0,
            .lossy => 1,
            .degraded => 2,
            .appeared => 3,
        };
    }
};

// A host whose recent scans differ from how it usually behaves
pub const Change = struct {
    ip: u32,
    kind: ChangeKind,
    since_us: i64, // how long ago the trailing bad run (or the host) began
    now_avg: ?u64, // newest scan's average
    baseline_us: ?u64, // the host's usual average before the run
    loss_pct: u8, // newest scan's loss

    fn lessThan(_: void, a: Change, b: Change) bool {
        const sa = a.kind.severity();
        const sb = b.kind.severity();
        if (sa != sb) return sa < sb;
        return a.ip < b.ip;
    }
};

// Bad cells in a row before a host is reported — one blip is noise
const min_run = 2;
// Scans of normal behaviour needed before a run counts as a change
const min_baseline = 4;

pub const History = struct {
    allocator: std.mem.Allocator,
    hosts: std.AutoHashMap(u32, HostHistory),
    scan_times: [max_scans]i64 = undefined, // monotonic µs, ring parallel to cells
    head: u16 = 0,
    len: u16 = 0,
    scan_count: u64 = 0, // scans ever recorded
    recording: bool = false,

    pub fn init(allocator: std.mem.Allocator) History {
        return .{
            .allocator = allocator,
            .hosts = std.AutoHashMap(u32, HostHistory).init(allocator),
        };
    }

    pub fn deinit(self: *History) void {
        self.hosts.deinit();
    }

    // One scan is recorded as beginScan → record(host)… → endScan. Hosts
    // known from earlier scans but not recorded this time get an absent
    // cell; hosts absent for the whole window are forgotten.
    pub fn beginScan(self: *History, now_us: i64) void {
        self.scan_count += 1;
        self.scan_times[self.head] = now_us;
        self.head = (self.head + 1) % max_scans;
        if (self.len < max_scans) self.len += 1;
        self.recording = true;
    }

    pub fn record(self: *History, ip: u32, cell: Cell) !void {
        std.debug.assert(self.recording);
        const gop = try self.hosts.getOrPut(ip);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        const host = gop.value_ptr;
        if (host.touched == self.scan_count) return; // duplicate within one scan
        host.touched = self.scan_count;
        host.seen_scan = self.scan_count;
        host.push(cell);
    }

    pub fn endScan(self: *History) void {
        std.debug.assert(self.recording);
        self.recording = false;
        var it = self.hosts.iterator();
        var evict: [64]u32 = undefined;
        var evict_n: usize = 0;
        while (it.next()) |kv| {
            const host = kv.value_ptr;
            if (host.touched != self.scan_count) {
                host.touched = self.scan_count;
                host.push(Cell.absent);
            }
            if (self.scan_count - host.seen_scan >= max_scans and evict_n < evict.len) {
                evict[evict_n] = kv.key_ptr.*;
                evict_n += 1;
            }
        }
        for (evict[0..evict_n]) |ip| _ = self.hosts.remove(ip);
    }

    // Convenience for a whole result set at once
    pub fn pushScan(self: *History, now_us: i64, results: []const common.PingResult) !void {
        self.beginScan(now_us);
        defer self.endScan();
        for (results) |r| {
            try self.record(common.ipToU32(r.ip), cellFromResult(r));
        }
    }

    pub fn get(self: *const History, ip: u32) ?*const HostHistory {
        return self.hosts.getPtr(ip);
    }

    // Monotonic time of the scan `age` scans back (0 = newest)
    pub fn scanTime(self: *const History, age: usize) ?i64 {
        if (age >= self.len) return null;
        const idx = (@as(usize, self.head) + max_scans - 1 - age) % max_scans;
        return self.scan_times[idx];
    }

    // Hosts whose recent scans depart from their own baseline, most severe
    // first. Returns how many of `out` were filled.
    pub fn changes(self: *const History, now_us: i64, out: []Change) usize {
        var n: usize = 0;
        var it = self.hosts.iterator();
        while (it.next()) |kv| {
            if (n >= out.len) break;
            if (self.hostChange(kv.key_ptr.*, kv.value_ptr, now_us)) |ch| {
                out[n] = ch;
                n += 1;
            }
        }
        std.mem.sort(Change, out[0..n], {}, Change.lessThan);
        return n;
    }

    fn hostChange(self: *const History, ip: u32, host: *const HostHistory, now_us: i64) ?Change {
        const newest = host.latest() orelse return null;

        // A host that showed up recently, once the window has some depth
        if (host.len <= min_run and self.len >= min_baseline + min_run and newest.sent > 0) {
            return .{
                .ip = ip,
                .kind = .appeared,
                .since_us = now_us - (self.scanTime(host.len - 1) orelse now_us),
                .now_avg = newest.avg(),
                .baseline_us = null,
                .loss_pct = newest.lossPct(),
            };
        }

        // Length of the trailing run of cells that are bad relative to the
        // host's baseline. The baseline must come from before the run, and
        // the run depends on the baseline, so iterate: start from a
        // baseline excluding only the newest cells and re-derive it from
        // beyond the run found, until the run stops moving.
        var run: usize = 0;
        var baseline: ?u64 = null;
        var pass: usize = 0;
        while (pass < 3) : (pass += 1) {
            const base = host.baseline(run + 1, min_baseline) orelse return null;
            var r: usize = 0;
            while (r < host.len and cellIsBad(host.at(r).?, base)) : (r += 1) {}
            baseline = base;
            if (r == run) break;
            run = r;
        }
        if (run < min_run or baseline == null) return null;

        const kind: ChangeKind = if (newest.avg() == null)
            .offline
        else if (newest.lossPct() >= 20)
            .lossy
        else
            .degraded;
        return .{
            .ip = ip,
            .kind = kind,
            .since_us = now_us - (self.scanTime(run - 1) orelse now_us),
            .now_avg = newest.avg(),
            .baseline_us = baseline,
            .loss_pct = newest.lossPct(),
        };
    }
};

pub fn cellFromResult(r: common.PingResult) Cell {
    return .{
        .avg_us = if (r.latency_avg) |a| @intCast(@min(a, no_data - 1)) else no_data,
        .sent = r.sent,
        .received = r.received,
    };
}

// ── Rendering ────────────────────────────────────────────────────────────

// Write exactly `width` display columns: the host's newest `width` cells,
// oldest on the left, left-padded with spaces where the record is shorter.
// Runs of the same tier share one color escape.
pub fn writeStrip(out: StdoutWriter, host: ?*const HostHistory, width: usize) void {
    const reset = common.sgr("\x1b[0m");
    const len: usize = if (host) |h| h.len else 0;
    const shown = @min(len, width);
    var i: usize = 0;
    while (i < width - shown) : (i += 1) out.writeAll(" ") catch {};

    var current: ?Tier = null;
    var age: usize = shown;
    while (age > 0) {
        age -= 1;
        const tier = cellTier(host.?.at(age).?);
        if (current == null or current.? != tier) {
            if (current != null) out.writeAll(reset) catch {};
            out.writeAll(tier.color()) catch {};
            current = tier;
        }
        out.writeAll(tier.glyph()) catch {};
    }
    if (current != null) out.writeAll(reset) catch {};
}

// Age labels under a strip: "now" at the right edge and an age every
// `tick` columns leftwards, from the actual scan timestamps
pub fn writeRuler(out: StdoutWriter, hist: *const History, now_us: i64, width: usize, tick: usize) void {
    var line: [max_scans + 8]u8 = undefined;
    @memset(line[0..width], ' ');
    if (width >= 3) @memcpy(line[width - 3 .. width], "now");
    var k: usize = 1;
    while (k * tick + 3 < width) : (k += 1) {
        const age = k * tick;
        const t = hist.scanTime(age) orelse break;
        var buf: [16]u8 = undefined;
        const label = formatAgo(now_us - t, &buf);
        const pos = width - 1 - age;
        if (pos + label.len + 3 >= width) continue;
        @memcpy(line[pos .. pos + label.len], label);
    }
    out.writeAll(line[0..width]) catch {};
}

// Compact "-3m20s" style age for ruler ticks and change reports
pub fn formatAgo(age_us: i64, buf: []u8) []const u8 {
    const s = @max(0, @divFloor(age_us, std.time.us_per_s));
    if (s < 60) return std.fmt.bufPrint(buf, "-{d}s", .{s}) catch "?";
    if (s < 3600) {
        const m = @divFloor(s, 60);
        const rem = s - m * 60;
        if (rem == 0) return std.fmt.bufPrint(buf, "-{d}m", .{m}) catch "?";
        return std.fmt.bufPrint(buf, "-{d}m{d:0>2}s", .{ m, rem }) catch "?";
    }
    const h = @divFloor(s, 3600);
    const m = @divFloor(s - h * 3600, 60);
    if (m == 0) return std.fmt.bufPrint(buf, "-{d}h", .{h}) catch "?";
    return std.fmt.bufPrint(buf, "-{d}h{d:0>2}m", .{ h, m }) catch "?";
}

// "3m20s ago" / "just now" for prose
pub fn formatAgoWords(age_us: i64, buf: []u8) []const u8 {
    if (age_us < 5 * std.time.us_per_s) return "just now";
    var tmp: [16]u8 = undefined;
    const compact = formatAgo(age_us, &tmp);
    return std.fmt.bufPrint(buf, "{s} ago", .{compact[1..]}) catch "?";
}

pub fn writeLegend(out: StdoutWriter) void {
    const reset = common.sgr("\x1b[0m");
    const tiers = [_]Tier{ .excellent, .good, .okay, .slow, .bad, .dead, .absent };
    const labels = [_][]const u8{ "<1ms", "<5ms", "<20ms", "<100ms", ">100ms", "no reply", "not found" };
    for (tiers, labels, 0..) |t, l, i| {
        out.print("{s}{s}{s} {s}{s}", .{ if (i == 0) "" else "  ", t.color(), t.glyph(), l, reset }) catch {};
    }
    out.print("  {s}(loss >20% ▒, >50% ░){s}", .{ common.sgr("\x1b[90m"), reset }) catch {};
}

// One line per change, most severe first; returns lines written
pub fn writeChanges(out: StdoutWriter, changes: []const Change, indent: []const u8) void {
    const reset = common.sgr("\x1b[0m");
    const bold = common.sgr("\x1b[1m");
    for (changes) |ch| {
        var ip_buf: [16]u8 = undefined;
        var ago_buf: [24]u8 = undefined;
        var a_buf: [16]u8 = undefined;
        var b_buf: [16]u8 = undefined;
        const ip = common.ipToString(common.u32ToIp(ch.ip), &ip_buf);
        const ago = formatAgoWords(ch.since_us, &ago_buf);
        switch (ch.kind) {
            .offline => out.print("{s}{s}{s}{s} stopped answering {s} (was {s})\n", .{
                indent, bold, ip, reset, ago, common.formatLatency(ch.baseline_us, &b_buf),
            }) catch {},
            .lossy => out.print("{s}{s}{s}{s} dropping probes since {s}: {d}% loss, {s} when it answers (usually {s})\n", .{
                indent, bold, ip, reset, ago, ch.loss_pct, common.formatLatency(ch.now_avg, &a_buf), common.formatLatency(ch.baseline_us, &b_buf),
            }) catch {},
            .degraded => out.print("{s}{s}{s}{s} degraded {s}: {s} now vs {s} usually\n", .{
                indent, bold, ip, reset, ago, common.formatLatency(ch.now_avg, &a_buf), common.formatLatency(ch.baseline_us, &b_buf),
            }) catch {},
            .appeared => out.print("{s}{s}{s}{s} appeared {s} at {s}\n", .{
                indent, bold, ip, reset, ago, common.formatLatency(ch.now_avg, &a_buf),
            }) catch {},
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn mk(avg: u32, sent: u8, received: u8) Cell {
    return .{ .avg_us = avg, .sent = sent, .received = received };
}

test "cellTier takes the worse of latency and loss" {
    try testing.expectEqual(Tier.excellent, cellTier(mk(500, 5, 5)));
    try testing.expectEqual(Tier.good, cellTier(mk(2_000, 5, 5)));
    try testing.expectEqual(Tier.okay, cellTier(mk(500, 5, 4))); // 20% loss beats 500µs
    try testing.expectEqual(Tier.slow, cellTier(mk(500, 5, 3))); // 40% loss
    try testing.expectEqual(Tier.bad, cellTier(mk(500, 5, 1))); // 80% loss
    try testing.expectEqual(Tier.bad, cellTier(mk(150_000, 5, 5))); // slow, no loss
    try testing.expectEqual(Tier.dead, cellTier(mk(no_data, 5, 0)));
    try testing.expectEqual(Tier.absent, cellTier(Cell.absent));
}

test "HostHistory is a ring newest-first" {
    var h = HostHistory{};
    try testing.expectEqual(@as(?Cell, null), h.latest());
    for (0..max_scans + 5) |i| h.push(mk(@intCast(i), 5, 5));
    try testing.expectEqual(@as(u16, max_scans), h.len);
    try testing.expectEqual(@as(u32, max_scans + 4), h.at(0).?.avg_us);
    try testing.expectEqual(@as(u32, 5), h.at(max_scans - 1).?.avg_us);
    try testing.expectEqual(@as(?Cell, null), h.at(max_scans));
}

test "window aggregates loss over probes actually sent" {
    var h = HostHistory{};
    h.push(mk(1000, 5, 5));
    h.push(Cell.absent);
    h.push(mk(3000, 5, 3));
    const w = h.window();
    try testing.expectEqual(@as(usize, 2), w.samples);
    try testing.expectEqual(@as(?u64, 2000), w.avg_us);
    try testing.expectEqual(@as(?u64, 3000), w.worst_us);
    try testing.expectEqual(@as(usize, 1), w.absent);
    try testing.expectEqual(@as(u8, 20), w.lossPct());
}

test "History fills absent cells and evicts hosts gone for the whole window" {
    var hist = History.init(testing.allocator);
    defer hist.deinit();
    const a: u32 = 1;
    const b: u32 = 2;

    hist.beginScan(1_000_000);
    try hist.record(a, mk(500, 5, 5));
    try hist.record(b, mk(700, 5, 5));
    hist.endScan();

    hist.beginScan(2_000_000);
    try hist.record(a, mk(600, 5, 5));
    hist.endScan();

    try testing.expectEqual(@as(u16, 2), hist.get(a).?.len);
    try testing.expectEqual(@as(u16, 2), hist.get(b).?.len);
    try testing.expectEqual(Tier.absent, cellTier(hist.get(b).?.latest().?));
    try testing.expectEqual(@as(?i64, 2_000_000), hist.scanTime(0));
    try testing.expectEqual(@as(?i64, 1_000_000), hist.scanTime(1));

    // b never returns: gone after max_scans scans without it
    for (0..max_scans) |i| {
        hist.beginScan(@intCast(3_000_000 + i));
        try hist.record(a, mk(600, 5, 5));
        hist.endScan();
    }
    try testing.expect(hist.get(b) == null);
    try testing.expect(hist.get(a) != null);
}

test "changes flags a degraded run against the host's own baseline" {
    var hist = History.init(testing.allocator);
    defer hist.deinit();
    const ip: u32 = 42;
    var t: i64 = 0;
    for (0..8) |_| {
        t += 10_000_000;
        hist.beginScan(t);
        try hist.record(ip, mk(800, 5, 5));
        hist.endScan();
    }
    var out: [8]Change = undefined;
    try testing.expectEqual(@as(usize, 0), hist.changes(t, &out));

    // One slow scan is a blip, not a change
    t += 10_000_000;
    hist.beginScan(t);
    try hist.record(ip, mk(9_000, 5, 5));
    hist.endScan();
    try testing.expectEqual(@as(usize, 0), hist.changes(t, &out));

    // Two in a row is
    t += 10_000_000;
    hist.beginScan(t);
    try hist.record(ip, mk(12_000, 5, 5));
    hist.endScan();
    try testing.expectEqual(@as(usize, 1), hist.changes(t, &out));
    try testing.expectEqual(ChangeKind.degraded, out[0].kind);
    try testing.expectEqual(ip, out[0].ip);
    try testing.expectEqual(@as(?u64, 800), out[0].baseline_us);
    try testing.expectEqual(@as(?u64, 12_000), out[0].now_avg);
    try testing.expectEqual(@as(i64, 10_000_000), out[0].since_us);
}

test "changes distinguishes offline, lossy, and appeared" {
    var hist = History.init(testing.allocator);
    defer hist.deinit();
    const gone: u32 = 1;
    const lossy: u32 = 2;
    const newcomer: u32 = 3;
    var t: i64 = 0;
    for (0..6) |_| {
        t += 1_000_000;
        hist.beginScan(t);
        try hist.record(gone, mk(800, 5, 5));
        try hist.record(lossy, mk(800, 5, 5));
        hist.endScan();
    }
    for (0..2) |_| {
        t += 1_000_000;
        hist.beginScan(t);
        try hist.record(lossy, mk(900, 5, 2));
        try hist.record(newcomer, mk(300, 5, 5));
        hist.endScan(); // `gone` gets absent cells
    }
    var out: [8]Change = undefined;
    const n = hist.changes(t, &out);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqual(ChangeKind.offline, out[0].kind);
    try testing.expectEqual(gone, out[0].ip);
    try testing.expectEqual(ChangeKind.lossy, out[1].kind);
    try testing.expectEqual(@as(u8, 60), out[1].loss_pct);
    try testing.expectEqual(ChangeKind.appeared, out[2].kind);
    try testing.expectEqual(newcomer, out[2].ip);
}

test "a host that was always slow is not a change" {
    var hist = History.init(testing.allocator);
    defer hist.deinit();
    for (0..10) |i| {
        hist.beginScan(@intCast(i * 1_000_000));
        try hist.record(7, mk(50_000, 5, 5));
        hist.endScan();
    }
    var out: [8]Change = undefined;
    try testing.expectEqual(@as(usize, 0), hist.changes(10_000_000, &out));
}

test "writeStrip pads short records on the left and orders oldest to newest" {
    common.color_enabled = false;
    var h = HostHistory{};
    h.push(mk(500, 5, 5));
    h.push(Cell.absent);
    h.push(mk(150_000, 5, 5));
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    writeStrip(&w, &h, 5);
    try testing.expectEqualStrings("  █·▪", w.buffered());

    // Wider record than width: only the newest cells
    w = .fixed(&buf);
    writeStrip(&w, &h, 2);
    try testing.expectEqualStrings("·▪", w.buffered());

    // No record at all: all padding
    w = .fixed(&buf);
    writeStrip(&w, null, 3);
    try testing.expectEqualStrings("   ", w.buffered());
}

test "writeRuler labels ticks from scan timestamps" {
    var hist = History.init(testing.allocator);
    defer hist.deinit();
    for (0..25) |i| {
        hist.beginScan(@intCast(i * 10_000_000)); // every 10s
        hist.endScan();
    }
    const now: i64 = 24 * 10_000_000;
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    writeRuler(&w, &hist, now, 25, 10);
    // col 4 is 20 scans back (200s = 3m20s), col 14 is 10 back (100s)
    try testing.expectEqualStrings("    -3m20s    -1m40s  now", w.buffered());
}

test "formatAgo is compact" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("-45s", formatAgo(45 * std.time.us_per_s, &buf));
    try testing.expectEqualStrings("-3m", formatAgo(180 * std.time.us_per_s, &buf));
    try testing.expectEqualStrings("-3m20s", formatAgo(200 * std.time.us_per_s, &buf));
    try testing.expectEqualStrings("-1h05m", formatAgo(3900 * std.time.us_per_s, &buf));
    try testing.expectEqualStrings("-2h", formatAgo(7200 * std.time.us_per_s, &buf));
    try testing.expectEqualStrings("just now", formatAgoWords(2 * std.time.us_per_s, &buf));
    var buf2: [24]u8 = undefined;
    try testing.expectEqualStrings("3m20s ago", formatAgoWords(200 * std.time.us_per_s, &buf2));
}
