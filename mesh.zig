// Mesh mode: multiple scanners on the same LAN discover each other over UDP
// and gossip their scan results, so every node can render an M×N latency
// matrix — each discovered host as measured from every vantage point.
//
// Protocol (UDP, all multi-byte integers little-endian):
//
//   Header (all messages, 13 bytes):
//     [0..4)   magic "NLH1" (protocol version baked into the magic)
//     [4]      message type: 1 = beacon, 2 = results chunk
//     [5..13)  node id (random u64, identifies a scanner instance)
//
//   Beacon (broadcast every beacon_interval, announces presence):
//     [13..17) results seq (bumped each scan; peers detect fresh data)
//     [17..19) host count of current results
//     [19]     hostname length (0..32)
//     [20..)   hostname bytes
//
//   Results chunk (results are split into datagram-sized chunks):
//     [13..17) results seq
//     [17..19) total entries in this result set
//     [19..21) offset of this chunk's first entry
//     [21..23) entry count in this chunk
//     [23..)   entries, 16 bytes each:
//                ip [4]u8 (network order), min/avg/max u32 µs
//                (0xFFFFFFFF = host discovered but no latency sample)
//
// Everything received is untrusted input: fixed caps on peers and hosts,
// strict length checks, unknown magic/type dropped silently.
const std = @import("std");
const posix = std.posix;
const c = std.c;
const common = @import("common.zig");

const ipToU32 = common.ipToU32;
const u32ToIp = common.u32ToIp;
const ipToString = common.ipToString;
const formatLatency = common.formatLatency;
const latencyToColor = common.latencyToColor;
const latencyToBlock = common.latencyToBlock;
const displayWidth = common.displayWidth;
const monotonicMicros = common.monotonicMicros;
const StdoutWriter = common.StdoutWriter;

pub const default_port: u16 = 47269;

const protocol_magic = [4]u8{ 'N', 'L', 'H', '1' };
const header_len = 13;
const beacon_fixed_len = header_len + 7; // + seq, host_count, hostname_len
const results_fixed_len = header_len + 10; // + seq, total, offset, count
const entry_len = 16;
const max_hostname = 32;
const entries_per_chunk = 80; // 80*16 + 23 = 1303 bytes, under typical MTU
const recv_buf_len = 2048;

pub const max_peers = 32;
pub const max_hosts_per_peer = 2048;

const beacon_interval_us: i64 = 2 * std.time.us_per_s;
const gossip_interval_us: i64 = 5 * std.time.us_per_s;
const peer_timeout_us: i64 = 30 * std.time.us_per_s;
const render_min_interval_us: i64 = 500 * std.time.us_per_ms;

const max_display_rows = 40;
const max_display_observers = 6;

// Sentinel in wire stats: host was discovered but produced no latency sample
pub const no_data: u32 = 0xFFFF_FFFF;

pub const HostStats = struct {
    min_us: u32,
    avg_us: u32,
    max_us: u32,

    pub fn hasData(self: HostStats) bool {
        return self.avg_us != no_data;
    }

    fn avg(self: HostStats) ?u64 {
        return if (self.hasData()) self.avg_us else null;
    }
};

pub const Entry = struct {
    ip: u32, // host byte order (as from ipToU32)
    stats: HostStats,
};

const MsgType = enum(u8) {
    beacon = 1,
    results = 2,
};

pub const Parsed = union(enum) {
    beacon: struct {
        node_id: u64,
        seq: u32,
        host_count: u16,
        hostname: []const u8,
    },
    results: struct {
        node_id: u64,
        seq: u32,
        total: u16,
        offset: u16,
        entries: []const u8, // count * entry_len raw bytes
    },
};

fn writeHeader(buf: []u8, msg_type: MsgType, node_id: u64) void {
    @memcpy(buf[0..4], &protocol_magic);
    buf[4] = @intFromEnum(msg_type);
    std.mem.writeInt(u64, buf[5..13], node_id, .little);
}

pub fn encodeBeacon(buf: []u8, node_id: u64, seq: u32, host_count: u16, hostname: []const u8) []const u8 {
    const name = hostname[0..@min(hostname.len, max_hostname)];
    writeHeader(buf, .beacon, node_id);
    std.mem.writeInt(u32, buf[13..17], seq, .little);
    std.mem.writeInt(u16, buf[17..19], host_count, .little);
    buf[19] = @intCast(name.len);
    @memcpy(buf[beacon_fixed_len..][0..name.len], name);
    return buf[0 .. beacon_fixed_len + name.len];
}

pub fn encodeResultsChunk(buf: []u8, node_id: u64, seq: u32, total: u16, offset: u16, entries: []const Entry) []const u8 {
    writeHeader(buf, .results, node_id);
    std.mem.writeInt(u32, buf[13..17], seq, .little);
    std.mem.writeInt(u16, buf[17..19], total, .little);
    std.mem.writeInt(u16, buf[19..21], offset, .little);
    std.mem.writeInt(u16, buf[21..23], @intCast(entries.len), .little);
    var off: usize = results_fixed_len;
    for (entries) |e| {
        const ip_bytes = u32ToIp(e.ip);
        @memcpy(buf[off..][0..4], &ip_bytes);
        std.mem.writeInt(u32, buf[off + 4 ..][0..4], e.stats.min_us, .little);
        std.mem.writeInt(u32, buf[off + 8 ..][0..4], e.stats.avg_us, .little);
        std.mem.writeInt(u32, buf[off + 12 ..][0..4], e.stats.max_us, .little);
        off += entry_len;
    }
    return buf[0..off];
}

pub fn decodeEntry(bytes: []const u8) Entry {
    const ip_bytes: [4]u8 = bytes[0..4].*;
    return .{
        .ip = ipToU32(ip_bytes),
        .stats = .{
            .min_us = std.mem.readInt(u32, bytes[4..8], .little),
            .avg_us = std.mem.readInt(u32, bytes[8..12], .little),
            .max_us = std.mem.readInt(u32, bytes[12..16], .little),
        },
    };
}

// Parse an incoming datagram. Returns null for anything malformed or from
// a different protocol/version — the mesh drops it silently.
pub fn parseMessage(buf: []const u8) ?Parsed {
    if (buf.len < header_len) return null;
    if (!std.mem.eql(u8, buf[0..4], &protocol_magic)) return null;
    const node_id = std.mem.readInt(u64, buf[5..13], .little);

    switch (buf[4]) {
        @intFromEnum(MsgType.beacon) => {
            if (buf.len < beacon_fixed_len) return null;
            const name_len: usize = buf[19];
            if (name_len > max_hostname) return null;
            if (buf.len < beacon_fixed_len + name_len) return null;
            return .{ .beacon = .{
                .node_id = node_id,
                .seq = std.mem.readInt(u32, buf[13..17], .little),
                .host_count = std.mem.readInt(u16, buf[17..19], .little),
                .hostname = buf[beacon_fixed_len..][0..name_len],
            } };
        },
        @intFromEnum(MsgType.results) => {
            if (buf.len < results_fixed_len) return null;
            const total = std.mem.readInt(u16, buf[17..19], .little);
            const offset = std.mem.readInt(u16, buf[19..21], .little);
            const count: usize = std.mem.readInt(u16, buf[21..23], .little);
            if (count > entries_per_chunk) return null;
            if (@as(usize, offset) + count > total) return null;
            if (total > max_hosts_per_peer) return null;
            if (buf.len < results_fixed_len + count * entry_len) return null;
            return .{ .results = .{
                .node_id = node_id,
                .seq = std.mem.readInt(u32, buf[13..17], .little),
                .total = total,
                .offset = offset,
                .entries = buf[results_fixed_len..][0 .. count * entry_len],
            } };
        },
        else => return null,
    }
}

// A latency spread across observers is worth flagging when the slowest
// vantage point sees 3x the fastest AND the gap is more than jitter noise.
pub fn spreadIsUneven(min_avg: u64, max_avg: u64) bool {
    return max_avg >= min_avg * 3 and (max_avg - min_avg) > 2000;
}

fn medianOfSorted(sorted: []const u64) ?u64 {
    if (sorted.len == 0) return null;
    return sorted[sorted.len / 2];
}

extern "c" fn gethostname(name: [*]u8, len: usize) c_int;

fn splitmix64(seed: u64) u64 {
    var z = seed +% 0x9E3779B97F4A7C15;
    z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
    return z ^ (z >> 31);
}

const Peer = struct {
    node_id: u64,
    addr: posix.sockaddr.in,
    hostname: [max_hostname]u8,
    hostname_len: u8,
    last_seen_us: i64, // monotonic; peer dropped after peer_timeout_us
    last_results_us: i64, // monotonic; when we last got result data
    results_seq: u32,
    hosts: std.AutoHashMap(u32, HostStats),

    fn name(self: *const Peer) []const u8 {
        return self.hostname[0..self.hostname_len];
    }
};

pub const Mesh = struct {
    allocator: std.mem.Allocator,
    sock: posix.fd_t,
    poller: common.SocketPoller,
    port: u16,
    node_id: u64,
    hostname: [max_hostname]u8,
    hostname_len: u8,

    // Broadcast destinations: the scanned subnet's broadcast address and
    // the limited broadcast address (same segment either way; sending both
    // covers hosts whose interface address falls outside the scanned range)
    bcast_addrs: [2]posix.sockaddr.in,

    // Our own results, as both a map (for rendering) and a sorted array
    // (for gossip chunking)
    seq: u32,
    local_hosts: std.AutoHashMap(u32, HostStats),
    local_entries: std.ArrayList(Entry),
    local_scan_us: i64, // monotonic time of our last scan, 0 = never

    peers: std.ArrayList(Peer),

    last_beacon_us: i64,
    last_gossip_us: i64,
    last_render_us: i64,
    dirty: bool,

    pub fn init(allocator: std.mem.Allocator, port: u16, subnet: [4]u8, mask_bits: u8) !Mesh {
        const sock_fd = c.socket(posix.AF.INET, c.SOCK.DGRAM, 0);
        if (sock_fd < 0) return error.MeshSocketFailed;
        const sock: posix.fd_t = @intCast(sock_fd);
        errdefer _ = c.close(sock);

        const one: c_int = 1;
        if (c.setsockopt(sock, posix.SOL.SOCKET, posix.SO.BROADCAST, &one, @sizeOf(c_int)) != 0)
            return error.MeshSocketFailed;
        // REUSEADDR+REUSEPORT so several instances on one machine can share
        // the port (each still receives every broadcast), handy for testing
        _ = c.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one, @sizeOf(c_int));
        _ = c.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEPORT, &one, @sizeOf(c_int));

        const flags = c.fcntl(sock, posix.F.GETFL, @as(c_int, 0));
        if (flags < 0) return error.MeshSocketFailed;
        const FlagsInt = std.meta.Int(.unsigned, @bitSizeOf(posix.O));
        const o_nonblock: FlagsInt = @bitCast(posix.O{ .NONBLOCK = true });
        if (c.fcntl(sock, posix.F.SETFL, flags | @as(c_int, o_nonblock)) < 0)
            return error.MeshSocketFailed;

        var bind_addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = 0, // INADDR_ANY
        };
        if (c.bind(sock, @ptrCast(&bind_addr), @sizeOf(posix.sockaddr.in)) != 0)
            return error.MeshBindFailed;

        const poller = try common.SocketPoller.init(sock);

        // Subnet-directed broadcast address: network | ~netmask
        const netmask: u32 = if (mask_bits >= 32)
            ~@as(u32, 0)
        else
            ~@as(u32, 0) << @intCast(32 - mask_bits);
        const subnet_bcast = u32ToIp((ipToU32(subnet) & netmask) | ~netmask);
        const limited_bcast = [4]u8{ 255, 255, 255, 255 };

        var hostname_buf: [max_hostname]u8 = undefined;
        var host_c: [256]u8 = @splat(0);
        var hostname_len: u8 = 0;
        if (gethostname(&host_c, host_c.len - 1) == 0) {
            const len = std.mem.indexOfScalar(u8, &host_c, 0) orelse 0;
            const take = @min(len, max_hostname);
            @memcpy(hostname_buf[0..take], host_c[0..take]);
            hostname_len = @intCast(take);
        }

        // Random-enough node id; only needs to distinguish scanner instances
        // on one LAN, not resist an adversary
        const pid: u32 = @bitCast(c.getpid());
        var node_id = splitmix64(@as(u64, @bitCast(common.wallMicros())));
        node_id ^= splitmix64(@as(u64, @bitCast(monotonicMicros())) ^ (@as(u64, pid) << 32));

        return Mesh{
            .allocator = allocator,
            .sock = sock,
            .poller = poller,
            .port = port,
            .node_id = node_id,
            .hostname = hostname_buf,
            .hostname_len = hostname_len,
            .bcast_addrs = .{
                .{
                    .family = posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, port),
                    .addr = std.mem.bytesToValue(u32, &subnet_bcast),
                },
                .{
                    .family = posix.AF.INET,
                    .port = std.mem.nativeToBig(u16, port),
                    .addr = std.mem.bytesToValue(u32, &limited_bcast),
                },
            },
            .seq = 0,
            .local_hosts = std.AutoHashMap(u32, HostStats).init(allocator),
            .local_entries = .empty,
            .local_scan_us = 0,
            .peers = .empty,
            .last_beacon_us = 0,
            .last_gossip_us = 0,
            .last_render_us = 0,
            .dirty = false,
        };
    }

    pub fn deinit(self: *Mesh) void {
        for (self.peers.items) |*p| p.hosts.deinit();
        self.peers.deinit(self.allocator);
        self.local_hosts.deinit();
        self.local_entries.deinit(self.allocator);
        self.poller.deinit();
        _ = c.close(self.sock);
    }

    // Replace our own results after a scan and schedule immediate gossip
    pub fn setLocalResults(self: *Mesh, results: []const common.PingResult) !void {
        self.seq +%= 1;
        self.local_hosts.clearRetainingCapacity();
        self.local_entries.clearRetainingCapacity();

        for (results) |r| {
            if (self.local_entries.items.len >= max_hosts_per_peer) break;
            const stats = HostStats{
                .min_us = clampStat(r.latency_us),
                .avg_us = clampStat(r.latency_avg),
                .max_us = clampStat(r.latency_max),
            };
            const ip = ipToU32(r.ip);
            try self.local_hosts.put(ip, stats);
            try self.local_entries.append(self.allocator, .{ .ip = ip, .stats = stats });
        }

        self.local_scan_us = monotonicMicros();
        self.last_gossip_us = 0; // gossip on next pump
        self.dirty = true;
    }

    fn clampStat(v: ?u64) u32 {
        const lat = v orelse return no_data;
        return @intCast(@min(lat, no_data - 1));
    }

    fn sendDatagram(self: *Mesh, data: []const u8, dest: *const posix.sockaddr.in) void {
        // Errors (buffer full, unreachable) are ignored: beacons and gossip
        // repeat on an interval, so a dropped datagram heals itself
        _ = c.sendto(self.sock, data.ptr, data.len, 0, @ptrCast(dest), @sizeOf(posix.sockaddr.in));
    }

    fn sendBeacons(self: *Mesh) void {
        var buf: [beacon_fixed_len + max_hostname]u8 = undefined;
        const msg = encodeBeacon(
            &buf,
            self.node_id,
            self.seq,
            @intCast(@min(self.local_entries.items.len, std.math.maxInt(u16))),
            self.hostname[0..self.hostname_len],
        );
        for (&self.bcast_addrs) |*addr| self.sendDatagram(msg, addr);
    }

    fn sendResultsTo(self: *Mesh, dest: *const posix.sockaddr.in) void {
        const entries = self.local_entries.items;
        if (entries.len == 0) return;
        var buf: [results_fixed_len + entries_per_chunk * entry_len]u8 = undefined;
        var offset: usize = 0;
        while (offset < entries.len) {
            const count = @min(entries_per_chunk, entries.len - offset);
            const msg = encodeResultsChunk(
                &buf,
                self.node_id,
                self.seq,
                @intCast(entries.len),
                @intCast(offset),
                entries[offset..][0..count],
            );
            self.sendDatagram(msg, dest);
            offset += count;
        }
    }

    fn gossipResults(self: *Mesh) void {
        for (&self.bcast_addrs) |*addr| self.sendResultsTo(addr);
    }

    fn findPeer(self: *Mesh, node_id: u64) ?*Peer {
        for (self.peers.items) |*p| {
            if (p.node_id == node_id) return p;
        }
        return null;
    }

    // Find or create the peer entry for a sender. Returns null when the
    // peer table is full (excess peers are ignored, not evicted).
    fn obtainPeer(self: *Mesh, node_id: u64, src: *const posix.sockaddr.in, now: i64) ?*Peer {
        if (self.findPeer(node_id)) |p| {
            p.last_seen_us = now;
            p.addr = src.*;
            return p;
        }
        if (self.peers.items.len >= max_peers) return null;
        self.peers.append(self.allocator, .{
            .node_id = node_id,
            .addr = src.*,
            .hostname = @splat(0),
            .hostname_len = 0,
            .last_seen_us = now,
            .last_results_us = 0,
            .results_seq = 0,
            .hosts = std.AutoHashMap(u32, HostStats).init(self.allocator),
        }) catch return null;
        self.dirty = true;

        // Fast join: a new peer gets our results immediately instead of
        // waiting for the next gossip broadcast
        self.sendResultsTo(src);
        return &self.peers.items[self.peers.items.len - 1];
    }

    fn handleMessage(self: *Mesh, parsed: Parsed, src: *const posix.sockaddr.in, now: i64) void {
        switch (parsed) {
            .beacon => |b| {
                if (b.node_id == self.node_id) return; // our own broadcast
                const peer = self.obtainPeer(b.node_id, src, now) orelse return;
                if (!std.mem.eql(u8, peer.name(), b.hostname)) {
                    @memcpy(peer.hostname[0..b.hostname.len], b.hostname);
                    peer.hostname_len = @intCast(b.hostname.len);
                    self.dirty = true;
                }
            },
            .results => |r| {
                if (r.node_id == self.node_id) return;
                const peer = self.obtainPeer(r.node_id, src, now) orelse return;
                if (peer.results_seq != r.seq) {
                    // A new scan from this peer supersedes the old one; the
                    // age shown for this column dates from here, not from
                    // re-gossips of the same data
                    peer.hosts.clearRetainingCapacity();
                    peer.results_seq = r.seq;
                    peer.last_results_us = now;
                }
                var off: usize = 0;
                while (off < r.entries.len) : (off += entry_len) {
                    if (peer.hosts.count() >= max_hosts_per_peer) break;
                    const e = decodeEntry(r.entries[off..][0..entry_len]);
                    peer.hosts.put(e.ip, e.stats) catch break;
                }
                self.dirty = true;
            },
        }
    }

    fn expirePeers(self: *Mesh, now: i64) void {
        var i: usize = 0;
        while (i < self.peers.items.len) {
            if (now - self.peers.items[i].last_seen_us > peer_timeout_us) {
                self.peers.items[i].hosts.deinit();
                _ = self.peers.swapRemove(i);
                self.dirty = true;
            } else {
                i += 1;
            }
        }
    }

    fn drainSocket(self: *Mesh, now: i64) void {
        var buf: [recv_buf_len]u8 = undefined;
        while (true) {
            var src: posix.sockaddr.in = undefined;
            var src_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
            const rc = c.recvfrom(self.sock, &buf, buf.len, 0, @ptrCast(&src), &src_len);
            if (rc <= 0) break;
            if (src.family != posix.AF.INET) continue;
            const parsed = parseMessage(buf[0..@intCast(rc)]) orelse continue;
            self.handleMessage(parsed, &src, now);
        }
    }

    // Beacon and drain only — no result gossip. Called from inside the
    // scanner's loops so that a long scan (a /16 discovery, or many hosts
    // with a generous timeout) doesn't go silent past peer_timeout_us and
    // get this node dropped from every peer's table, and so the UDP receive
    // buffer doesn't overflow while the scan runs. Gossip stays deferred
    // until the scan finishes, keeping mesh traffic out of the measurement
    // window.
    pub fn keepAlive(self: *Mesh) void {
        const now = monotonicMicros();
        if (now - self.last_beacon_us >= beacon_interval_us) {
            self.last_beacon_us = now;
            self.sendBeacons();
            self.expirePeers(now);
        }
        self.drainSocket(now);
    }

    // One iteration of mesh housekeeping: announce, gossip, drain the
    // socket. Call from the main loop; never blocks.
    pub fn pump(self: *Mesh) void {
        const now = monotonicMicros();

        if (now - self.last_beacon_us >= beacon_interval_us) {
            self.last_beacon_us = now;
            self.sendBeacons();
            self.expirePeers(now);
        }
        if (self.local_entries.items.len > 0 and now - self.last_gossip_us >= gossip_interval_us) {
            self.last_gossip_us = now;
            self.gossipResults();
        }

        self.drainSocket(now);
    }

    pub fn renderIfDue(self: *Mesh, stdout: StdoutWriter, next_scan_at: ?i64) void {
        const now = monotonicMicros();
        if (!self.dirty or now - self.last_render_us < render_min_interval_us) return;
        self.last_render_us = now;
        self.dirty = false;
        self.render(stdout, now, next_scan_at);
    }

    // Everything below is display: the M×N matrix plus derived insights

    const Observer = struct {
        label_buf: [16]u8,
        label_len: usize,
        hosts: *const std.AutoHashMap(u32, HostStats),
        age_us: i64, // since this observer's data was produced/received

        fn label(self: *const Observer) []const u8 {
            return self.label_buf[0..self.label_len];
        }
    };

    fn makeObserver(label_text: []const u8, hosts: *const std.AutoHashMap(u32, HostStats), age_us: i64) Observer {
        var o = Observer{
            .label_buf = undefined,
            .label_len = 0,
            .hosts = hosts,
            .age_us = age_us,
        };
        const take = @min(label_text.len, o.label_buf.len);
        @memcpy(o.label_buf[0..take], label_text[0..take]);
        o.label_len = take;
        return o;
    }

    fn render(self: *Mesh, stdout: StdoutWriter, now: i64, next_scan_at: ?i64) void {
        const reset = common.sgr("\x1b[0m");
        const bold = common.sgr("\x1b[1m");
        const gray = common.sgr("\x1b[90m");
        const cyan = common.sgr("\x1b[96m");
        const yellow = common.sgr("\x1b[93m");
        const col_width = 13;
        const label_width = 17;
        const pad = " " ** 32;

        // Assemble the observer columns: self first, then live peers
        var observers: [1 + max_peers]Observer = undefined;
        var num_obs: usize = 0;
        observers[0] = makeObserver("self", &self.local_hosts, if (self.local_scan_us > 0) now - self.local_scan_us else -1);
        num_obs = 1;
        for (self.peers.items) |*p| {
            if (num_obs >= observers.len) break;
            var ip_buf: [16]u8 = undefined;
            const peer_ip: [4]u8 = @bitCast(p.addr.addr);
            const label_text = if (p.hostname_len > 0) p.name() else ipToString(peer_ip, &ip_buf);
            const age: i64 = if (p.last_results_us > 0) now - p.last_results_us else -1;
            observers[num_obs] = makeObserver(label_text, &p.hosts, age);
            num_obs += 1;
        }
        const shown_obs = @min(num_obs, max_display_observers);

        // Row set: every host any observer has measured
        var row_set = std.AutoHashMap(u32, void).init(self.allocator);
        defer row_set.deinit();
        for (observers[0..num_obs]) |*o| {
            var it = o.hosts.keyIterator();
            while (it.next()) |k| row_set.put(k.*, {}) catch {};
        }
        var rows: std.ArrayList(u32) = .empty;
        defer rows.deinit(self.allocator);
        var kit = row_set.keyIterator();
        while (kit.next()) |k| rows.append(self.allocator, k.*) catch {};
        std.mem.sort(u32, rows.items, {}, std.sort.asc(u32));

        // Redraw from the top; the matrix is a live view, not a log. When
        // output is piped there is no screen to clear — each render is
        // appended as a plain snapshot instead.
        if (common.stdout_is_tty) stdout.print("\x1b[2J\x1b[H", .{}) catch {};
        stdout.print("{s}╔══════════════════════════════════════════════════════════════╗{s}\n", .{ cyan, reset }) catch {};
        stdout.print("{s}║{s}               {s}Network Latency Mesh View{s}                      {s}║{s}\n", .{ cyan, reset, bold, reset, cyan, reset }) catch {};
        stdout.print("{s}╚══════════════════════════════════════════════════════════════╝{s}\n\n", .{ cyan, reset }) catch {};

        stdout.print("  Node {s}{s}{s} (id {x:0>8}) · UDP port {d} · {d} peer{s} · {d} target{s}\n", .{
            bold,
            self.hostname[0..self.hostname_len],
            reset,
            @as(u32, @truncate(self.node_id)),
            self.port,
            self.peers.items.len,
            if (self.peers.items.len == 1) "" else "s",
            rows.items.len,
            if (rows.items.len == 1) "" else "s",
        }) catch {};
        if (next_scan_at) |at| {
            const remaining_s = @max(0, @divFloor(at - now, std.time.us_per_s));
            stdout.print("  Next rescan in {d}s\n", .{remaining_s}) catch {};
        }
        if (self.peers.items.len == 0) {
            stdout.print("\n  {s}Waiting for peers... run this tool with --mesh on other devices{s}\n", .{ gray, reset }) catch {};
        }

        // Header: observer labels, then data age
        stdout.print("\n  {s}{s}{s}{s}", .{ bold, "target", reset, pad[0 .. label_width - 6] }) catch {};
        for (observers[0..shown_obs]) |*o| {
            const l = o.label()[0..@min(o.label().len, col_width - 1)];
            stdout.print("{s}{s}{s}{s}", .{ bold, l, reset, pad[0 .. col_width - l.len] }) catch {};
        }
        if (num_obs > shown_obs) {
            stdout.print("{s}+{d} more{s}", .{ gray, num_obs - shown_obs, reset }) catch {};
        }
        stdout.print("\n  {s}", .{pad[0..label_width]}) catch {};
        for (observers[0..shown_obs]) |*o| {
            var age_buf: [16]u8 = undefined;
            const age_str = if (o.age_us < 0)
                "no data"
            else
                std.fmt.bufPrint(&age_buf, "{d}s ago", .{@divFloor(o.age_us, std.time.us_per_s)}) catch "?";
            stdout.print("{s}{s}{s}{s}", .{ gray, age_str, reset, pad[0 .. col_width - age_str.len] }) catch {};
        }
        stdout.print("\n", .{}) catch {};

        // Matrix body
        const shown_rows = @min(rows.items.len, max_display_rows);
        var uneven_count: usize = 0;
        for (rows.items[0..shown_rows]) |ip| {
            var ip_buf: [16]u8 = undefined;
            const ip_str = ipToString(u32ToIp(ip), &ip_buf);
            stdout.print("  {s}{s}", .{ ip_str, pad[0 .. label_width - ip_str.len] }) catch {};

            var row_min: u64 = std.math.maxInt(u64);
            var row_max: u64 = 0;
            var row_samples: usize = 0;
            for (observers[0..shown_obs]) |*o| {
                const stats = o.hosts.get(ip);
                const avg: ?u64 = if (stats) |s| s.avg() else null;
                if (avg) |a| {
                    row_min = @min(row_min, a);
                    row_max = @max(row_max, a);
                    row_samples += 1;
                }
                var lat_buf: [16]u8 = undefined;
                const lat_str = formatLatency(avg, &lat_buf);
                const color = latencyToColor(avg);
                const block = latencyToBlock(avg);
                stdout.print("{s}{s} {s}{s}", .{ color, block, lat_str, reset }) catch {};
                const used = 2 + displayWidth(lat_str);
                stdout.print("{s}", .{pad[0..@max(1, col_width - @min(used, col_width - 1))]}) catch {};
            }
            if (row_samples >= 2 and spreadIsUneven(row_min, row_max)) {
                uneven_count += 1;
                stdout.print("{s}◀ uneven{s}", .{ yellow, reset }) catch {};
            }
            stdout.print("\n", .{}) catch {};
        }
        if (rows.items.len > shown_rows) {
            stdout.print("  {s}... +{d} more targets{s}\n", .{ gray, rows.items.len - shown_rows, reset }) catch {};
        }

        stdout.print("\n  {s}avg latency as seen from each observer · {s}◀ uneven{s}{s} = slowest vantage ≥3x fastest{s}\n", .{ gray, yellow, reset, gray, reset }) catch {};

        self.renderInsights(stdout, observers[0..num_obs], rows.items, uneven_count);
    }

    // Column-level analysis: an observer whose median latency to everything
    // is far above the mesh-wide median is itself poorly connected
    fn renderInsights(self: *Mesh, stdout: StdoutWriter, observers: []const Observer, rows: []const u32, uneven_count: usize) void {
        const reset = common.sgr("\x1b[0m");
        const yellow = common.sgr("\x1b[93m");
        var all_avgs: std.ArrayList(u64) = .empty;
        defer all_avgs.deinit(self.allocator);
        var col_medians: [1 + max_peers]?u64 = @splat(null);

        for (observers, 0..) |*o, oi| {
            var col_avgs: std.ArrayList(u64) = .empty;
            defer col_avgs.deinit(self.allocator);
            for (rows) |ip| {
                const stats = o.hosts.get(ip) orelse continue;
                const avg = stats.avg() orelse continue;
                col_avgs.append(self.allocator, avg) catch {};
                all_avgs.append(self.allocator, avg) catch {};
            }
            std.mem.sort(u64, col_avgs.items, {}, std.sort.asc(u64));
            col_medians[oi] = medianOfSorted(col_avgs.items);
        }

        std.mem.sort(u64, all_avgs.items, {}, std.sort.asc(u64));
        const global_median = medianOfSorted(all_avgs.items) orelse return;

        var printed_header = false;
        for (observers, 0..) |*o, oi| {
            const col_median = col_medians[oi] orelse continue;
            if (col_median >= global_median * 3 and col_median - global_median > 2000) {
                if (!printed_header) {
                    stdout.print("\n  {s}⚠ Insights:{s}\n", .{ yellow, reset }) catch {};
                    printed_header = true;
                }
                var m_buf: [16]u8 = undefined;
                var g_buf: [16]u8 = undefined;
                stdout.print("    Observer {s} sees a median of {s} vs {s} mesh-wide — its own link is likely the bottleneck\n", .{
                    o.label(),
                    formatLatency(col_median, &m_buf),
                    formatLatency(global_median, &g_buf),
                }) catch {};
            }
        }
        if (uneven_count > 0) {
            if (!printed_header) {
                stdout.print("\n  {s}⚠ Insights:{s}\n", .{ yellow, reset }) catch {};
                printed_header = true;
            }
            stdout.print("    {d} target{s} with uneven latency across observers — likely a slow link or AP between network segments\n", .{
                uneven_count,
                if (uneven_count == 1) "" else "s",
            }) catch {};
        }
    }
};

const testing = std.testing;

test "beacon round-trips through encode and parse" {
    var buf: [beacon_fixed_len + max_hostname]u8 = undefined;
    const msg = encodeBeacon(&buf, 0xDEADBEEFCAFEF00D, 7, 42, "office-nas");
    const parsed = parseMessage(msg).?;
    try testing.expectEqual(@as(u64, 0xDEADBEEFCAFEF00D), parsed.beacon.node_id);
    try testing.expectEqual(@as(u32, 7), parsed.beacon.seq);
    try testing.expectEqual(@as(u16, 42), parsed.beacon.host_count);
    try testing.expectEqualStrings("office-nas", parsed.beacon.hostname);
}

test "beacon encode truncates an oversized hostname" {
    var buf: [beacon_fixed_len + max_hostname]u8 = undefined;
    const long_name = "x" ** 100;
    const msg = encodeBeacon(&buf, 1, 0, 0, long_name);
    const parsed = parseMessage(msg).?;
    try testing.expectEqual(@as(usize, max_hostname), parsed.beacon.hostname.len);
}

test "results chunk round-trips including the no-data sentinel" {
    const entries = [_]Entry{
        .{ .ip = ipToU32(.{ 192, 168, 1, 1 }), .stats = .{ .min_us = 100, .avg_us = 250, .max_us = 900 } },
        .{ .ip = ipToU32(.{ 192, 168, 1, 7 }), .stats = .{ .min_us = no_data, .avg_us = no_data, .max_us = no_data } },
    };
    var buf: [results_fixed_len + entries_per_chunk * entry_len]u8 = undefined;
    const msg = encodeResultsChunk(&buf, 99, 3, 10, 4, &entries);
    const parsed = parseMessage(msg).?;
    try testing.expectEqual(@as(u64, 99), parsed.results.node_id);
    try testing.expectEqual(@as(u32, 3), parsed.results.seq);
    try testing.expectEqual(@as(u16, 10), parsed.results.total);
    try testing.expectEqual(@as(u16, 4), parsed.results.offset);
    try testing.expectEqual(@as(usize, 2 * entry_len), parsed.results.entries.len);

    const e0 = decodeEntry(parsed.results.entries[0..entry_len]);
    try testing.expectEqual(entries[0].ip, e0.ip);
    try testing.expectEqual(@as(u32, 250), e0.stats.avg_us);
    try testing.expect(e0.stats.hasData());

    const e1 = decodeEntry(parsed.results.entries[entry_len .. 2 * entry_len]);
    try testing.expectEqual(entries[1].ip, e1.ip);
    try testing.expect(!e1.stats.hasData());
}

test "parseMessage rejects malformed datagrams" {
    // Too short for any header
    try testing.expect(parseMessage(&.{ 'N', 'L', 'H' }) == null);

    // Wrong magic/version
    var bad_magic: [beacon_fixed_len]u8 = @splat(0);
    @memcpy(bad_magic[0..4], "NLH2");
    bad_magic[4] = 1;
    try testing.expect(parseMessage(&bad_magic) == null);

    // Unknown message type
    var bad_type: [beacon_fixed_len]u8 = @splat(0);
    @memcpy(bad_type[0..4], &protocol_magic);
    bad_type[4] = 9;
    try testing.expect(parseMessage(&bad_type) == null);

    // Beacon whose hostname length exceeds the buffer
    var buf: [beacon_fixed_len + max_hostname]u8 = undefined;
    const msg = encodeBeacon(&buf, 1, 0, 0, "ok");
    var truncated: [beacon_fixed_len + 1]u8 = undefined;
    @memcpy(&truncated, msg[0 .. beacon_fixed_len + 1]);
    truncated[19] = 30; // claims 30 bytes of hostname, buffer has 1
    try testing.expect(parseMessage(&truncated) == null);

    // Results chunk whose entry count exceeds the payload
    const entries = [_]Entry{
        .{ .ip = 1, .stats = .{ .min_us = 1, .avg_us = 2, .max_us = 3 } },
    };
    var rbuf: [results_fixed_len + entries_per_chunk * entry_len]u8 = undefined;
    const rmsg = encodeResultsChunk(&rbuf, 1, 1, 4, 0, &entries);
    var lying: [results_fixed_len + entry_len]u8 = undefined;
    @memcpy(&lying, rmsg[0 .. results_fixed_len + entry_len]);
    std.mem.writeInt(u16, lying[21..23], 3, .little); // claims 3 entries, has 1
    try testing.expect(parseMessage(&lying) == null);

    // Results chunk claiming more hosts than the per-peer cap
    var capped: [results_fixed_len + entry_len]u8 = undefined;
    @memcpy(&capped, rmsg[0 .. results_fixed_len + entry_len]);
    std.mem.writeInt(u16, capped[17..19], max_hosts_per_peer + 1, .little);
    try testing.expect(parseMessage(&capped) == null);

    // offset + count past total
    var overrun: [results_fixed_len + entry_len]u8 = undefined;
    @memcpy(&overrun, rmsg[0 .. results_fixed_len + entry_len]);
    std.mem.writeInt(u16, overrun[19..21], 4, .little); // offset 4 of total 4
    try testing.expect(parseMessage(&overrun) == null);
}

test "spreadIsUneven requires both ratio and absolute gap" {
    try testing.expect(spreadIsUneven(1000, 5000)); // 5x and 4ms apart
    try testing.expect(!spreadIsUneven(1000, 2500)); // gap but under 3x
    try testing.expect(!spreadIsUneven(100, 900)); // 9x but under 2ms gap
    try testing.expect(!spreadIsUneven(500, 500)); // identical
}

test "medianOfSorted picks the middle element" {
    try testing.expectEqual(@as(?u64, null), medianOfSorted(&.{}));
    try testing.expectEqual(@as(?u64, 5), medianOfSorted(&.{5}));
    try testing.expectEqual(@as(?u64, 7), medianOfSorted(&.{ 1, 7, 9 }));
    try testing.expectEqual(@as(?u64, 8), medianOfSorted(&.{ 1, 7, 8, 9 }));
}
