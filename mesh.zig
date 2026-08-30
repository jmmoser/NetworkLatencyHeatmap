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
//   Ping / pong (types 3 / 4, unicast, measure node↔node UDP RTT):
//     [13..21) token u64, opaque to the receiver and echoed back verbatim
//              (senders put their monotonic µs clock in it, so a pong is
//              its own timestamp and no send-table is needed)
//
//   Links (type 5, broadcast every beacon interval): the sender's direct
//   probe measurements, so every node can render the full node×node link
//   matrix and every node's view of each TCP target:
//     [13]     peer link count   (≤ max_peers)
//     [14]     tcp target count  (≤ probe.max_targets)
//     [15..)   peer links, 17 bytes each:
//                node id u64, udp avg u32 µs, tcp avg u32 µs, flags u8
//                (bit 0 = tcp sample was an RST; 0xFFFFFFFF = no data)
//              then tcp targets, 11 bytes each:
//                ip [4]u8 (network order), port u16, tcp avg u32 µs, flags u8
//
// Node↔node latency is also measured over TCP: each node listens on the
// mesh port and peers time a SYN → SYN-ACK handshake against it, torn down
// with an RST (zero window) rather than FIN so nothing lingers. See
// probe.zig; the same probe works against hosts not running this tool.
//
// Everything received is untrusted input: fixed caps on peers and hosts,
// strict length checks, unknown magic/type dropped silently. Old nodes
// drop ping/pong as unknown types, so mixing versions stays harmless.
const std = @import("std");
const posix = std.posix;
const c = std.c;
const common = @import("common.zig");
const probe = @import("probe.zig");

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
const ping_len = header_len + 8; // + token
const links_fixed_len = header_len + 2; // + peer link count, target count
const link_entry_len = 17; // node id, udp avg, tcp avg, flags
const target_entry_len = 11; // ip, port, tcp avg, flags
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

// UDP pings ride the beacon cadence; a pong slower than this is treated as
// stale (or forged) and dropped rather than recorded
const udp_ping_max_rtt_us: i64 = 10 * std.time.us_per_s;

// TCP probe rounds run on their own thread so connect() timing is never
// quantized by the main loop's sleep granularity
const tcp_probe_interval_us: i64 = 3 * std.time.us_per_s;
const tcp_probe_timeout_ms: u32 = 1000;

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
    ping = 3,
    pong = 4,
    links = 5,
};

// One gossiped node→node link measurement (avg over the sender's rolling
// window; no_data when the sender has no fresh samples for that transport)
pub const LinkEntry = struct {
    node_id: u64, // the link's far end
    udp_avg: u32,
    tcp_avg: u32,
    tcp_refused: bool, // tcp sample came from an RST, not a SYN-ACK
};

// One gossiped --tcp-ping target measurement
pub const TargetEntry = struct {
    ip: u32, // host byte order (as from ipToU32)
    port: u16,
    tcp_avg: u32,
    refused: bool,
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
    ping: struct {
        node_id: u64,
        token: u64,
    },
    pong: struct {
        node_id: u64,
        token: u64,
    },
    links: struct {
        node_id: u64,
        link_bytes: []const u8, // count * link_entry_len raw bytes
        target_bytes: []const u8, // count * target_entry_len raw bytes
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

fn encodeEcho(buf: []u8, msg_type: MsgType, node_id: u64, token: u64) []const u8 {
    writeHeader(buf, msg_type, node_id);
    std.mem.writeInt(u64, buf[13..21], token, .little);
    return buf[0..ping_len];
}

pub fn encodePing(buf: []u8, node_id: u64, token: u64) []const u8 {
    return encodeEcho(buf, .ping, node_id, token);
}

pub fn encodePong(buf: []u8, node_id: u64, token: u64) []const u8 {
    return encodeEcho(buf, .pong, node_id, token);
}

pub fn encodeLinks(buf: []u8, node_id: u64, links: []const LinkEntry, targets: []const TargetEntry) []const u8 {
    writeHeader(buf, .links, node_id);
    buf[13] = @intCast(links.len);
    buf[14] = @intCast(targets.len);
    var off: usize = links_fixed_len;
    for (links) |l| {
        std.mem.writeInt(u64, buf[off..][0..8], l.node_id, .little);
        std.mem.writeInt(u32, buf[off + 8 ..][0..4], l.udp_avg, .little);
        std.mem.writeInt(u32, buf[off + 12 ..][0..4], l.tcp_avg, .little);
        buf[off + 16] = @intFromBool(l.tcp_refused);
        off += link_entry_len;
    }
    for (targets) |t| {
        const ip_bytes = u32ToIp(t.ip);
        @memcpy(buf[off..][0..4], &ip_bytes);
        std.mem.writeInt(u16, buf[off + 4 ..][0..2], t.port, .little);
        std.mem.writeInt(u32, buf[off + 6 ..][0..4], t.tcp_avg, .little);
        buf[off + 10] = @intFromBool(t.refused);
        off += target_entry_len;
    }
    return buf[0..off];
}

pub fn decodeLinkEntry(bytes: []const u8) LinkEntry {
    return .{
        .node_id = std.mem.readInt(u64, bytes[0..8], .little),
        .udp_avg = std.mem.readInt(u32, bytes[8..12], .little),
        .tcp_avg = std.mem.readInt(u32, bytes[12..16], .little),
        .tcp_refused = bytes[16] & 1 != 0,
    };
}

pub fn decodeTargetEntry(bytes: []const u8) TargetEntry {
    const ip_bytes: [4]u8 = bytes[0..4].*;
    return .{
        .ip = ipToU32(ip_bytes),
        .port = std.mem.readInt(u16, bytes[4..6], .little),
        .tcp_avg = std.mem.readInt(u32, bytes[6..10], .little),
        .refused = bytes[10] & 1 != 0,
    };
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
        @intFromEnum(MsgType.links) => {
            if (buf.len < links_fixed_len) return null;
            const n_links: usize = buf[13];
            const n_targets: usize = buf[14];
            if (n_links > max_peers or n_targets > probe.max_targets) return null;
            const links_len = n_links * link_entry_len;
            if (buf.len < links_fixed_len + links_len + n_targets * target_entry_len) return null;
            return .{ .links = .{
                .node_id = node_id,
                .link_bytes = buf[links_fixed_len..][0..links_len],
                .target_bytes = buf[links_fixed_len + links_len ..][0 .. n_targets * target_entry_len],
            } };
        },
        @intFromEnum(MsgType.ping), @intFromEnum(MsgType.pong) => {
            if (buf.len < ping_len) return null;
            const token = std.mem.readInt(u64, buf[13..21], .little);
            if (buf[4] == @intFromEnum(MsgType.ping)) {
                return .{ .ping = .{ .node_id = node_id, .token = token } };
            }
            return .{ .pong = .{ .node_id = node_id, .token = token } };
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

    // Node↔node UDP echo RTT, fed by ping/pong on the beacon cadence.
    // A ping still outstanding when the next one goes out counts as a miss.
    udp_stats: probe.ProbeStats,
    udp_ping_outstanding: bool,

    // This peer's gossiped link measurements: its view of its own links to
    // other nodes, and of its own --tcp-ping targets. Replaced wholesale on
    // each links message (it is a full snapshot, not a delta).
    links: [max_peers]LinkEntry,
    link_count: u8,
    remote_targets: [probe.max_targets]TargetEntry,
    remote_target_count: u8,

    fn name(self: *const Peer) []const u8 {
        return self.hostname[0..self.hostname_len];
    }

    fn linkTo(self: *const Peer, node_id: u64) ?LinkEntry {
        for (self.links[0..self.link_count]) |e| {
            if (e.node_id == node_id) return e;
        }
        return null;
    }

    fn targetStats(self: *const Peer, ip: u32, port: u16) ?TargetEntry {
        for (self.remote_targets[0..self.remote_target_count]) |e| {
            if (e.ip == ip and e.port == port) return e;
        }
        return null;
    }
};

// TCP RTT results for one peer, produced by the prober thread. Keyed by
// node id (not a Peer pointer) because the peer list is owned by the main
// thread and entries can vanish between probe rounds.
const PeerTcp = struct {
    node_id: u64,
    stats: probe.ProbeStats,
};

// Minimal blocking lock for the prober handoff: the critical sections copy
// a few hundred bytes and contention is one thread every few seconds, so
// spinning with a scheduler yield is plenty. (Zig 0.16's std has no plain
// blocking thread mutex — std.Io.Mutex wants an Io instance this module
// doesn't carry.)
const SpinLock = struct {
    inner: std.atomic.Mutex = .unlocked,

    fn lock(self: *SpinLock) void {
        while (!self.inner.tryLock()) std.Thread.yield() catch {};
    }

    fn unlock(self: *SpinLock) void {
        self.inner.unlock();
    }
};

// Everything the prober thread and the main thread exchange, under one
// mutex: the main thread refreshes the peer snapshot each pump and reads
// results for rendering; the prober owns the probing itself.
const ProbeShared = struct {
    mutex: SpinLock = .{},
    stop: bool = false,

    // Snapshot of live peers (main → prober)
    peer_ids: [max_peers]u64 = undefined,
    peer_addrs: [max_peers]posix.sockaddr.in = undefined,
    peer_count: usize = 0,

    // Extra --tcp-ping targets, fixed at init
    extras: [probe.max_targets]probe.TcpTarget = undefined,
    extra_count: usize = 0,

    // Results (prober → main)
    peer_tcp: [max_peers]PeerTcp = undefined,
    peer_tcp_count: usize = 0,
    extra_tcp: [probe.max_targets]probe.ProbeStats = @splat(.{}),
    updated: bool = false,
};

pub const Mesh = struct {
    allocator: std.mem.Allocator,
    sock: posix.fd_t,
    poller: common.SocketPoller,
    port: u16,

    // TCP listener on the mesh port so peers can time SYN → SYN-ACK against
    // us; -1 when it couldn't be opened (peers then measure our RST instead)
    tcp_listen: posix.fd_t,
    probes: ProbeShared,
    prober: ?std.Thread,
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

    pub fn init(allocator: std.mem.Allocator, port: u16, subnet: [4]u8, mask_bits: u8, tcp_targets: []const probe.TcpTarget) !Mesh {
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

        // TCP listener for incoming SYN probes. Best-effort: without it the
        // kernel answers peers' SYNs with an RST, which they can still time.
        var tcp_listen: posix.fd_t = -1;
        tcp: {
            const tfd_c = c.socket(posix.AF.INET, c.SOCK.STREAM, 0);
            if (tfd_c < 0) break :tcp;
            const tfd: posix.fd_t = @intCast(tfd_c);
            _ = c.setsockopt(tfd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one, @sizeOf(c_int));
            _ = c.setsockopt(tfd, posix.SOL.SOCKET, posix.SO.REUSEPORT, &one, @sizeOf(c_int));
            const tflags = c.fcntl(tfd, posix.F.GETFL, @as(c_int, 0));
            if (tflags < 0 or
                c.fcntl(tfd, posix.F.SETFL, tflags | @as(c_int, o_nonblock)) < 0 or
                c.bind(tfd, @ptrCast(&bind_addr), @sizeOf(posix.sockaddr.in)) != 0 or
                c.listen(tfd, 16) != 0)
            {
                _ = c.close(tfd);
                break :tcp;
            }
            tcp_listen = tfd;
        }

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

        var probes = ProbeShared{};
        probes.extra_count = @min(tcp_targets.len, probe.max_targets);
        for (tcp_targets[0..probes.extra_count], 0..) |t, i| probes.extras[i] = t;

        return Mesh{
            .allocator = allocator,
            .sock = sock,
            .poller = poller,
            .port = port,
            .tcp_listen = tcp_listen,
            .probes = probes,
            .prober = null,
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
        if (self.prober) |thread| {
            {
                self.probes.mutex.lock();
                defer self.probes.mutex.unlock();
                self.probes.stop = true;
            }
            thread.join();
        }
        for (self.peers.items) |*p| p.hosts.deinit();
        self.peers.deinit(self.allocator);
        self.local_hosts.deinit();
        self.local_entries.deinit(self.allocator);
        self.poller.deinit();
        if (self.tcp_listen >= 0) _ = c.close(self.tcp_listen);
        _ = c.close(self.sock);
    }

    // Start the TCP probe thread. Call once the Mesh has its final address
    // (the thread keeps a pointer to self.probes).
    pub fn startProber(self: *Mesh) !void {
        self.prober = try std.Thread.spawn(.{}, proberMain, .{ &self.probes, self.port });
    }

    // Runs on its own thread: every interval, probe all live peers (on the
    // mesh TCP port) plus the extra targets concurrently, then publish the
    // results. Off-thread so RTTs come from poll wakeups, not from whenever
    // the main loop happens to spin.
    fn proberMain(shared: *ProbeShared, tcp_port: u16) void {
        while (true) {
            var addrs: [max_peers + probe.max_targets]posix.sockaddr.in = undefined;
            var ids: [max_peers]u64 = undefined;
            var n_peers: usize = 0;
            var n_extra: usize = 0;
            {
                shared.mutex.lock();
                defer shared.mutex.unlock();
                if (shared.stop) return;
                n_peers = shared.peer_count;
                for (0..n_peers) |i| {
                    ids[i] = shared.peer_ids[i];
                    addrs[i] = shared.peer_addrs[i];
                    addrs[i].port = std.mem.nativeToBig(u16, tcp_port);
                }
                n_extra = shared.extra_count;
                for (shared.extras[0..n_extra], 0..) |t, i| {
                    addrs[n_peers + i] = .{
                        .family = posix.AF.INET,
                        .port = std.mem.nativeToBig(u16, t.port),
                        .addr = std.mem.bytesToValue(u32, &t.ip),
                    };
                }
            }

            const total = n_peers + n_extra;
            var results: [max_peers + probe.max_targets]probe.Outcome = undefined;
            if (total > 0)
                probe.tcpProbeBatch(addrs[0..total], results[0..total], tcp_probe_timeout_ms);

            {
                shared.mutex.lock();
                defer shared.mutex.unlock();
                if (shared.stop) return;
                if (total > 0) {
                    // Rebuild the per-peer table from this round's snapshot:
                    // carry stats forward by node id, dropping vanished peers
                    var kept: [max_peers]PeerTcp = undefined;
                    for (0..n_peers) |i| {
                        kept[i] = .{ .node_id = ids[i], .stats = .{} };
                        for (shared.peer_tcp[0..shared.peer_tcp_count]) |old| {
                            if (old.node_id == ids[i]) {
                                kept[i].stats = old.stats;
                                break;
                            }
                        }
                        kept[i].stats.record(results[i]);
                    }
                    shared.peer_tcp = kept;
                    shared.peer_tcp_count = n_peers;
                    for (0..n_extra) |i| shared.extra_tcp[i].record(results[n_peers + i]);
                    shared.updated = true;
                }
            }

            // Sleep in short ticks so stop is honored promptly
            var slept: i64 = 0;
            while (slept < tcp_probe_interval_us) {
                {
                    shared.mutex.lock();
                    defer shared.mutex.unlock();
                    if (shared.stop) return;
                }
                common.sleepNanos(100 * std.time.ns_per_ms);
                slept += 100 * std.time.us_per_ms;
            }
        }
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

    // Unicast a UDP ping to every peer. The token is our monotonic clock,
    // so the echoed pong dates itself; a ping still unanswered from the
    // previous round is recorded as a miss first.
    fn sendPeerPings(self: *Mesh) void {
        var buf: [ping_len]u8 = undefined;
        for (self.peers.items) |*p| {
            if (p.udp_ping_outstanding) {
                p.udp_stats.record(.{ .rtt_us = null, .refused = false });
            }
            p.udp_ping_outstanding = true;
            // Fresh timestamp per send so queueing behind earlier sends in
            // this loop doesn't inflate the sample
            const msg = encodePing(&buf, self.node_id, @bitCast(monotonicMicros()));
            self.sendDatagram(msg, &p.addr);
        }
    }

    // Broadcast our direct probe measurements so every node can render the
    // full node×node link matrix, not just its own row. Everything fits one
    // datagram (max ~750 bytes), so no chunking.
    fn sendLinks(self: *Mesh) void {
        var links: [max_peers]LinkEntry = undefined;
        var n_links: usize = 0;
        var targets: [probe.max_targets]TargetEntry = undefined;
        var n_targets: usize = 0;
        {
            self.probes.mutex.lock();
            defer self.probes.mutex.unlock();
            for (self.peers.items) |*p| {
                if (n_links >= max_peers) break;
                var tcp_avg: u32 = no_data;
                var refused = false;
                for (self.probes.peer_tcp[0..self.probes.peer_tcp_count]) |entry| {
                    if (entry.node_id == p.node_id) {
                        if (entry.stats.alive()) {
                            tcp_avg = clampStat(entry.stats.avg());
                            refused = entry.stats.refused;
                        }
                        break;
                    }
                }
                links[n_links] = .{
                    .node_id = p.node_id,
                    .udp_avg = if (p.udp_stats.alive()) clampStat(p.udp_stats.avg()) else no_data,
                    .tcp_avg = tcp_avg,
                    .tcp_refused = refused,
                };
                n_links += 1;
            }
            for (0..self.probes.extra_count) |i| {
                const s = self.probes.extra_tcp[i];
                const t = self.probes.extras[i];
                targets[n_targets] = .{
                    .ip = ipToU32(t.ip),
                    .port = t.port,
                    .tcp_avg = if (s.alive()) clampStat(s.avg()) else no_data,
                    .refused = s.alive() and s.refused,
                };
                n_targets += 1;
            }
        }
        if (n_links == 0 and n_targets == 0) return;

        var buf: [links_fixed_len + max_peers * link_entry_len + probe.max_targets * target_entry_len]u8 = undefined;
        const msg = encodeLinks(&buf, self.node_id, links[0..n_links], targets[0..n_targets]);
        for (&self.bcast_addrs) |*addr| self.sendDatagram(msg, addr);
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
            .udp_stats = .{},
            .udp_ping_outstanding = false,
            .links = undefined,
            .link_count = 0,
            .remote_targets = undefined,
            .remote_target_count = 0,
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
            .ping => |p| {
                if (p.node_id == self.node_id) return;
                // Echo service: answer any well-formed ping, even from a
                // node we don't track (it may be over its own peer cap)
                var buf: [ping_len]u8 = undefined;
                const msg = encodePong(&buf, self.node_id, p.token);
                self.sendDatagram(msg, src);
            },
            .pong => |p| {
                if (p.node_id == self.node_id) return;
                const peer = self.findPeer(p.node_id) orelse return;
                // The token is our own monotonic send time; sanity-bound it
                // so a garbled or replayed pong can't record a junk RTT.
                // (A LAN peer could lie here, same trust level as gossip.)
                const rtt = monotonicMicros() - @as(i64, @bitCast(p.token));
                if (rtt < 0 or rtt > udp_ping_max_rtt_us) return;
                peer.udp_stats.record(.{ .rtt_us = @intCast(rtt), .refused = false });
                peer.udp_ping_outstanding = false;
                self.dirty = true;
            },
            .links => |l| {
                if (l.node_id == self.node_id) return;
                const peer = self.obtainPeer(l.node_id, src, now) orelse return;
                // Full snapshot: replace what we held (parse already capped
                // both counts at the storage sizes)
                var i: usize = 0;
                var off: usize = 0;
                while (off < l.link_bytes.len) : (off += link_entry_len) {
                    peer.links[i] = decodeLinkEntry(l.link_bytes[off..][0..link_entry_len]);
                    i += 1;
                }
                peer.link_count = @intCast(i);
                i = 0;
                off = 0;
                while (off < l.target_bytes.len) : (off += target_entry_len) {
                    peer.remote_targets[i] = decodeTargetEntry(l.target_bytes[off..][0..target_entry_len]);
                    i += 1;
                }
                peer.remote_target_count = @intCast(i);
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
        // Keep the TCP accept queue drained too, or a scan longer than a few
        // probe rounds fills the backlog and peers' SYNs start timing out.
        // Peer pings stay out of keepAlive on purpose: an RTT sampled while
        // the scanner is blasting would be inflated by our own load.
        self.drainTcpAccepts();
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
            self.sendPeerPings();
            self.sendLinks();
        }
        if (self.local_entries.items.len > 0 and now - self.last_gossip_us >= gossip_interval_us) {
            self.last_gossip_us = now;
            self.gossipResults();
        }

        self.drainTcpAccepts();

        // Refresh the prober's peer snapshot and pick up finished rounds
        {
            self.probes.mutex.lock();
            defer self.probes.mutex.unlock();
            const count = @min(self.peers.items.len, max_peers);
            for (self.peers.items[0..count], 0..) |*p, i| {
                self.probes.peer_ids[i] = p.node_id;
                self.probes.peer_addrs[i] = p.addr;
            }
            self.probes.peer_count = count;
            if (self.probes.updated) {
                self.probes.updated = false;
                self.dirty = true;
            }
        }

        self.drainSocket(now);
    }

    // Drain incoming TCP probe connections: accept and abort each with an
    // RST (zero window) so probers get their timing without either side
    // accumulating open connections or TIME_WAIT state
    fn drainTcpAccepts(self: *Mesh) void {
        if (self.tcp_listen < 0) return;
        while (true) {
            const cfd = c.accept(self.tcp_listen, null, null);
            if (cfd < 0) break;
            const lo = c.linger{ .onoff = 1, .linger = 0 };
            _ = c.setsockopt(@intCast(cfd), posix.SOL.SOCKET, posix.SO.LINGER, &lo, @sizeOf(c.linger));
            _ = c.close(@intCast(cfd));
        }
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
        node_id: u64,
        hosts: *const std.AutoHashMap(u32, HostStats),
        age_us: i64, // since this observer's data was produced/received

        fn label(self: *const Observer) []const u8 {
            return self.label_buf[0..self.label_len];
        }
    };

    fn makeObserver(label_text: []const u8, node_id: u64, hosts: *const std.AutoHashMap(u32, HostStats), age_us: i64) Observer {
        var o = Observer{
            .label_buf = undefined,
            .label_len = 0,
            .node_id = node_id,
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
        observers[0] = makeObserver("self", self.node_id, &self.local_hosts, if (self.local_scan_us > 0) now - self.local_scan_us else -1);
        num_obs = 1;
        for (self.peers.items) |*p| {
            if (num_obs >= observers.len) break;
            var ip_buf: [16]u8 = undefined;
            const peer_ip: [4]u8 = @bitCast(p.addr.addr);
            const label_text = if (p.hostname_len > 0) p.name() else ipToString(peer_ip, &ip_buf);
            const age: i64 = if (p.last_results_us > 0) now - p.last_results_us else -1;
            observers[num_obs] = makeObserver(label_text, p.node_id, &p.hosts, age);
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

        self.renderLinks(stdout, observers[0..num_obs], shown_obs);
        self.renderInsights(stdout, observers[0..num_obs], rows.items, uneven_count);
    }

    const Link = struct { udp: ?u64, tcp: ?u64, refused: bool };

    fn statToOpt(v: u32) ?u64 {
        return if (v == no_data) null else v;
    }

    // The link from observer `from` to node `to_id`, as this node knows it:
    // our own live measurements when `from` is us, the peer's gossiped
    // snapshot otherwise.
    fn linkBetween(self: *Mesh, from: *const Observer, to_id: u64, peer_tcp: []const PeerTcp) Link {
        const none = Link{ .udp = null, .tcp = null, .refused = false };
        if (from.node_id == self.node_id) {
            const p = self.findPeer(to_id) orelse return none;
            var link = Link{
                .udp = if (p.udp_stats.alive()) p.udp_stats.avg() else null,
                .tcp = null,
                .refused = false,
            };
            for (peer_tcp) |e| {
                if (e.node_id == to_id and e.stats.alive()) {
                    link.tcp = e.stats.avg();
                    link.refused = e.stats.refused;
                    break;
                }
            }
            return link;
        }
        const p = self.findPeer(from.node_id) orelse return none;
        const e = p.linkTo(to_id) orelse return none;
        return .{ .udp = statToOpt(e.udp_avg), .tcp = statToOpt(e.tcp_avg), .refused = e.tcp_refused };
    }

    // Node↔node link matrix, plus every node's view of the --tcp-ping
    // targets. The self column comes from our own probes; every other
    // column from that peer's gossiped links message, so all nodes converge
    // on the same picture from any seat.
    fn renderLinks(self: *Mesh, stdout: StdoutWriter, observers: []const Observer, shown_obs: usize) void {
        const reset = common.sgr("\x1b[0m");
        const bold = common.sgr("\x1b[1m");
        const gray = common.sgr("\x1b[90m");
        const col_width = 13;
        const label_width = 17;
        const pad = " " ** 32;

        // Copy the prober's results out under the lock; render unlocked
        var peer_tcp: [max_peers]PeerTcp = undefined;
        var peer_tcp_count: usize = 0;
        var extras: [probe.max_targets]probe.TcpTarget = undefined;
        var extra_tcp: [probe.max_targets]probe.ProbeStats = undefined;
        var extra_count: usize = 0;
        {
            self.probes.mutex.lock();
            defer self.probes.mutex.unlock();
            peer_tcp_count = self.probes.peer_tcp_count;
            @memcpy(peer_tcp[0..peer_tcp_count], self.probes.peer_tcp[0..peer_tcp_count]);
            extra_count = self.probes.extra_count;
            @memcpy(extras[0..extra_count], self.probes.extras[0..extra_count]);
            @memcpy(extra_tcp[0..extra_count], self.probes.extra_tcp[0..extra_count]);
        }

        // Union of TCP targets: ours plus everything peers gossip
        const TargetKey = struct { ip: u32, port: u16 };
        var target_keys: [32]TargetKey = undefined;
        var n_targets: usize = 0;
        for (extras[0..extra_count]) |t| {
            if (n_targets >= target_keys.len) break;
            target_keys[n_targets] = .{ .ip = ipToU32(t.ip), .port = t.port };
            n_targets += 1;
        }
        outer: for (self.peers.items) |*p| {
            for (p.remote_targets[0..p.remote_target_count]) |e| {
                if (n_targets >= target_keys.len) break :outer;
                var seen = false;
                for (target_keys[0..n_targets]) |k| {
                    if (k.ip == e.ip and k.port == e.port) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) {
                    target_keys[n_targets] = .{ .ip = e.ip, .port = e.port };
                    n_targets += 1;
                }
            }
        }

        if (observers.len <= 1 and n_targets == 0) return;

        stdout.print("\n  {s}Node links{s} {s}· cell = from column node to row, udp/tcp avg · * = RST (closed port){s}\n", .{
            bold, reset, gray, reset,
        }) catch {};

        if (observers.len > 1) {
            stdout.print("  {s}node{s}{s}", .{ bold, reset, pad[0 .. label_width - 4] }) catch {};
            for (observers[0..shown_obs]) |*o| {
                const l = o.label()[0..@min(o.label().len, col_width - 1)];
                stdout.print("{s}{s}{s}{s}", .{ bold, l, reset, pad[0 .. col_width - l.len] }) catch {};
            }
            stdout.print("\n", .{}) catch {};

            for (observers) |*row| {
                const l = row.label()[0..@min(row.label().len, label_width - 1)];
                stdout.print("  {s}{s}", .{ l, pad[0 .. label_width - l.len] }) catch {};
                for (observers[0..shown_obs]) |*col| {
                    if (col.node_id == row.node_id) {
                        stdout.print("{s}—{s}{s}", .{ gray, reset, pad[0 .. col_width - 1] }) catch {};
                        continue;
                    }
                    printLinkCell(stdout, self.linkBetween(col, row.node_id, peer_tcp[0..peer_tcp_count]), col_width);
                }
                stdout.print("\n", .{}) catch {};
            }
        }

        if (n_targets > 0) {
            if (observers.len > 1) stdout.print("\n", .{}) catch {};
            stdout.print("  {s}tcp target{s}{s}", .{ bold, reset, pad[0 .. label_width - 10] }) catch {};
            for (observers[0..shown_obs]) |*o| {
                const l = o.label()[0..@min(o.label().len, col_width - 1)];
                stdout.print("{s}{s}{s}{s}", .{ bold, l, reset, pad[0 .. col_width - l.len] }) catch {};
            }
            stdout.print("\n", .{}) catch {};

            for (target_keys[0..n_targets]) |k| {
                var ip_buf: [16]u8 = undefined;
                var label_buf: [24]u8 = undefined;
                const label = std.fmt.bufPrint(&label_buf, "{s}:{d}", .{ ipToString(u32ToIp(k.ip), &ip_buf), k.port }) catch "?";
                const shown = label[0..@min(label.len, label_width - 1)];
                stdout.print("  {s}{s}", .{ shown, pad[0 .. label_width - shown.len] }) catch {};

                for (observers[0..shown_obs]) |*col| {
                    if (col.node_id == self.node_id) {
                        var avg: ?u64 = null;
                        var refused = false;
                        for (extras[0..extra_count], 0..) |t, i| {
                            if (ipToU32(t.ip) == k.ip and t.port == k.port and extra_tcp[i].alive()) {
                                avg = extra_tcp[i].avg();
                                refused = extra_tcp[i].refused;
                                break;
                            }
                        }
                        printTcpCell(stdout, avg, refused, col_width);
                    } else if (self.findPeer(col.node_id)) |p| {
                        if (p.targetStats(k.ip, k.port)) |e| {
                            printTcpCell(stdout, statToOpt(e.tcp_avg), e.refused, col_width);
                        } else {
                            printTcpCell(stdout, null, false, col_width);
                        }
                    } else {
                        printTcpCell(stdout, null, false, col_width);
                    }
                }
                stdout.print("\n", .{}) catch {};
            }
        }
    }

    fn printLinkCell(stdout: StdoutWriter, link: Link, col_width: usize) void {
        const reset = common.sgr("\x1b[0m");
        const gray = common.sgr("\x1b[90m");
        const pad = " " ** 32;
        if (link.udp == null and link.tcp == null) {
            stdout.print("{s}---{s}{s}", .{ gray, reset, pad[0 .. col_width - 3] }) catch {};
            return;
        }
        var u_buf: [16]u8 = undefined;
        var t_buf: [16]u8 = undefined;
        const u_str = formatLatency(link.udp, &u_buf);
        const t_str = formatLatency(link.tcp, &t_buf);
        // Color the cell by the slower transport — the interesting one
        const worst = @max(link.udp orelse 0, link.tcp orelse 0);
        const star = if (link.refused and link.tcp != null) "*" else "";
        stdout.print("{s}{s}/{s}{s}{s}", .{ latencyToColor(worst), u_str, t_str, star, reset }) catch {};
        const used = displayWidth(u_str) + 1 + displayWidth(t_str) + star.len;
        stdout.print("{s}", .{pad[0..@max(1, col_width - @min(used, col_width - 1))]}) catch {};
    }

    fn printTcpCell(stdout: StdoutWriter, avg_us: ?u64, refused: bool, col_width: usize) void {
        const reset = common.sgr("\x1b[0m");
        const gray = common.sgr("\x1b[90m");
        const pad = " " ** 32;
        var buf: [16]u8 = undefined;
        const s = formatLatency(avg_us, &buf);
        const star = if (refused and avg_us != null) "*" else "";
        const color = if (avg_us == null) gray else latencyToColor(avg_us);
        stdout.print("{s}{s}{s}{s}", .{ color, s, star, reset }) catch {};
        const used = displayWidth(s) + star.len;
        stdout.print("{s}", .{pad[0..@max(1, col_width - @min(used, col_width - 1))]}) catch {};
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

test "ping and pong round-trip through encode and parse" {
    var buf: [ping_len]u8 = undefined;

    const ping = parseMessage(encodePing(&buf, 0x1122334455667788, 0xAABBCCDDEEFF0011)).?;
    try testing.expectEqual(@as(u64, 0x1122334455667788), ping.ping.node_id);
    try testing.expectEqual(@as(u64, 0xAABBCCDDEEFF0011), ping.ping.token);

    const pong = parseMessage(encodePong(&buf, 42, 99)).?;
    try testing.expectEqual(@as(u64, 42), pong.pong.node_id);
    try testing.expectEqual(@as(u64, 99), pong.pong.token);
}

test "links message round-trips peer links and tcp targets" {
    const links = [_]LinkEntry{
        .{ .node_id = 0xAAAA, .udp_avg = 640, .tcp_avg = 810, .tcp_refused = false },
        .{ .node_id = 0xBBBB, .udp_avg = no_data, .tcp_avg = 1200, .tcp_refused = true },
    };
    const targets = [_]TargetEntry{
        .{ .ip = ipToU32(.{ 192, 168, 1, 1 }), .port = 443, .tcp_avg = 2100, .refused = false },
        .{ .ip = ipToU32(.{ 192, 168, 1, 9 }), .port = 22, .tcp_avg = no_data, .refused = false },
    };
    var buf: [links_fixed_len + max_peers * link_entry_len + probe.max_targets * target_entry_len]u8 = undefined;
    const msg = encodeLinks(&buf, 77, &links, &targets);
    const parsed = parseMessage(msg).?;
    try testing.expectEqual(@as(u64, 77), parsed.links.node_id);
    try testing.expectEqual(@as(usize, 2 * link_entry_len), parsed.links.link_bytes.len);
    try testing.expectEqual(@as(usize, 2 * target_entry_len), parsed.links.target_bytes.len);

    const l0 = decodeLinkEntry(parsed.links.link_bytes[0..link_entry_len]);
    try testing.expectEqual(links[0], l0);
    const l1 = decodeLinkEntry(parsed.links.link_bytes[link_entry_len .. 2 * link_entry_len]);
    try testing.expectEqual(links[1], l1);
    try testing.expect(l1.tcp_refused);

    const t0 = decodeTargetEntry(parsed.links.target_bytes[0..target_entry_len]);
    try testing.expectEqual(targets[0], t0);
    const t1 = decodeTargetEntry(parsed.links.target_bytes[target_entry_len .. 2 * target_entry_len]);
    try testing.expectEqual(targets[1], t1);
}

test "parseMessage rejects malformed links messages" {
    const links = [_]LinkEntry{
        .{ .node_id = 1, .udp_avg = 10, .tcp_avg = 20, .tcp_refused = false },
    };
    var buf: [links_fixed_len + max_peers * link_entry_len]u8 = undefined;
    const msg = encodeLinks(&buf, 1, &links, &.{});

    // Truncated payload
    try testing.expect(parseMessage(msg[0 .. msg.len - 1]) == null);

    // Counts over the caps
    var over_links: [links_fixed_len + link_entry_len]u8 = undefined;
    @memcpy(&over_links, msg[0 .. links_fixed_len + link_entry_len]);
    over_links[13] = max_peers + 1;
    try testing.expect(parseMessage(&over_links) == null);

    var over_targets: [links_fixed_len + link_entry_len]u8 = undefined;
    @memcpy(&over_targets, msg[0 .. links_fixed_len + link_entry_len]);
    over_targets[14] = probe.max_targets + 1;
    try testing.expect(parseMessage(&over_targets) == null);

    // Count claiming more entries than the datagram carries
    var lying: [links_fixed_len + link_entry_len]u8 = undefined;
    @memcpy(&lying, msg[0 .. links_fixed_len + link_entry_len]);
    lying[13] = 2;
    try testing.expect(parseMessage(&lying) == null);
}

test "parseMessage rejects a truncated ping" {
    var buf: [ping_len]u8 = undefined;
    const msg = encodePing(&buf, 1, 2);
    try testing.expect(parseMessage(msg[0 .. ping_len - 1]) == null);
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
