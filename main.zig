const std = @import("std");
const posix = std.posix;
const c = std.c;
const builtin = @import("builtin");
const common = @import("common.zig");
const mesh_mod = @import("mesh.zig");
const probe = @import("probe.zig");
const plat = @import("plat.zig");
const neigh = @import("neigh.zig");

const SocketPoller = common.SocketPoller;
const PingResult = common.PingResult;
const StdoutWriter = common.StdoutWriter;
const ipToU32 = common.ipToU32;
const u32ToIp = common.u32ToIp;
const clockMicros = common.clockMicros;
const monotonicMicros = common.monotonicMicros;
const wallMicros = common.wallMicros;
const sleepNanos = common.sleepNanos;
const ipToString = common.ipToString;
const latencyToColor = common.latencyToColor;
const latencyToBlock = common.latencyToBlock;
const formatLatency = common.formatLatency;
const displayWidth = common.displayWidth;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

// Network interface detection: getifaddrs on POSIX, GetIpAddrTable
// (via plat.zig) on Windows
const ifaddrs = extern struct {
    next: ?*ifaddrs,
    name: [*:0]const u8,
    flags: c_uint,
    addr: ?*posix.sockaddr,
    netmask: ?*posix.sockaddr,
    data: ?*anyopaque, // ifu_broadaddr or ifu_dstaddr union
    data2: ?*anyopaque,
};

extern "c" fn getifaddrs(ifap: *?*ifaddrs) c_int;
extern "c" fn freeifaddrs(ifa: *ifaddrs) void;

const IFF_UP: c_uint = 0x1;
const IFF_LOOPBACK: c_uint = 0x8;
const IFF_RUNNING: c_uint = 0x40;

// Local address the default route would use, found by connect()ing a UDP
// socket to a public address (no packet is sent — connect on UDP only
// selects the route) and reading back the chosen source address. Null when
// there is no default route. Works unprivileged on every platform, unlike
// parsing /proc/net/route or the PF_ROUTE sysctls.
fn defaultRouteLocalAddr() ?u32 {
    const sock = plat.openSocket(plat.AF_INET, plat.SOCK_DGRAM, 0);
    if (!plat.isValidSocket(sock)) return null;
    defer plat.closeSocket(sock);

    const probe_ip = [4]u8{ 8, 8, 8, 8 };
    const dest = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, 53),
        .addr = std.mem.bytesToValue(u32, &probe_ip),
    };
    if (plat.connect(sock, &dest, @sizeOf(posix.sockaddr.in)) != 0) return null;

    var local: posix.sockaddr.in = undefined;
    var len: u32 = @sizeOf(posix.sockaddr.in);
    if (plat.getsockname(sock, &local, &len) != 0) return null;
    return local.addr;
}

const DetectedSubnet = struct {
    subnet: [4]u8,
    mask: u8,
    ifname: [16]u8, // IFNAMSIZ; zero-padded
    ifname_len: u8,
    on_default_route: bool,

    fn name(self: *const DetectedSubnet) []const u8 {
        return self.ifname[0..self.ifname_len];
    }
};

const max_ifaces = 32;

// One usable IPv4 interface address, however the platform enumerated it
const IfaceEntry = struct {
    addr_be: u32, // interface address, network byte order
    mask_be: u32, // netmask, network byte order
    name: [16]u8, // zero-padded
    name_len: u8,
};

// Enumerate IPv4 interface addresses. Loopback and down interfaces are
// already filtered out; everything else (link-local, weird masks) is left
// to the caller's policy.
fn collectIfaces(out: *[max_ifaces]IfaceEntry) usize {
    if (plat.is_windows) {
        var rows: [max_ifaces]plat.WinIface = undefined;
        const n = plat.windowsListIfaces(&rows);
        for (rows[0..n], 0..) |row, i| {
            var e = IfaceEntry{
                .addr_be = row.addr_be,
                .mask_be = row.mask_be,
                .name = @splat(0),
                .name_len = 0,
            };
            // GetIpAddrTable has no interface names; show the index
            const label = std.fmt.bufPrint(&e.name, "if{d}", .{row.index}) catch "";
            e.name_len = @intCast(label.len);
            out[i] = e;
        }
        return n;
    } else {
        return collectIfacesPosix(out);
    }
}

fn collectIfacesPosix(out: *[max_ifaces]IfaceEntry) usize {
    var ifa_list: ?*ifaddrs = null;
    if (getifaddrs(&ifa_list) != 0) return 0;
    defer if (ifa_list) |list| freeifaddrs(list);

    var count: usize = 0;
    var ifa = ifa_list;
    while (ifa) |iface| : (ifa = iface.next) {
        if (count >= out.len) break;

        // Skip loopback and down interfaces
        if ((iface.flags & IFF_LOOPBACK) != 0) continue;
        if ((iface.flags & IFF_UP) == 0) continue;
        if ((iface.flags & IFF_RUNNING) == 0) continue;

        // Only handle IPv4 (AF_INET = 2)
        const addr = iface.addr orelse continue;
        if (addr.family != posix.AF.INET) continue;

        const netmask = iface.netmask orelse continue;
        if (netmask.family != posix.AF.INET) continue;

        const addr_in: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
        const mask_in: *const posix.sockaddr.in = @ptrCast(@alignCast(netmask));

        var e = IfaceEntry{
            .addr_be = addr_in.addr,
            .mask_be = mask_in.addr,
            .name = @splat(0),
            .name_len = 0,
        };
        const name_slice = std.mem.span(iface.name);
        const take = @min(name_slice.len, e.name.len);
        @memcpy(e.name[0..take], name_slice[0..take]);
        e.name_len = @intCast(take);

        out[count] = e;
        count += 1;
    }
    return count;
}

// Pick the subnet to scan. Machines often have several eligible interfaces
// (VPN tunnels, VM bridges, container networks), so prefer the one carrying
// the default route; fall back to the first eligible interface when no
// default route exists or its interface fails the eligibility checks.
fn detectLocalSubnet() ?DetectedSubnet {
    var entries: [max_ifaces]IfaceEntry = undefined;
    const n = collectIfaces(&entries);

    const preferred_addr = defaultRouteLocalAddr();
    var fallback: ?DetectedSubnet = null;

    for (entries[0..n]) |*e| {
        // Address and mask bytes (network byte order)
        const ip_bytes: [4]u8 = @bitCast(e.addr_be);
        const mask_bytes: [4]u8 = @bitCast(e.mask_be);

        // Skip link-local addresses (169.254.x.x)
        if (ip_bytes[0] == 169 and ip_bytes[1] == 254) continue;

        // Calculate mask bits from netmask; reject non-contiguous masks
        const mask_u32 = ipToU32(mask_bytes);
        const mask_bits: u8 = @intCast(@clz(~mask_u32));
        if (mask_bits < 32 and (mask_u32 << @intCast(mask_bits)) != 0) continue;

        // Skip host/point-to-point masks (e.g. /32 on VPN utun interfaces)
        // and masks too wide to scan sensibly
        if (mask_bits > 30 or mask_bits < 16) continue;

        // Calculate network address (IP & mask)
        const subnet: [4]u8 = .{
            ip_bytes[0] & mask_bytes[0],
            ip_bytes[1] & mask_bytes[1],
            ip_bytes[2] & mask_bytes[2],
            ip_bytes[3] & mask_bytes[3],
        };

        const is_preferred = preferred_addr != null and e.addr_be == preferred_addr.?;
        const detected = DetectedSubnet{
            .subnet = subnet,
            .mask = mask_bits,
            .ifname = e.name,
            .ifname_len = e.name_len,
            .on_default_route = is_preferred,
        };

        if (is_preferred) return detected;
        if (fallback == null) fallback = detected;
    }
    return fallback;
}

// Windows only: a raw socket must be bound to a specific local address to
// receive anything, so find the interface address on the scanned subnet,
// falling back to the default route's address, then INADDR_ANY.
fn rawSocketBindAddr(subnet: [4]u8, mask_bits: u8) u32 {
    var entries: [max_ifaces]IfaceEntry = undefined;
    const n = collectIfaces(&entries);

    const netmask: u32 = if (mask_bits >= 32)
        ~@as(u32, 0)
    else
        ~@as(u32, 0) << @intCast(32 - mask_bits);
    const network = ipToU32(subnet) & netmask;

    for (entries[0..n]) |*e| {
        const ip = ipToU32(@as([4]u8, @bitCast(e.addr_be)));
        if ((ip & netmask) == network) return e.addr_be;
    }
    return defaultRouteLocalAddr() orelse 0;
}

// Kernel receive timestamps: with SO_TIMESTAMP enabled, the kernel records
// each packet's arrival time as it enters the network stack and delivers it
// via recvmsg ancillary data (SCM_TIMESTAMP + struct timeval). Using that
// instead of a userspace timestamp removes poller wakeup, scheduling, and
// drain-queue delay in this process from measured RTTs. The timestamp is in
// the realtime clock domain, the same clock as std.time.microTimestamp(),
// so it is directly comparable to our send timestamps.
//
// Supported on Linux and Apple platforms; elsewhere (or if setsockopt
// fails) receive times fall back to userspace timestamps.
const kernel_ts = struct {
    const supported = SocketPoller.is_linux or builtin.os.tag.isDarwin();

    const level: i32 = @intCast(posix.SOL.SOCKET);

    // Socket option that enables timestamps, and the cmsg type carrying them.
    // On Linux SCM_TIMESTAMP == SO_TIMESTAMP; on Darwin it is 0x02. Zig's
    // std doesn't expose SO_TIMESTAMP for Darwin, so use the XNU value.
    const sockopt: u32 = if (SocketPoller.is_linux)
        std.os.linux.SO.TIMESTAMP_OLD
    else
        0x0400; // SO_TIMESTAMP from xnu bsd/sys/socket.h
    const scm_type: i32 = if (SocketPoller.is_linux) @intCast(std.os.linux.SO.TIMESTAMP_OLD) else 0x02;

    // cmsghdr layout differs: Linux aligns the header and each entry to
    // @sizeOf(usize) and uses a usize length; Apple platforms align to 4
    // bytes (__DARWIN_ALIGN32) and use a u32 length.
    const CmsgHdr = if (SocketPoller.is_linux) extern struct {
        len: usize,
        level: i32,
        type: i32,
    } else extern struct {
        len: u32,
        level: i32,
        type: i32,
    };
    const alignment: usize = if (SocketPoller.is_linux) @sizeOf(usize) else 4;
    const data_offset: usize = std.mem.alignForward(usize, @sizeOf(CmsgHdr), alignment);

    // Parse SCM_TIMESTAMP out of a recvmsg control buffer. Returns µs since
    // epoch (same clock as std.time.microTimestamp) or null if absent.
    fn parse(control: []const u8) ?i64 {
        var off: usize = 0;
        while (off + @sizeOf(CmsgHdr) <= control.len) {
            // Copy the header out: entries after the first may not be
            // aligned for a direct pointer cast
            var hdr: CmsgHdr = undefined;
            @memcpy(std.mem.asBytes(&hdr), control[off..][0..@sizeOf(CmsgHdr)]);
            const cmsg_len: usize = @intCast(hdr.len);
            if (cmsg_len < @sizeOf(CmsgHdr) or off + cmsg_len > control.len) return null;
            if (hdr.level == level and hdr.type == scm_type and
                cmsg_len >= data_offset + @sizeOf(posix.timeval))
            {
                const tv = std.mem.bytesToValue(posix.timeval, control[off + data_offset ..][0..@sizeOf(posix.timeval)]);
                return @as(i64, @intCast(tv.sec)) * std.time.us_per_s + @as(i64, @intCast(tv.usec));
            }
            off += std.mem.alignForward(usize, cmsg_len, alignment);
        }
        return null;
    }
};

const IcmpHeader = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    id: u16,
    sequence: u16,
};

const Config = struct {
    subnet: [4]u8 = .{ 192, 168, 1, 0 },
    mask_bits: u8 = 24,
    discovery_timeout_ms: u32 = 1000, // Time to wait for discovery responses
    latency_pings: u8 = 5, // Number of pings per host for latency measurement
    latency_timeout_ms: u32 = 1000, // Timeout per ping in latency phase
    mesh: bool = false, // Share results with peers and render the mesh matrix
    mesh_port: u16 = mesh_mod.default_port,
    rescan_interval_s: u32 = 60, // Mesh mode: seconds between scans, 0 = scan once

    // Extra TCP ping targets (--tcp-ping ip:port): hosts that aren't running
    // this tool but answer a SYN on a known port with SYN-ACK or RST
    tcp_targets: [probe.max_targets]probe.TcpTarget = undefined,
    tcp_target_count: usize = 0,

    // Mesh mode: shared secret authenticating mesh traffic (--mesh-key)
    mesh_key: ?[]const u8 = null,

    // Discovery send rate in packets/s; 0 = unlimited, null = auto (see
    // autoSendRate)
    send_rate_pps: ?u32 = null,
    // Extra discovery passes re-pinging addresses that stayed silent
    retries: u8 = 1,
    // Also report hosts that answer ARP but not ping (neighbor table)
    arp: bool = true,
    output: OutputFormat = .text,
};

const OutputFormat = enum { text, json, csv };

// Discovery pacing. Pinging an address on a directly attached subnet makes
// the kernel ARP for it first, and every address in flight holds a
// neighbor-table entry for the ~3s ARP takes to give up. Blasting more than
// the table holds (Linux's default hard cap, gc_thresh3, is 1024) makes
// the kernel drop packets — hosts silently go missing. So large on-link
// scans are paced by default; routed subnets need no ARP and go full speed.
const auto_rate_threshold = 1024;
const auto_rate_pps: u32 = 300;

fn autoSendRate(target_count: usize, on_link: bool) u32 {
    return if (on_link and target_count > auto_rate_threshold) auto_rate_pps else 0;
}

// Whether the scanned subnet overlaps a local interface's subnet (so its
// hosts are reached directly, via ARP, rather than through a router)
fn subnetIsOnLink(subnet: [4]u8, mask_bits: u8) bool {
    var entries: [max_ifaces]IfaceEntry = undefined;
    const n = collectIfaces(&entries);
    const scan_mask = prefixMask(mask_bits);
    const scan_net = ipToU32(subnet) & scan_mask;
    for (entries[0..n]) |*e| {
        const ip = ipToU32(@as([4]u8, @bitCast(e.addr_be)));
        const mask = ipToU32(@as([4]u8, @bitCast(e.mask_be)));
        // Overlap: either network contains the other's base address
        const wider = mask & scan_mask;
        if ((ip & wider) == (scan_net & wider)) return true;
    }
    return false;
}

fn prefixMask(mask_bits: u8) u32 {
    if (mask_bits == 0) return 0;
    return if (mask_bits >= 32) ~@as(u32, 0) else ~@as(u32, 0) << @intCast(32 - mask_bits);
}

// Per-host latency samples collected during Phase 2
const LatencyData = struct {
    samples: [max_samples]u64,
    count: u8,

    // Also the upper bound for the -p option
    pub const max_samples = 16;

    fn init() LatencyData {
        return LatencyData{
            .samples = undefined,
            .count = 0,
        };
    }

    fn add(self: *LatencyData, latency: u64) void {
        if (self.count < max_samples) {
            self.samples[self.count] = latency;
            self.count += 1;
        }
    }

    fn getMin(self: *const LatencyData) ?u64 {
        if (self.count == 0) return null;
        var min: u64 = self.samples[0];
        for (self.samples[1..self.count]) |s| {
            if (s < min) min = s;
        }
        return min;
    }

    fn getMax(self: *const LatencyData) ?u64 {
        if (self.count == 0) return null;
        var max: u64 = self.samples[0];
        for (self.samples[1..self.count]) |s| {
            if (s > max) max = s;
        }
        return max;
    }

    fn getAvg(self: *const LatencyData) ?u64 {
        if (self.count == 0) return null;
        var total: u64 = 0;
        for (self.samples[0..self.count]) |s| {
            total += s;
        }
        return total / self.count;
    }

    // Jitter as the (population) standard deviation of the samples; null
    // with fewer than two samples, where spread isn't defined
    fn getStddev(self: *const LatencyData) ?u64 {
        if (self.count < 2) return null;
        var total: f64 = 0;
        for (self.samples[0..self.count]) |s| total += @floatFromInt(s);
        const mean = total / @as(f64, @floatFromInt(self.count));
        var sq: f64 = 0;
        for (self.samples[0..self.count]) |s| {
            const d = @as(f64, @floatFromInt(s)) - mean;
            sq += d * d;
        }
        return @intFromFloat(@round(@sqrt(sq / @as(f64, @floatFromInt(self.count)))));
    }
};

fn calculateChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    // Internet checksum (RFC 1071) - sum 16-bit words in native byte order
    while (i + 1 < data.len) : (i += 2) {
        const word: u16 = @as(u16, data[i]) | (@as(u16, data[i + 1]) << 8);
        sum += word;
    }

    if (i < data.len) {
        sum += @as(u32, data[i]);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}

// State shared between the sender thread and the main (receiver) thread.
// Only the atomics are written by the sender; everything else is read-only.
const ScanState = struct {
    sent_count: std.atomic.Value(usize),
    sender_done: std.atomic.Value(bool),

    // Shared socket
    sock: plat.Socket,

    // Payload tag identifying this run's discovery packets
    magic: [4]u8,

    ips: []const [4]u8,
    rate_pps: u32, // 0 = unlimited
};

// Sender thread function - uses shared socket
fn senderThread(state: *ScanState) void {
    const start_us = monotonicMicros();
    for (state.ips, 0..) |ip, i| {
        // Pace against the schedule (not per-packet sleeps), so coarse
        // sleep granularity costs burstiness, never the average rate
        if (state.rate_pps > 0) {
            const due_us = start_us + @as(i64, @intCast(i * std.time.us_per_s / state.rate_pps));
            const now_us = monotonicMicros();
            if (due_us > now_us) sleepNanos(@intCast((due_us - now_us) * std.time.ns_per_us));
        }

        const dest_addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = 0,
            .addr = std.mem.bytesToValue(u32, &ip),
        };

        var packet: [64]u8 align(4) = undefined;
        const header: *IcmpHeader = @ptrCast(@alignCast(&packet));
        header.type = ICMP_ECHO_REQUEST;
        header.code = 0;
        header.checksum = 0;
        const ip_key = ipToU32(ip);
        header.id = @truncate(ip_key >> 16);
        header.sequence = @truncate(ip_key & 0xFFFF);

        for (packet[@sizeOf(IcmpHeader)..]) |*b| {
            b.* = 0xAB;
        }
        @memcpy(packet[@sizeOf(IcmpHeader)..][0..4], &state.magic);
        header.checksum = calculateChecksum(&packet);

        // Raw sendto (not Zig's error-set wrappers) to avoid a panic on
        // unknown errno (like macOS EHOSTDOWN=64)
        var tries: u32 = 0;
        while (true) {
            const rc = plat.sendto(
                state.sock,
                &packet,
                &dest_addr,
                @sizeOf(posix.sockaddr.in),
            );
            if (rc >= 0) break;

            // Blasting a subnet can fill the local send buffer; back off
            // briefly and retry so the host isn't silently skipped. Other
            // errors (host down, unreachable, ...) are expected and ignored.
            const err = plat.lastError();
            const buffer_full = plat.errNoBufs(err) or plat.errWouldBlock(err);
            if (!buffer_full or tries >= 100) break;
            tries += 1;
            sleepNanos(1 * std.time.ns_per_ms);
        }

        _ = state.sent_count.fetchAdd(1, .seq_cst);
    }

    state.sender_done.store(true, .seq_cst);
}

// Two-phase scanner using threads
const Scanner = struct {
    sock: plat.Socket,
    poller: SocketPoller,
    allocator: std.mem.Allocator,
    all_ips: []const [4]u8,
    config: Config,
    is_raw_socket: bool,
    magic: [4]u8,
    kernel_ts_enabled: bool,
    generation: u8 = 0,

    // Optional callback invoked periodically from inside the scan loops, so
    // mesh mode can keep beaconing and draining its UDP socket during a
    // scan that outlasts the peer timeout. Throttled to tick_interval_us.
    tick_fn: ?*const fn (ctx: *anyopaque) void = null,
    tick_ctx: ?*anyopaque = null,
    last_tick_us: i64 = 0,

    const tick_interval_us: i64 = 200_000;

    fn tick(self: *Scanner, now: i64) void {
        const f = self.tick_fn orelse return;
        if (now - self.last_tick_us < tick_interval_us) return;
        self.last_tick_us = now;
        f(self.tick_ctx.?);
    }

    // Payload tag written into every echo request and checked on every reply,
    // so replies to other processes' pings (a raw ICMP socket sees them all)
    // and stale replies from a previous phase are ignored. The phase byte
    // distinguishes discovery packets from latency packets; the generation
    // byte (bumped per discover) separates repeated scans in mesh mode.
    fn phaseMagic(self: *const Scanner, phase: u8) [4]u8 {
        var m = self.magic;
        m[3] ^= phase;
        m[2] ^= self.generation;
        return m;
    }

    pub fn init(allocator: std.mem.Allocator, all_ips: []const [4]u8, config: Config) !Scanner {
        // Prefer a RAW ICMP socket - requires root (or CAP_NET_RAW) on
        // Linux/macOS, Administrator on Windows. Raw calls (not Zig's
        // error-set wrappers) to report errno properly.
        plat.netInit();
        var is_raw = true;
        var sock = plat.openSocket(plat.AF_INET, plat.SOCK_RAW, plat.IPPROTO_ICMP);
        const err: i32 = if (plat.isValidSocket(sock)) 0 else plat.lastError();

        // Linux without privileges: fall back to an unprivileged ICMP
        // "ping socket" (SOCK_DGRAM + IPPROTO_ICMP), allowed for groups in
        // net.ipv4.ping_group_range. The kernel strips the IP header from
        // replies, rewrites the echo id to the socket's own, and delivers
        // only our replies; the payload carries everything we match on.
        // (macOS has DGRAM ICMP too, but its replies aren't usable here.)
        if (!plat.isValidSocket(sock) and builtin.os.tag == .linux and plat.errPermission(err)) {
            sock = plat.openSocket(plat.AF_INET, plat.SOCK_DGRAM, plat.IPPROTO_ICMP);
            if (plat.isValidSocket(sock)) is_raw = false;
        }

        if (!plat.isValidSocket(sock)) {
            if (plat.errPermission(err)) {
                std.debug.print("\nError: Raw ICMP socket requires elevated privileges.\n", .{});
                if (plat.is_windows) {
                    std.debug.print("Please run from an Administrator prompt.\n\n", .{});
                } else {
                    std.debug.print("Please run with: sudo ./zig-out/bin/latency-heatmap ...\n", .{});
                    if (builtin.os.tag == .linux) {
                        std.debug.print(
                            \\Or, to run without sudo, either grant the binary raw-socket access:
                            \\  sudo setcap cap_net_raw+ep ./zig-out/bin/latency-heatmap
                            \\or allow unprivileged ICMP ping sockets for your group:
                            \\  sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
                            \\
                        , .{});
                    }
                    std.debug.print("\n", .{});
                }
            } else {
                std.debug.print("\nSocket creation failed with error: {}\n", .{err});
            }
            return error.SocketCreationFailed;
        }

        // Windows: a raw socket receives nothing until it is bound to a
        // specific local interface address
        if (plat.is_windows) {
            var baddr = posix.sockaddr.in{
                .family = posix.AF.INET,
                .port = 0,
                .addr = rawSocketBindAddr(config.subnet, config.mask_bits),
            };
            if (plat.bind(sock, &baddr, @sizeOf(posix.sockaddr.in)) != 0) {
                const ip: [4]u8 = @bitCast(baddr.addr);
                std.debug.print("Warning: could not bind the raw ICMP socket to {d}.{d}.{d}.{d} (error {d}); replies may not be received\n", .{
                    ip[0], ip[1], ip[2], ip[3], plat.lastError(),
                });
            }
        }

        return initWithSocket(allocator, all_ips, config, sock, is_raw);
    }

    // Finish setting up a scanner around an already-open ICMP socket
    // (raw, or a Linux ping socket when is_raw is false). Takes ownership
    // of sock.
    fn initWithSocket(allocator: std.mem.Allocator, all_ips: []const [4]u8, config: Config, sock: plat.Socket, is_raw: bool) !Scanner {
        errdefer plat.closeSocket(sock);

        // Set socket to non-blocking for receives
        if (!plat.setNonblocking(sock))
            return error.SocketCreationFailed;

        // Ask the kernel to stamp arrival times on received packets so RTT
        // measurement doesn't include our own wakeup/scheduling delay
        var ts_enabled = false;
        if (kernel_ts.supported) {
            const one: c_int = 1;
            ts_enabled = plat.setsockopt(sock, kernel_ts.level, kernel_ts.sockopt, &one, @sizeOf(c_int)) == 0;
        }

        // Create event poller for efficient socket waiting
        const poller = try SocketPoller.init(sock);

        var magic: [4]u8 = undefined;
        const pid: u32 = plat.getpid();
        std.mem.writeInt(u32, &magic, pid ^ 0x5CA9B1E5, .little);

        return Scanner{
            .sock = sock,
            .poller = poller,
            .allocator = allocator,
            .all_ips = all_ips,
            .config = config,
            .is_raw_socket = is_raw,
            .magic = magic,
            .kernel_ts_enabled = ts_enabled,
        };
    }

    const RecvPacket = struct {
        len: usize,
        src: posix.sockaddr.in,
        kernel_ts_us: ?i64, // Kernel arrival time, null if unavailable
    };

    // Receive one packet along with its kernel arrival timestamp (if enabled)
    fn recvPacket(self: *Scanner, buf: []u8) ?RecvPacket {
        if (plat.is_windows) {
            // No recvmsg/cmsg on Winsock; no kernel timestamps either
            var src: posix.sockaddr.in = undefined;
            var src_len: u32 = @sizeOf(posix.sockaddr.in);
            const rc = plat.recvfrom(self.sock, buf, &src, &src_len);
            if (rc < 0) return null;
            return .{ .len = @intCast(rc), .src = src, .kernel_ts_us = null };
        } else {
            var src: posix.sockaddr.in = undefined;
            var iov = [_]posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
            var control: [64]u8 align(8) = undefined;
            var msg = std.mem.zeroes(c.msghdr);
            msg.name = @ptrCast(&src);
            msg.namelen = @sizeOf(posix.sockaddr.in);
            msg.iov = &iov;
            msg.iovlen = 1;
            msg.control = &control;
            msg.controllen = @intCast(control.len);

            const rc = c.recvmsg(self.sock, &msg, c.MSG.DONTWAIT);
            if (rc < 0) return null;

            const controllen: usize = @intCast(msg.controllen);
            const ts = if (self.kernel_ts_enabled)
                kernel_ts.parse(control[0..@min(controllen, control.len)])
            else
                null;
            return .{ .len = @intCast(rc), .src = src, .kernel_ts_us = ts };
        }
    }

    pub fn deinit(self: *Scanner) void {
        self.poller.deinit();
        plat.closeSocket(self.sock);
    }

    // Phase 1: Discovery - sender thread + receiver in main thread. The
    // first pass pings every address; each retry pass re-pings only the
    // addresses still silent, so one lost packet (an ARP miss, a dropped
    // reply) doesn't hide a host. Late replies to an earlier pass still
    // count: every pass of one discover shares a magic.
    pub fn discover(self: *Scanner, stdout: StdoutWriter) !std.ArrayList([4]u8) {
        self.generation +%= 1;
        const magic = self.phaseMagic(1);

        // Discovered hosts; only this (receiver) thread touches the map,
        // so no locking is needed.
        var discovered = std.AutoHashMap(u32, void).init(self.allocator);
        defer discovered.deinit();

        const rate = self.sendRate();
        if (rate > 0) {
            stdout.print("  Phase 1: Discovery - scanning {d} hosts at {d} pings/s...\n", .{ self.all_ips.len, rate }) catch {};
        } else {
            stdout.print("  Phase 1: Discovery - scanning {d} hosts...\n", .{self.all_ips.len}) catch {};
        }

        var retry_ips: std.ArrayList([4]u8) = .empty;
        defer retry_ips.deinit(self.allocator);

        const passes: usize = 1 + @as(usize, self.config.retries);
        var pass: usize = 0;
        while (pass < passes) : (pass += 1) {
            var targets: []const [4]u8 = self.all_ips;
            if (pass > 0) {
                retry_ips.clearRetainingCapacity();
                for (self.all_ips) |ip| {
                    if (!discovered.contains(ipToU32(ip))) try retry_ips.append(self.allocator, ip);
                }
                if (retry_ips.items.len == 0) break;
                targets = retry_ips.items;
                stdout.print("  Retry {d}: re-pinging {d} silent address{s}...\n", .{
                    pass,
                    targets.len,
                    if (targets.len == 1) "" else "es",
                }) catch {};
            }
            // Intermediate passes only wait briefly before retrying (their
            // stragglers are still caught later); the last pass waits the
            // full discovery timeout
            const final = pass + 1 == passes;
            const wait_ms: u32 = if (final) self.config.discovery_timeout_ms else @min(self.config.discovery_timeout_ms, 250);
            try self.discoveryPass(&discovered, targets, magic, rate, wait_ms, final, stdout);
        }

        stdout.print("{s}  Discovered: {d} hosts                                      \n", .{ common.cr(), discovered.count() }) catch {};

        // Convert to array
        var alive_hosts: std.ArrayList([4]u8) = .empty;
        errdefer alive_hosts.deinit(self.allocator);
        var iter = discovered.keyIterator();
        while (iter.next()) |key| {
            try alive_hosts.append(self.allocator, u32ToIp(key.*));
        }

        return alive_hosts;
    }

    fn sendRate(self: *const Scanner) u32 {
        return self.config.send_rate_pps orelse
            autoSendRate(self.all_ips.len, subnetIsOnLink(self.config.subnet, self.config.mask_bits));
    }

    // One discovery pass: send to `targets` on the sender thread while
    // receiving here, then keep receiving for wait_ms after the last send.
    // With early_exit, give up sooner when nothing at all has answered.
    fn discoveryPass(
        self: *Scanner,
        discovered: *std.AutoHashMap(u32, void),
        targets: []const [4]u8,
        magic: [4]u8,
        rate: u32,
        wait_ms: u32,
        early_exit: bool,
        stdout: StdoutWriter,
    ) !void {
        var state = ScanState{
            .sent_count = std.atomic.Value(usize).init(0),
            .sender_done = std.atomic.Value(bool).init(false),
            .sock = self.sock,
            .magic = magic,
            .ips = targets,
            .rate_pps = rate,
        };

        // Start sender thread (shares the ICMP socket; replies are received here)
        const sender = try std.Thread.spawn(.{}, senderThread, .{&state});
        defer sender.join();

        // Only accept replies from addresses inside the scanned subnet
        const netmask = prefixMask(self.config.mask_bits);
        const network: u32 = ipToU32(self.config.subnet) & netmask;

        // Main thread receives replies
        var recv_buf: [1024]u8 align(4) = undefined;

        var last_print: i64 = 0;

        // Track when sender finishes for timeout calculation
        var sender_finish_time: ?i64 = null;

        // Give up early when nothing answered — but never sooner than the
        // configured timeout itself (-d 3000 on a slow link must wait 3s)
        const early_exit_ms: i64 = @min(500, wait_ms);

        // Receive loop - runs until sender is done + timeout
        while (true) {
            // Drain all available packets first
            while (true) {
                const pkt = self.recvPacket(&recv_buf) orelse break;
                const recv_len = pkt.len;

                // Parse ICMP reply - DGRAM sockets don't have IP header, RAW sockets do
                var icmp_offset: usize = 0;
                if (self.is_raw_socket and recv_len >= 20 and (recv_buf[0] >> 4) == 4) {
                    icmp_offset = (@as(usize, recv_buf[0] & 0x0F)) * 4;
                }
                if (recv_len < icmp_offset + @sizeOf(IcmpHeader)) continue;

                const icmp_reply: *const IcmpHeader = @ptrCast(@alignCast(&recv_buf[icmp_offset]));
                if (icmp_reply.type != ICMP_ECHO_REPLY) continue;

                // Ignore replies to other processes' pings
                const payload_off = icmp_offset + @sizeOf(IcmpHeader);
                if (recv_len < payload_off + 4) continue;
                if (!std.mem.eql(u8, recv_buf[payload_off..][0..4], &magic)) continue;

                // Record this host as alive (if it's in the scanned range)
                const src_ip_bytes: [4]u8 = @bitCast(pkt.src.addr);
                const src_ip_key = ipToU32(src_ip_bytes);
                if ((src_ip_key & netmask) != network) continue;

                discovered.put(src_ip_key, {}) catch {};
            }

            // Now check exit conditions and update progress
            const now = monotonicMicros();
            self.tick(now);
            const sender_done = state.sender_done.load(.seq_cst);

            // Record when sender finishes
            if (sender_done and sender_finish_time == null) {
                sender_finish_time = now;
                // Print final send count
                stdout.print("{s}  Sent: {d}/{d} - waiting for replies...                    \n", .{ common.cr(), state.sent_count.load(.seq_cst), targets.len }) catch {};
            }

            // Check exit conditions after sender finished
            if (sender_finish_time) |finish_time| {
                const time_since_finish_ms = @divFloor(now - finish_time, 1000);

                if (early_exit and discovered.count() == 0 and time_since_finish_ms > early_exit_ms) {
                    stdout.print("{s}  No hosts found, exiting early.                              \n", .{common.cr()}) catch {};
                    break;
                }

                if (time_since_finish_ms > wait_ms) break;
            }

            // Update progress periodically (\r-rewriting lines, TTY only)
            if (common.stdout_is_tty and now - last_print > 100_000) {
                last_print = now;
                const sent = state.sent_count.load(.seq_cst);
                const discovered_count = discovered.count();

                if (!sender_done) {
                    stdout.print("\r  Sent: {d}/{d} | Discovered: {d}   ", .{ sent, targets.len, discovered_count }) catch {};
                } else if (sender_finish_time) |finish_time| {
                    const time_since_ms = @divFloor(now - finish_time, 1000);
                    const remaining_ms: i64 = @as(i64, wait_ms) - time_since_ms;
                    stdout.print("\r  Discovered: {d} hosts (elapsed: {d}ms, remaining: {d}ms)   ", .{ discovered_count, time_since_ms, remaining_ms }) catch {};
                }
            }

            // Wait for more data (event-driven)
            _ = self.poller.wait(10);
        }
    }

    // Phase 2: Event-driven latency measurement using kqueue/epoll
    // Processes responses IMMEDIATELY when they arrive for accurate timing
    pub fn measureLatency(self: *Scanner, hosts: []const [4]u8, results: []PingResult, stdout: StdoutWriter) !void {
        if (hosts.len == 0) return;

        const num_rounds = self.config.latency_pings;
        stdout.print("  Phase 2: Measuring latency on {d} hosts ({d} pings each)...\n", .{ hosts.len, num_rounds }) catch {};

        // Initialize results
        for (results, 0..) |*r, i| {
            r.* = PingResult{
                .ip = hosts[i],
                .latency_us = null,
                .latency_avg = null,
                .latency_max = null,
            };
        }

        // Allocate arrays to track per-host latencies
        const latencies = try self.allocator.alloc(LatencyData, hosts.len);
        defer self.allocator.free(latencies);
        for (latencies) |*lat| lat.* = LatencyData.init();

        // Send times for ALL pings (hosts * rounds), in both clock domains:
        // monotonic for the step-immune measurement, wall clock to compare
        // against kernel receive stamps (which are wall clock only)
        const SendTime = struct { mono: i64, real: i64 };
        const total_pings = hosts.len * num_rounds;
        const send_times = try self.allocator.alloc(SendTime, total_pings);
        defer self.allocator.free(send_times);
        @memset(send_times, .{ .mono = 0, .real = 0 });

        // Track which pings have been received
        const received = try self.allocator.alloc(bool, total_pings);
        defer self.allocator.free(received);
        @memset(received, false);

        // Pre-build destination addresses
        const dest_addrs = try self.allocator.alloc(posix.sockaddr.in, hosts.len);
        defer self.allocator.free(dest_addrs);
        for (hosts, 0..) |ip, i| {
            dest_addrs[i] = posix.sockaddr.in{
                .family = posix.AF.INET,
                .port = 0,
                .addr = std.mem.bytesToValue(u32, &ip),
            };
        }

        // Timing control
        const inter_ping_delay_us: i64 = 1000; // 1ms between pings to avoid flooding
        const round_delay_us: i64 = 20_000; // 20ms between rounds
        const adaptive_timeout_us: i64 = 100_000; // minimum silence before exiting early
        const max_timeout_us: i64 = @as(i64, self.config.latency_timeout_ms) * 1000;

        var responses_received: usize = 0;
        var next_send_host: usize = 0;
        var next_send_round: usize = 0;
        var last_send_time: i64 = 0;
        var last_response_time: i64 = 0;
        var last_progress_print: i64 = 0;
        var max_rtt_seen: i64 = 0;
        var all_sent = false;

        var recv_buf: [1024]u8 align(4) = undefined;
        var packet: [64]u8 align(4) = undefined;

        // Initialize packet template
        const magic = self.phaseMagic(2);
        const header: *IcmpHeader = @ptrCast(@alignCast(&packet));
        header.type = ICMP_ECHO_REQUEST;
        header.code = 0;
        for (packet[@sizeOf(IcmpHeader)..]) |*b| b.* = 0xAB;
        @memcpy(packet[@sizeOf(IcmpHeader)..][0..4], &magic);

        // Event loop: interleave sending and receiving
        while (true) {
            const now = monotonicMicros();
            self.tick(now);

            // Check exit conditions
            if (all_sent) {
                // Adaptive exit: no responses for a while. The silence
                // window scales with the slowest RTT observed so far —
                // a fixed 100ms would clip replies still in flight from
                // hosts slower than that (exactly the hosts worth seeing)
                // whenever a burst of fast hosts finishes answering first.
                const silence_needed = @max(adaptive_timeout_us, 2 * max_rtt_seen);
                if (last_response_time > 0 and (now - last_response_time) > silence_needed) break;
                // Hard timeout, measured from the last send so the final
                // round still gets its full reply window (-t is the timeout
                // per ping, and sending alone can take longer than -t)
                if ((now - last_send_time) > max_timeout_us) break;
                // All responses received
                if (responses_received >= total_pings) break;
            }

            // Send next ping if it's time. A new round starts only after the
            // longer round delay has elapsed since the previous send.
            const starting_new_round = next_send_host == 0 and next_send_round > 0;
            const send_delay_us = if (starting_new_round) round_delay_us else inter_ping_delay_us;
            if (!all_sent and (now - last_send_time) >= send_delay_us) {
                const host_idx = next_send_host;
                const round = next_send_round;
                const ping_idx = host_idx * num_rounds + round;

                // Build and send packet. The host index and round travel in
                // the payload (after the magic): a ping socket's kernel
                // rewrites the echo id, so the header can't carry them.
                header.id = @truncate(host_idx);
                header.sequence = @intCast(round);
                std.mem.writeInt(u32, packet[@sizeOf(IcmpHeader) + 4 ..][0..4], @intCast(host_idx), .little);
                packet[@sizeOf(IcmpHeader) + 8] = @intCast(round);
                header.checksum = 0;
                header.checksum = calculateChecksum(&packet);

                // Record send time IMMEDIATELY before send, in both domains
                const send_time = SendTime{ .mono = monotonicMicros(), .real = wallMicros() };
                send_times[ping_idx] = send_time;

                _ = plat.sendto(
                    self.sock,
                    &packet,
                    &dest_addrs[host_idx],
                    @sizeOf(posix.sockaddr.in),
                );

                last_send_time = send_time.mono;

                // Advance to next ping
                next_send_host += 1;
                if (next_send_host >= hosts.len) {
                    next_send_host = 0;
                    next_send_round += 1;
                    if (next_send_round >= num_rounds) {
                        all_sent = true;
                    }
                }
            }

            // Process incoming responses - use kqueue/epoll with 0 timeout for non-blocking check
            // This gives us immediate notification when data is available
            const has_data = self.poller.poll();

            if (has_data) {
                // Drain ALL available packets immediately
                while (true) {
                    // Monotonic timestamp taken BEFORE reading: the packet
                    // has already arrived, so this is an upper bound on the
                    // true RTT that is immune to wall-clock steps
                    const recv_mono = monotonicMicros();

                    const pkt = self.recvPacket(&recv_buf) orelse break;
                    const recv_len = pkt.len;

                    // Parse ICMP reply - skip IP header for raw socket
                    var icmp_offset: usize = 0;
                    if (self.is_raw_socket and recv_len >= 20 and (recv_buf[0] >> 4) == 4) {
                        icmp_offset = (@as(usize, recv_buf[0] & 0x0F)) * 4;
                    }
                    if (recv_len < icmp_offset + @sizeOf(IcmpHeader)) continue;

                    if (recv_buf[icmp_offset] != ICMP_ECHO_REPLY) continue;

                    // Ignore replies to other processes' pings and stale
                    // discovery replies still arriving from Phase 1
                    const payload_off = icmp_offset + @sizeOf(IcmpHeader);
                    if (recv_len < payload_off + 9) continue;
                    if (!std.mem.eql(u8, recv_buf[payload_off..][0..4], &magic)) continue;

                    const host_idx: usize = std.mem.readInt(u32, recv_buf[payload_off + 4 ..][0..4], .little);
                    const reply_round: usize = recv_buf[payload_off + 8];
                    if (host_idx >= hosts.len or reply_round >= num_rounds) continue;

                    // The reply must come from the address that was pinged:
                    // id/sequence alone would credit a stray or duplicated
                    // reply to whichever host the id happens to index
                    if (pkt.src.addr != dest_addrs[host_idx].addr) continue;

                    const ping_idx = host_idx * num_rounds + reply_round;
                    if (ping_idx >= total_pings or received[ping_idx]) continue;

                    const send_time = send_times[ping_idx];
                    if (send_time.mono == 0) continue; // Not sent yet (shouldn't happen)

                    // Step-immune measurement from the monotonic clock
                    const mono_rtt = recv_mono - send_time.mono;

                    // Prefer the kernel's arrival stamp — it excludes our
                    // wakeup/scheduling/drain delay — but the kernel only
                    // offers it in the wall-clock domain, so accept it only
                    // when consistent with the monotonic bound (a wall-clock
                    // step mid-flight would otherwise corrupt the sample)
                    var rtt = mono_rtt;
                    if (pkt.kernel_ts_us) |kernel_time| {
                        const kernel_rtt = kernel_time - send_time.real;
                        if (kernel_rtt >= 0 and kernel_rtt <= mono_rtt) rtt = kernel_rtt;
                    }

                    const latency: u64 = @intCast(@max(0, rtt));
                    latencies[host_idx].add(latency);
                    received[ping_idx] = true;
                    responses_received += 1;
                    last_response_time = recv_mono;
                    max_rtt_seen = @max(max_rtt_seen, mono_rtt);
                }

                // Throttle progress output: stdout is unbuffered, so each
                // update is a blocking write syscall that would otherwise
                // sit in the receive path and delay fallback timestamps.
                // In-place updates only make sense on a TTY.
                if (common.stdout_is_tty and now - last_progress_print > 100_000) {
                    last_progress_print = now;
                    printProgress(stdout, responses_received, total_pings);
                }
            } else if (all_sent) {
                // No data available and all sent - wait with short timeout
                _ = self.poller.wait(10);
            } else {
                // Sends still pending but not due yet - wait briefly instead
                // of busy-spinning (returns early if a reply arrives)
                _ = self.poller.wait(1);
            }
        }

        // Final progress line (updates were throttled during the loop)
        printProgress(stdout, responses_received, total_pings);
        stdout.print("\n", .{}) catch {};

        // Copy results. Every host got num_rounds pings unless the loop
        // ended early, so count what was actually sent per host.
        for (0..hosts.len) |i| {
            var sent: u8 = 0;
            for (send_times[i * num_rounds ..][0..num_rounds]) |t| {
                if (t.mono != 0) sent += 1;
            }
            results[i].latency_us = latencies[i].getMin();
            results[i].latency_avg = latencies[i].getAvg();
            results[i].latency_max = latencies[i].getMax();
            results[i].stddev_us = latencies[i].getStddev();
            results[i].sent = sent;
            results[i].received = latencies[i].count;
        }
    }
};

// Pinging one of our own addresses never leaves the machine — the local
// stack answers directly — so it measures nothing about the network. Compact
// the scan list to drop any IP that belongs to a local interface, returning
// the kept length.
fn removeLocalAddrs(ips: [][4]u8) usize {
    var entries: [max_ifaces]IfaceEntry = undefined;
    const n = collectIfaces(&entries);
    if (n == 0) return ips.len;
    var kept: usize = 0;
    for (ips) |ip| {
        const addr_be: u32 = @bitCast(ip);
        const is_local = for (entries[0..n]) |*e| {
            if (e.addr_be == addr_be) break true;
        } else false;
        if (!is_local) {
            ips[kept] = ip;
            kept += 1;
        }
    }
    return kept;
}

fn generateIpRange(allocator: std.mem.Allocator, subnet: [4]u8, mask_bits: u8) ![][4]u8 {
    const host_bits: u5 = @intCast(32 - mask_bits);
    const total: u32 = @as(u32, 1) << host_bits;
    // /31 (RFC 3021) and /32 have no network/broadcast addresses to exclude
    const num_hosts: u32 = if (mask_bits >= 31) total else total - 2;
    const first_offset: u32 = if (mask_bits >= 31) 0 else 1;

    const ips = try allocator.alloc([4]u8, num_hosts);

    const base = ipToU32(subnet);

    for (0..num_hosts) |i| {
        ips[i] = u32ToIp(base + @as(u32, @intCast(i)) + first_offset);
    }

    return ips;
}

// Pad a grid cell out to col_width display columns (at least one space)
fn padCell(stdout: StdoutWriter, used: usize, col_width: usize) void {
    const spaces = " " ** 32;
    const pad = if (used < col_width) col_width - used else 1;
    stdout.print("{s}", .{spaces[0..@min(pad, spaces.len)]}) catch {};
}

fn printHeatmapGrid(stdout: StdoutWriter, results: []const PingResult, width: usize) void {
    const reset = common.sgr("\x1b[0m");
    const gray = common.sgr("\x1b[90m");
    const col_width = 28; // Fixed column width for alignment

    stdout.print("\n", .{}) catch {};

    var row_start: usize = 0;
    while (row_start < results.len) {
        const row_end = @min(row_start + width, results.len);

        // Print IP labels for this row (padded to col_width)
        for (results[row_start..row_end]) |r| {
            var buf: [16]u8 = undefined;
            const ip_str = ipToString(r.ip, &buf);
            stdout.print("{s}", .{ip_str}) catch {};
            padCell(stdout, ip_str.len, col_width);
        }
        stdout.print("\n", .{}) catch {};

        // Print heatmap blocks with min/avg/max latency (each colored independently)
        for (results[row_start..row_end]) |r| {
            const block = latencyToBlock(r.latency_avg);
            const block_color = latencyToColor(r.latency_avg);
            var min_buf: [16]u8 = undefined;
            var avg_buf: [16]u8 = undefined;
            var max_buf: [16]u8 = undefined;
            const min_str = formatLatency(r.latency_us, &min_buf);
            const avg_str = formatLatency(r.latency_avg, &avg_buf);
            const max_str = formatLatency(r.latency_max, &max_buf);

            // Format: "█ min/avg/max" with each value colored independently
            var lat_combined: [128]u8 = undefined;
            const combined_str = if (!r.icmp)
                "no ICMP (ARP only)"
            else if (r.latency_us != null) blk: {
                const min_color = latencyToColor(r.latency_us);
                const avg_color = latencyToColor(r.latency_avg);
                const max_color = latencyToColor(r.latency_max);
                break :blk std.fmt.bufPrint(&lat_combined, "{s}{s}{s}/{s}{s}{s}/{s}{s}{s}", .{
                    min_color, min_str, reset,
                    avg_color, avg_str, reset,
                    max_color, max_str, reset,
                }) catch "???";
            } else "---";

            stdout.print("{s}{s}{s} {s}", .{ block_color, block, reset, combined_str }) catch {};
            // 2 display chars for "█ ", rest is latency string (use display width for proper alignment)
            padCell(stdout, 2 + displayWidth(combined_str), col_width);
        }
        stdout.print("\n", .{}) catch {};

        // Jitter and loss: "±0.3ms · 0% loss"
        for (results[row_start..row_end]) |r| {
            var detail_buf: [64]u8 = undefined;
            var jit_buf: [16]u8 = undefined;
            const detail: []const u8 = if (!r.icmp or r.sent == 0)
                ""
            else if (r.received == 0)
                "100% loss"
            else if (r.stddev_us) |sd|
                std.fmt.bufPrint(&detail_buf, "±{s} · {d:.0}% loss", .{ formatLatency(sd, &jit_buf), r.lossPct().? }) catch ""
            else
                std.fmt.bufPrint(&detail_buf, "{d:.0}% loss", .{r.lossPct().?}) catch "";
            const lossy = r.icmp and r.received < r.sent;
            const color = if (lossy) common.sgr("\x1b[93m") else gray;
            stdout.print("{s}{s}{s}", .{ color, detail, reset }) catch {};
            padCell(stdout, displayWidth(detail), col_width);
        }
        stdout.print("\n\n", .{}) catch {};

        row_start = row_end;
    }
}

fn printSummary(stdout: StdoutWriter, results: []const PingResult, scanned: usize) void {
    var alive_count: usize = 0;
    var silent_count: usize = 0;
    var unanswered_count: usize = 0; // answered discovery, then no latency replies
    var total_avg_latency: u64 = 0;
    var best_avg: u64 = std.math.maxInt(u64);
    var worst_avg: u64 = 0;
    var total_sent: usize = 0;
    var total_received: usize = 0;

    const list_cap = 10;
    var slow_devices: [list_cap]PingResult = undefined;
    var slow_count: usize = 0;
    var lossy_devices: [list_cap]PingResult = undefined;
    var lossy_count: usize = 0;
    var stddevs: [256]u64 = undefined;
    var stddev_count: usize = 0;

    for (results) |r| {
        if (!r.icmp) {
            silent_count += 1;
            continue;
        }
        total_sent += r.sent;
        total_received += @min(r.received, r.sent);
        if (r.received < r.sent) {
            if (lossy_count < list_cap) lossy_devices[lossy_count] = r;
            lossy_count += 1;
        }
        if (r.stddev_us) |sd| {
            if (stddev_count < stddevs.len) {
                stddevs[stddev_count] = sd;
                stddev_count += 1;
            }
        }
        if (r.latency_avg) |avg_lat| {
            alive_count += 1;
            total_avg_latency += avg_lat;
            if (avg_lat < best_avg) best_avg = avg_lat;
            if (avg_lat > worst_avg) worst_avg = avg_lat;

            // Track slow devices (avg >20ms)
            if (avg_lat > 20000) {
                if (slow_count < list_cap) slow_devices[slow_count] = r;
                slow_count += 1;
            }
        } else {
            unanswered_count += 1;
        }
    }

    const bold = common.sgr("\x1b[1m");
    const reset = common.sgr("\x1b[0m");
    const yellow = common.sgr("\x1b[93m");
    stdout.print("\n{s}══════════════════════════════════════════════════════════════{s}\n", .{ bold, reset }) catch {};
    stdout.print("{s}                     NETWORK SUMMARY{s}\n", .{ bold, reset }) catch {};
    stdout.print("{s}══════════════════════════════════════════════════════════════{s}\n\n", .{ bold, reset }) catch {};

    stdout.print("  Addresses scanned: {d}\n", .{scanned}) catch {};
    stdout.print("  Hosts responding:  {d} ({d:.1}%)\n", .{
        alive_count,
        if (scanned > 0) @as(f64, @floatFromInt(alive_count)) / @as(f64, @floatFromInt(scanned)) * 100.0 else 0.0,
    }) catch {};
    if (unanswered_count > 0) {
        stdout.print("  Went quiet:        {d} (answered discovery, then no latency replies)\n", .{unanswered_count}) catch {};
    }
    if (silent_count > 0) {
        stdout.print("  Silent to ping:    {d} (answer ARP but not ICMP echo)\n", .{silent_count}) catch {};
    }
    if (total_sent > 0) {
        const lost = total_sent - total_received;
        stdout.print("  {s}Packet loss:       {d}/{d} ({d:.1}%){s}\n", .{
            if (lost > 0) yellow else "",
            lost,
            total_sent,
            @as(f64, @floatFromInt(lost)) / @as(f64, @floatFromInt(total_sent)) * 100.0,
            if (lost > 0) reset else "",
        }) catch {};
    }

    if (alive_count > 0) {
        var buf1: [16]u8 = undefined;
        var buf2: [16]u8 = undefined;
        var buf3: [16]u8 = undefined;

        stdout.print("\n  Latency stats (by avg):\n", .{}) catch {};
        stdout.print("    Best:  {s}\n", .{formatLatency(best_avg, &buf1)}) catch {};
        stdout.print("    Mean:  {s}\n", .{formatLatency(total_avg_latency / alive_count, &buf2)}) catch {};
        stdout.print("    Worst: {s}\n", .{formatLatency(worst_avg, &buf3)}) catch {};
        if (stddev_count > 0) {
            var buf4: [16]u8 = undefined;
            std.mem.sort(u64, stddevs[0..stddev_count], {}, std.sort.asc(u64));
            stdout.print("    Jitter (median stddev): {s}\n", .{formatLatency(stddevs[stddev_count / 2], &buf4)}) catch {};
        }
    }

    if (slow_count > 0) {
        stdout.print("\n  {s}⚠ Slow devices (avg >20ms):{s}\n", .{ yellow, reset }) catch {};
        for (slow_devices[0..@min(slow_count, list_cap)]) |r| {
            var ip_buf: [16]u8 = undefined;
            var lat_buf: [16]u8 = undefined;
            stdout.print("    {s}: {s} avg\n", .{
                ipToString(r.ip, &ip_buf),
                formatLatency(r.latency_avg, &lat_buf),
            }) catch {};
        }
        if (slow_count > list_cap) stdout.print("    ... and {d} more\n", .{slow_count - list_cap}) catch {};
    }

    if (lossy_count > 0) {
        stdout.print("\n  {s}⚠ Devices with packet loss:{s}\n", .{ yellow, reset }) catch {};
        for (lossy_devices[0..@min(lossy_count, list_cap)]) |r| {
            var ip_buf: [16]u8 = undefined;
            stdout.print("    {s}: {d}/{d} replies ({d:.0}% loss)\n", .{
                ipToString(r.ip, &ip_buf),
                r.received,
                r.sent,
                r.lossPct().?,
            }) catch {};
        }
        if (lossy_count > list_cap) stdout.print("    ... and {d} more\n", .{lossy_count - list_cap}) catch {};
    }

    stdout.print("\n{s}══════════════════════════════════════════════════════════════{s}\n", .{ bold, reset }) catch {};
}

// Machine-readable results. JSON: one object for the scan, hosts in an
// array (one per line). CSV: a header row, then one row per host. Missing
// values are null in JSON and empty in CSV.
const ReportMeta = struct {
    subnet: []const u8,
    timestamp_s: i64,
    scanned: usize,
    pings_per_host: u8,
};

fn writeOptU64(out: *std.Io.Writer, v: ?u64, none: []const u8) !void {
    if (v) |x| try out.print("{d}", .{x}) else try out.writeAll(none);
}

fn writeJson(out: *std.Io.Writer, meta: ReportMeta, results: []const PingResult) !void {
    try out.print("{{\"subnet\":\"{s}\",\"timestamp\":{d},\"addresses_scanned\":{d},\"pings_per_host\":{d},\"hosts\":[", .{
        meta.subnet, meta.timestamp_s, meta.scanned, meta.pings_per_host,
    });
    for (results, 0..) |r, i| {
        var ip_buf: [16]u8 = undefined;
        try out.print("{s}\n  {{\"ip\":\"{s}\",\"responds_to_icmp\":{},\"min_us\":", .{
            if (i == 0) "" else ",", ipToString(r.ip, &ip_buf), r.icmp,
        });
        try writeOptU64(out, r.latency_us, "null");
        try out.writeAll(",\"avg_us\":");
        try writeOptU64(out, r.latency_avg, "null");
        try out.writeAll(",\"max_us\":");
        try writeOptU64(out, r.latency_max, "null");
        try out.writeAll(",\"stddev_us\":");
        try writeOptU64(out, r.stddev_us, "null");
        try out.print(",\"sent\":{d},\"received\":{d},\"loss_pct\":", .{ r.sent, r.received });
        if (r.lossPct()) |l| try out.print("{d:.1}", .{l}) else try out.writeAll("null");
        try out.writeAll("}");
    }
    try out.writeAll(if (results.len > 0) "\n]}\n" else "]}\n");
}

fn writeCsv(out: *std.Io.Writer, results: []const PingResult) !void {
    try out.writeAll("ip,responds_to_icmp,min_us,avg_us,max_us,stddev_us,sent,received,loss_pct\n");
    for (results) |r| {
        var ip_buf: [16]u8 = undefined;
        try out.print("{s},{},", .{ ipToString(r.ip, &ip_buf), r.icmp });
        try writeOptU64(out, r.latency_us, "");
        try out.writeAll(",");
        try writeOptU64(out, r.latency_avg, "");
        try out.writeAll(",");
        try writeOptU64(out, r.latency_max, "");
        try out.writeAll(",");
        try writeOptU64(out, r.stddev_us, "");
        try out.print(",{d},{d},", .{ r.sent, r.received });
        if (r.lossPct()) |l| try out.print("{d:.1}", .{l});
        try out.writeAll("\n");
    }
}

fn printLegend(stdout: StdoutWriter) void {
    const reset = common.sgr("\x1b[0m");
    stdout.print("\n{s}Legend:{s} ", .{ common.sgr("\x1b[1m"), reset }) catch {};
    stdout.print("{s}█ <1ms{s}  ", .{ common.sgr("\x1b[92m"), reset }) catch {};
    stdout.print("{s}▓ <5ms{s}  ", .{ common.sgr("\x1b[32m"), reset }) catch {};
    stdout.print("{s}▒ <20ms{s}  ", .{ common.sgr("\x1b[93m"), reset }) catch {};
    stdout.print("{s}░ <100ms{s}  ", .{ common.sgr("\x1b[33m"), reset }) catch {};
    stdout.print("{s}▪ >100ms{s}  ", .{ common.sgr("\x1b[91m"), reset }) catch {};
    stdout.print("{s}· offline{s}\n", .{ common.sgr("\x1b[90m"), reset }) catch {};
}

fn printProgress(stdout: StdoutWriter, done: usize, total: usize) void {
    const percent = @as(f64, @floatFromInt(done)) / @as(f64, @floatFromInt(total)) * 100.0;
    const bar_width: usize = 40;
    // Explicit type: @min with a comptime-known bound would otherwise
    // narrow the result to u6, and filled * 3 overflows u6
    const filled: usize = @min(bar_width, @as(usize, @intFromFloat(@as(f64, @floatFromInt(bar_width)) * percent / 100.0)));

    // Each block is 3 bytes of UTF-8; slice pre-built runs so the whole
    // update is a single write (stdout is unbuffered)
    const full_blocks = "█" ** bar_width;
    const empty_blocks = "░" ** bar_width;
    var buf: [256]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s}  Measuring: [{s}{s}] {d:.1}% ({d}/{d})", .{
        common.cr(),
        full_blocks[0 .. filled * 3],
        empty_blocks[0 .. (bar_width - filled) * 3],
        percent,
        done,
        total,
    }) catch return;
    stdout.print("{s}", .{line}) catch {};
}

fn parseSubnet(arg: []const u8) ?struct { subnet: [4]u8, mask: u8 } {
    // Parse CIDR notation: 192.168.1.0/24
    var parts = std.mem.splitScalar(u8, arg, '/');
    const ip_part = parts.next() orelse return null;
    const mask_part = parts.next() orelse "24";

    var ip: [4]u8 = undefined;
    var octets = std.mem.splitScalar(u8, ip_part, '.');
    var i: usize = 0;
    while (octets.next()) |octet| : (i += 1) {
        if (i >= 4) return null;
        ip[i] = std.fmt.parseInt(u8, octet, 10) catch return null;
    }
    if (i != 4) return null;

    const mask = std.fmt.parseInt(u8, mask_part, 10) catch return null;
    if (mask > 32 or mask < 16) return null; // Reasonable limits

    // Zero the host bits so e.g. 192.168.1.5/24 scans 192.168.1.0-255
    // instead of running past the end of the subnet
    const netmask: u32 = if (mask == 32) ~@as(u32, 0) else ~@as(u32, 0) << @intCast(32 - mask);
    const base = ipToU32(ip) & netmask;

    return .{ .subnet = u32ToIp(base), .mask = mask };
}

// Whether ip (host byte order) is a scannable host address of the subnet:
// inside it, and not its network or broadcast address (below /31)
fn isHostOf(ip: u32, subnet: [4]u8, mask_bits: u8) bool {
    const mask = prefixMask(mask_bits);
    if (ip & mask != ipToU32(subnet) & mask) return false;
    if (mask_bits >= 31) return true;
    const host = ip & ~mask;
    return host != 0 and host != ~mask;
}

// Neighbor-table addresses this scan resolved that never answered ping:
// present on the segment, silent to ICMP. Returns host-order [4]u8 IPs.
fn silentNeighbors(
    allocator: std.mem.Allocator,
    config: Config,
    before: []const neigh.Neighbor,
    alive: []const [4]u8,
) ![][4]u8 {
    var after: std.ArrayList(neigh.Neighbor) = .empty;
    defer after.deinit(allocator);
    neigh.collect(allocator, &after);

    const fresh = try neigh.fresh(allocator, before, after.items);
    defer allocator.free(fresh);

    var alive_set = std.AutoHashMap(u32, void).init(allocator);
    defer alive_set.deinit();
    for (alive) |ip| try alive_set.put(ipToU32(ip), {});

    var silent: std.ArrayList([4]u8) = .empty;
    errdefer silent.deinit(allocator);
    for (fresh) |addr_be| {
        const ip: [4]u8 = @bitCast(addr_be);
        const key = ipToU32(ip);
        if (!isHostOf(key, config.subnet, config.mask_bits)) continue;
        if (alive_set.contains(key)) continue;
        try alive_set.put(key, {}); // dedupe repeated table rows
        try silent.append(allocator, ip);
    }
    return silent.toOwnedSlice(allocator);
}

// Run one full discovery + latency scan. Returns owned results sorted by IP;
// empty (not an error) when nothing responded, so mesh mode can keep going.
fn runScanOnce(scanner: *Scanner, allocator: std.mem.Allocator, stdout: StdoutWriter) ![]PingResult {
    const use_arp = scanner.config.arp and neigh.supported;

    // Snapshot the neighbor table first, so entries left over from before
    // this scan can be told apart from ones it resolved
    var before: std.ArrayList(neigh.Neighbor) = .empty;
    defer before.deinit(allocator);
    if (use_arp) neigh.collect(allocator, &before);

    var alive_hosts = try scanner.discover(stdout);
    defer alive_hosts.deinit(allocator);

    const silent: [][4]u8 = if (use_arp)
        try silentNeighbors(allocator, scanner.config, before.items, alive_hosts.items)
    else
        &.{};
    defer if (use_arp) allocator.free(silent);
    if (silent.len > 0) {
        stdout.print("  Neighbor table: {d} more host{s} ARP but not ping\n", .{
            silent.len,
            if (silent.len == 1) " answers" else "s answer",
        }) catch {};
    }

    const lessThan = struct {
        fn ip(_: void, a: [4]u8, b: [4]u8) bool {
            return ipToU32(a) < ipToU32(b);
        }
        fn result(_: void, a: PingResult, b: PingResult) bool {
            return ipToU32(a.ip) < ipToU32(b.ip);
        }
    };
    std.mem.sort([4]u8, alive_hosts.items, {}, lessThan.ip);

    const n_alive = alive_hosts.items.len;
    const results = try allocator.alloc(PingResult, n_alive + silent.len);
    errdefer allocator.free(results);
    if (n_alive > 0) {
        stdout.print("\n", .{}) catch {};
        try scanner.measureLatency(alive_hosts.items, results[0..n_alive], stdout);
    }
    for (silent, 0..) |ip, i| {
        results[n_alive + i] = .{
            .ip = ip,
            .latency_us = null,
            .latency_avg = null,
            .latency_max = null,
            .icmp = false,
        };
    }
    std.mem.sort(PingResult, results, {}, lessThan.result);
    return results;
}

// Mesh mode: scan, share results with peers over UDP, render the combined
// latency matrix, and rescan on an interval. Runs until interrupted.
fn runMeshMode(scanner: *Scanner, allocator: std.mem.Allocator, stdout: StdoutWriter, config: Config) !void {
    // Peers may be on the scanned subnet or on any directly attached one
    var entries: [max_ifaces]IfaceEntry = undefined;
    const n_ifaces = collectIfaces(&entries);
    var local_networks: [max_ifaces]mesh_mod.Network = undefined;
    for (entries[0..n_ifaces], 0..) |*e, i| {
        const mask = ipToU32(@as([4]u8, @bitCast(e.mask_be)));
        const ip = ipToU32(@as([4]u8, @bitCast(e.addr_be)));
        local_networks[i] = .{ .addr = ip & mask, .mask = mask };
    }

    var mesh = mesh_mod.Mesh.init(allocator, .{
        .port = config.mesh_port,
        .subnet = config.subnet,
        .mask_bits = config.mask_bits,
        .tcp_targets = config.tcp_targets[0..config.tcp_target_count],
        .local_networks = local_networks[0..n_ifaces],
        .key = config.mesh_key,
    }) catch |err| {
        std.debug.print("Error: failed to open mesh UDP socket on port {d}: {s}\n", .{ config.mesh_port, @errorName(err) });
        return err;
    };
    defer mesh.deinit();
    // All sockets are open (the mesh port may be a privileged one)
    dropPrivilegesOrExit(stdout);
    try mesh.startProber();

    // Keep the mesh alive (beacons + socket drain, no gossip) while scans
    // run, so a scan longer than the peer timeout doesn't get this node
    // dropped from every peer's table
    scanner.tick_ctx = @ptrCast(&mesh);
    scanner.tick_fn = &struct {
        fn call(ctx: *anyopaque) void {
            const m: *mesh_mod.Mesh = @ptrCast(@alignCast(ctx));
            m.keepAlive();
        }
    }.call;
    defer {
        scanner.tick_fn = null;
        scanner.tick_ctx = null;
    }

    const rescan_us: i64 = @as(i64, config.rescan_interval_s) * std.time.us_per_s;
    var next_scan_at: i64 = monotonicMicros(); // first scan runs immediately

    while (true) {
        const now = monotonicMicros();
        if (next_scan_at <= now) {
            const results = try runScanOnce(scanner, allocator, stdout);
            defer allocator.free(results);
            try mesh.setLocalResults(results);
            next_scan_at = if (rescan_us > 0)
                monotonicMicros() + rescan_us
            else
                std.math.maxInt(i64);
        }
        mesh.pump();
        mesh.renderIfDue(stdout, if (rescan_us > 0) next_scan_at else null);
        // Sleep until mesh traffic arrives or a short tick elapses
        _ = mesh.poller.wait(100);
    }
}

fn nextArgValue(args: []const [:0]const u8, i: *usize) []const u8 {
    if (i.* + 1 >= args.len) {
        std.debug.print("Error: {s} requires a value (see --help)\n", .{args[i.*]});
        std.process.exit(1);
    }
    i.* += 1;
    return args[i.*];
}

fn invalidArgValue(flag: []const u8, value: []const u8) noreturn {
    std.debug.print("Error: invalid value for {s}: '{s}'\n", .{ flag, value });
    std.process.exit(1);
}

// Root is needed only to open sockets; give it up once they are open
fn dropPrivilegesOrExit(log: StdoutWriter) void {
    switch (plat.dropPrivileges()) {
        .dropped => |d| log.print("  Privileges: dropped root after opening sockets (now uid {d}{s})\n", .{
            d.uid,
            if (d.sudo_user) ", the sudo user" else ", nobody",
        }) catch {},
        .failed => fail("could not drop root privileges after opening sockets", .{}),
        .not_root, .unsupported => {},
    }
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    std.debug.print("Error: " ++ fmt ++ "\n", args);
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    // Windows: initialize Winsock once, before any thread might race to
    plat.netInit();

    // Get unbuffered stdout writer for immediate output (pass empty slice for unbuffered)
    var stdout_writer = std.Io.File.stdout().writer(init.io, &.{});
    const stdout = &stdout_writer.interface;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &.{});

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    var config = Config{};

    // Parse command line args
    var no_color = false;
    var subnet_set = false;
    var mesh_key_file: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            stdout.print(
                \\
                \\Network Latency Heatmap Scanner (two-phase, event-loop based)
                \\
                \\Usage: {s} [subnet/mask] [options]
                \\
                \\Examples:
                \\  {s}                      (auto-detect local subnet)
                \\  {s} 192.168.1.0/24
                \\  {s} 192.168.0.0/16 -d 3000
                \\
                \\Options:
                \\  -d <ms>     Discovery timeout in milliseconds (default: 1000)
                \\  -p <count>  Number of pings per host for latency (default: 5, max 16)
                \\  -t <ms>     Timeout per ping in latency phase (default: 1000)
                \\  --rate <pps>  Discovery send rate in pings/s, 0 = unlimited (default:
                \\              unlimited, or 300 for on-link subnets over 1024 hosts,
                \\              which would otherwise overflow the ARP table)
                \\  --retries <n>  Extra discovery passes re-pinging silent addresses
                \\              (default: 1, max 10)
                \\  --no-arp    Don't report hosts that answer ARP but not ping
                \\  --json      Print results as JSON on stdout (progress goes to stderr)
                \\  --csv       Print results as CSV on stdout (progress goes to stderr)
                \\  --mesh      Mesh mode: discover other instances of this tool on the
                \\              LAN over UDP, share results, and render a live matrix of
                \\              every host's latency from every vantage point
                \\  --mesh-port <port>  UDP+TCP port for mesh discovery, gossip, and
                \\              node-to-node probes (default: 47269)
                \\  --mesh-key <secret>  Mesh mode: authenticate mesh traffic with a
                \\              shared secret (HMAC-SHA256); nodes ignore anyone without
                \\              it. Visible in the process list; prefer --mesh-key-file
                \\  --mesh-key-file <path>  Read the mesh secret from a file
                \\  -i <sec>    Mesh mode: rescan interval in seconds, 0 = scan once
                \\              (default: 60)
                \\  --tcp-ping <ip:port>  Mesh mode: also TCP-ping this host on a known
                \\              port (SYN→SYN-ACK, or RST from a closed port — both time
                \\              the host's stack). Works on devices not running this
                \\              tool; repeatable, up to 16 targets
                \\  --no-color  Disable colored output (also disabled when stdout is
                \\              not a terminal, or the NO_COLOR env var is set)
                \\  -h, --help  Show this help
                \\
                \\The subnet is auto-detected from your network interface if not specified.
                \\
                \\How it works:
                \\  Phase 1: Blasts pings to all IPs (re-pinging silent ones), waits for
                \\           the discovery timeout, then checks the ARP table for hosts
                \\           that answered ARP but not ping
                \\  Phase 2: Measures latency, jitter and loss on hosts that responded
                \\  Mesh:    Peers announce themselves via UDP broadcast beacons and
                \\           gossip scan results; each node renders the combined matrix.
                \\           Nodes also measure each other directly with UDP echo pings
                \\           and TCP connect pings (handshakes are torn down with an
                \\           RST, zero window, so nothing lingers on either side)
                \\
                \\Note: Requires elevated privileges for raw ICMP sockets on most
                \\systems (root/sudo; an Administrator prompt on Windows). Under sudo,
                \\root is dropped right after the socket is opened. On Linux it also
                \\runs unprivileged with CAP_NET_RAW or ICMP ping sockets enabled.
                \\
            , .{ args[0], args[0], args[0], args[0] }) catch {};
            return;
        } else if (std.mem.eql(u8, arg, "-d")) {
            const value = nextArgValue(args, &i);
            config.discovery_timeout_ms = std.fmt.parseInt(u32, value, 10) catch
                return invalidArgValue("-d", value);
        } else if (std.mem.eql(u8, arg, "-p")) {
            const value = nextArgValue(args, &i);
            const pings = std.fmt.parseInt(u8, value, 10) catch
                return invalidArgValue("-p", value);
            if (pings < 1 or pings > LatencyData.max_samples) {
                fail("-p must be between 1 and {d} (got {d})", .{ LatencyData.max_samples, pings });
            }
            config.latency_pings = pings;
        } else if (std.mem.eql(u8, arg, "-t")) {
            const value = nextArgValue(args, &i);
            config.latency_timeout_ms = std.fmt.parseInt(u32, value, 10) catch
                return invalidArgValue("-t", value);
        } else if (std.mem.eql(u8, arg, "--rate")) {
            const value = nextArgValue(args, &i);
            config.send_rate_pps = std.fmt.parseInt(u32, value, 10) catch
                return invalidArgValue("--rate", value);
        } else if (std.mem.eql(u8, arg, "--retries")) {
            const value = nextArgValue(args, &i);
            const retries = std.fmt.parseInt(u8, value, 10) catch
                return invalidArgValue("--retries", value);
            if (retries > 10) fail("--retries must be at most 10 (got {d})", .{retries});
            config.retries = retries;
        } else if (std.mem.eql(u8, arg, "--no-arp")) {
            config.arp = false;
        } else if (std.mem.eql(u8, arg, "--json")) {
            config.output = .json;
        } else if (std.mem.eql(u8, arg, "--csv")) {
            config.output = .csv;
        } else if (std.mem.eql(u8, arg, "--no-color")) {
            no_color = true;
        } else if (std.mem.eql(u8, arg, "--mesh")) {
            config.mesh = true;
        } else if (std.mem.eql(u8, arg, "--mesh-port")) {
            const value = nextArgValue(args, &i);
            config.mesh_port = std.fmt.parseInt(u16, value, 10) catch
                return invalidArgValue("--mesh-port", value);
            if (config.mesh_port == 0) return invalidArgValue("--mesh-port", value);
        } else if (std.mem.eql(u8, arg, "--mesh-key")) {
            const value = nextArgValue(args, &i);
            if (value.len == 0) fail("--mesh-key must not be empty", .{});
            config.mesh_key = value;
        } else if (std.mem.eql(u8, arg, "--mesh-key-file")) {
            mesh_key_file = nextArgValue(args, &i);
        } else if (std.mem.eql(u8, arg, "-i")) {
            const value = nextArgValue(args, &i);
            config.rescan_interval_s = std.fmt.parseInt(u32, value, 10) catch
                return invalidArgValue("-i", value);
        } else if (std.mem.eql(u8, arg, "--tcp-ping")) {
            const value = nextArgValue(args, &i);
            const target = probe.parseTcpTarget(value) orelse
                return invalidArgValue("--tcp-ping", value);
            if (config.tcp_target_count >= probe.max_targets) {
                fail("at most {d} --tcp-ping targets", .{probe.max_targets});
            }
            config.tcp_targets[config.tcp_target_count] = target;
            config.tcp_target_count += 1;
        } else if (!subnet_set) {
            const parsed = parseSubnet(arg) orelse fail("unrecognized argument '{s}' (see --help)", .{arg});
            config.subnet = parsed.subnet;
            config.mask_bits = parsed.mask;
            subnet_set = true;
        } else {
            fail("unrecognized argument '{s}' (see --help)", .{arg});
        }
    }

    if (config.tcp_target_count > 0 and !config.mesh) {
        fail("--tcp-ping targets are probed by mesh mode; add --mesh", .{});
    }
    if ((config.mesh_key != null or mesh_key_file != null) and !config.mesh) {
        fail("--mesh-key and --mesh-key-file only apply to mesh mode; add --mesh", .{});
    }
    if (config.mesh_key != null and mesh_key_file != null) {
        fail("give either --mesh-key or --mesh-key-file, not both", .{});
    }
    if (config.output != .text and config.mesh) {
        fail("--json/--csv report a single scan; they can't be combined with --mesh", .{});
    }

    // Read the mesh secret now, while any privileges needed to read the
    // file are still held
    if (mesh_key_file) |path| {
        const raw = std.Io.Dir.cwd().readFileAlloc(init.io, path, init.arena.allocator(), .limited(4096)) catch |err|
            fail("could not read --mesh-key-file '{s}': {s}", .{ path, @errorName(err) });
        const key = std.mem.trim(u8, raw, " \t\r\n");
        if (key.len == 0) fail("--mesh-key-file '{s}' is empty", .{path});
        config.mesh_key = key;
    }

    // Detect the local subnet only when none was given; fall back to
    // 192.168.1.0/24
    const detected_subnet = if (subnet_set) null else detectLocalSubnet();
    if (detected_subnet) |detected| {
        config.subnet = detected.subnet;
        config.mask_bits = detected.mask;
    }

    common.initTerm(no_color);

    // Machine-readable output owns stdout; the human-readable log (banner,
    // progress, notices) goes to stderr as plain text
    const machine = config.output != .text;
    if (machine) {
        common.stdout_is_tty = false;
        common.color_enabled = false;
    }
    const log: StdoutWriter = if (machine) &stderr_writer.interface else stdout;

    // Print banner
    const cyan = common.sgr("\x1b[96m");
    const bold = common.sgr("\x1b[1m");
    const reset = common.sgr("\x1b[0m");
    log.print("\n", .{}) catch {};
    log.print("{s}╔══════════════════════════════════════════════════════════════╗{s}\n", .{ cyan, reset }) catch {};
    log.print("{s}║{s}             {s}Network Latency Heatmap Scanner{s}                  {s}║{s}\n", .{ cyan, reset, bold, reset, cyan, reset }) catch {};
    log.print("{s}╚══════════════════════════════════════════════════════════════╝{s}\n", .{ cyan, reset }) catch {};

    var subnet_buf: [32]u8 = undefined;
    const subnet_str = std.fmt.bufPrint(&subnet_buf, "{}.{}.{}.{}/{}", .{
        config.subnet[0],
        config.subnet[1],
        config.subnet[2],
        config.subnet[3],
        config.mask_bits,
    }) catch "???";

    log.print("\n  Subnet: {s}", .{subnet_str}) catch {};
    if (!subnet_set) {
        if (detected_subnet) |detected| {
            log.print(" (auto-detected on {s}{s})", .{
                detected.name(),
                if (detected.on_default_route) ", default route" else "",
            }) catch {};
        } else {
            log.print(" (default; no local subnet detected)", .{}) catch {};
        }
    }
    log.print("\n", .{}) catch {};
    log.print("  Discovery timeout: {d}ms | Latency pings: {d} | Ping timeout: {d}ms\n", .{
        config.discovery_timeout_ms,
        config.latency_pings,
        config.latency_timeout_ms,
    }) catch {};

    const full_range = try generateIpRange(allocator, config.subnet, config.mask_bits);
    defer allocator.free(full_range);
    const all_ips = full_range[0..removeLocalAddrs(full_range)];

    log.print("  Total IPs to scan: {d}", .{all_ips.len}) catch {};
    if (all_ips.len < full_range.len) {
        log.print(" (excluding {d} own address{s})", .{
            full_range.len - all_ips.len,
            if (full_range.len - all_ips.len == 1) "" else "es",
        }) catch {};
    }
    log.print("\n", .{}) catch {};

    // Two-phase scanner
    var scanner = Scanner.init(allocator, all_ips, config) catch |err| {
        if (err == error.SocketCreationFailed) {
            std.process.exit(1); // Error already printed
        }
        return err;
    };
    defer scanner.deinit();

    log.print("  ICMP socket: {s}\n", .{
        if (scanner.is_raw_socket) "raw" else "unprivileged ping socket",
    }) catch {};
    log.print("  Receive timestamps: {s}\n", .{
        if (scanner.kernel_ts_enabled) "kernel (SO_TIMESTAMP)" else "userspace (kernel timestamps unavailable)",
    }) catch {};

    if (config.mesh) {
        log.print("  Mesh: UDP port {d}, rescan interval {d}s{s}{s}\n\n", .{
            config.mesh_port,
            config.rescan_interval_s,
            if (config.rescan_interval_s == 0) " (scan once)" else "",
            if (config.mesh_key != null) ", authenticated" else "",
        }) catch {};
        return runMeshMode(&scanner, allocator, log, config);
    }
    // The ICMP socket is open: nothing from here on needs root
    dropPrivilegesOrExit(log);
    log.print("\n", .{}) catch {};

    const results = try runScanOnce(&scanner, allocator, log);
    defer allocator.free(results);

    switch (config.output) {
        .json => {
            try writeJson(stdout, .{
                .subnet = subnet_str,
                .timestamp_s = @divFloor(wallMicros(), std.time.us_per_s),
                .scanned = all_ips.len,
                .pings_per_host = config.latency_pings,
            }, results);
            return;
        },
        .csv => {
            try writeCsv(stdout, results);
            return;
        },
        .text => {},
    }

    if (results.len == 0) {
        stdout.print("\n{s}No devices responded. Are you on the right subnet?{s}\n", .{ common.sgr("\x1b[93m"), reset }) catch {};
        if (plat.is_windows) {
            stdout.print("Try running from an Administrator prompt if you haven't already.\n", .{}) catch {};
        } else {
            stdout.print("Try running with sudo if you haven't already.\n", .{}) catch {};
        }
        return;
    }

    printLegend(stdout);

    stdout.print("\n{s}Active Devices:{s}\n", .{ bold, reset }) catch {};
    printHeatmapGrid(stdout, results, 4);

    printSummary(stdout, results, all_ips.len);
}

const testing = std.testing;

test {
    _ = @import("common.zig");
    _ = @import("mesh.zig");
    _ = @import("probe.zig");
    _ = @import("plat.zig");
    _ = @import("neigh.zig");
}

test "calculateChecksum verifies to zero over a packet containing its own checksum" {
    var packet: [16]u8 align(4) = undefined;
    const header: *IcmpHeader = @ptrCast(@alignCast(&packet));
    header.type = ICMP_ECHO_REQUEST;
    header.code = 0;
    header.checksum = 0;
    header.id = 0x1234;
    header.sequence = 7;
    for (packet[@sizeOf(IcmpHeader)..]) |*b| b.* = 0xAB;

    header.checksum = calculateChecksum(&packet);
    try testing.expectEqual(@as(u16, 0), calculateChecksum(&packet));
}

test "parseSubnet masks host bits" {
    const parsed = parseSubnet("192.168.1.5/24").?;
    try testing.expectEqual([4]u8{ 192, 168, 1, 0 }, parsed.subnet);
    try testing.expectEqual(@as(u8, 24), parsed.mask);
}

test "parseSubnet defaults to /24 and rejects bad input" {
    const parsed = parseSubnet("10.1.2.3").?;
    try testing.expectEqual([4]u8{ 10, 1, 2, 0 }, parsed.subnet);
    try testing.expectEqual(@as(u8, 24), parsed.mask);

    try testing.expect(parseSubnet("10.1.2/24") == null);
    try testing.expect(parseSubnet("10.1.2.3.4/24") == null);
    try testing.expect(parseSubnet("10.1.2.3/33") == null);
    try testing.expect(parseSubnet("10.1.2.3/8") == null);
    try testing.expect(parseSubnet("a.b.c.d/24") == null);
    try testing.expect(parseSubnet("10.1.2.256/24") == null);
}

test "generateIpRange /24 excludes network and broadcast" {
    const ips = try generateIpRange(testing.allocator, .{ 192, 168, 1, 0 }, 24);
    defer testing.allocator.free(ips);
    try testing.expectEqual(@as(usize, 254), ips.len);
    try testing.expectEqual([4]u8{ 192, 168, 1, 1 }, ips[0]);
    try testing.expectEqual([4]u8{ 192, 168, 1, 254 }, ips[253]);
}

test "generateIpRange handles /31 and /32 without underflow" {
    const one = try generateIpRange(testing.allocator, .{ 10, 0, 0, 5 }, 32);
    defer testing.allocator.free(one);
    try testing.expectEqual(@as(usize, 1), one.len);
    try testing.expectEqual([4]u8{ 10, 0, 0, 5 }, one[0]);

    const two = try generateIpRange(testing.allocator, .{ 10, 0, 0, 4 }, 31);
    defer testing.allocator.free(two);
    try testing.expectEqual(@as(usize, 2), two.len);
    try testing.expectEqual([4]u8{ 10, 0, 0, 4 }, two[0]);
    try testing.expectEqual([4]u8{ 10, 0, 0, 5 }, two[1]);
}

test "kernel_ts.parse extracts SCM_TIMESTAMP, skipping unrelated cmsgs" {
    var buf: [96]u8 align(8) = @splat(0);
    var off: usize = 0;

    // Unrelated cmsg first (wrong type) with 4 bytes of data
    {
        const hdr = kernel_ts.CmsgHdr{
            .len = @intCast(kernel_ts.data_offset + 4),
            .level = kernel_ts.level,
            .type = kernel_ts.scm_type + 1,
        };
        @memcpy(buf[off..][0..@sizeOf(kernel_ts.CmsgHdr)], std.mem.asBytes(&hdr));
        off += std.mem.alignForward(usize, @as(usize, @intCast(hdr.len)), kernel_ts.alignment);
    }

    // The timestamp cmsg
    {
        const tv = posix.timeval{ .sec = 12, .usec = 345678 };
        const hdr = kernel_ts.CmsgHdr{
            .len = @intCast(kernel_ts.data_offset + @sizeOf(posix.timeval)),
            .level = kernel_ts.level,
            .type = kernel_ts.scm_type,
        };
        @memcpy(buf[off..][0..@sizeOf(kernel_ts.CmsgHdr)], std.mem.asBytes(&hdr));
        @memcpy(buf[off + kernel_ts.data_offset ..][0..@sizeOf(posix.timeval)], std.mem.asBytes(&tv));
        off += std.mem.alignForward(usize, @as(usize, @intCast(hdr.len)), kernel_ts.alignment);
    }

    try testing.expectEqual(@as(?i64, 12_345_678), kernel_ts.parse(buf[0..off]));
}

test "kernel_ts.parse rejects empty, truncated, and mismatched buffers" {
    try testing.expectEqual(@as(?i64, null), kernel_ts.parse(&.{}));

    // Header alone, no timeval payload
    var short: [@sizeOf(kernel_ts.CmsgHdr)]u8 align(8) = undefined;
    const hdr = kernel_ts.CmsgHdr{
        .len = @intCast(@sizeOf(kernel_ts.CmsgHdr)),
        .level = kernel_ts.level,
        .type = kernel_ts.scm_type,
    };
    @memcpy(&short, std.mem.asBytes(&hdr));
    try testing.expectEqual(@as(?i64, null), kernel_ts.parse(&short));

    // Length claims more data than the buffer holds
    var lying: [@sizeOf(kernel_ts.CmsgHdr)]u8 align(8) = undefined;
    const bad = kernel_ts.CmsgHdr{
        .len = @intCast(@sizeOf(kernel_ts.CmsgHdr) + 64),
        .level = kernel_ts.level,
        .type = kernel_ts.scm_type,
    };
    @memcpy(&lying, std.mem.asBytes(&bad));
    try testing.expectEqual(@as(?i64, null), kernel_ts.parse(&lying));
}

test "LatencyData caps samples and computes min/avg/max" {
    var data = LatencyData.init();
    try testing.expectEqual(@as(?u64, null), data.getMin());

    data.add(300);
    data.add(100);
    data.add(200);
    try testing.expectEqual(@as(?u64, 100), data.getMin());
    try testing.expectEqual(@as(?u64, 200), data.getAvg());
    try testing.expectEqual(@as(?u64, 300), data.getMax());

    for (0..LatencyData.max_samples * 2) |_| data.add(1);
    try testing.expectEqual(@as(u8, LatencyData.max_samples), data.count);
}

test "Scanner discovers and measures loopback over an unprivileged ping socket" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // Needs net.ipv4.ping_group_range to include our group (the default on
    // many distros, including Ubuntu); skip where it doesn't
    const sock = plat.openSocket(plat.AF_INET, plat.SOCK_DGRAM, plat.IPPROTO_ICMP);
    if (!plat.isValidSocket(sock)) return error.SkipZigTest;

    const ips = [_][4]u8{.{ 127, 0, 0, 1 }};
    var config = Config{ .subnet = .{ 127, 0, 0, 1 }, .mask_bits = 32, .latency_pings = 3, .retries = 0, .arp = false };
    config.discovery_timeout_ms = 300;
    var scanner = try Scanner.initWithSocket(testing.allocator, &ips, config, sock, false);
    defer scanner.deinit();

    var log_buf: [4096]u8 = undefined;
    var log = std.Io.Writer.fixed(&log_buf);
    var alive = try scanner.discover(&log);
    defer alive.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), alive.items.len);
    try testing.expectEqual(ips[0], alive.items[0]);

    var results: [1]PingResult = undefined;
    try scanner.measureLatency(alive.items, &results, &log);
    try testing.expectEqual(@as(u8, 3), results[0].sent);
    try testing.expectEqual(@as(u8, 3), results[0].received);
    try testing.expect(results[0].latency_avg != null);
    try testing.expect(results[0].stddev_us != null);
}

test "LatencyData stddev" {
    var data = LatencyData.init();
    data.add(100);
    try testing.expectEqual(@as(?u64, null), data.getStddev());
    data.add(300);
    try testing.expectEqual(@as(?u64, 100), data.getStddev());
}

test "isHostOf excludes network and broadcast addresses" {
    const net = [4]u8{ 192, 168, 1, 0 };
    try testing.expect(isHostOf(ipToU32(.{ 192, 168, 1, 1 }), net, 24));
    try testing.expect(!isHostOf(ipToU32(.{ 192, 168, 1, 0 }), net, 24));
    try testing.expect(!isHostOf(ipToU32(.{ 192, 168, 1, 255 }), net, 24));
    try testing.expect(!isHostOf(ipToU32(.{ 192, 168, 2, 1 }), net, 24));
    try testing.expect(isHostOf(ipToU32(.{ 10, 0, 0, 5 }), .{ 10, 0, 0, 4 }, 31));
}

test "autoSendRate paces only large on-link scans" {
    try testing.expectEqual(@as(u32, 0), autoSendRate(254, true));
    try testing.expectEqual(@as(u32, 0), autoSendRate(65534, false));
    try testing.expectEqual(auto_rate_pps, autoSendRate(65534, true));
}

test "writeJson and writeCsv render present and missing values" {
    const results = [_]PingResult{
        .{ .ip = .{ 10, 0, 0, 1 }, .latency_us = 100, .latency_avg = 150, .latency_max = 200, .stddev_us = 40, .sent = 4, .received = 3 },
        .{ .ip = .{ 10, 0, 0, 2 }, .latency_us = null, .latency_avg = null, .latency_max = null, .icmp = false },
    };
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeJson(&w, .{ .subnet = "10.0.0.0/24", .timestamp_s = 1700000000, .scanned = 254, .pings_per_host = 4 }, &results);
    try testing.expectEqualStrings(
        \\{"subnet":"10.0.0.0/24","timestamp":1700000000,"addresses_scanned":254,"pings_per_host":4,"hosts":[
        \\  {"ip":"10.0.0.1","responds_to_icmp":true,"min_us":100,"avg_us":150,"max_us":200,"stddev_us":40,"sent":4,"received":3,"loss_pct":25.0},
        \\  {"ip":"10.0.0.2","responds_to_icmp":false,"min_us":null,"avg_us":null,"max_us":null,"stddev_us":null,"sent":0,"received":0,"loss_pct":null}
        \\]}
        \\
    , w.buffered());

    w = std.Io.Writer.fixed(&buf);
    try writeCsv(&w, &results);
    try testing.expectEqualStrings(
        \\ip,responds_to_icmp,min_us,avg_us,max_us,stddev_us,sent,received,loss_pct
        \\10.0.0.1,true,100,150,200,40,4,3,25.0
        \\10.0.0.2,false,,,,,0,0,
        \\
    , w.buffered());
}
