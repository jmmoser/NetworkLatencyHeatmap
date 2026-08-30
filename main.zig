const std = @import("std");
const posix = std.posix;
const c = std.c;
const builtin = @import("builtin");
const common = @import("common.zig");
const mesh_mod = @import("mesh.zig");
const probe = @import("probe.zig");
const plat = @import("plat.zig");

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
};

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

    all_ips: []const [4]u8,
};

// Sender thread function - uses shared socket
fn senderThread(state: *ScanState) void {
    for (state.all_ips) |ip| {
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
        // Use RAW ICMP socket - requires sudo on macOS, Administrator on
        // Windows (DGRAM ICMP can send but cannot receive replies on macOS)
        // Raw calls (not Zig's error-set wrappers) to report errno properly
        plat.netInit();
        const sock = plat.openSocket(plat.AF_INET, plat.SOCK_RAW, plat.IPPROTO_ICMP);
        if (!plat.isValidSocket(sock)) {
            const err = plat.lastError();
            if (plat.errPermission(err)) {
                std.debug.print("\nError: Raw ICMP socket requires elevated privileges.\n", .{});
                if (plat.is_windows) {
                    std.debug.print("Please run from an Administrator prompt.\n\n", .{});
                } else {
                    std.debug.print("Please run with: sudo ./zig-out/bin/latency-heatmap ...\n\n", .{});
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
            _ = plat.bind(sock, &baddr, @sizeOf(posix.sockaddr.in));
        }

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
            .is_raw_socket = true,
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

    // Phase 1: Discovery - sender thread + receiver in main thread
    pub fn discover(self: *Scanner, stdout: StdoutWriter) !std.ArrayList([4]u8) {
        self.generation +%= 1;
        const magic = self.phaseMagic(1);
        var state = ScanState{
            .sent_count = std.atomic.Value(usize).init(0),
            .sender_done = std.atomic.Value(bool).init(false),
            .sock = self.sock,
            .magic = magic,
            .all_ips = self.all_ips,
        };

        // Discovered hosts; only this (receiver) thread touches the map,
        // so no locking is needed.
        var discovered = std.AutoHashMap(u32, void).init(self.allocator);
        defer discovered.deinit();

        stdout.print("  Phase 1: Discovery - scanning {d} hosts...\n", .{self.all_ips.len}) catch {};

        // Start sender thread (shares the raw socket; replies are received here)
        const sender = try std.Thread.spawn(.{}, senderThread, .{&state});

        // Only accept replies from addresses inside the scanned subnet
        const netmask: u32 = if (self.config.mask_bits >= 32)
            ~@as(u32, 0)
        else
            ~@as(u32, 0) << @intCast(32 - self.config.mask_bits);
        const network: u32 = ipToU32(self.config.subnet) & netmask;

        // Main thread receives replies
        var recv_buf: [1024]u8 align(4) = undefined;

        var last_print: i64 = 0;

        // Track when sender finishes for timeout calculation
        var sender_finish_time: ?i64 = null;

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
                stdout.print("{s}  Sent: {d}/{d} - waiting for replies...                    \n", .{ common.cr(), state.sent_count.load(.seq_cst), self.all_ips.len }) catch {};
            }

            // Check exit conditions after sender finished
            if (sender_finish_time) |finish_time| {
                const time_since_finish_us = now - finish_time;
                const time_since_finish_ms = @divFloor(time_since_finish_us, 1000);

                const discovered_count = discovered.count();

                // Exit early if no hosts discovered after 500ms
                if (discovered_count == 0 and time_since_finish_ms > 500) {
                    stdout.print("{s}  No hosts found, exiting early.                              \n", .{common.cr()}) catch {};
                    break;
                }

                // Normal timeout for when we have discovered hosts
                if (time_since_finish_ms > self.config.discovery_timeout_ms) {
                    break;
                }
            }

            // Update progress periodically (\r-rewriting lines, TTY only)
            if (common.stdout_is_tty and now - last_print > 100_000) {
                last_print = now;
                const sent = state.sent_count.load(.seq_cst);
                const discovered_count = discovered.count();

                if (!sender_done) {
                    stdout.print("\r  Sent: {d}/{d} | Discovered: {d}   ", .{ sent, self.all_ips.len, discovered_count }) catch {};
                } else if (sender_finish_time) |finish_time| {
                    const time_since_ms = @divFloor(now - finish_time, 1000);
                    const remaining_ms: i64 = @as(i64, self.config.discovery_timeout_ms) - time_since_ms;
                    stdout.print("\r  Discovered: {d} hosts (elapsed: {d}ms, remaining: {d}ms)   ", .{ discovered_count, time_since_ms, remaining_ms }) catch {};
                }
            }

            // Wait for more data (event-driven)
            _ = self.poller.wait(10);
        }

        // Wait for sender to finish
        sender.join();

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

                // Build and send packet
                header.id = @truncate(host_idx);
                header.sequence = @intCast(round);
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

                    const icmp_reply: *const IcmpHeader = @ptrCast(@alignCast(&recv_buf[icmp_offset]));
                    if (icmp_reply.type != ICMP_ECHO_REPLY) continue;

                    // Ignore replies to other processes' pings and stale
                    // discovery replies still arriving from Phase 1
                    const payload_off = icmp_offset + @sizeOf(IcmpHeader);
                    if (recv_len < payload_off + 4) continue;
                    if (!std.mem.eql(u8, recv_buf[payload_off..][0..4], &magic)) continue;

                    const host_idx: usize = icmp_reply.id;
                    const reply_round: usize = icmp_reply.sequence;
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

        // Copy results
        for (0..hosts.len) |i| {
            results[i].latency_us = latencies[i].getMin();
            results[i].latency_avg = latencies[i].getAvg();
            results[i].latency_max = latencies[i].getMax();
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

fn printHeatmapGrid(stdout: StdoutWriter, results: []const PingResult, width: usize) void {
    const reset = common.sgr("\x1b[0m");
    const col_width = 28; // Fixed column width for alignment
    const spaces = " " ** col_width;

    stdout.print("\n", .{}) catch {};

    var row_start: usize = 0;
    while (row_start < results.len) {
        const row_end = @min(row_start + width, results.len);

        // Print IP labels for this row (padded to col_width)
        for (results[row_start..row_end]) |r| {
            var buf: [16]u8 = undefined;
            const ip_str = ipToString(r.ip, &buf);
            stdout.print("{s}{s}", .{ ip_str, spaces[0 .. col_width - ip_str.len] }) catch {};
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
            const combined_str = if (r.latency_us != null) blk: {
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
            const used = 2 + displayWidth(combined_str);
            const pad = if (used < col_width) col_width - used else 1; // At least one space between columns
            stdout.print("{s}", .{spaces[0..pad]}) catch {};
        }
        stdout.print("\n\n", .{}) catch {};

        row_start = row_end;
    }
}

fn printSummary(stdout: StdoutWriter, results: []const PingResult) void {
    var alive_count: usize = 0;
    var total_avg_latency: u64 = 0;
    var best_avg: u64 = std.math.maxInt(u64);
    var worst_avg: u64 = 0;
    var slow_devices: [10]PingResult = undefined;
    var slow_count: usize = 0;

    for (results) |r| {
        if (r.latency_avg) |avg_lat| {
            alive_count += 1;
            total_avg_latency += avg_lat;
            if (avg_lat < best_avg) best_avg = avg_lat;
            if (avg_lat > worst_avg) worst_avg = avg_lat;

            // Track slow devices (avg >20ms)
            if (avg_lat > 20000) {
                if (slow_count < 10) {
                    slow_devices[slow_count] = r;
                    slow_count += 1;
                }
            }
        }
    }

    const bold = common.sgr("\x1b[1m");
    const reset = common.sgr("\x1b[0m");
    stdout.print("\n{s}══════════════════════════════════════════════════════════════{s}\n", .{ bold, reset }) catch {};
    stdout.print("{s}                     NETWORK SUMMARY{s}\n", .{ bold, reset }) catch {};
    stdout.print("{s}══════════════════════════════════════════════════════════════{s}\n\n", .{ bold, reset }) catch {};

    stdout.print("  Hosts scanned:  {d}\n", .{results.len}) catch {};
    stdout.print("  Hosts alive:    {d} ({d:.1}%)\n", .{
        alive_count,
        if (results.len > 0) @as(f64, @floatFromInt(alive_count)) / @as(f64, @floatFromInt(results.len)) * 100.0 else 0.0,
    }) catch {};

    if (alive_count > 0) {
        var buf1: [16]u8 = undefined;
        var buf2: [16]u8 = undefined;
        var buf3: [16]u8 = undefined;

        stdout.print("\n  Latency stats (by avg):\n", .{}) catch {};
        stdout.print("    Best:  {s}\n", .{formatLatency(best_avg, &buf1)}) catch {};
        stdout.print("    Mean:  {s}\n", .{formatLatency(total_avg_latency / alive_count, &buf2)}) catch {};
        stdout.print("    Worst: {s}\n", .{formatLatency(worst_avg, &buf3)}) catch {};
    }

    if (slow_count > 0) {
        stdout.print("\n  {s}⚠ Slow devices (avg >20ms):{s}\n", .{ common.sgr("\x1b[93m"), reset }) catch {};
        for (slow_devices[0..slow_count]) |r| {
            var ip_buf: [16]u8 = undefined;
            var lat_buf: [16]u8 = undefined;
            stdout.print("    {s}: {s} avg\n", .{
                ipToString(r.ip, &ip_buf),
                formatLatency(r.latency_avg, &lat_buf),
            }) catch {};
        }
    }

    stdout.print("\n{s}══════════════════════════════════════════════════════════════{s}\n", .{ bold, reset }) catch {};
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

// Run one full discovery + latency scan. Returns owned results sorted by IP;
// empty (not an error) when nothing responded, so mesh mode can keep going.
fn runScanOnce(scanner: *Scanner, allocator: std.mem.Allocator, stdout: StdoutWriter) ![]PingResult {
    var alive_hosts = try scanner.discover(stdout);
    defer alive_hosts.deinit(allocator);

    std.mem.sort([4]u8, alive_hosts.items, {}, struct {
        fn lessThan(_: void, a: [4]u8, b: [4]u8) bool {
            return ipToU32(a) < ipToU32(b);
        }
    }.lessThan);

    const results = try allocator.alloc(PingResult, alive_hosts.items.len);
    errdefer allocator.free(results);
    if (results.len > 0) {
        stdout.print("\n", .{}) catch {};
        try scanner.measureLatency(alive_hosts.items, results, stdout);
    }
    return results;
}

// Mesh mode: scan, share results with peers over UDP, render the combined
// latency matrix, and rescan on an interval. Runs until interrupted.
fn runMeshMode(scanner: *Scanner, allocator: std.mem.Allocator, stdout: StdoutWriter, config: Config) !void {
    var mesh = mesh_mod.Mesh.init(
        allocator,
        config.mesh_port,
        config.subnet,
        config.mask_bits,
        config.tcp_targets[0..config.tcp_target_count],
    ) catch |err| {
        std.debug.print("Error: failed to open mesh UDP socket on port {d}: {s}\n", .{ config.mesh_port, @errorName(err) });
        return err;
    };
    defer mesh.deinit();
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

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    // Windows: initialize Winsock once, before any thread might race to
    plat.netInit();

    // Get unbuffered stdout writer for immediate output (pass empty slice for unbuffered)
    var stdout_writer = std.Io.File.stdout().writer(init.io, &.{});
    const stdout = &stdout_writer.interface;

    const args = try init.minimal.args.toSlice(init.arena.allocator());

    // Detect local subnet, fall back to 192.168.1.0/24
    const detected_subnet = detectLocalSubnet();
    var config = if (detected_subnet) |detected|
        Config{ .subnet = detected.subnet, .mask_bits = detected.mask }
    else
        Config{};

    // Parse command line args
    var no_color = false;
    var subnet_set = false;
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
                \\  --mesh      Mesh mode: discover other instances of this tool on the
                \\              LAN over UDP, share results, and render a live matrix of
                \\              every host's latency from every vantage point
                \\  --mesh-port <port>  UDP+TCP port for mesh discovery, gossip, and
                \\              node-to-node probes (default: 47269)
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
                \\  Phase 1: Blasts pings to all IPs, waits for discovery timeout
                \\  Phase 2: Measures latency only on hosts that responded
                \\  Mesh:    Peers announce themselves via UDP broadcast beacons and
                \\           gossip scan results; each node renders the combined matrix.
                \\           Nodes also measure each other directly with UDP echo pings
                \\           and TCP connect pings (handshakes are torn down with an
                \\           RST, zero window, so nothing lingers on either side)
                \\
                \\Note: Requires elevated privileges for raw ICMP sockets on most
                \\systems (root/sudo; an Administrator prompt on Windows).
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
                std.debug.print("Error: -p must be between 1 and {d} (got {d})\n", .{ LatencyData.max_samples, pings });
                std.process.exit(1);
            }
            config.latency_pings = pings;
        } else if (std.mem.eql(u8, arg, "-t")) {
            const value = nextArgValue(args, &i);
            config.latency_timeout_ms = std.fmt.parseInt(u32, value, 10) catch
                return invalidArgValue("-t", value);
        } else if (std.mem.eql(u8, arg, "--no-color")) {
            no_color = true;
        } else if (std.mem.eql(u8, arg, "--mesh")) {
            config.mesh = true;
        } else if (std.mem.eql(u8, arg, "--mesh-port")) {
            const value = nextArgValue(args, &i);
            config.mesh_port = std.fmt.parseInt(u16, value, 10) catch
                return invalidArgValue("--mesh-port", value);
            if (config.mesh_port == 0) return invalidArgValue("--mesh-port", value);
        } else if (std.mem.eql(u8, arg, "-i")) {
            const value = nextArgValue(args, &i);
            config.rescan_interval_s = std.fmt.parseInt(u32, value, 10) catch
                return invalidArgValue("-i", value);
        } else if (std.mem.eql(u8, arg, "--tcp-ping")) {
            const value = nextArgValue(args, &i);
            const target = probe.parseTcpTarget(value) orelse
                return invalidArgValue("--tcp-ping", value);
            if (config.tcp_target_count >= probe.max_targets) {
                std.debug.print("Error: at most {d} --tcp-ping targets\n", .{probe.max_targets});
                std.process.exit(1);
            }
            config.tcp_targets[config.tcp_target_count] = target;
            config.tcp_target_count += 1;
        } else if (!subnet_set) {
            const parsed = parseSubnet(arg) orelse {
                std.debug.print("Error: unrecognized argument '{s}' (see --help)\n", .{arg});
                std.process.exit(1);
            };
            config.subnet = parsed.subnet;
            config.mask_bits = parsed.mask;
            subnet_set = true;
        } else {
            std.debug.print("Error: unrecognized argument '{s}' (see --help)\n", .{arg});
            std.process.exit(1);
        }
    }

    if (config.tcp_target_count > 0 and !config.mesh) {
        std.debug.print("Error: --tcp-ping targets are probed by mesh mode; add --mesh\n", .{});
        std.process.exit(1);
    }

    common.initTerm(no_color);

    // Print banner
    const cyan = common.sgr("\x1b[96m");
    const bold = common.sgr("\x1b[1m");
    const reset = common.sgr("\x1b[0m");
    stdout.print("\n", .{}) catch {};
    stdout.print("{s}╔══════════════════════════════════════════════════════════════╗{s}\n", .{ cyan, reset }) catch {};
    stdout.print("{s}║{s}             {s}Network Latency Heatmap Scanner{s}                  {s}║{s}\n", .{ cyan, reset, bold, reset, cyan, reset }) catch {};
    stdout.print("{s}╚══════════════════════════════════════════════════════════════╝{s}\n", .{ cyan, reset }) catch {};

    var subnet_buf: [32]u8 = undefined;
    const subnet_str = std.fmt.bufPrint(&subnet_buf, "{}.{}.{}.{}/{}", .{
        config.subnet[0],
        config.subnet[1],
        config.subnet[2],
        config.subnet[3],
        config.mask_bits,
    }) catch "???";

    stdout.print("\n  Subnet: {s}", .{subnet_str}) catch {};
    if (!subnet_set) {
        if (detected_subnet) |detected| {
            stdout.print(" (auto-detected on {s}{s})", .{
                detected.name(),
                if (detected.on_default_route) ", default route" else "",
            }) catch {};
        } else {
            stdout.print(" (default; no local subnet detected)", .{}) catch {};
        }
    }
    stdout.print("\n", .{}) catch {};
    stdout.print("  Discovery timeout: {d}ms | Latency pings: {d} | Ping timeout: {d}ms\n", .{
        config.discovery_timeout_ms,
        config.latency_pings,
        config.latency_timeout_ms,
    }) catch {};

    const full_range = try generateIpRange(allocator, config.subnet, config.mask_bits);
    defer allocator.free(full_range);
    const all_ips = full_range[0..removeLocalAddrs(full_range)];

    stdout.print("  Total IPs to scan: {d}", .{all_ips.len}) catch {};
    if (all_ips.len < full_range.len) {
        stdout.print(" (excluding {d} own address{s})", .{
            full_range.len - all_ips.len,
            if (full_range.len - all_ips.len == 1) "" else "es",
        }) catch {};
    }
    stdout.print("\n", .{}) catch {};

    // Two-phase scanner
    var scanner = Scanner.init(allocator, all_ips, config) catch |err| {
        if (err == error.SocketCreationFailed) {
            return; // Error already printed
        }
        return err;
    };
    defer scanner.deinit();

    stdout.print("  Receive timestamps: {s}\n", .{
        if (scanner.kernel_ts_enabled) "kernel (SO_TIMESTAMP)" else "userspace (kernel timestamps unavailable)",
    }) catch {};

    if (config.mesh) {
        stdout.print("  Mesh: UDP port {d}, rescan interval {d}s{s}\n\n", .{
            config.mesh_port,
            config.rescan_interval_s,
            if (config.rescan_interval_s == 0) " (scan once)" else "",
        }) catch {};
        return runMeshMode(&scanner, allocator, stdout, config);
    }
    stdout.print("\n", .{}) catch {};

    const results = try runScanOnce(&scanner, allocator, stdout);
    defer allocator.free(results);

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

    printSummary(stdout, results);
}

const testing = std.testing;

test {
    _ = @import("common.zig");
    _ = @import("mesh.zig");
    _ = @import("probe.zig");
    _ = @import("plat.zig");
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
