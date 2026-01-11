const std = @import("std");
const posix = std.posix;
const net = std.net;
const c = std.c;
const builtin = @import("builtin");

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

// Network interface detection using getifaddrs
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

fn detectLocalSubnet() ?struct { subnet: [4]u8, mask: u8 } {
    var ifa_list: ?*ifaddrs = null;
    if (getifaddrs(&ifa_list) != 0) return null;
    defer if (ifa_list) |list| freeifaddrs(list);

    var ifa = ifa_list;
    while (ifa) |iface| : (ifa = iface.next) {
        // Skip loopback and down interfaces
        if ((iface.flags & IFF_LOOPBACK) != 0) continue;
        if ((iface.flags & IFF_UP) == 0) continue;
        if ((iface.flags & IFF_RUNNING) == 0) continue;

        // Only handle IPv4 (AF_INET = 2)
        const addr = iface.addr orelse continue;
        if (addr.family != posix.AF.INET) continue;

        const netmask = iface.netmask orelse continue;
        if (netmask.family != posix.AF.INET) continue;

        // Get the sockaddr_in pointers
        const addr_in: *const posix.sockaddr.in = @ptrCast(@alignCast(addr));
        const mask_in: *const posix.sockaddr.in = @ptrCast(@alignCast(netmask));

        // Get IP address bytes (network byte order)
        const ip_bytes: [4]u8 = @bitCast(addr_in.addr);
        const mask_bytes: [4]u8 = @bitCast(mask_in.addr);

        // Skip link-local addresses (169.254.x.x)
        if (ip_bytes[0] == 169 and ip_bytes[1] == 254) continue;

        // Calculate mask bits from netmask
        var mask_bits: u8 = 0;
        for (mask_bytes) |byte| {
            var b = byte;
            while (b != 0) : (b <<= 1) {
                if ((b & 0x80) != 0) mask_bits += 1 else break;
            }
        }

        // Calculate network address (IP & mask)
        const subnet: [4]u8 = .{
            ip_bytes[0] & mask_bytes[0],
            ip_bytes[1] & mask_bytes[1],
            ip_bytes[2] & mask_bytes[2],
            ip_bytes[3] & mask_bytes[3],
        };

        return .{ .subnet = subnet, .mask = mask_bits };
    }
    return null;
}

// Platform-agnostic event poller for socket readiness
const SocketPoller = struct {
    // Use kqueue on macOS/BSD, epoll on Linux
    const is_darwin = builtin.os.tag == .macos or builtin.os.tag == .ios or
        builtin.os.tag == .watchos or builtin.os.tag == .tvos or
        builtin.os.tag == .freebsd or builtin.os.tag == .netbsd or
        builtin.os.tag == .openbsd or builtin.os.tag == .dragonfly;

    const is_linux = builtin.os.tag == .linux;

    fd: posix.fd_t,
    sock: posix.fd_t,

    pub fn init(sock: posix.fd_t) !SocketPoller {
        if (is_darwin) {
            const kq = try posix.kqueue();
            // Register socket for read events
            var changelist = [_]posix.Kevent{.{
                .ident = @intCast(sock),
                .filter = posix.system.EVFILT.READ,
                .flags = posix.system.EV.ADD,
                .fflags = 0,
                .data = 0,
                .udata = 0,
            }};
            _ = try posix.kevent(kq, &changelist, &[_]posix.Kevent{}, null);
            return .{ .fd = kq, .sock = sock };
        } else if (is_linux) {
            const epfd = try posix.epoll_create1(0);
            var ev = posix.linux.epoll_event{
                .events = posix.linux.EPOLL.IN,
                .data = .{ .fd = sock },
            };
            try posix.epoll_ctl(epfd, posix.linux.EPOLL.CTL_ADD, sock, &ev);
            return .{ .fd = epfd, .sock = sock };
        } else {
            // Fallback: no event fd, will use polling
            return .{ .fd = -1, .sock = sock };
        }
    }

    pub fn deinit(self: *SocketPoller) void {
        if (self.fd >= 0) {
            posix.close(self.fd);
        }
    }

    // Wait for socket to be readable, returns true if data available, false on timeout
    // timeout_ms: max time to wait in milliseconds
    pub fn wait(self: *SocketPoller, timeout_ms: u32) bool {
        if (is_darwin) {
            const timeout = posix.timespec{
                .sec = @intCast(timeout_ms / 1000),
                .nsec = @intCast((timeout_ms % 1000) * 1_000_000),
            };
            var events: [1]posix.Kevent = undefined;
            const n = posix.kevent(self.fd, &[_]posix.Kevent{}, &events, &timeout) catch return false;
            return n > 0;
        } else if (is_linux) {
            var events: [1]posix.linux.epoll_event = undefined;
            const n = posix.epoll_wait(self.fd, &events, @intCast(timeout_ms)) catch return false;
            return n > 0;
        } else {
            // Fallback: simple sleep-based polling
            std.Thread.sleep(timeout_ms * std.time.ns_per_ms);
            return true; // Assume data might be available
        }
    }

    // Non-blocking check if data is available (timeout = 0)
    pub fn poll(self: *SocketPoller) bool {
        return self.wait(0);
    }
};

const IcmpHeader = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    id: u16,
    sequence: u16,
};

const PingResult = struct {
    ip: [4]u8,
    latency_us: ?u64, // microseconds, null if timeout (min latency)
    latency_avg: ?u64, // average latency
    latency_max: ?u64, // max latency
    hostname: ?[]const u8,

    pub fn isAlive(self: PingResult) bool {
        return self.latency_us != null;
    }
};

const Config = struct {
    subnet: [4]u8 = .{ 192, 168, 1, 0 },
    mask_bits: u8 = 24,
    discovery_timeout_ms: u32 = 1000, // Time to wait for discovery responses
    latency_pings: u8 = 5, // Number of pings per host for latency measurement
    latency_timeout_ms: u32 = 1000, // Timeout per ping in latency phase
};

// Tracks pending ping requests - use IP address as key instead of sequence
const PendingPing = struct {
    send_time: i64,
    round: u8,
};

// State for parallel latency measurement (Phase 2)
// Uses lock-free arrays indexed by host_index for minimal contention
const LatencyState = struct {
    // Atomic counters
    rounds_sent: std.atomic.Value(usize),
    sender_done: std.atomic.Value(bool),

    // Lock-free send time tracking: [host_index * max_rounds + round] -> send_time
    // Sender writes, receiver reads - no mutex needed (atomic stores/loads)
    send_times: []std.atomic.Value(i64),

    // Latency results per host (only receiver writes, so no contention)
    latencies: []LatencyData,

    // Map from IP to host index for fast lookup
    ip_to_index: std.AutoHashMap(u32, usize),

    // Shared socket and config
    sock: posix.fd_t,
    hosts: []const [4]u8,
    config: Config,
    allocator: std.mem.Allocator,

    const LatencyData = struct {
        samples: [16]u64, // Store up to 16 latency samples
        count: u8,

        fn init() LatencyData {
            return LatencyData{
                .samples = undefined,
                .count = 0,
            };
        }

        fn add(self: *LatencyData, latency: u64) void {
            if (self.count < 16) {
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

    fn init(allocator: std.mem.Allocator, hosts: []const [4]u8, config: Config, sock: posix.fd_t) !LatencyState {
        const max_rounds: usize = config.latency_pings;
        const num_hosts = hosts.len;

        // Allocate send_times array: hosts * rounds
        const send_times = try allocator.alloc(std.atomic.Value(i64), num_hosts * max_rounds);
        for (send_times) |*st| {
            st.* = std.atomic.Value(i64).init(0);
        }

        // Allocate latencies array
        const latencies = try allocator.alloc(LatencyData, num_hosts);
        for (latencies) |*lat| {
            lat.* = LatencyData.init();
        }

        // Build IP to index map
        var ip_to_index = std.AutoHashMap(u32, usize).init(allocator);
        for (hosts, 0..) |ip, idx| {
            try ip_to_index.put(ipToU32(ip), idx);
        }

        return LatencyState{
            .rounds_sent = std.atomic.Value(usize).init(0),
            .sender_done = std.atomic.Value(bool).init(false),
            .send_times = send_times,
            .latencies = latencies,
            .ip_to_index = ip_to_index,
            .sock = sock,
            .hosts = hosts,
            .config = config,
            .allocator = allocator,
        };
    }

    fn deinit(self: *LatencyState) void {
        self.allocator.free(self.send_times);
        self.allocator.free(self.latencies);
        self.ip_to_index.deinit();
    }

    // Get index into send_times array
    fn sendTimeIndex(self: *const LatencyState, host_idx: usize, round: u8) usize {
        return host_idx * self.config.latency_pings + round;
    }
};

// Writer interface type for Zig 0.15
const StdoutWriter = *std.Io.Writer;

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

fn pingHost(ip: [4]u8, timeout_ms: u32) ?u64 {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.ICMP) catch {
        // Try raw socket if DGRAM fails (needs root for raw)
        return pingHostRaw(ip, timeout_ms);
    };
    defer posix.close(sock);

    // Set receive timeout
    const timeout = posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    const dest_addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.bytesToValue(u32, &ip),
    };

    // Build ICMP packet
    var packet: [64]u8 = undefined;
    const header: *IcmpHeader = @ptrCast(@alignCast(&packet));
    header.type = ICMP_ECHO_REQUEST;
    header.code = 0;
    header.checksum = 0;
    header.id = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())) & 0xFFFF);
    header.sequence = 1;

    // Fill payload
    for (packet[@sizeOf(IcmpHeader)..]) |*b| {
        b.* = 0xAB;
    }

    header.checksum = calculateChecksum(&packet);

    const start = std.time.microTimestamp();

    _ = posix.sendto(sock, &packet, 0, @ptrCast(&dest_addr), @sizeOf(posix.sockaddr.in)) catch {
        return null;
    };

    var recv_buf: [1024]u8 = undefined;
    _ = posix.recvfrom(sock, &recv_buf, 0, null, null) catch {
        return null;
    };

    const end = std.time.microTimestamp();
    return @intCast(end - start);
}

fn pingHostRaw(ip: [4]u8, timeout_ms: u32) ?u64 {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.RAW, posix.IPPROTO.ICMP) catch {
        return null;
    };
    defer posix.close(sock);

    const timeout = posix.timeval{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    const dest_addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.bytesToValue(u32, &ip),
    };

    var packet: [64]u8 = undefined;
    const header: *IcmpHeader = @ptrCast(@alignCast(&packet));
    header.type = ICMP_ECHO_REQUEST;
    header.code = 0;
    header.checksum = 0;
    header.id = @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())) & 0xFFFF);
    header.sequence = 1;

    for (packet[@sizeOf(IcmpHeader)..]) |*b| {
        b.* = 0xAB;
    }

    header.checksum = calculateChecksum(&packet);

    const start = std.time.microTimestamp();

    _ = posix.sendto(sock, &packet, 0, @ptrCast(&dest_addr), @sizeOf(posix.sockaddr.in)) catch {
        return null;
    };

    var recv_buf: [1024]u8 = undefined;
    const recv_len = posix.recvfrom(sock, &recv_buf, 0, null, null) catch {
        return null;
    };

    if (recv_len < 20 + @sizeOf(IcmpHeader)) return null;

    // Skip IP header (usually 20 bytes) and check ICMP reply
    const icmp_reply: *const IcmpHeader = @ptrCast(@alignCast(&recv_buf[20]));
    if (icmp_reply.type != ICMP_ECHO_REPLY) return null;

    const end = std.time.microTimestamp();
    return @intCast(end - start);
}

fn pingMultiple(ip: [4]u8, count: u8, timeout_ms: u32) ?u64 {
    var min_latency: ?u64 = null;

    for (0..count) |_| {
        if (pingHost(ip, timeout_ms)) |latency| {
            if (min_latency == null or latency < min_latency.?) {
                min_latency = latency;
            }
        }
        std.Thread.sleep(50 * std.time.ns_per_ms);
    }

    return min_latency;
}

fn ipToU32(ip: [4]u8) u32 {
    return @as(u32, ip[0]) << 24 | @as(u32, ip[1]) << 16 | @as(u32, ip[2]) << 8 | @as(u32, ip[3]);
}

fn u32ToIp(val: u32) [4]u8 {
    return .{
        @truncate(val >> 24),
        @truncate(val >> 16),
        @truncate(val >> 8),
        @truncate(val),
    };
}

// Shared state between sender and receiver threads
const ScanState = struct {
    // Atomic counters
    sent_count: std.atomic.Value(usize),
    sender_done: std.atomic.Value(bool),

    // Thread-safe discovered hosts (protected by mutex)
    mutex: std.Thread.Mutex,
    discovered: std.AutoHashMap(u32, u64), // IP -> latency

    // Shared socket
    sock: posix.fd_t,

    // Config
    all_ips: []const [4]u8,
    config: Config,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, all_ips: []const [4]u8, config: Config, sock: posix.fd_t) ScanState {
        return ScanState{
            .sent_count = std.atomic.Value(usize).init(0),
            .sender_done = std.atomic.Value(bool).init(false),
            .mutex = std.Thread.Mutex{},
            .discovered = std.AutoHashMap(u32, u64).init(allocator),
            .sock = sock,
            .all_ips = all_ips,
            .config = config,
            .allocator = allocator,
        };
    }

    fn deinit(self: *ScanState) void {
        self.discovered.deinit();
    }
};

// Sender thread for Phase 2 latency measurement - sends pings in rounds
// Also receives responses inline to minimize latency measurement error
fn latencySenderThread(state: *LatencyState) void {
    var recv_buf: [1024]u8 = undefined;

    for (0..state.config.latency_pings) |round| {
        for (state.hosts, 0..) |ip, host_idx| {
            const dest_addr = posix.sockaddr.in{
                .family = posix.AF.INET,
                .port = 0,
                .addr = std.mem.bytesToValue(u32, &ip),
            };

            var packet: [64]u8 = undefined;
            const header: *IcmpHeader = @ptrCast(@alignCast(&packet));
            header.type = ICMP_ECHO_REQUEST;
            header.code = 0;
            header.checksum = 0;
            // Encode host_idx and round in packet for identification
            // id = host_idx, sequence = round (simpler than IP-based encoding)
            header.id = @truncate(host_idx);
            header.sequence = @intCast(round);

            for (packet[@sizeOf(IcmpHeader)..]) |*b| {
                b.* = 0xAB;
            }
            header.checksum = calculateChecksum(&packet);

            // Record send time immediately before sending for accurate measurement
            const send_time = std.time.microTimestamp();

            // Use C sendto directly to avoid Zig's panic on unknown errno
            const rc = c.sendto(
                state.sock,
                &packet,
                packet.len,
                0,
                @ptrCast(&dest_addr),
                @sizeOf(posix.sockaddr.in),
            );
            _ = rc;

            // Store send time atomically - NO MUTEX NEEDED
            const idx = state.sendTimeIndex(host_idx, @intCast(round));
            state.send_times[idx].store(send_time, .release);

            _ = state.rounds_sent.fetchAdd(1, .seq_cst);

            // Immediately try to receive any pending responses (critical for accurate timing)
            // This catches fast responses before they queue up
            while (true) {
                var src_addr_c: posix.sockaddr.in = undefined;
                var addr_len_c: c.socklen_t = @sizeOf(posix.sockaddr.in);
                const recv_rc = c.recvfrom(
                    state.sock,
                    &recv_buf,
                    recv_buf.len,
                    c.MSG.DONTWAIT,
                    @ptrCast(&src_addr_c),
                    &addr_len_c,
                );

                if (recv_rc < 0) break; // No more packets

                const recv_len: usize = @intCast(recv_rc);
                const recv_time = std.time.microTimestamp();

                // Parse ICMP reply - skip IP header for raw socket
                var icmp_offset: usize = 0;
                if (recv_len >= 20 and (recv_buf[0] >> 4) == 4) {
                    icmp_offset = (@as(usize, recv_buf[0] & 0x0F)) * 4;
                }
                if (recv_len < icmp_offset + @sizeOf(IcmpHeader)) continue;

                const icmp_reply: *const IcmpHeader = @ptrCast(@alignCast(&recv_buf[icmp_offset]));
                if (icmp_reply.type != ICMP_ECHO_REPLY) continue;

                // Extract host_idx and round from ICMP header
                const reply_host_idx: usize = icmp_reply.id;
                const reply_round: u8 = @truncate(icmp_reply.sequence);

                // Validate
                if (reply_host_idx >= state.hosts.len) continue;
                if (reply_round >= state.config.latency_pings) continue;

                // Load send time and calculate latency
                const reply_idx = state.sendTimeIndex(reply_host_idx, reply_round);
                const reply_send_time = state.send_times[reply_idx].load(.acquire);
                if (reply_send_time == 0) continue;

                const latency: u64 = @intCast(@max(0, recv_time - reply_send_time));
                state.latencies[reply_host_idx].add(latency);
            }
        }

        // Delay between rounds - 100ms gives time for slow hosts to respond
        // and prevents flooding the network
        if (round + 1 < state.config.latency_pings) {
            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    }

    state.sender_done.store(true, .seq_cst);
}

// Sender thread function - uses shared socket
fn senderThread(state: *ScanState) void {
    for (state.all_ips) |ip| {
        const dest_addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = 0,
            .addr = std.mem.bytesToValue(u32, &ip),
        };

        var packet: [64]u8 = undefined;
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
        header.checksum = calculateChecksum(&packet);

        // Use C sendto directly to avoid Zig's panic on unknown errno (like macOS EHOSTDOWN=64)
        const rc = c.sendto(
            state.sock,
            &packet,
            packet.len,
            0,
            @ptrCast(&dest_addr),
            @sizeOf(posix.sockaddr.in),
        );
        // Ignore errors - host may be down, unreachable, etc.
        _ = rc;

        _ = state.sent_count.fetchAdd(1, .seq_cst);
    }

    state.sender_done.store(true, .seq_cst);
}

// Two-phase scanner using threads
const Scanner = struct {
    sock: posix.fd_t,
    poller: SocketPoller,
    allocator: std.mem.Allocator,
    all_ips: []const [4]u8,
    config: Config,
    is_raw_socket: bool,

    pub fn init(allocator: std.mem.Allocator, all_ips: []const [4]u8, config: Config) !Scanner {
        // Use RAW ICMP socket - requires sudo on macOS
        // (DGRAM ICMP can send but cannot receive replies on macOS)
        // Use C socket directly to handle macOS EPERM properly
        const sock_fd = c.socket(posix.AF.INET, c.SOCK.RAW, posix.IPPROTO.ICMP);
        if (sock_fd < 0) {
            const err = std.c._errno().*;
            if (err == 1) { // EPERM on macOS
                std.debug.print("\nError: Raw ICMP socket requires root privileges.\n", .{});
                std.debug.print("Please run with: sudo ./zig-out/bin/latency-heatmap ...\n\n", .{});
            } else {
                std.debug.print("\nSocket creation failed with errno: {}\n", .{err});
            }
            return error.SocketCreationFailed;
        }
        const sock: posix.fd_t = @intCast(sock_fd);

        // Set socket to non-blocking for receives
        const flags = try posix.fcntl(sock, posix.F.GETFL, 0);
        _ = try posix.fcntl(sock, posix.F.SETFL, flags | @as(usize, posix.SOCK.NONBLOCK));

        // Create event poller for efficient socket waiting
        const poller = try SocketPoller.init(sock);

        return Scanner{
            .sock = sock,
            .poller = poller,
            .allocator = allocator,
            .all_ips = all_ips,
            .config = config,
            .is_raw_socket = true,
        };
    }

    pub fn deinit(self: *Scanner) void {
        self.poller.deinit();
        posix.close(self.sock);
    }

    // Phase 1: Discovery - sender thread + receiver in main thread
    pub fn discover(self: *Scanner, stdout: StdoutWriter) !std.ArrayList([4]u8) {
        var state = ScanState.init(self.allocator, self.all_ips, self.config, self.sock);
        defer state.deinit();

        stdout.print("  Phase 1: Discovery - scanning {d} hosts...\n", .{self.all_ips.len}) catch {};

        // Start sender thread (creates its own socket)
        const sender = try std.Thread.spawn(.{}, senderThread, .{&state});

        // Give sender a moment to start
        std.Thread.sleep(10 * std.time.ns_per_ms);

        // Main thread receives replies
        var recv_buf: [1024]u8 = undefined;
        var src_addr: posix.sockaddr.in = undefined;

        const start_time = std.time.microTimestamp();
        var last_print: i64 = 0;

        // Track when sender finishes for timeout calculation
        var sender_finish_time: ?i64 = null;
        var no_discovery_streak: usize = 0; // Count consecutive checks with 0 discovered

        // Receive loop - runs until sender is done + timeout
        while (true) {
            // Drain all available packets first
            while (true) {
                var src_addr_c: posix.sockaddr.in = undefined;
                var addr_len_c: c.socklen_t = @sizeOf(posix.sockaddr.in);
                const recv_rc = c.recvfrom(
                    self.sock,
                    &recv_buf,
                    recv_buf.len,
                    c.MSG.DONTWAIT,
                    @ptrCast(&src_addr_c),
                    &addr_len_c,
                );

                if (recv_rc < 0) {
                    // No more packets available
                    break;
                }

                const recv_len: usize = @intCast(recv_rc);
                src_addr = src_addr_c;

                // Reset streak when we receive something
                no_discovery_streak = 0;

                const recv_time = std.time.microTimestamp();

                // Parse ICMP reply - DGRAM sockets don't have IP header, RAW sockets do
                var icmp_offset: usize = 0;
                if (self.is_raw_socket and recv_len >= 20 and (recv_buf[0] >> 4) == 4) {
                    icmp_offset = (@as(usize, recv_buf[0] & 0x0F)) * 4;
                }
                if (recv_len < icmp_offset + @sizeOf(IcmpHeader)) continue;

                const icmp_reply: *const IcmpHeader = @ptrCast(@alignCast(&recv_buf[icmp_offset]));
                if (icmp_reply.type != ICMP_ECHO_REPLY) continue;

                // Record this host as alive
                const src_ip_bytes: [4]u8 = @bitCast(src_addr.addr);
                const src_ip_key = ipToU32(src_ip_bytes);

                // Estimate latency (rough, since we don't track per-IP send time in discovery)
                const latency: u64 = @intCast(@max(0, recv_time - start_time));

                state.mutex.lock();
                const existing = state.discovered.get(src_ip_key);
                if (existing == null or latency < existing.?) {
                    state.discovered.put(src_ip_key, latency) catch {};
                }
                state.mutex.unlock();
            }

            // Now check exit conditions and update progress
            const now = std.time.microTimestamp();
            const sender_done = state.sender_done.load(.seq_cst);

            // Record when sender finishes
            if (sender_done and sender_finish_time == null) {
                sender_finish_time = now;
                // Print final send count
                stdout.print("\r  Sent: {d}/{d} - waiting for replies...                    \n", .{ state.sent_count.load(.seq_cst), self.all_ips.len }) catch {};
            }

            // Check exit conditions after sender finished
            if (sender_finish_time) |finish_time| {
                const time_since_finish_us = now - finish_time;
                const time_since_finish_ms = @divFloor(time_since_finish_us, 1000);

                state.mutex.lock();
                const discovered_count = state.discovered.count();
                state.mutex.unlock();

                // Exit early if no hosts discovered after 500ms
                if (discovered_count == 0 and time_since_finish_ms > 500) {
                    stdout.print("\r  No hosts found, exiting early.                              \n", .{}) catch {};
                    break;
                }

                // Normal timeout for when we have discovered hosts
                if (time_since_finish_ms > self.config.discovery_timeout_ms) {
                    break;
                }
            }

            // Update progress periodically
            if (now - last_print > 100_000) {
                last_print = now;
                const sent = state.sent_count.load(.seq_cst);
                state.mutex.lock();
                const discovered_count = state.discovered.count();
                state.mutex.unlock();

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

        state.mutex.lock();
        const final_count = state.discovered.count();
        state.mutex.unlock();
        stdout.print("\r  Discovered: {d} hosts                                      \n", .{final_count}) catch {};

        // Convert to array
        var alive_hosts = std.ArrayList([4]u8){};
        state.mutex.lock();
        var iter = state.discovered.iterator();
        while (iter.next()) |entry| {
            try alive_hosts.append(self.allocator, u32ToIp(entry.key_ptr.*));
        }
        state.mutex.unlock();

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
                .hostname = null,
            };
        }

        // Allocate arrays to track per-host latencies
        const latencies = try self.allocator.alloc(LatencyState.LatencyData, hosts.len);
        defer self.allocator.free(latencies);
        for (latencies) |*lat| lat.* = LatencyState.LatencyData.init();

        // Allocate send times for ALL pings (hosts * rounds)
        const total_pings = hosts.len * num_rounds;
        const send_times = try self.allocator.alloc(i64, total_pings);
        defer self.allocator.free(send_times);
        @memset(send_times, 0);

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
        const adaptive_timeout_us: i64 = 100_000; // 100ms of silence = done
        const max_timeout_us: i64 = @as(i64, self.config.latency_timeout_ms) * 1000;

        var responses_received: usize = 0;
        var next_send_host: usize = 0;
        var next_send_round: usize = 0;
        var last_send_time: i64 = 0;
        var last_response_time: i64 = 0;
        var all_sent = false;
        const phase_start = std.time.microTimestamp();

        var recv_buf: [1024]u8 = undefined;
        var packet: [64]u8 = undefined;

        // Initialize packet template
        const header: *IcmpHeader = @ptrCast(@alignCast(&packet));
        header.type = ICMP_ECHO_REQUEST;
        header.code = 0;
        for (packet[@sizeOf(IcmpHeader)..]) |*b| b.* = 0xAB;

        // Event loop: interleave sending and receiving
        while (true) {
            const now = std.time.microTimestamp();

            // Check exit conditions
            if (all_sent) {
                // Adaptive exit: no responses for a while
                if (last_response_time > 0 and (now - last_response_time) > adaptive_timeout_us) break;
                // Hard timeout
                if ((now - phase_start) > max_timeout_us) break;
                // All responses received
                if (responses_received >= total_pings) break;
            }

            // Send next ping if it's time
            if (!all_sent and (now - last_send_time) >= inter_ping_delay_us) send: {
                // Check if we need to wait between rounds
                if (next_send_host == 0 and next_send_round > 0) {
                    // Starting a new round - add delay
                    if ((now - last_send_time) < round_delay_us) {
                        // Not ready for next round yet, just process receives
                        break :send;
                    }
                }

                const host_idx = next_send_host;
                const round = next_send_round;
                const ping_idx = host_idx * num_rounds + round;

                // Build and send packet
                header.id = @truncate(host_idx);
                header.sequence = @intCast(round);
                header.checksum = 0;
                header.checksum = calculateChecksum(&packet);

                // Record send time IMMEDIATELY before send
                const send_time = std.time.microTimestamp();
                send_times[ping_idx] = send_time;

                _ = c.sendto(
                    self.sock,
                    &packet,
                    packet.len,
                    0,
                    @ptrCast(&dest_addrs[host_idx]),
                    @sizeOf(posix.sockaddr.in),
                );

                last_send_time = send_time;

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
                    // Get timestamp BEFORE reading to minimize latency measurement error
                    const recv_time = std.time.microTimestamp();

                    var src_addr_c: posix.sockaddr.in = undefined;
                    var addr_len_c: c.socklen_t = @sizeOf(posix.sockaddr.in);
                    const recv_rc = c.recvfrom(
                        self.sock,
                        &recv_buf,
                        recv_buf.len,
                        c.MSG.DONTWAIT,
                        @ptrCast(&src_addr_c),
                        &addr_len_c,
                    );

                    if (recv_rc < 0) break; // No more packets

                    const recv_len: usize = @intCast(recv_rc);

                    // Parse ICMP reply - skip IP header for raw socket
                    var icmp_offset: usize = 0;
                    if (self.is_raw_socket and recv_len >= 20 and (recv_buf[0] >> 4) == 4) {
                        icmp_offset = (@as(usize, recv_buf[0] & 0x0F)) * 4;
                    }
                    if (recv_len < icmp_offset + @sizeOf(IcmpHeader)) continue;

                    const icmp_reply: *const IcmpHeader = @ptrCast(@alignCast(&recv_buf[icmp_offset]));
                    if (icmp_reply.type != ICMP_ECHO_REPLY) continue;

                    const host_idx: usize = icmp_reply.id;
                    const reply_round: usize = icmp_reply.sequence;
                    if (host_idx >= hosts.len or reply_round >= num_rounds) continue;

                    const ping_idx = host_idx * num_rounds + reply_round;
                    if (ping_idx >= total_pings or received[ping_idx]) continue;

                    const send_time = send_times[ping_idx];
                    if (send_time == 0) continue; // Not sent yet (shouldn't happen)

                    const latency: u64 = @intCast(@max(0, recv_time - send_time));
                    latencies[host_idx].add(latency);
                    received[ping_idx] = true;
                    responses_received += 1;
                    last_response_time = recv_time;
                }

                printProgress(stdout, responses_received, total_pings);
            } else if (all_sent) {
                // No data available and all sent - wait with short timeout
                _ = self.poller.wait(10);
            }
            // If not all sent and no data, loop immediately to send next ping
        }

        stdout.print("\n", .{}) catch {};

        // Copy results
        for (0..hosts.len) |i| {
            results[i].latency_us = latencies[i].getMin();
            results[i].latency_avg = latencies[i].getAvg();
            results[i].latency_max = latencies[i].getMax();
        }
    }
};

fn ipToString(ip: [4]u8, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "";
}

fn latencyToColor(latency_us: ?u64) []const u8 {
    if (latency_us == null) return "\x1b[90m"; // Gray - offline

    const lat = latency_us.?;
    if (lat < 1000) return "\x1b[92m"; // Bright green - excellent (<1ms)
    if (lat < 5000) return "\x1b[32m"; // Green - good (<5ms)
    if (lat < 20000) return "\x1b[93m"; // Yellow - okay (<20ms)
    if (lat < 100000) return "\x1b[33m"; // Orange - slow (<100ms)
    return "\x1b[91m"; // Red - very slow
}

fn latencyToBlock(latency_us: ?u64) []const u8 {
    if (latency_us == null) return "·";

    const lat = latency_us.?;
    if (lat < 1000) return "█";
    if (lat < 5000) return "▓";
    if (lat < 20000) return "▒";
    if (lat < 100000) return "░";
    return "▪";
}

fn formatLatency(latency_us: ?u64, buf: []u8) []const u8 {
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

fn generateIpRange(allocator: std.mem.Allocator, subnet: [4]u8, mask_bits: u8) ![]const [4]u8 {
    const host_bits: u5 = @intCast(32 - mask_bits);
    const num_hosts: u32 = (@as(u32, 1) << host_bits) - 2; // Exclude network and broadcast

    const ips = try allocator.alloc([4]u8, num_hosts);

    const base: u32 = @as(u32, subnet[0]) << 24 |
        @as(u32, subnet[1]) << 16 |
        @as(u32, subnet[2]) << 8 |
        @as(u32, subnet[3]);

    for (0..num_hosts) |i| {
        const ip_num = base + @as(u32, @intCast(i)) + 1;
        ips[i] = .{
            @truncate(ip_num >> 24),
            @truncate(ip_num >> 16),
            @truncate(ip_num >> 8),
            @truncate(ip_num),
        };
    }

    return ips;
}

fn displayWidth(s: []const u8) usize {
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

fn printHeatmapGrid(stdout: StdoutWriter, results: []const PingResult, width: usize) void {
    const reset = "\x1b[0m";
    const col_width = 28; // Fixed column width for alignment

    stdout.print("\n", .{}) catch {};

    var row_start: usize = 0;
    while (row_start < results.len) {
        const row_end = @min(row_start + width, results.len);

        // Print IP labels for this row (left-padded to col_width)
        for (results[row_start..row_end]) |r| {
            var buf: [16]u8 = undefined;
            const ip_str = ipToString(r.ip, &buf);
            stdout.print("{s}", .{ip_str}) catch {};
            for (0..(col_width - ip_str.len)) |_| {
                stdout.print(" ", .{}) catch {};
            }
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
            if (used < col_width) {
                for (0..(col_width - used)) |_| {
                    stdout.print(" ", .{}) catch {};
                }
            } else {
                stdout.print(" ", .{}) catch {}; // At least one space between columns
            }
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

    stdout.print("\n\x1b[1m══════════════════════════════════════════════════════════════\x1b[0m\n", .{}) catch {};
    stdout.print("\x1b[1m                     NETWORK SUMMARY\x1b[0m\n", .{}) catch {};
    stdout.print("\x1b[1m══════════════════════════════════════════════════════════════\x1b[0m\n\n", .{}) catch {};

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
        stdout.print("\n  \x1b[93m⚠ Slow devices (avg >20ms):\x1b[0m\n", .{}) catch {};
        for (slow_devices[0..slow_count]) |r| {
            var ip_buf: [16]u8 = undefined;
            var lat_buf: [16]u8 = undefined;
            stdout.print("    {s}: {s} avg\n", .{
                ipToString(r.ip, &ip_buf),
                formatLatency(r.latency_avg, &lat_buf),
            }) catch {};
        }
    }

    stdout.print("\n\x1b[1m══════════════════════════════════════════════════════════════\x1b[0m\n", .{}) catch {};
}

fn printLegend(stdout: StdoutWriter) void {
    stdout.print("\n\x1b[1mLegend:\x1b[0m ", .{}) catch {};
    stdout.print("\x1b[92m█ <1ms\x1b[0m  ", .{}) catch {};
    stdout.print("\x1b[32m▓ <5ms\x1b[0m  ", .{}) catch {};
    stdout.print("\x1b[93m▒ <20ms\x1b[0m  ", .{}) catch {};
    stdout.print("\x1b[33m░ <100ms\x1b[0m  ", .{}) catch {};
    stdout.print("\x1b[91m▪ >100ms\x1b[0m  ", .{}) catch {};
    stdout.print("\x1b[90m· offline\x1b[0m\n", .{}) catch {};
}

fn printProgress(stdout: StdoutWriter, done: usize, total: usize) void {
    const percent = @as(f64, @floatFromInt(done)) / @as(f64, @floatFromInt(total)) * 100.0;
    const bar_width: usize = 40;
    const filled = @as(usize, @intFromFloat(@as(f64, @floatFromInt(bar_width)) * percent / 100.0));

    stdout.print("\r  Measuring: [", .{}) catch {};
    for (0..bar_width) |i| {
        if (i < filled) {
            stdout.print("█", .{}) catch {};
        } else {
            stdout.print("░", .{}) catch {};
        }
    }
    stdout.print("] {d:.1}% ({d}/{d})", .{ percent, done, total }) catch {};
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

    return .{ .subnet = ip, .mask = mask };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get unbuffered stdout writer for immediate output (pass empty slice for unbuffered)
    var stdout_writer = std.fs.File.stdout().writer(&.{});
    const stdout = &stdout_writer.interface;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Detect local subnet, fall back to 192.168.1.0/24
    var config = if (detectLocalSubnet()) |detected|
        Config{ .subnet = detected.subnet, .mask_bits = detected.mask }
    else
        Config{};

    // Parse command line args
    if (args.len > 1) {
        if (std.mem.eql(u8, args[1], "-h") or std.mem.eql(u8, args[1], "--help")) {
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
                \\  -p <count>  Number of pings per host for latency (default: 5)
                \\  -t <ms>     Timeout per ping in latency phase (default: 1000)
                \\  -h, --help  Show this help
                \\
                \\The subnet is auto-detected from your network interface if not specified.
                \\
                \\How it works:
                \\  Phase 1: Blasts pings to all IPs, waits for discovery timeout
                \\  Phase 2: Measures latency only on hosts that responded
                \\
                \\Note: Requires root/sudo for raw ICMP sockets on most systems.
                \\
            , .{ args[0], args[0], args[0], args[0] }) catch {};
            return;
        }

        if (parseSubnet(args[1])) |parsed| {
            config.subnet = parsed.subnet;
            config.mask_bits = parsed.mask;
        }

        var i: usize = 2;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "-d") and i + 1 < args.len) {
                config.discovery_timeout_ms = std.fmt.parseInt(u32, args[i + 1], 10) catch 5000;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "-p") and i + 1 < args.len) {
                config.latency_pings = std.fmt.parseInt(u8, args[i + 1], 10) catch 3;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "-t") and i + 1 < args.len) {
                config.latency_timeout_ms = std.fmt.parseInt(u32, args[i + 1], 10) catch 1000;
                i += 1;
            }
        }
    }

    // Print banner
    stdout.print("\n", .{}) catch {};
    stdout.print("\x1b[96m╔══════════════════════════════════════════════════════════════╗\x1b[0m\n", .{}) catch {};
    stdout.print("\x1b[96m║\x1b[0m             \x1b[1mNetwork Latency Heatmap Scanner\x1b[0m                  \x1b[96m║\x1b[0m\n", .{}) catch {};
    stdout.print("\x1b[96m╚══════════════════════════════════════════════════════════════╝\x1b[0m\n", .{}) catch {};

    var subnet_buf: [32]u8 = undefined;
    const subnet_str = std.fmt.bufPrint(&subnet_buf, "{}.{}.{}.{}/{}", .{
        config.subnet[0],
        config.subnet[1],
        config.subnet[2],
        config.subnet[3],
        config.mask_bits,
    }) catch "???";

    stdout.print("\n  Subnet: {s}\n", .{subnet_str}) catch {};
    stdout.print("  Discovery timeout: {d}ms | Latency pings: {d} | Ping timeout: {d}ms\n", .{
        config.discovery_timeout_ms,
        config.latency_pings,
        config.latency_timeout_ms,
    }) catch {};

    const all_ips = try generateIpRange(allocator, config.subnet, config.mask_bits);
    defer allocator.free(all_ips);

    stdout.print("  Total IPs to scan: {d}\n\n", .{all_ips.len}) catch {};

    // Two-phase scanner
    var scanner = Scanner.init(allocator, all_ips, config) catch |err| {
        if (err == error.SocketCreationFailed) {
            return; // Error already printed
        }
        return err;
    };
    defer scanner.deinit();

    // Phase 1: Discovery
    var alive_hosts = try scanner.discover(stdout);
    defer alive_hosts.deinit(allocator);

    if (alive_hosts.items.len == 0) {
        stdout.print("\n\x1b[93mNo devices responded. Are you on the right subnet?\x1b[0m\n", .{}) catch {};
        stdout.print("Try running with sudo if you haven't already.\n", .{}) catch {};
        return;
    }

    // Sort discovered hosts by IP
    std.mem.sort([4]u8, alive_hosts.items, {}, struct {
        fn lessThan(_: void, a: [4]u8, b: [4]u8) bool {
            const a_num: u32 = @as(u32, a[0]) << 24 | @as(u32, a[1]) << 16 | @as(u32, a[2]) << 8 | @as(u32, a[3]);
            const b_num: u32 = @as(u32, b[0]) << 24 | @as(u32, b[1]) << 16 | @as(u32, b[2]) << 8 | @as(u32, b[3]);
            return a_num < b_num;
        }
    }.lessThan);

    // Phase 2: Latency measurement
    const results = try allocator.alloc(PingResult, alive_hosts.items.len);
    defer allocator.free(results);

    stdout.print("\n", .{}) catch {};
    try scanner.measureLatency(alive_hosts.items, results, stdout);

    printLegend(stdout);

    stdout.print("\n\x1b[1mActive Devices:\x1b[0m\n", .{}) catch {};
    printHeatmapGrid(stdout, results, 4);

    printSummary(stdout, results);
}
