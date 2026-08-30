// Platform layer: the small slice of socket, clock, and console APIs this
// tool needs, normalized across POSIX (libc) and Windows (Winsock2 +
// kernel32 + iphlpapi). Call sites keep BSD-socket shapes; Windows quirks
// (SOCKET handles, WSAGetLastError, ioctlsocket, WSAPoll, the required
// WSAStartup) live here.
//
// Every function branches on the comptime-known is_windows with a full
// if/else, never an early return: only an untaken *branch* is exempt from
// analysis, and each side references declarations that don't exist on the
// other platform.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const c = std.c;

pub const is_windows = builtin.os.tag == .windows;

// Windows API declarations. Zig links the named DLLs automatically when a
// declaration is referenced; nothing here is analyzed on other targets.
pub const win = struct {
    pub const SOCKET = usize; // UINT_PTR
    pub const INVALID_SOCKET: SOCKET = ~@as(SOCKET, 0);

    // Winsock error codes (WSAGetLastError)
    pub const WSAEINTR: i32 = 10004;
    pub const WSAEACCES: i32 = 10013;
    pub const WSAEWOULDBLOCK: i32 = 10035;
    pub const WSAECONNRESET: i32 = 10054;
    pub const WSAENOBUFS: i32 = 10055;
    pub const WSAECONNREFUSED: i32 = 10061;

    pub const FIONBIO: i32 = @bitCast(@as(u32, 0x8004667E));
    pub const SIO_UDP_CONNRESET: u32 = 0x9800000C;

    pub const POLLRDNORM: i16 = 0x0100;
    pub const POLLRDBAND: i16 = 0x0200;
    pub const POLLWRNORM: i16 = 0x0010;

    pub const WSAPOLLFD = extern struct {
        fd: SOCKET,
        events: i16,
        revents: i16,
    };

    pub extern "ws2_32" fn WSAStartup(wVersionRequested: u16, lpWSAData: *anyopaque) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAGetLastError() callconv(.winapi) c_int;
    pub extern "ws2_32" fn socket(af: c_int, sock_type: c_int, protocol: c_int) callconv(.winapi) SOCKET;
    pub extern "ws2_32" fn closesocket(s: SOCKET) callconv(.winapi) c_int;
    pub extern "ws2_32" fn bind(s: SOCKET, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn listen(s: SOCKET, backlog: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn accept(s: SOCKET, addr: ?*anyopaque, addrlen: ?*c_int) callconv(.winapi) SOCKET;
    pub extern "ws2_32" fn connect(s: SOCKET, name: *const anyopaque, namelen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getsockname(s: SOCKET, name: *anyopaque, namelen: *c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn getsockopt(s: SOCKET, level: c_int, optname: c_int, optval: [*]u8, optlen: *c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn setsockopt(s: SOCKET, level: c_int, optname: c_int, optval: ?*const anyopaque, optlen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn sendto(s: SOCKET, buf: [*]const u8, len: c_int, flags: c_int, to: *const anyopaque, tolen: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn recvfrom(s: SOCKET, buf: [*]u8, len: c_int, flags: c_int, from: ?*anyopaque, fromlen: ?*c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn ioctlsocket(s: SOCKET, cmd: c_long, argp: *c_ulong) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAPoll(fdArray: [*]WSAPOLLFD, fds: c_ulong, timeout: c_int) callconv(.winapi) c_int;
    pub extern "ws2_32" fn WSAIoctl(s: SOCKET, dwIoControlCode: u32, lpvInBuffer: ?*const anyopaque, cbInBuffer: u32, lpvOutBuffer: ?*anyopaque, cbOutBuffer: u32, lpcbBytesReturned: *u32, lpOverlapped: ?*anyopaque, lpCompletionRoutine: ?*anyopaque) callconv(.winapi) c_int;
    pub extern "ws2_32" fn gethostname(name: [*]u8, namelen: c_int) callconv(.winapi) c_int;

    pub const FILETIME = extern struct {
        low: u32,
        high: u32,
    };

    pub const STD_OUTPUT_HANDLE: u32 = @bitCast(@as(i32, -11));
    pub const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    pub const CP_UTF8: u32 = 65001;

    pub extern "kernel32" fn QueryPerformanceCounter(lpPerformanceCount: *i64) callconv(.winapi) c_int;
    pub extern "kernel32" fn QueryPerformanceFrequency(lpFrequency: *i64) callconv(.winapi) c_int;
    pub extern "kernel32" fn GetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime: *FILETIME) callconv(.winapi) void;
    pub extern "kernel32" fn Sleep(dwMilliseconds: u32) callconv(.winapi) void;
    pub extern "kernel32" fn GetStdHandle(nStdHandle: u32) callconv(.winapi) ?*anyopaque;
    pub extern "kernel32" fn GetConsoleMode(hConsoleHandle: ?*anyopaque, lpMode: *u32) callconv(.winapi) c_int;
    pub extern "kernel32" fn SetConsoleMode(hConsoleHandle: ?*anyopaque, dwMode: u32) callconv(.winapi) c_int;
    pub extern "kernel32" fn SetConsoleOutputCP(wCodePageID: u32) callconv(.winapi) c_int;
    pub extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;

    // MIB_IPADDRROW from iphlpapi's GetIpAddrTable: one IPv4 address with
    // its netmask per row. Much simpler than GetAdaptersAddresses and
    // carries everything subnet detection needs.
    pub const MIB_IPADDRROW = extern struct {
        addr: u32, // network byte order
        index: u32,
        mask: u32, // network byte order
        bcast_addr: u32,
        reasm_size: u32,
        unused1: u16,
        wtype: u16,
    };

    pub const MIB_IPADDR_DISCONNECTED: u16 = 0x0008;
    pub const MIB_IPADDR_DELETED: u16 = 0x0040;

    pub extern "iphlpapi" fn GetIpAddrTable(pIpAddrTable: ?*anyopaque, pdwSize: *u32, bOrder: c_int) callconv(.winapi) u32;
};

pub const Socket = if (is_windows) win.SOCKET else posix.fd_t;
pub const invalid_socket: Socket = if (is_windows) win.INVALID_SOCKET else -1;

pub fn isValidSocket(s: Socket) bool {
    if (is_windows) {
        return s != win.INVALID_SOCKET;
    } else {
        return s >= 0;
    }
}

// Socket type / protocol values, identical on every supported platform
pub const AF_INET: i32 = 2;
pub const SOCK_STREAM: i32 = 1;
pub const SOCK_DGRAM: i32 = 2;
pub const SOCK_RAW: i32 = 3;
pub const IPPROTO_ICMP: i32 = 1;

// Winsock must be initialized once per process before any socket call.
// openSocket does this lazily so tests and helpers need no explicit setup.
// The flag is atomic, but for a guaranteed-complete init call netInit()
// from the main thread before spawning others (main() does).
var wsa_started = std.atomic.Value(bool).init(false);

pub fn netInit() void {
    if (is_windows) {
        if (wsa_started.swap(true, .seq_cst)) return;
        // WSADATA's layout differs between 32/64-bit; an oversized aligned
        // buffer sidesteps declaring it
        var wsadata: [512]u8 align(8) = undefined;
        _ = win.WSAStartup(0x0202, &wsadata);
    }
}

pub fn openSocket(family: i32, sock_type: i32, protocol: i32) Socket {
    if (is_windows) {
        netInit();
        return win.socket(family, sock_type, protocol);
    } else {
        const fd = c.socket(@intCast(family), @intCast(sock_type), @intCast(protocol));
        if (fd < 0) return invalid_socket;
        return @intCast(fd);
    }
}

pub fn closeSocket(s: Socket) void {
    if (is_windows) {
        _ = win.closesocket(s);
    } else {
        _ = c.close(s);
    }
}

// Last error from a socket call: errno on POSIX, WSAGetLastError on Windows
pub fn lastError() i32 {
    if (is_windows) {
        return win.WSAGetLastError();
    } else {
        return std.c._errno().*;
    }
}

pub fn errWouldBlock(e: i32) bool {
    if (is_windows) {
        return e == win.WSAEWOULDBLOCK;
    } else {
        return e == @intFromEnum(posix.E.AGAIN);
    }
}

// Non-blocking connect in flight: EINPROGRESS on POSIX, WSAEWOULDBLOCK on
// Windows (Winsock never reports EINPROGRESS for this)
pub fn errConnectInProgress(e: i32) bool {
    if (is_windows) {
        return e == win.WSAEWOULDBLOCK;
    } else {
        return e == @intFromEnum(posix.E.INPROGRESS);
    }
}

pub fn errConnRefusedOrReset(e: i32) bool {
    if (is_windows) {
        return e == win.WSAECONNREFUSED or e == win.WSAECONNRESET;
    } else {
        return e == @intFromEnum(posix.E.CONNREFUSED) or e == @intFromEnum(posix.E.CONNRESET);
    }
}

pub fn errInterrupted(e: i32) bool {
    if (is_windows) {
        return e == win.WSAEINTR;
    } else {
        return e == @intFromEnum(posix.E.INTR);
    }
}

pub fn errNoBufs(e: i32) bool {
    if (is_windows) {
        return e == win.WSAENOBUFS;
    } else {
        return e == @intFromEnum(posix.E.NOBUFS);
    }
}

// Raw sockets denied: EPERM/EACCES on POSIX, WSAEACCES on Windows
pub fn errPermission(e: i32) bool {
    if (is_windows) {
        return e == win.WSAEACCES;
    } else {
        return e == @intFromEnum(posix.E.PERM) or e == @intFromEnum(posix.E.ACCES);
    }
}

pub fn setNonblocking(s: Socket) bool {
    if (is_windows) {
        var mode: c_ulong = 1;
        return win.ioctlsocket(s, win.FIONBIO, &mode) == 0;
    } else {
        // O.NONBLOCK, not SOCK.NONBLOCK - the latter is a socket() creation
        // flag and is a different bit on some platforms, e.g. macOS
        const flags = c.fcntl(s, posix.F.GETFL, @as(c_int, 0));
        if (flags < 0) return false;
        const FlagsInt = std.meta.Int(.unsigned, @bitSizeOf(posix.O));
        const o_nonblock: FlagsInt = @bitCast(posix.O{ .NONBLOCK = true });
        return c.fcntl(s, posix.F.SETFL, flags | @as(c_int, o_nonblock)) >= 0;
    }
}

pub fn bind(s: Socket, addr: *const anyopaque, len: u32) i32 {
    if (is_windows) {
        return win.bind(s, addr, @intCast(len));
    } else {
        return c.bind(s, @ptrCast(@alignCast(addr)), len);
    }
}

pub fn listen(s: Socket, backlog: u31) i32 {
    if (is_windows) {
        return win.listen(s, backlog);
    } else {
        return c.listen(s, backlog);
    }
}

pub fn accept(s: Socket) Socket {
    if (is_windows) {
        return win.accept(s, null, null);
    } else {
        const fd = c.accept(s, null, null);
        if (fd < 0) return invalid_socket;
        return @intCast(fd);
    }
}

pub fn connect(s: Socket, addr: *const anyopaque, len: u32) i32 {
    if (is_windows) {
        return win.connect(s, addr, @intCast(len));
    } else {
        return c.connect(s, @ptrCast(@alignCast(addr)), len);
    }
}

pub fn getsockname(s: Socket, addr: *anyopaque, len: *u32) i32 {
    if (is_windows) {
        var wlen: c_int = @intCast(len.*);
        const rc = win.getsockname(s, addr, &wlen);
        if (rc == 0) len.* = @intCast(wlen);
        return rc;
    } else {
        return c.getsockname(s, @ptrCast(@alignCast(addr)), @ptrCast(@alignCast(len)));
    }
}

pub fn setsockopt(s: Socket, level: i32, optname: u32, optval: *const anyopaque, len: u32) i32 {
    if (is_windows) {
        return win.setsockopt(s, level, @intCast(optname), optval, @intCast(len));
    } else {
        return c.setsockopt(s, level, optname, optval, len);
    }
}

pub fn getsockopt(s: Socket, level: i32, optname: u32, optval: *anyopaque, len: *u32) i32 {
    if (is_windows) {
        var wlen: c_int = @intCast(len.*);
        const rc = win.getsockopt(s, level, @intCast(optname), @ptrCast(optval), &wlen);
        if (rc == 0) len.* = @intCast(wlen);
        return rc;
    } else {
        return c.getsockopt(s, level, optname, optval, @ptrCast(@alignCast(len)));
    }
}

pub fn sendto(s: Socket, buf: []const u8, addr: *const anyopaque, addr_len: u32) isize {
    if (is_windows) {
        return win.sendto(s, buf.ptr, @intCast(buf.len), 0, addr, @intCast(addr_len));
    } else {
        return c.sendto(s, buf.ptr, buf.len, 0, @ptrCast(@alignCast(addr)), addr_len);
    }
}

pub fn recvfrom(s: Socket, buf: []u8, addr: ?*anyopaque, addr_len: ?*u32) isize {
    if (is_windows) {
        var wlen: c_int = if (addr_len) |l| @intCast(l.*) else 0;
        const rc = win.recvfrom(s, buf.ptr, @intCast(buf.len), 0, addr, if (addr_len != null) &wlen else null);
        if (rc >= 0) {
            if (addr_len) |l| l.* = @intCast(wlen);
        }
        return rc;
    } else {
        return c.recvfrom(s, buf.ptr, buf.len, 0, @ptrCast(@alignCast(addr)), @ptrCast(@alignCast(addr_len)));
    }
}

// Poll: WSAPoll on Windows, poll(2) elsewhere. Event constants are
// normalized; WSAPoll rejects flag combinations it doesn't know, so the
// Windows values use the RDNORM/WRNORM forms it accepts.
pub const Pollfd = if (is_windows) win.WSAPOLLFD else posix.pollfd;
pub const POLL_IN: i16 = if (is_windows) win.POLLRDNORM | win.POLLRDBAND else posix.POLL.IN;
pub const POLL_OUT: i16 = if (is_windows) win.POLLWRNORM else posix.POLL.OUT;

pub fn poll(fds: []Pollfd, timeout_ms: i32) i32 {
    if (is_windows) {
        return win.WSAPoll(fds.ptr, @intCast(fds.len), timeout_ms);
    } else {
        return c.poll(fds.ptr, @intCast(fds.len), timeout_ms);
    }
}

// Wait for one event on one socket; true when it fired, false on timeout
// or error. POLLERR/POLLHUP also count as "fired" so callers go observe
// the socket state instead of sleeping through it.
pub fn pollOne(s: Socket, events: i16, timeout_ms: i32) bool {
    var fds = [_]Pollfd{.{ .fd = s, .events = events, .revents = 0 }};
    const n = poll(&fds, timeout_ms);
    return n > 0;
}

// Abortive close: SO_LINGER {on, 0s} makes close send an RST (with a zero
// window) instead of a graceful FIN exchange - no TIME_WAIT piles up on
// either side, and the accepting application (if any) sees an abort.
pub fn rstClose(s: Socket) void {
    if (is_windows) {
        const lo = std.os.windows.ws2_32.linger{ .onoff = 1, .linger = 0 };
        _ = win.setsockopt(s, @intCast(posix.SOL.SOCKET), posix.SO.LINGER, &lo, @sizeOf(@TypeOf(lo)));
        _ = win.closesocket(s);
    } else {
        const lo = c.linger{ .onoff = 1, .linger = 0 };
        _ = c.setsockopt(s, posix.SOL.SOCKET, posix.SO.LINGER, &lo, @sizeOf(c.linger));
        _ = c.close(s);
    }
}

// Windows delivers ICMP port-unreachable for a previous UDP send as a
// WSAECONNRESET error on a later recvfrom - poison for a broadcast socket
// whose peers come and go. SIO_UDP_CONNRESET(FALSE) turns that off.
pub fn disableUdpConnReset(s: Socket) void {
    if (is_windows) {
        var off: u32 = 0;
        var returned: u32 = 0;
        _ = win.WSAIoctl(s, win.SIO_UDP_CONNRESET, &off, @sizeOf(u32), null, 0, &returned, null, null);
    }
}

pub fn getpid() u32 {
    if (is_windows) {
        return win.GetCurrentProcessId();
    } else {
        return @bitCast(c.getpid());
    }
}

extern "c" fn gethostname(name: [*]u8, len: usize) c_int;

pub fn getHostname(buf: []u8) bool {
    if (is_windows) {
        netInit(); // ws2_32's gethostname needs WSAStartup
        return win.gethostname(buf.ptr, @intCast(buf.len)) == 0;
    } else {
        return gethostname(buf.ptr, buf.len) == 0;
    }
}

// Monotonic microseconds on Windows via QueryPerformanceCounter. The
// division goes through i128 so counter * 1e6 can't overflow, whatever
// the performance-counter frequency.
var qpc_freq: i64 = 0;

pub fn windowsMonotonicMicros() i64 {
    if (qpc_freq == 0) {
        var f: i64 = 0;
        if (win.QueryPerformanceFrequency(&f) == 0 or f <= 0) return 0;
        qpc_freq = f;
    }
    var counter: i64 = 0;
    if (win.QueryPerformanceCounter(&counter) == 0) return 0;
    const us = @divTrunc(@as(i128, counter) * std.time.us_per_s, qpc_freq);
    return @intCast(us);
}

// Wall clock in µs since the Unix epoch: FILETIME is 100ns units since
// 1601-01-01; the offset to 1970-01-01 is 11644473600 seconds.
const filetime_unix_offset_100ns: i64 = 116444736000000000;

pub fn windowsWallMicros() i64 {
    var ft: win.FILETIME = undefined;
    win.GetSystemTimePreciseAsFileTime(&ft);
    const ticks: i64 = @bitCast(@as(u64, ft.high) << 32 | ft.low);
    return @divTrunc(ticks - filetime_unix_offset_100ns, 10);
}

pub fn windowsSleepNanos(ns: u64) void {
    // Sleep has millisecond granularity; round up so a 1ms pacing delay
    // doesn't become a busy spin
    const ms: u64 = @min((ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms, std.math.maxInt(u32));
    win.Sleep(@intCast(ms));
}

// Console setup: returns whether stdout is a console, and while at it
// enables ANSI escape processing and UTF-8 output so the colored heatmap
// blocks render. Redirected output (pipe/file) returns false, same as
// isatty elsewhere.
pub fn windowsSetupConsole() bool {
    const handle = win.GetStdHandle(win.STD_OUTPUT_HANDLE) orelse return false;
    var mode: u32 = 0;
    if (win.GetConsoleMode(handle, &mode) == 0) return false;
    _ = win.SetConsoleMode(handle, mode | win.ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    _ = win.SetConsoleOutputCP(win.CP_UTF8);
    return true;
}

// IPv4 interface enumeration for Windows via GetIpAddrTable. Rows land in
// out as {addr, mask} in network byte order; returns the count. Loopback,
// unassigned, and disconnected/deleted rows are skipped.
pub const WinIface = struct {
    addr_be: u32,
    mask_be: u32,
    index: u32,
};

pub fn windowsListIfaces(out: []WinIface) usize {
    var buf: [4 + 128 * @sizeOf(win.MIB_IPADDRROW)]u8 align(4) = undefined;
    var size: u32 = buf.len;
    if (win.GetIpAddrTable(&buf, &size, 0) != 0) return 0;

    const count = std.mem.readInt(u32, buf[0..4], .little);
    const rows: [*]align(4) const win.MIB_IPADDRROW = @ptrCast(@alignCast(buf[4..].ptr));
    var n: usize = 0;
    for (0..count) |i| {
        if (n >= out.len) break;
        const row = rows[i];
        if (row.addr == 0) continue;
        const ip_bytes: [4]u8 = @bitCast(row.addr);
        if (ip_bytes[0] == 127) continue; // loopback
        if (row.wtype & (win.MIB_IPADDR_DISCONNECTED | win.MIB_IPADDR_DELETED) != 0) continue;
        out[n] = .{ .addr_be = row.addr, .mask_be = row.mask, .index = row.index };
        n += 1;
    }
    return n;
}

const testing = std.testing;

test "socket helpers round-trip on the host platform" {
    netInit();
    const s = openSocket(AF_INET, SOCK_DGRAM, 0);
    try testing.expect(isValidSocket(s));
    defer closeSocket(s);
    try testing.expect(setNonblocking(s));

    // Bind to an ephemeral loopback port and read the choice back
    const loopback = [4]u8{ 127, 0, 0, 1 };
    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.bytesToValue(u32, &loopback),
    };
    try testing.expect(bind(s, &addr, @sizeOf(posix.sockaddr.in)) == 0);
    var len: u32 = @sizeOf(posix.sockaddr.in);
    try testing.expect(getsockname(s, &addr, &len) == 0);
    try testing.expect(addr.port != 0);

    // Nothing to read: recvfrom on the non-blocking socket must fail with
    // a would-block error, not hang
    var rbuf: [16]u8 = undefined;
    try testing.expect(recvfrom(s, &rbuf, null, null) < 0);
    try testing.expect(errWouldBlock(lastError()));
}

test "pollOne times out on a quiet socket" {
    netInit();
    const s = openSocket(AF_INET, SOCK_DGRAM, 0);
    try testing.expect(isValidSocket(s));
    defer closeSocket(s);
    const loopback = [4]u8{ 127, 0, 0, 1 };
    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.bytesToValue(u32, &loopback),
    };
    try testing.expect(bind(s, &addr, @sizeOf(posix.sockaddr.in)) == 0);
    try testing.expect(!pollOne(s, POLL_IN, 0));
}
