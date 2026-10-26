// Neighbor (ARP) cache harvesting. Plenty of devices drop ICMP echo —
// Windows' default firewall does — so a ping sweep alone can't see them.
// But a host on the local segment has to answer ARP to receive anything at
// all, and the discovery sweep makes the kernel ARP for every address it
// pings. Reading the neighbor table after the sweep therefore finds hosts
// that are present but silent to ping.
//
// The table also holds entries from before the scan, which may be for
// hosts that have since gone away. Only entries this scan demonstrably
// resolved are trusted (see `fresh`):
//   - Linux reports per-entry reachability state (netlink RTM_GETNEIGH);
//     NUD_REACHABLE means the neighbor confirmed itself recently.
//   - macOS (PF_ROUTE sysctl) and Windows (GetIpNetTable) don't, so there
//     an entry counts only if it wasn't in the table before the sweep.
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const c = std.c;
const plat = @import("plat.zig");

pub const Neighbor = struct {
    ip: u32, // network byte order
    reachable: bool, // kernel confirms recent reachability (Linux only)
};

pub const supported = builtin.os.tag == .linux or builtin.os.tag.isDarwin() or plat.is_windows;

// Whether Neighbor.reachable is meaningful (only Linux exposes the state)
pub const reports_reachability = builtin.os.tag == .linux;

// Append every resolved IPv4 neighbor entry to out. Best-effort: any
// failure just yields fewer (or no) entries.
pub fn collect(allocator: std.mem.Allocator, out: *std.ArrayList(Neighbor)) void {
    if (builtin.os.tag == .linux) {
        collectLinux(allocator, out);
    } else if (builtin.os.tag.isDarwin()) {
        collectDarwin(allocator, out);
    } else if (plat.is_windows) {
        var addrs: std.ArrayList(u32) = .empty;
        defer addrs.deinit(allocator);
        plat.windowsArpTable(allocator, &addrs);
        for (addrs.items) |a| out.append(allocator, .{ .ip = a, .reachable = false }) catch return;
    }
}

// Entries in `after` that the scan itself resolved: reachable per the
// kernel, or absent from the `before` snapshot. Returns network-order IPs.
pub fn fresh(allocator: std.mem.Allocator, before: []const Neighbor, after: []const Neighbor) ![]u32 {
    var seen = std.AutoHashMap(u32, void).init(allocator);
    defer seen.deinit();
    for (before) |n| try seen.put(n.ip, {});

    var result: std.ArrayList(u32) = .empty;
    errdefer result.deinit(allocator);
    for (after) |n| {
        if (n.reachable or !seen.contains(n.ip)) try result.append(allocator, n.ip);
    }
    return result.toOwnedSlice(allocator);
}

// ---- Linux: rtnetlink neighbor dump ----

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWNEIGH: u16 = 28;
const RTM_GETNEIGH: u16 = 30;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const nlmsg_hdr_len = 16;
// Netlink headers and attributes are in host byte order
const nl_endian = builtin.cpu.arch.endian();
const ndmsg_len = 12;

// ndm_state bits
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_REACHABLE: u16 = 0x02;
const NUD_FAILED: u16 = 0x20;
const NUD_NOARP: u16 = 0x40;

fn collectLinux(allocator: std.mem.Allocator, out: *std.ArrayList(Neighbor)) void {
    const AF_NETLINK = 16;
    const NETLINK_ROUTE = 0;
    const fd = c.socket(AF_NETLINK, posix.SOCK.RAW | posix.SOCK.CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return;
    defer _ = c.close(fd);

    // Don't let a misbehaving kernel reply hang the scanner
    const tv = posix.timeval{ .sec = 1, .usec = 0 };
    _ = c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &tv, @sizeOf(posix.timeval));

    var req: [nlmsg_hdr_len + ndmsg_len]u8 = @splat(0);
    std.mem.writeInt(u32, req[0..4], req.len, nl_endian);
    std.mem.writeInt(u16, req[4..6], RTM_GETNEIGH, nl_endian);
    std.mem.writeInt(u16, req[6..8], NLM_F_REQUEST | NLM_F_DUMP, nl_endian);
    std.mem.writeInt(u32, req[8..12], 1, nl_endian); // seq
    req[nlmsg_hdr_len] = posix.AF.INET; // ndm_family
    if (c.send(fd, &req, req.len, 0) != req.len) return;

    var buf: [32 * 1024]u8 align(4) = undefined;
    while (true) {
        const rc = c.recv(fd, &buf, buf.len, 0);
        if (rc <= 0) return;
        if (parseNetlink(buf[0..@intCast(rc)], allocator, out)) return;
    }
}

// Parse one recv's worth of netlink messages; true once the dump is done
// (or broken), false when more datagrams follow
pub fn parseNetlink(buf: []const u8, allocator: std.mem.Allocator, out: *std.ArrayList(Neighbor)) bool {
    var off: usize = 0;
    while (off + nlmsg_hdr_len <= buf.len) {
        const len = std.mem.readInt(u32, buf[off..][0..4], nl_endian);
        const msg_type = std.mem.readInt(u16, buf[off + 4 ..][0..2], nl_endian);
        // len > buf.len - off, not off + len > buf.len: a bogus length
        // must not overflow a 32-bit usize
        if (len < nlmsg_hdr_len or len > buf.len - off) return true;
        if (msg_type == NLMSG_DONE or msg_type == NLMSG_ERROR) return true;

        if (msg_type == RTM_NEWNEIGH and len >= nlmsg_hdr_len + ndmsg_len) {
            const nd = buf[off + nlmsg_hdr_len ..][0..ndmsg_len];
            const family = nd[0];
            const state = std.mem.readInt(u16, nd[8..10], nl_endian);
            const resolved = state & (NUD_INCOMPLETE | NUD_FAILED | NUD_NOARP) == 0 and state != 0;
            if (family == posix.AF.INET and resolved) {
                var dst: ?u32 = null;
                var has_lladdr = false;
                var aoff: usize = off + nlmsg_hdr_len + ndmsg_len;
                const end = off + len;
                while (aoff + 4 <= end) {
                    const alen = std.mem.readInt(u16, buf[aoff..][0..2], nl_endian);
                    const atype = std.mem.readInt(u16, buf[aoff + 2 ..][0..2], nl_endian) & 0x3FFF;
                    if (alen < 4 or alen > end - aoff) break;
                    const payload = buf[aoff + 4 .. aoff + alen];
                    if (atype == NDA_DST and payload.len == 4) dst = std.mem.bytesToValue(u32, payload[0..4]);
                    if (atype == NDA_LLADDR and payload.len > 0) has_lladdr = true;
                    aoff += std.mem.alignForward(usize, alen, 4);
                }
                if (dst) |ip| {
                    if (has_lladdr) {
                        out.append(allocator, .{
                            .ip = ip,
                            .reachable = state & NUD_REACHABLE != 0,
                        }) catch return true;
                    }
                }
            }
        }
        off += std.mem.alignForward(usize, len, 4);
    }
    return false;
}

// ---- macOS: PF_ROUTE sysctl dump of the link-layer (ARP) routes ----

// sizeof(struct rt_msghdr) on Darwin: 36 bytes of header fields plus a
// 56-byte struct rt_metrics (fourteen 32-bit fields)
const darwin_rt_msghdr_len = 92;
const RTA_DST: i32 = 0x1;
const RTA_GATEWAY: i32 = 0x2;
const AF_LINK: u8 = 18;

fn collectDarwin(allocator: std.mem.Allocator, out: *std.ArrayList(Neighbor)) void {
    const CTL_NET = 4;
    const PF_ROUTE = 17;
    const NET_RT_FLAGS = 2;
    const RTF_LLINFO = 0x400;
    const mib = [_]c_int{ CTL_NET, PF_ROUTE, 0, posix.AF.INET, NET_RT_FLAGS, RTF_LLINFO };

    var len: usize = 0;
    if (c.sysctl(&mib, mib.len, null, &len, null, 0) != 0 or len == 0) return;
    len += len / 4; // headroom if the table grows between the two calls
    const buf = allocator.alignedAlloc(u8, .@"4", len) catch return;
    defer allocator.free(buf);
    if (c.sysctl(&mib, mib.len, buf.ptr, &len, null, 0) != 0) return;
    parseRouteDump(buf[0..len], allocator, out);
}

pub fn parseRouteDump(buf: []const u8, allocator: std.mem.Allocator, out: *std.ArrayList(Neighbor)) void {
    var off: usize = 0;
    while (off + darwin_rt_msghdr_len <= buf.len) {
        const msglen: usize = std.mem.readInt(u16, buf[off..][0..2], .little);
        if (msglen < darwin_rt_msghdr_len or off + msglen > buf.len) return;
        const addrs = std.mem.readInt(i32, buf[off + 12 ..][0..4], .little);
        const end = off + msglen;

        var sa_off = off + darwin_rt_msghdr_len;
        var dst: ?u32 = null;
        var complete = false;
        // Sockaddrs follow in RTA_* bit order, each padded to 4 bytes
        var bit: u5 = 0;
        while (bit < 8 and sa_off + 2 <= end) : (bit += 1) {
            const mask = @as(i32, 1) << bit;
            if (addrs & mask == 0) continue;
            const sa_len: usize = buf[sa_off];
            const family = buf[sa_off + 1];
            const step = if (sa_len == 0) 4 else std.mem.alignForward(usize, sa_len, 4);
            if (sa_off + @max(sa_len, 2) > end) break;
            if (mask == RTA_DST and family == posix.AF.INET and sa_len >= 8) {
                dst = std.mem.bytesToValue(u32, buf[sa_off + 4 ..][0..4]);
            } else if (mask == RTA_GATEWAY and family == AF_LINK and sa_len >= 8) {
                complete = buf[sa_off + 6] > 0; // sdl_alen: link address present
            }
            sa_off += step;
        }
        if (dst) |ip| {
            if (complete) {
                out.append(allocator, .{ .ip = ip, .reachable = false }) catch return;
            }
        }
        off = end;
    }
}

const testing = std.testing;

fn wireIp(ip: [4]u8) u32 {
    return std.mem.bytesToValue(u32, &ip);
}

test "parseNetlink keeps resolved IPv4 neighbors and their reachability" {
    var buf: [256]u8 align(4) = @splat(0);
    var off: usize = 0;
    const Ent = struct { ip: [4]u8, state: u16, lladdr: bool };
    const ents = [_]Ent{
        .{ .ip = .{ 192, 168, 1, 1 }, .state = NUD_REACHABLE, .lladdr = true },
        .{ .ip = .{ 192, 168, 1, 2 }, .state = 0x04, .lladdr = true }, // STALE
        .{ .ip = .{ 192, 168, 1, 3 }, .state = NUD_INCOMPLETE, .lladdr = false },
        .{ .ip = .{ 192, 168, 1, 4 }, .state = NUD_FAILED, .lladdr = false },
    };
    for (ents) |e| {
        const len: usize = nlmsg_hdr_len + ndmsg_len + 8 + (if (e.lladdr) @as(usize, 12) else 0);
        std.mem.writeInt(u32, buf[off..][0..4], @intCast(len), nl_endian);
        std.mem.writeInt(u16, buf[off + 4 ..][0..2], RTM_NEWNEIGH, nl_endian);
        buf[off + nlmsg_hdr_len] = posix.AF.INET;
        std.mem.writeInt(u16, buf[off + nlmsg_hdr_len + 8 ..][0..2], e.state, nl_endian);
        var a = off + nlmsg_hdr_len + ndmsg_len;
        std.mem.writeInt(u16, buf[a..][0..2], 8, nl_endian);
        std.mem.writeInt(u16, buf[a + 2 ..][0..2], NDA_DST, nl_endian);
        @memcpy(buf[a + 4 ..][0..4], &e.ip);
        a += 8;
        if (e.lladdr) {
            std.mem.writeInt(u16, buf[a..][0..2], 10, nl_endian);
            std.mem.writeInt(u16, buf[a + 2 ..][0..2], NDA_LLADDR, nl_endian);
            @memcpy(buf[a + 4 ..][0..6], &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff });
        }
        off += len;
    }
    std.mem.writeInt(u32, buf[off..][0..4], nlmsg_hdr_len, nl_endian);
    std.mem.writeInt(u16, buf[off + 4 ..][0..2], NLMSG_DONE, nl_endian);
    off += nlmsg_hdr_len;

    var out: std.ArrayList(Neighbor) = .empty;
    defer out.deinit(testing.allocator);
    try testing.expect(parseNetlink(buf[0..off], testing.allocator, &out));
    try testing.expectEqual(@as(usize, 2), out.items.len);
    try testing.expectEqual(wireIp(.{ 192, 168, 1, 1 }), out.items[0].ip);
    try testing.expect(out.items[0].reachable);
    try testing.expectEqual(wireIp(.{ 192, 168, 1, 2 }), out.items[1].ip);
    try testing.expect(!out.items[1].reachable);
}

test "parseRouteDump keeps entries with a link-layer address" {
    var buf: [2 * 128]u8 align(4) = @splat(0);
    var off: usize = 0;
    for ([_]struct { ip: [4]u8, alen: u8 }{
        .{ .ip = .{ 10, 0, 0, 1 }, .alen = 6 },
        .{ .ip = .{ 10, 0, 0, 2 }, .alen = 0 }, // incomplete
    }) |e| {
        const msglen = darwin_rt_msghdr_len + 16 + 20;
        std.mem.writeInt(u16, buf[off..][0..2], msglen, .little);
        std.mem.writeInt(i32, buf[off + 12 ..][0..4], RTA_DST | RTA_GATEWAY, .little);
        const sa = off + darwin_rt_msghdr_len;
        buf[sa] = 16;
        buf[sa + 1] = posix.AF.INET;
        @memcpy(buf[sa + 4 ..][0..4], &e.ip);
        const dl = sa + 16;
        buf[dl] = 20;
        buf[dl + 1] = AF_LINK;
        buf[dl + 6] = e.alen;
        off += msglen;
    }
    var out: std.ArrayList(Neighbor) = .empty;
    defer out.deinit(testing.allocator);
    parseRouteDump(buf[0..off], testing.allocator, &out);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(wireIp(.{ 10, 0, 0, 1 }), out.items[0].ip);
}

test "fresh keeps reachable or newly appeared entries only" {
    const before = [_]Neighbor{
        .{ .ip = 1, .reachable = false },
        .{ .ip = 2, .reachable = false },
    };
    const after = [_]Neighbor{
        .{ .ip = 1, .reachable = false }, // pre-existing, unverified
        .{ .ip = 2, .reachable = true }, // pre-existing, confirmed
        .{ .ip = 3, .reachable = false }, // new during the scan
    };
    const got = try fresh(testing.allocator, &before, &after);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u32, &.{ 2, 3 }, got);
}

test "collect runs without crashing on the host platform" {
    var out: std.ArrayList(Neighbor) = .empty;
    defer out.deinit(testing.allocator);
    collect(testing.allocator, &out);
}

test "parseNetlink stops on an oversized length instead of overflowing" {
    var buf: [2 * nlmsg_hdr_len]u8 align(4) = @splat(0);
    std.mem.writeInt(u32, buf[0..4], nlmsg_hdr_len, nl_endian);
    std.mem.writeInt(u16, buf[4..6], RTM_NEWNEIGH, nl_endian);
    std.mem.writeInt(u32, buf[nlmsg_hdr_len..][0..4], 0xFFFF_FFF8, nl_endian);
    var out: std.ArrayList(Neighbor) = .empty;
    defer out.deinit(testing.allocator);
    try testing.expect(parseNetlink(&buf, testing.allocator, &out));
    try testing.expectEqual(@as(usize, 0), out.items.len);
}
