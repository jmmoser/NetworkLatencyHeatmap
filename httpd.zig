// Minimal embedded HTTP server for mesh mode (--http): serves the mesh
// state as JSON (/json) and Prometheus metrics (/metrics), so a node can
// feed Grafana or scripts without anyone parsing terminal output.
//
// The design keeps the server completely out of the measurement path: the
// main thread renders point-in-time snapshots into shared byte buffers on
// its own schedule, and the server thread only ever copies bytes out from
// under a lock. A slow, stuck, or hostile client can therefore never stall
// probing, gossip, or rendering.
//
// Deliberately not a general HTTP implementation: GET only, one request
// per connection, bounded reads with a deadline, connection closed after
// the response.
const std = @import("std");
const common = @import("common.zig");
const plat = @import("plat.zig");
const posix = std.posix;

const max_request_bytes = 2048;
const request_deadline_us: i64 = 2 * std.time.us_per_s;
const accept_poll_ms: i32 = 200;

const Shared = struct {
    mutex: common.SpinLock = .{},
    stop: bool = false,
    json: std.ArrayList(u8) = .empty,
    metrics: std.ArrayList(u8) = .empty,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    sock: plat.Socket,
    port: u16,
    thread: ?std.Thread,
    shared: Shared,

    pub fn init(allocator: std.mem.Allocator, port: u16) !Server {
        plat.netInit();
        const sock = plat.openSocket(plat.AF_INET, plat.SOCK_STREAM, 0);
        if (!plat.isValidSocket(sock)) return error.HttpSocketFailed;
        errdefer plat.closeSocket(sock);

        const one: c_int = 1;
        _ = plat.setsockopt(sock, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one, @sizeOf(c_int));

        var addr = posix.sockaddr.in{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = 0, // INADDR_ANY: this is a LAN tool and --http is opt-in
        };
        if (plat.bind(sock, &addr, @sizeOf(posix.sockaddr.in)) != 0)
            return error.HttpBindFailed;
        if (plat.listen(sock, 8) != 0)
            return error.HttpListenFailed;

        return .{
            .allocator = allocator,
            .sock = sock,
            .port = port,
            .thread = null,
            .shared = .{},
        };
    }

    // Call once the Server has its final address (the thread keeps a
    // pointer to self.shared).
    pub fn start(self: *Server) !void {
        self.thread = try std.Thread.spawn(.{}, serverMain, .{self});
    }

    pub fn deinit(self: *Server) void {
        if (self.thread) |thread| {
            {
                self.shared.mutex.lock();
                defer self.shared.mutex.unlock();
                self.shared.stop = true;
            }
            thread.join();
        }
        plat.closeSocket(self.sock);
        self.shared.json.deinit(self.allocator);
        self.shared.metrics.deinit(self.allocator);
    }

    // Replace the served snapshots (main thread). Copies, so the caller's
    // buffers can be reused immediately.
    pub fn setSnapshots(self: *Server, json: []const u8, metrics: []const u8) void {
        self.shared.mutex.lock();
        defer self.shared.mutex.unlock();
        self.shared.json.clearRetainingCapacity();
        self.shared.json.appendSlice(self.allocator, json) catch {};
        self.shared.metrics.clearRetainingCapacity();
        self.shared.metrics.appendSlice(self.allocator, metrics) catch {};
    }

    fn shouldStop(self: *Server) bool {
        self.shared.mutex.lock();
        defer self.shared.mutex.unlock();
        return self.shared.stop;
    }

    fn serverMain(self: *Server) void {
        while (true) {
            if (self.shouldStop()) return;
            if (!plat.pollOne(self.sock, plat.POLL_IN, accept_poll_ms)) continue;
            const conn = plat.accept(self.sock);
            if (!plat.isValidSocket(conn)) continue;
            self.handleConnection(conn);
        }
    }

    fn handleConnection(self: *Server, conn: plat.Socket) void {
        defer plat.closeSocket(conn);
        if (!plat.setNonblocking(conn)) return;

        // Read until the end of the request head, a bounded size, or the
        // deadline — whichever comes first
        var buf: [max_request_bytes]u8 = undefined;
        var have: usize = 0;
        const deadline = common.monotonicMicros() + request_deadline_us;
        while (std.mem.indexOf(u8, buf[0..have], "\r\n\r\n") == null) {
            if (have >= buf.len) return; // oversized request head
            const now = common.monotonicMicros();
            if (now >= deadline) return;
            const wait_ms: i32 = @intCast(@min(
                @divFloor(deadline - now, std.time.us_per_ms) + 1,
                @as(i64, 1000),
            ));
            if (!plat.pollOne(conn, plat.POLL_IN, wait_ms)) continue;
            const rc = plat.recv(conn, buf[have..]);
            if (rc == 0) return; // peer closed mid-request
            if (rc < 0) {
                if (plat.errWouldBlock(plat.lastError())) continue;
                return;
            }
            have += @intCast(rc);
        }

        const path = requestPath(buf[0..have]) orelse {
            self.respondStatic(conn, "400 Bad Request", "text/plain; charset=utf-8", "bad request\n");
            return;
        };

        if (std.mem.eql(u8, path, "/json")) {
            self.respondSnapshot(conn, "application/json", .json);
        } else if (std.mem.eql(u8, path, "/metrics")) {
            self.respondSnapshot(conn, "text/plain; version=0.0.4; charset=utf-8", .metrics);
        } else if (std.mem.eql(u8, path, "/")) {
            self.respondStatic(conn, "200 OK", "text/plain; charset=utf-8", "latency-heatmap mesh node\n\n/json     mesh state snapshot\n/metrics  Prometheus metrics\n");
        } else {
            self.respondStatic(conn, "404 Not Found", "text/plain; charset=utf-8", "not found\n");
        }
    }

    // First request line must be "GET <path> HTTP/x.y"; query strings are
    // ignored, anything else is rejected
    fn requestPath(head: []const u8) ?[]const u8 {
        const line_end = std.mem.indexOfAny(u8, head, "\r\n") orelse return null;
        var it = std.mem.splitScalar(u8, head[0..line_end], ' ');
        const method = it.next() orelse return null;
        if (!std.mem.eql(u8, method, "GET")) return null;
        const target = it.next() orelse return null;
        if (it.next() == null) return null; // no HTTP version present
        const q = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
        const path = target[0..q];
        if (path.len == 0 or path[0] != '/') return null;
        return path;
    }

    const Which = enum { json, metrics };

    fn respondSnapshot(self: *Server, conn: plat.Socket, content_type: []const u8, which: Which) void {
        // Copy the snapshot out under the lock, serve outside it: sending
        // to a slow client must not block the main thread's next update
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.allocator);
        {
            self.shared.mutex.lock();
            defer self.shared.mutex.unlock();
            const src = switch (which) {
                .json => self.shared.json.items,
                .metrics => self.shared.metrics.items,
            };
            body.appendSlice(self.allocator, src) catch return;
        }
        if (body.items.len == 0) {
            self.respondStatic(conn, "503 Service Unavailable", "text/plain; charset=utf-8", "no scan data yet\n");
            return;
        }
        writeResponse(conn, "200 OK", content_type, body.items);
    }

    fn respondStatic(self: *Server, conn: plat.Socket, status: []const u8, content_type: []const u8, body: []const u8) void {
        _ = self;
        writeResponse(conn, status, content_type, body);
    }

    fn writeResponse(conn: plat.Socket, status: []const u8, content_type: []const u8, body: []const u8) void {
        var head_buf: [256]u8 = undefined;
        const head = std.fmt.bufPrint(&head_buf, "HTTP/1.1 {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{
            status, content_type, body.len,
        }) catch return;
        if (!sendAll(conn, head)) return;
        _ = sendAll(conn, body);
    }

    // Send with a deadline; the socket is non-blocking, so wait for
    // writability between partial sends instead of spinning
    fn sendAll(conn: plat.Socket, data: []const u8) bool {
        var off: usize = 0;
        const deadline = common.monotonicMicros() + request_deadline_us;
        while (off < data.len) {
            if (common.monotonicMicros() >= deadline) return false;
            const rc = plat.send(conn, data[off..]);
            if (rc < 0) {
                if (!plat.errWouldBlock(plat.lastError())) return false;
                if (!plat.pollOne(conn, plat.POLL_OUT, 200)) continue;
                continue;
            }
            off += @intCast(rc);
        }
        return true;
    }
};

const testing = std.testing;

test "requestPath parses GET request lines and rejects the rest" {
    try testing.expectEqualStrings("/json", Server.requestPath("GET /json HTTP/1.1\r\nHost: x\r\n\r\n").?);
    try testing.expectEqualStrings("/metrics", Server.requestPath("GET /metrics?x=1 HTTP/1.0\r\n\r\n").?);
    try testing.expectEqualStrings("/", Server.requestPath("GET / HTTP/1.1\r\n\r\n").?);

    try testing.expect(Server.requestPath("POST /json HTTP/1.1\r\n\r\n") == null);
    try testing.expect(Server.requestPath("GET json HTTP/1.1\r\n\r\n") == null);
    try testing.expect(Server.requestPath("GET /json\r\n\r\n") == null); // no version
    try testing.expect(Server.requestPath("garbage") == null);
}

test "server serves snapshots end to end on loopback" {
    var srv = try Server.init(testing.allocator, 0);
    defer srv.deinit();

    // Ephemeral port: read back what bind chose
    var addr = posix.sockaddr.in{ .family = posix.AF.INET, .port = 0, .addr = 0 };
    var alen: u32 = @sizeOf(posix.sockaddr.in);
    try testing.expect(plat.getsockname(srv.sock, &addr, &alen) == 0);

    try srv.start();
    srv.setSnapshots("{\"ok\":true}", "nlh_up 1\n");

    const loopback = [4]u8{ 127, 0, 0, 1 };
    var dest = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = addr.port,
        .addr = std.mem.bytesToValue(u32, &loopback),
    };

    for ([_][]const u8{ "/json", "/metrics", "/nope" }) |path| {
        const cfd = plat.openSocket(plat.AF_INET, plat.SOCK_STREAM, 0);
        try testing.expect(plat.isValidSocket(cfd));
        defer plat.closeSocket(cfd);
        try testing.expect(plat.connect(cfd, &dest, @sizeOf(posix.sockaddr.in)) == 0);

        var req_buf: [128]u8 = undefined;
        const req = try std.fmt.bufPrint(&req_buf, "GET {s} HTTP/1.1\r\nHost: t\r\n\r\n", .{path});
        try testing.expect(Server.sendAll(cfd, req));

        // Read until the server closes the connection
        var resp: [4096]u8 = undefined;
        var have: usize = 0;
        while (have < resp.len) {
            if (!plat.pollOne(cfd, plat.POLL_IN, 2000)) break;
            const rc = plat.recv(cfd, resp[have..]);
            if (rc <= 0) break;
            have += @intCast(rc);
        }
        const text = resp[0..have];

        if (std.mem.eql(u8, path, "/json")) {
            try testing.expect(std.mem.startsWith(u8, text, "HTTP/1.1 200 OK\r\n"));
            try testing.expect(std.mem.endsWith(u8, text, "{\"ok\":true}"));
            try testing.expect(std.mem.indexOf(u8, text, "Content-Type: application/json\r\n") != null);
        } else if (std.mem.eql(u8, path, "/metrics")) {
            try testing.expect(std.mem.startsWith(u8, text, "HTTP/1.1 200 OK\r\n"));
            try testing.expect(std.mem.endsWith(u8, text, "nlh_up 1\n"));
        } else {
            try testing.expect(std.mem.startsWith(u8, text, "HTTP/1.1 404"));
        }
    }
}
