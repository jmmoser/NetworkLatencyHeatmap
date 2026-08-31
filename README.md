# Network Latency Heatmap Scanner

[![CI](https://github.com/jmmoser/NetworkLatencyHeatmap/actions/workflows/ci.yml/badge.svg)](https://github.com/jmmoser/NetworkLatencyHeatmap/actions/workflows/ci.yml)

A fast network scanner that discovers hosts on your network and measures their latency, displaying results as a visual heatmap.

## Features

- **Cross-platform**: Runs natively on Linux (epoll), macOS/BSD (kqueue), and Windows (Winsock2 + WSAPoll)
- **Two-phase scanning**: Fast discovery phase followed by accurate latency measurement
- **Kernel receive timestamps**: Uses `SO_TIMESTAMP` on Linux and macOS so replies are stamped by the kernel on arrival — process wakeup and scheduling delay don't inflate measured RTTs (falls back to userspace timestamps where unavailable, including on Windows)
- **Monotonic timing**: All pacing, timeouts, and fallback measurements use `CLOCK_MONOTONIC` (`QueryPerformanceCounter` on Windows); kernel stamps (wall clock only) are cross-checked against a monotonic upper bound, so an NTP step or slew mid-scan can't corrupt samples or stall the scanner
- **Packet loss and jitter**: Every host reports probes sent vs answered and the standard deviation of its samples (ping's mdev) alongside min/avg/max — an average computed only from surviving probes understates a lossy or jittery link, so loss is flagged right in the heatmap cells
- **Reverse-DNS names**: Discovered hosts are named through the system resolver after each scan (mDNS/NetBIOS too, wherever the OS consults them), under a soft time budget so slow DNS can't stall scanning (`--no-names` to disable)
- **Machine-readable output**: `--json` turns a one-shot scan into a single JSON document; in mesh mode `--http` serves the live matrix as JSON and Prometheus metrics for Grafana or scripts
- **Trend detection**: Mesh mode keeps a rolling history of scan averages per host and calls out hosts that just degraded versus their own recent baseline
- **Authenticated mesh**: `--mesh-key` HMAC-tags every mesh datagram so only nodes sharing the key can join or inject results
- **Visual heatmap**: Color-coded latency display to quickly identify slow devices
- **Flicker-free live view**: the mesh matrix never clears the screen between frames — each redraw overwrites the previous frame in place (erasing only stale line tails and leftover rows), is emitted as a single write, and is wrapped in terminal synchronized output (mode 2026) so capable terminals commit it atomically
- **Concurrent scanning**: Uses separate sender/receiver threads for maximum throughput
- **Large subnet support**: Can scan /16 networks (65k+ hosts) efficiently
- **Default-route-aware auto-detection**: With no subnet argument, the scanner picks the interface carrying the default route (not just the first one up), so VPN tunnels, VM bridges, and container networks don't hijack the scan — the chosen interface is printed so you can verify
- **Pipe-friendly output**: Colors and in-place progress bars are emitted only on a terminal; redirect to a file and you get plain text (`--no-color` and the `NO_COLOR` env var also disable color)
- **Mesh mode**: Run the scanner on several devices and they discover each other over UDP, gossip their results, and each render a live matrix of every host's latency from every vantage point
- **TCP and UDP node-to-node pings**: Mesh nodes also measure each other directly — a UDP echo ping and a TCP connect ping (SYN → SYN-ACK, torn down with an RST with a zero window) — so link latency between observers is visible alongside the ICMP matrix
- **TCP pings to anything with a known port**: `--tcp-ping ip:port` times the SYN → SYN-ACK (or RST from a closed port) of hosts that aren't running this tool at all — routers, printers, servers

## Requirements

- macOS/BSD (kqueue), Linux (epoll), or Windows 10+ (Winsock2) — uses raw ICMP sockets
- Elevated privileges for raw socket access: root/sudo on macOS and Linux, an Administrator prompt on Windows
- Zig 0.16+ (only for building from source — tagged releases ship prebuilt binaries for x86_64/aarch64 Linux, macOS, and Windows)

IPv4 only for now: every address path in the scanner, the mesh protocol, and the display is v4. ICMPv6 + multicast discovery is a planned follow-up, tracked separately because it touches every module.

## Installing

Prebuilt binaries for x86_64/aarch64 Linux, macOS, and Windows are attached to every [tagged release](https://github.com/jmmoser/NetworkLatencyHeatmap/releases) (with a `SHA256SUMS` file) — mesh mode is most useful when it's trivial to drop the binary on a Pi, a NAS, and a laptop at once.

## Building

```bash
zig build
```

Run the unit tests with:

```bash
zig build test
```

Cross-compile for another platform with `-Dtarget`, e.g. a Windows binary from any host:

```bash
zig build -Dtarget=x86_64-windows    # or aarch64-windows, aarch64-macos, ...
```

## Usage

```bash
sudo ./zig-out/bin/latency-heatmap [subnet/mask] [options]
```

On Windows, run from an elevated (Administrator) terminal:

```powershell
.\zig-out\bin\latency-heatmap.exe [subnet/mask] [options]
```

### Examples

```bash
# Scan default subnet (192.168.1.0/24)
sudo ./zig-out/bin/latency-heatmap

# Scan a specific subnet
sudo ./zig-out/bin/latency-heatmap 192.168.1.0/24

# Scan a larger network with custom timeout
sudo ./zig-out/bin/latency-heatmap 192.168.0.0/16 -d 3000

# Quick scan with minimal latency probes
sudo ./zig-out/bin/latency-heatmap 10.0.0.0/24 -p 1

# Mesh mode: run this on each device; they find each other automatically
sudo ./zig-out/bin/latency-heatmap --mesh

# Mesh mode, also TCP-pinging the router's web UI and an SSH server
sudo ./zig-out/bin/latency-heatmap --mesh --tcp-ping 192.168.1.1:443 --tcp-ping 192.168.1.10:22

# One-shot scan as JSON, piped into jq
sudo ./zig-out/bin/latency-heatmap --json 192.168.1.0/24 | jq '.hosts[] | select(.loss_pct > 0)'

# Authenticated mesh node also serving JSON + Prometheus metrics on :9464
sudo ./zig-out/bin/latency-heatmap --mesh --mesh-key hunter2 --http 9464
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d <ms>` | Discovery timeout in milliseconds | 1000 |
| `-p <count>` | Number of pings per host for latency measurement (1-16) | 5 |
| `-t <ms>` | Timeout per ping in latency phase | 1000 |
| `--mesh` | Mesh mode: discover peers, share results, render the combined matrix | off |
| `--mesh-port <port>` | UDP+TCP port for mesh discovery, gossip, and node-to-node probes | 47269 |
| `-i <sec>` | Mesh mode: rescan interval in seconds (0 = scan once) | 60 |
| `--tcp-ping <ip:port>` | Mesh mode: TCP-ping this host on a known port (repeatable, up to 16) | none |
| `--json` | One-shot scan: print a single JSON document on stdout instead of the heatmap | off |
| `--http <port>` | Mesh mode: serve `/json` and `/metrics` (Prometheus) over HTTP | off |
| `--mesh-key <secret>` | Mesh mode: HMAC-authenticate every mesh datagram; all nodes need the same secret | off |
| `--no-names` | Skip reverse-DNS lookups of discovered hosts | resolve |
| `--no-color` | Disable colored output (also off when stdout is not a terminal or `NO_COLOR` is set) | |
| `-h, --help` | Show help message | |

### Windows notes

- Raw ICMP sockets require an elevated (Administrator) terminal; without one the scanner exits with a clear error.
- The raw socket is automatically bound to the interface on the scanned subnet (Winsock requires a specific local address to receive raw ICMP).
- Windows Defender Firewall can silently drop inbound traffic: if discovery finds nothing on a network you know is populated, check the firewall profile for the active network.
- ANSI colors and the Unicode heatmap blocks are enabled automatically (virtual terminal processing + UTF-8 code page); Windows Terminal and modern conhost both render them.
- Auto-detected interfaces display as `if<index>` (Windows' address table carries no interface names).

## How It Works

1. **Phase 1: Discovery**
   - Blasts ICMP echo requests to all IPs in the subnet
   - Waits for the discovery timeout to collect responses
   - Records which hosts are alive

2. **Phase 2: Latency Measurement**
   - For each discovered host, sends multiple pings
   - On Linux and macOS, reply arrival times come from kernel timestamps (`SCM_TIMESTAMP`), not userspace clocks, so scheduling jitter is excluded from the samples; Windows has no equivalent, so samples there use monotonic userspace timestamps taken at poll wakeup
   - Records min/avg/max latency, jitter (standard deviation, ping's mdev), and probes sent vs answered for each host — a host that answers discovery but drops latency probes shows up as loss, not as a healthy average
   - The early-exit silence window scales with the slowest RTT observed so far, so replies from high-latency hosts still in flight aren't clipped by a burst of fast responders finishing first
   - Resolves reverse-DNS names for the discovered hosts through the system resolver (a small worker pool with a soft time budget, so an unresponsive DNS server costs seconds, not minutes)
   - Displays results with color-coded heatmap; cells with dropped probes carry a red `!N%` loss marker

The phases are deliberately sequential: latency is measured in a quiet window after the discovery blast, so probes never compete with the scanner's own traffic for the NIC and socket buffers.

## Machine-Readable Output

### One-shot scans: `--json`

`--json` suppresses all decoration and progress and prints exactly one JSON document on stdout:

```json
{
  "schema_version": 1,
  "scanned_at_unix_us": 1788143705607332,
  "subnet": "192.168.1.0/24",
  "pings_per_host": 5,
  "hosts": [
    { "ip": "192.168.1.1", "name": "router.lan", "min_us": 610, "avg_us": 640,
      "max_us": 702, "jitter_us": 31, "sent": 5, "received": 5, "loss_pct": 0 }
  ]
}
```

Latency fields are integers in microseconds, `null` where the host produced no sample (a host with `loss_pct: 100` answered discovery but none of the latency probes — exactly the hosts worth noticing).

### Mesh mode: `--http <port>`

Any mesh node can serve its converged view over HTTP:

- `/json` — the full snapshot: observers, the host matrix (min/avg/max/jitter/loss from every vantage), degradation flags, node-to-node links, and TCP targets
- `/metrics` — Prometheus exposition format (`nlh_host_latency_seconds`, `nlh_host_loss_ratio`, `nlh_link_seconds`, `nlh_tcp_target_seconds`, ...), ready to scrape into Grafana; series are keyed by stable node ids, and `nlh_observer_info` maps ids to labels

The server thread only ever serves byte snapshots the main thread refreshes every two seconds — a slow or hostile client can never stall probing, gossip, or rendering. Requests are GET-only with bounded reads and deadlines. The endpoint binds all interfaces (it's a LAN tool) and is opt-in; don't expose it past your LAN.

## Mesh Mode

A single scanner sees the network from exactly one vantage point. `--mesh` removes that limitation: run the tool on several devices on the same LAN and they find each other automatically, share their scan results, and each render an M×N latency matrix — every discovered host as measured from every observer.

```
  Node office-nas (id 1a2b3c4d) · UDP port 47269 · 2 peers · 14 targets

  target           self         laptop       pi4
                   3s ago       7s ago       12s ago
  192.168.1.1      █ 640µs      █ 812µs      ▓ 1.2ms
  192.168.1.42     ▓ 1.8ms      ▓ 2.1ms      ▒ 9.0ms      ◀ uneven

  Node links · cell = from column node to row, udp/tcp avg · * = RST (closed port)
  node             self         laptop       pi4
  self             —            .5ms/.6ms    8.0ms/8.3ms
  laptop           640µs/710µs  —            8.2ms/8.5ms
  pi4              8.1ms/8.4ms  7.9ms/8.2ms  —

  tcp target       self         laptop       pi4
  192.168.1.1:443  1.2ms        1.3ms        9.0ms
  192.168.1.9:22   3.4ms*       3.2ms*       ---

  ⚠ Insights:
    Observer pi4 sees a median of 8.2ms vs 900µs mesh-wide — its own link is likely the bottleneck
```

Comparing the same host from multiple vantage points localizes problems a single scanner can't:

- A host slow from **every** observer is itself the problem (slow radio, power-saving NIC, overload)
- A host slow from **some** observers (`◀ uneven`) points at a link, switch, or AP between network segments
- An observer that measures **everything** slow has a bad uplink of its own — the insight section calls this out
- A cell marked `!` is dropping ≥20% of probes from that vantage — a host can average fast while losing packets (radio interference, power saving, overload); the insights section counts these
- A host whose average jumped to ≥3x its own median over the previous scans is flagged as **degraded** — the rescan loop keeps a 16-scan history per host, so a fresh problem is distinguishable from a device that has always been slow

Rows scanned by this node also show their reverse-DNS names; names aren't gossiped (every node asks the same resolver anyway), so rows only peers scanned appear as bare IPs.

How it works: each node broadcasts a small UDP beacon every 2 seconds to announce itself, and gossips its scan results (chunked to fit under the MTU) every 5 seconds plus immediately to newly joined peers. There is no coordinator — every node converges on the full matrix and renders it live. By default each node rescans every 60 seconds (`-i` changes this; `-i 0` scans once and keeps sharing). Mesh traffic is deliberately phase-separated from measurement: while a scan runs, only the tiny beacons keep flowing (so a long scan doesn't get the node dropped from its peers' tables, and incoming datagrams keep being drained), while result gossip is deferred until the scan completes — the mesh never competes with its own probes.

Incoming datagrams are treated as untrusted input: fixed caps on peers and hosts, strict length validation, and anything malformed or from a different protocol version is dropped silently. The parser is additionally covered by a fuzz test (`zig build test --fuzz` exercises it continuously).

### Mesh authentication: `--mesh-key`

By default anyone on the LAN can join the mesh and inject results. With `--mesh-key <secret>` (the same secret on every node), each datagram carries a truncated HMAC-SHA256 tag and everything unauthenticated is dropped. Keyed meshes speak under their own protocol magic, so a keyed and an unkeyed mesh on one LAN ignore each other cleanly rather than half-seeing each other.

Scope, honestly stated: this authenticates and integrity-protects. It does **not** encrypt (measurements are readable on the wire) and does not prevent replay of captured datagrams — it keeps casual injection and accidental cross-talk out, not a determined on-LAN attacker.

### Node-to-node TCP and UDP pings

The ICMP matrix shows how each node sees the *scanned hosts*; mesh nodes additionally probe **each other** directly, over both transports:

- **UDP echo ping**: each node unicasts a small ping to every peer on the beacon cadence; the peer echoes it back. The ping carries the sender's monotonic clock as an opaque token, so the pong timestamps itself and no state is kept per ping. A pong slower than 10s is discarded as stale.
- **TCP connect ping**: each node listens on the mesh port over TCP, and peers time a full `SYN → SYN-ACK` handshake against it. The handshake is then torn down abortively — `SO_LINGER {on, 0s}`, so `close()` emits an **RST with a zero window** instead of a graceful FIN exchange — leaving no TIME_WAIT or half-open state on either side. The accepting node does the same to every connection it receives.

These measurements are **gossiped like everything else**: every node broadcasts its link results (message type 5, one small datagram) on the beacon cadence, so every node renders the full node×node `Node links` matrix — each cell is the RTT from the column node to the row node — not just its own row. An asymmetric cell pair (A→B fast, B→A slow) points at a duplex or buffering problem a single vantage point can't see.

Comparing UDP/TCP against the ICMP numbers separates the network from the stack: ICMP is often handled in the kernel's fast path (or deprioritized by rate limits), while TCP handshakes and UDP sockets exercise the same path your actual traffic takes.

TCP probes run concurrently on a dedicated thread, so one unreachable target never delays the others and RTTs are taken at socket readiness rather than being quantized by the render loop.

### TCP pings to devices not running the tool

A TCP connect ping doesn't need cooperation: anything with a known TCP port answers a SYN — with a SYN-ACK if the port is open, or an RST if it is closed. Both come from the target's network stack, so both are honest latency samples; closed-port samples are tagged `(rst)` in the display. Point `--tcp-ping` at a router's web UI, an SSH server, a printer:

```bash
sudo ./zig-out/bin/latency-heatmap --mesh --tcp-ping 192.168.1.1:443 --tcp-ping 192.168.1.20:9100
```

Up to 16 targets can be given; each is probed every 3 seconds alongside the peer probes. (No response at all — a firewall silently dropping the SYN — yields no sample, and the target ages out of the display after a few consecutive misses.)

Target results are gossiped too: the `tcp target` matrix shows the union of every node's targets as measured from every node, so a target configured on one node still gets a column from each vantage point that probes it (`---` where a node doesn't probe that target).

## Heatmap Legend

| Symbol | Latency | Color |
|--------|---------|-------|
| `█` | < 1ms | Bright Green |
| `▓` | < 5ms | Green |
| `▒` | < 20ms | Yellow |
| `░` | < 100ms | Orange |
| `▪` | > 100ms | Red |
| `·` | offline | Gray |

## Output Example

```
╔══════════════════════════════════════════════════════════════╗
║       Network Latency Heatmap Scanner                        ║
╚══════════════════════════════════════════════════════════════╝

  Subnet: 192.168.1.0/24
  Discovery timeout: 1000ms | Latency pings: 3 | Ping timeout: 1000ms
  Total IPs to scan: 254

  Phase 1: Discovery - scanning 254 hosts...
  Discovered: 4 hosts

  Phase 2: Measuring latency on 12 hosts (3 pings each)...

Legend: █ <1ms  ▓ <5ms  ▒ <20ms  ░ <100ms  ▪ >100ms  · offline

Active Devices:
192.168.1.1     192.168.1.10    192.168.1.15    192.168.1.20
█ 0.8ms         ▓ 2.1ms         ▒ 15.3ms        ░ 85.2ms
```

## Use Cases

- **Network troubleshooting**: Find hosts that are slow, lossy, or jittery — and whether they just became so
- **Network inventory**: Quick discovery of all active devices on a subnet, with names
- **Performance monitoring**: Leave mesh nodes running with `--http` and scrape them into Prometheus/Grafana; or script one-shot `--json` scans

## License

MIT
