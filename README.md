# Network Latency Heatmap Scanner

[![CI](https://github.com/jmmoser/NetworkLatencyHeatmap/actions/workflows/ci.yml/badge.svg)](https://github.com/jmmoser/NetworkLatencyHeatmap/actions/workflows/ci.yml)

A fast network scanner that discovers hosts on your network and measures their latency, displaying results as a visual heatmap — and, in watch mode, as a timeline: one cell per host per scan, so you can see *when* a host went bad, not just that it is bad now.

## Features

- **Cross-platform**: Runs natively on Linux (epoll), macOS/BSD (kqueue), and Windows (Winsock2 + WSAPoll)
- **Two-phase scanning**: Fast discovery phase followed by accurate latency measurement
- **Kernel receive timestamps**: Uses `SO_TIMESTAMP` on Linux and macOS so replies are stamped by the kernel on arrival — process wakeup and scheduling delay don't inflate measured RTTs (falls back to userspace timestamps where unavailable, including on Windows)
- **Monotonic timing**: All pacing, timeouts, and fallback measurements use `CLOCK_MONOTONIC` (`QueryPerformanceCounter` on Windows); kernel stamps (wall clock only) are cross-checked against a monotonic upper bound, so an NTP step or slew mid-scan can't corrupt samples or stall the scanner
- **Visual heatmap**: Color-coded latency display to quickly identify slow devices
- **Time axis**: `-i <sec>` rescans on an interval and keeps the last 120 scans per host, rendered as a live timeline strip per host (oldest left, newest right) with a time ruler, window averages, and packet loss — intermittent problems that a single snapshot can never catch become a visible pattern
- **Packet loss**: Every scan records probes sent and answered per host; a cell is colored by the worse of latency and loss, so a host answering 2 of 5 probes at 1ms is not painted healthy green
- **Change detection**: Each host is compared against its own baseline (the median of its earlier scans), and the view names the hosts that degraded, started dropping probes, went offline, or newly appeared — and since when
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
- Zig 0.16+

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

# Watch mode: rescan every 10 seconds and render a live timeline per host
sudo ./zig-out/bin/latency-heatmap -i 10

# Same, logged to a file (one plain-text snapshot per scan, with UTC timestamps)
sudo ./zig-out/bin/latency-heatmap -i 30 > latency.log

# Mesh mode: run this on each device; they find each other automatically
sudo ./zig-out/bin/latency-heatmap --mesh

# Mesh mode, also TCP-pinging the router's web UI and an SSH server
sudo ./zig-out/bin/latency-heatmap --mesh --tcp-ping 192.168.1.1:443 --tcp-ping 192.168.1.10:22
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d <ms>` | Discovery timeout in milliseconds | 1000 |
| `-p <count>` | Number of pings per host for latency measurement (1-16) | 5 |
| `-t <ms>` | Timeout per ping in latency phase | 1000 |
| `--mesh` | Mesh mode: discover peers, share results, render the combined matrix | off |
| `--mesh-port <port>` | UDP+TCP port for mesh discovery, gossip, and node-to-node probes | 47269 |
| `-i <sec>` | Rescan interval in seconds; keeps a rolling history and renders it as a timeline (0 = scan once) | 0 standalone, 60 in mesh mode |
| `--tcp-ping <ip:port>` | Mesh mode: TCP-ping this host on a known port (repeatable, up to 16) | none |
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
   - Records min/avg/max latency and probes sent/answered (packet loss) for each host
   - The early-exit silence window scales with the slowest RTT observed so far, so replies from high-latency hosts still in flight aren't clipped by a burst of fast responders finishing first
   - Displays results with color-coded heatmap

The phases are deliberately sequential: latency is measured in a quiet window after the discovery blast, so probes never compete with the scanner's own traffic for the NIC and socket buffers.

## Watch Mode: the time axis

A single scan is a snapshot, and the problems people reach for a latency tool to diagnose are almost never visible in a snapshot: the Wi-Fi that hiccups every few minutes, the NAS that stalls under backup load, the switch port that drops a fraction of everything. `-i <sec>` turns the heatmap into a timeline. The scanner rescans on the interval, keeps the last 120 scans per host, and redraws the view in place:

```
  192.168.1.0/24 · scan #47 every 10s · 13 hosts up of 14 seen · running 7m50s · 13:11:18Z
  Next rescan in 6s

  host             -6m40s    -5m       -3m20s    -1m40s   now  now         avg/worst       loss
  192.168.1.1      ████████████████████████████████████████  █ 640µs     612µs/1.2ms     0%
  192.168.1.9      ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▓ 1.8ms     1.7ms/2.4ms     0%
  192.168.1.42     ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░  ░ 48.2ms    9.1ms/61.0ms    0%
  192.168.1.77     ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  ▓ 2.1ms     2.0ms/2.6ms     0%
  192.168.1.120    ▓▓▓▓▒▓▓▓▓▓▒▒▓▓▓▓▓▓▒▓▓▓▓▓▒▓▓▓▓▓▓▒▓▓▓▓▓▓▒▓  ▒ 2.3ms     2.2ms/3.0ms    11%
  192.168.1.200    ████████████████████████████·····×······  · gone      710µs/900µs     0%

  Legend: █ <1ms  ▓ <5ms  ▒ <20ms  ░ <100ms  ▪ >100ms  × no reply  · not found  (loss >20% ▒, >50% ░)
  each cell is one scan, oldest left, showing the worse of latency and loss · avg/worst and loss cover the whole window

  ⚠ Changes:
    192.168.1.200 stopped answering 1m50s ago (was 710µs)
    192.168.1.120 dropping probes since 40s ago: 20% loss, 2.3ms when it answers (usually 2.2ms)
    192.168.1.42 degraded 2m20s ago: 48.2ms now vs 9.1ms usually
```

Each row is one host; each cell is one scan, oldest on the left. The ruler above the strip is built from the actual scan timestamps, so it stays honest when a scan takes longer than the interval. The strip is as wide as the terminal allows (up to 120 scans); `avg/worst` and `loss` summarize the whole window, while `now` is the newest scan.

Three things become visible that a snapshot hides:

- **When it started.** `.42` was fine for the first two thirds of the window and has been slow since — something changed at that moment (a backup job, a new client on the AP). A host that has always been slow is not flagged, because it is compared against its own baseline, not an absolute threshold.
- **Intermittent loss.** `.120` looks fine in any single scan (2ms) but the strip shows a `▒` every few scans: it drops a probe now and then. Cells show the worse of latency and loss — a host answering 2 of 5 probes at 1ms is painted by the loss, not the latency — so this pattern cannot hide behind fast replies.
- **Disappearance.** `.200` stopped being discovered (`·`), briefly answered discovery but no probes (`×`), and is gone. The `Changes` section says since when and what it used to measure.

Change detection compares each host's newest scans against the median of its earlier ones, and only reports a run of at least two bad scans (one blip is noise) with at least four normal scans before it (so the baseline is real). "Bad" means gone, dropping ≥20% of probes, or ≥3x slower than baseline and more than 2ms apart.

When stdout is not a terminal, every scan appends one plain-text snapshot (with a UTC clock in the header) instead of redrawing, so `-i 30 > latency.log` gives a log you can grep later.

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

On a wide enough terminal the matrix also carries a `self, per scan` timeline strip per row (this node's own scans over time, as in watch mode), and every node keeps a history for each peer's gossiped results too, so the `Changes` section reports hosts that recently degraded, went lossy, or vanished — as seen from each vantage point. A host that degraded from every observer at the same moment is itself the problem; one that degraded from only one observer points at that observer's path. Cells in the matrix show the worse of latency and loss, with `✗N%` after the latency when probes were dropped.

Comparing the same host from multiple vantage points localizes problems a single scanner can't:

- A host slow from **every** observer is itself the problem (slow radio, power-saving NIC, overload)
- A host slow from **some** observers (`◀ uneven`) points at a link, switch, or AP between network segments
- An observer that measures **everything** slow has a bad uplink of its own — the insight section calls this out

How it works: each node broadcasts a small UDP beacon every 2 seconds to announce itself, and gossips its scan results (chunked to fit under the MTU; each entry carries min/avg/max and the probe counts sent and answered) every 5 seconds plus immediately to newly joined peers. There is no coordinator — every node converges on the full matrix and renders it live. By default each node rescans every 60 seconds (`-i` changes this; `-i 0` scans once and keeps sharing). Mesh traffic is deliberately phase-separated from measurement: while a scan runs, only the tiny beacons keep flowing (so a long scan doesn't get the node dropped from its peers' tables, and incoming datagrams keep being drained), while result gossip is deferred until the scan completes — the mesh never competes with its own probes.

Incoming datagrams are treated as untrusted input: fixed caps on peers and hosts, strict length validation, and anything malformed or from a different protocol version is dropped silently. (The protocol magic is `NLH2`; nodes still running the `NLH1` build — whose entries lack the probe counts — ignore each other and this version, so mixing them is harmless but they will not see each other.)

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

| Symbol | Latency | or packet loss | Color |
|--------|---------|----------------|-------|
| `█` | < 1ms | 0% | Bright Green |
| `▓` | < 5ms | | Green |
| `▒` | < 20ms | ≤ 20% | Yellow |
| `░` | < 100ms | ≤ 50% | Orange |
| `▪` | > 100ms | > 50% | Red |
| `×` | discovered, but no probe answered | 100% | Red |
| `·` | not discovered / offline | | Gray |

A cell shows the worse of its two columns: a host at 800µs that dropped 2 of 5 probes is `░`, not `█`. In the single-scan grid, loss is also printed after the min/avg/max as `✗N%`.

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
█ 0.8ms         ▓ 2.1ms         ▒ 15.3ms        ░ 85.2ms ✗20%
```

## Use Cases

- **Network troubleshooting**: Find hosts that are slow to respond
- **Network inventory**: Quick discovery of all active devices on a subnet
- **Performance monitoring**: Track latency to critical infrastructure over time with `-i`, and see exactly when something changed
- **Intermittent problems**: Catch the Wi-Fi that drops out every few minutes or the host that loses a probe every few scans — patterns no single scan can show

## License

MIT
