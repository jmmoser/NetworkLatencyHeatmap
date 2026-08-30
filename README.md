# Network Latency Heatmap Scanner

A fast network scanner that discovers hosts on your network and measures their latency, displaying results as a visual heatmap.

## Features

- **Two-phase scanning**: Fast discovery phase followed by accurate latency measurement
- **Kernel receive timestamps**: Uses `SO_TIMESTAMP` so replies are stamped by the kernel on arrival — process wakeup and scheduling delay don't inflate measured RTTs (falls back to userspace timestamps where unavailable)
- **Monotonic timing**: All pacing, timeouts, and fallback measurements use `CLOCK_MONOTONIC`; kernel stamps (wall clock only) are cross-checked against a monotonic upper bound, so an NTP step or slew mid-scan can't corrupt samples or stall the scanner
- **Visual heatmap**: Color-coded latency display to quickly identify slow devices
- **Concurrent scanning**: Uses separate sender/receiver threads for maximum throughput
- **Large subnet support**: Can scan /16 networks (65k+ hosts) efficiently
- **Mesh mode**: Run the scanner on several devices and they discover each other over UDP, gossip their results, and each render a live matrix of every host's latency from every vantage point
- **TCP and UDP node-to-node pings**: Mesh nodes also measure each other directly — a UDP echo ping and a TCP connect ping (SYN → SYN-ACK, torn down with an RST with a zero window) — so link latency between observers is visible alongside the ICMP matrix
- **TCP pings to anything with a known port**: `--tcp-ping ip:port` times the SYN → SYN-ACK (or RST from a closed port) of hosts that aren't running this tool at all — routers, printers, servers

## Requirements

- macOS (kqueue) or Linux (epoll) — uses raw ICMP sockets
- Root privileges (sudo) for raw socket access
- Zig 0.15+

## Building

```bash
zig build
```

Run the unit tests with:

```bash
zig build test
```

## Usage

```bash
sudo ./zig-out/bin/latency-heatmap [subnet/mask] [options]
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
| `-h, --help` | Show help message | |

## How It Works

1. **Phase 1: Discovery**
   - Blasts ICMP echo requests to all IPs in the subnet
   - Waits for the discovery timeout to collect responses
   - Records which hosts are alive

2. **Phase 2: Latency Measurement**
   - For each discovered host, sends multiple pings
   - Reply arrival times come from kernel timestamps (`SCM_TIMESTAMP`), not userspace clocks, so scheduling jitter is excluded from the samples
   - Records min/avg/max latency for each host
   - Displays results with color-coded heatmap

The phases are deliberately sequential: latency is measured in a quiet window after the discovery blast, so probes never compete with the scanner's own traffic for the NIC and socket buffers.

## Mesh Mode

A single scanner sees the network from exactly one vantage point. `--mesh` removes that limitation: run the tool on several devices on the same LAN and they find each other automatically, share their scan results, and each render an M×N latency matrix — every discovered host as measured from every observer.

```
  Node office-nas (id 1a2b3c4d) · UDP port 47269 · 2 peers · 14 targets

  target           self         laptop       pi4
                   3s ago       7s ago       12s ago
  192.168.1.1      █ 640µs      █ 812µs      ▓ 1.2ms
  192.168.1.42     ▓ 1.8ms      ▓ 2.1ms      ▒ 9.0ms      ◀ uneven

  Direct probes from this node · UDP echo / TCP SYN→SYN-ACK · (rst) = closed port answered
    laptop               udp 640µs         tcp 710µs
    pi4                  udp 8.1ms         tcp 8.4ms
    192.168.1.1:443      tcp 1.2ms
    192.168.1.9:22       tcp 3.4ms (rst)

  ⚠ Insights:
    Observer pi4 sees a median of 8.2ms vs 900µs mesh-wide — its own link is likely the bottleneck
```

Comparing the same host from multiple vantage points localizes problems a single scanner can't:

- A host slow from **every** observer is itself the problem (slow radio, power-saving NIC, overload)
- A host slow from **some** observers (`◀ uneven`) points at a link, switch, or AP between network segments
- An observer that measures **everything** slow has a bad uplink of its own — the insight section calls this out

How it works: each node broadcasts a small UDP beacon every 2 seconds to announce itself, and gossips its scan results (chunked to fit under the MTU) every 5 seconds plus immediately to newly joined peers. There is no coordinator — every node converges on the full matrix and renders it live. By default each node rescans every 60 seconds (`-i` changes this; `-i 0` scans once and keeps sharing). Mesh traffic is deliberately phase-separated from measurement: gossip only queues while a scan is running, so the mesh never competes with its own probes.

Incoming datagrams are treated as untrusted input: fixed caps on peers and hosts, strict length validation, and anything malformed or from a different protocol version is dropped silently.

### Node-to-node TCP and UDP pings

The ICMP matrix shows how each node sees the *scanned hosts*; mesh nodes additionally probe **each other** directly, over both transports, and render the results in a `Direct probes` section:

- **UDP echo ping**: each node unicasts a small ping to every peer on the beacon cadence; the peer echoes it back. The ping carries the sender's monotonic clock as an opaque token, so the pong timestamps itself and no state is kept per ping. A pong slower than 10s is discarded as stale.
- **TCP connect ping**: each node listens on the mesh port over TCP, and peers time a full `SYN → SYN-ACK` handshake against it. The handshake is then torn down abortively — `SO_LINGER {on, 0s}`, so `close()` emits an **RST with a zero window** instead of a graceful FIN exchange — leaving no TIME_WAIT or half-open state on either side. The accepting node does the same to every connection it receives.

Comparing the two against the ICMP numbers separates the network from the stack: ICMP is often handled in the kernel's fast path (or deprioritized by rate limits), while TCP handshakes and UDP sockets exercise the same path your actual traffic takes.

TCP probes run concurrently on a dedicated thread, so one unreachable target never delays the others and RTTs are taken at socket readiness rather than being quantized by the render loop.

### TCP pings to devices not running the tool

A TCP connect ping doesn't need cooperation: anything with a known TCP port answers a SYN — with a SYN-ACK if the port is open, or an RST if it is closed. Both come from the target's network stack, so both are honest latency samples; closed-port samples are tagged `(rst)` in the display. Point `--tcp-ping` at a router's web UI, an SSH server, a printer:

```bash
sudo ./zig-out/bin/latency-heatmap --mesh --tcp-ping 192.168.1.1:443 --tcp-ping 192.168.1.20:9100
```

Up to 16 targets can be given; each is probed every 3 seconds alongside the peer probes. (No response at all — a firewall silently dropping the SYN — yields no sample, and the target ages out of the display after a few consecutive misses.)

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

- **Network troubleshooting**: Find hosts that are slow to respond
- **Network inventory**: Quick discovery of all active devices on a subnet
- **Performance monitoring**: Track latency to critical infrastructure

## License

MIT
