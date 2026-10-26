# Network Latency Heatmap Scanner

[![CI](https://github.com/jmmoser/NetworkLatencyHeatmap/actions/workflows/ci.yml/badge.svg)](https://github.com/jmmoser/NetworkLatencyHeatmap/actions/workflows/ci.yml)

A fast network scanner that discovers hosts on your network and measures their latency, displaying results as a visual heatmap.

## Features

- **Cross-platform**: Runs natively on Linux (epoll), macOS/BSD (kqueue), and Windows (Winsock2 + WSAPoll)
- **Two-phase scanning**: Fast discovery phase followed by accurate latency measurement
- **Kernel receive timestamps**: Uses `SO_TIMESTAMP` on Linux and macOS so replies are stamped by the kernel on arrival — process wakeup and scheduling delay don't inflate measured RTTs (falls back to userspace timestamps where unavailable, including on Windows)
- **Monotonic timing**: All pacing, timeouts, and fallback measurements use `CLOCK_MONOTONIC` (`QueryPerformanceCounter` on Windows); kernel stamps (wall clock only) are cross-checked against a monotonic upper bound, so an NTP step or slew mid-scan can't corrupt samples or stall the scanner
- **Visual heatmap**: Color-coded latency display to quickly identify slow devices
- **Flicker-free live view**: the mesh matrix never clears the screen between frames — each redraw overwrites the previous frame in place (erasing only stale line tails and leftover rows), is emitted as a single write, and is wrapped in terminal synchronized output (mode 2026) so capable terminals commit it atomically. Frames are fitted to the terminal size (fewer observer columns and rows on small windows, then clipping with a "N more lines" note), so they never wrap or scroll out of place
- **Concurrent scanning**: Uses separate sender/receiver threads for maximum throughput
- **Large subnet support**: Can scan /16 networks (65k+ hosts); large on-link scans are paced so they don't overflow the kernel's ARP table (see `--rate`)
- **Loss and jitter**: every host gets packet loss and jitter (standard deviation) alongside min/avg/max, and the summary lists lossy devices
- **Retry pass**: addresses that stay silent are pinged again, so one lost packet doesn't hide a host
- **Finds hosts that ignore ping**: after the sweep, the neighbor (ARP) table is checked for hosts that answered ARP but not ICMP echo — e.g. Windows machines with the default firewall — and they're listed as "no ICMP"
- **Machine-readable output**: `--json` and `--csv` print results on stdout (the progress log moves to stderr), for tracking over time
- **Least privilege**: root is only used to open sockets and is dropped straight after (to the sudo user, or `nobody`); on Linux it can run without root entirely
- **Default-route-aware auto-detection**: With no subnet argument, the scanner picks the interface carrying the default route (not just the first one up), so VPN tunnels, VM bridges, and container networks don't hijack the scan — the chosen interface is printed so you can verify
- **Pipe-friendly output**: Colors and in-place progress bars are emitted only on a terminal; redirect to a file and you get plain text (`--no-color` and the `NO_COLOR` env var also disable color)
- **Mesh mode**: Run the scanner on several devices and they discover each other over UDP, gossip their results, and each render a live matrix of every host's latency from every vantage point. Traffic from outside the local subnets is ignored, and `--mesh-key` authenticates nodes with a shared secret
- **TCP and UDP node-to-node pings**: Mesh nodes also measure each other directly — a UDP echo ping and a TCP connect ping (SYN → SYN-ACK, torn down with an RST with a zero window) — so link latency between observers is visible alongside the ICMP matrix
- **TCP pings to anything with a known port**: `--tcp-ping ip:port` times the SYN → SYN-ACK (or RST from a closed port) of hosts that aren't running this tool at all — routers, printers, servers

## Requirements

- macOS/BSD (kqueue), Linux (epoll), or Windows 10+ (Winsock2) — uses raw ICMP sockets
- Elevated privileges for raw socket access: root/sudo on macOS and Linux, an Administrator prompt on Windows. Under sudo, root is dropped as soon as the sockets are open. (Root without the capability to switch users, such as a container started with `--cap-drop=ALL --cap-add=NET_RAW`, keeps running as that already-confined root and says so.) On Linux there are two ways to avoid sudo altogether:
  - grant the binary raw-socket access: `sudo setcap cap_net_raw+ep ./zig-out/bin/latency-heatmap`
  - or allow unprivileged ICMP "ping sockets" for your group (already the default on many distros, including Ubuntu and Fedora): `sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"` — the scanner falls back to one automatically when it can't open a raw socket
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

# Mesh mode: run this on each device; they find each other automatically
sudo ./zig-out/bin/latency-heatmap --mesh

# Mesh mode, also TCP-pinging the router's web UI and an SSH server
sudo ./zig-out/bin/latency-heatmap --mesh --tcp-ping 192.168.1.1:443 --tcp-ping 192.168.1.10:22

# Authenticated mesh: only nodes with the same secret see each other
sudo ./zig-out/bin/latency-heatmap --mesh --mesh-key-file ~/.config/latency-heatmap.key

# Machine-readable results, e.g. appended to a log by cron
sudo ./zig-out/bin/latency-heatmap 192.168.1.0/24 --json > scan-$(date +%s).json
sudo ./zig-out/bin/latency-heatmap 192.168.1.0/24 --csv 2>/dev/null
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d <ms>` | Discovery timeout in milliseconds | 1000 |
| `-p <count>` | Number of pings per host for latency measurement (1-16) | 5 |
| `-t <ms>` | Timeout per ping in latency phase | 1000 |
| `--rate <pps>` | Discovery send rate in pings/s (0 = unlimited) | unlimited; 300 for on-link subnets over 1024 hosts |
| `--retries <n>` | Extra discovery passes re-pinging silent addresses (0-10) | 1 |
| `--no-arp` | Don't report hosts that answer ARP but not ping | |
| `--json` | Print results as JSON on stdout; progress goes to stderr | |
| `--csv` | Print results as CSV on stdout; progress goes to stderr | |
| `--mesh` | Mesh mode: discover peers, share results, render the combined matrix | off |
| `--mesh-port <port>` | UDP+TCP port for mesh discovery, gossip, and node-to-node probes | 47269 |
| `--mesh-key <secret>` | Mesh mode: authenticate mesh traffic with a shared secret (visible in `ps`; prefer the file form) | none |
| `--mesh-key-file <path>` | Mesh mode: read the shared secret from a file (surrounding whitespace is trimmed) | none |
| `-i <sec>` | Mesh mode: rescan interval in seconds (0 = scan once) | 60 |
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
   - Re-pings the addresses that stayed silent (`--retries`, 1 extra pass by default); late replies to an earlier pass still count
   - Waits for the discovery timeout to collect responses (under the default timeout it gives up 500ms after sending if nothing at all answered; an explicit `-d` is always waited out in full, for slow links)
   - Records which hosts are alive
   - Checks the neighbor (ARP) table for hosts that answered ARP but not ping (see below)

2. **Phase 2: Latency Measurement**
   - For each discovered host, sends multiple pings
   - On Linux and macOS, reply arrival times come from kernel timestamps (`SCM_TIMESTAMP`), not userspace clocks, so scheduling jitter is excluded from the samples; Windows has no equivalent, so samples there use monotonic userspace timestamps taken at poll wakeup
   - Records min/avg/max latency, jitter (standard deviation), and packet loss for each host
   - The early-exit silence window scales with the slowest RTT observed so far, so replies from high-latency hosts still in flight aren't clipped by a burst of fast responders finishing first
   - Displays results with color-coded heatmap

### Discovery pacing

On a directly attached (on-link) subnet, the kernel has to ARP for every address before it can ping it, and each address waiting on ARP holds a neighbor-table entry for the ~3 seconds ARP takes to give up. Linux caps that table at 1024 entries by default (`net.ipv4.neigh.default.gc_thresh3`); past that the kernel drops packets and hosts silently go missing. So when an on-link scan covers more than 1024 addresses, discovery is paced to 300 pings/s by default — a /16 takes a few minutes instead of seconds, but finds every host. Routed subnets (reached through a gateway, no per-host ARP) and smaller scans go at full speed. `--rate` overrides the choice either way; `--rate 0` always blasts.

### Hosts that don't answer ping

Plenty of devices drop ICMP echo (Windows' default firewall does). A device on the local segment still has to answer ARP to receive anything, and the discovery sweep makes the kernel ARP for every address. So after the sweep the scanner reads the neighbor table and reports the addresses it resolved that never answered ping, as `no ICMP (ARP only)`. Entries left over from before the scan may be stale, so only entries this scan demonstrably resolved count: on Linux, those the kernel marks `REACHABLE` (netlink `RTM_GETNEIGH`); on macOS and Windows, which don't expose reachability, those that weren't in the table before the sweep. In mesh mode a host found that way stays listed on later rescans while its entry remains in the table, so once it leaves it can linger until the OS expires the entry (up to 20 minutes on macOS). This only sees hosts on the same layer-2 segment; `--no-arp` turns it off.

### Machine-readable output

`--json` prints one object per scan: subnet, timestamp, addresses scanned, pings per host, and a `hosts` array with `ip`, `responds_to_icmp`, `min_us`, `avg_us`, `max_us`, `stddev_us`, `sent`, `received` and `loss_pct` (`null` where there is no value). `--csv` prints the same per-host fields with a header row (missing values empty). The banner and progress log go to stderr, uncolored, so stdout stays parseable. Both report a single scan and can't be combined with `--mesh`.

The phases are deliberately sequential: latency is measured in a quiet window after the discovery blast, so probes never compete with the scanner's own traffic for the NIC and socket buffers.

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

How it works: each node broadcasts a small UDP beacon every 2 seconds to announce itself, and gossips its scan results (chunked to fit under the MTU) every 5 seconds plus immediately to newly joined peers. There is no coordinator — every node converges on the full matrix and renders it live. By default each node rescans every 60 seconds (`-i` changes this; `-i 0` scans once and keeps sharing). Mesh traffic is deliberately phase-separated from measurement: while a scan runs, only the tiny beacons keep flowing (so a long scan doesn't get the node dropped from its peers' tables, and incoming datagrams keep being drained), while result gossip is deferred until the scan completes — the mesh never competes with its own probes.

Incoming datagrams are treated as untrusted input. Anything whose source isn't on the scanned subnet or one of the machine's own interface subnets is dropped before it is parsed, so a forged beacon from elsewhere can't take a peer slot or trigger the results a new peer is sent. Beyond that: fixed caps on peers and hosts, strict length validation, and anything malformed or from a different protocol version is dropped silently.

#### Authenticated mesh

Anyone on the LAN can join an open mesh or forge its messages. With `--mesh-key <secret>` (or `--mesh-key-file <path>`, which keeps the secret out of the process list), every message carries an HMAC-SHA256 tag (truncated to 16 bytes) under a distinct protocol magic, and nodes drop anything not tagged with the same secret. Keyed and open meshes on the same port ignore each other. A tag alone proves a message was made by a key holder, not that it is fresh or came from where it claims, so a captured message could be replayed later from a forged source. To close that off, a keyed node trusts an address only after a challenge. A message from an unknown node, or from a known node at a new address, makes it ping that address with a fresh token. The node is accepted only once a pong echoing that exact token comes back from that address, which needs both the key and the address. A keyed peer also stays alive only by answering its latest ping, and results only move forward in sequence. So replays can't bring back a departed node, redirect a live one, trigger a results burst, or roll data back. What remains possible is re-delivering a peer's current data from its own address, or causing at most one challenge ping per second per (node, address), with no amplification. One consequence: two keyed nodes on the *same* machine (sharing the port via `SO_REUSEPORT`) generally can't pair, because the kernel may deliver a challenge ping back to its sender. Run keyed nodes on separate hosts.

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
| `·` | offline / no ICMP | Gray |

## Output Example

```
╔══════════════════════════════════════════════════════════════╗
║       Network Latency Heatmap Scanner                        ║
╚══════════════════════════════════════════════════════════════╝

  Subnet: 192.168.1.0/24 (auto-detected on en0, default route)
  Discovery timeout: 1000ms | Latency pings: 5 | Ping timeout: 1000ms
  Total IPs to scan: 253 (excluding 1 own address)
  ICMP socket: raw
  Receive timestamps: kernel (SO_TIMESTAMP)
  Privileges: dropped root after opening sockets (now uid 501, the sudo user)

  Phase 1: Discovery - scanning 253 hosts...
  Sent: 253/253 - waiting for replies...
  Retry 1: re-pinging 250 silent addresses...
  Sent: 250/250 - waiting for replies...
  Discovered: 3 hosts
  Neighbor table: 1 more host answers ARP but not ping

  Phase 2: Measuring latency on 3 hosts (5 pings each)...

Legend: █ <1ms  ▓ <5ms  ▒ <20ms  ░ <100ms  ▪ >100ms  · offline

Active Devices:

192.168.1.1                 192.168.1.10                192.168.1.15                192.168.1.20
█ 612µs/840µs/1.2ms         ▓ 1.9ms/2.1ms/2.6ms         ▒ 9.8ms/15.3ms/31.0ms       · no ICMP (ARP only)
±210µs · 0% loss            ±270µs · 0% loss            ±7.4ms · 20% loss
```

## Use Cases

- **Network troubleshooting**: Find hosts that are slow to respond
- **Network inventory**: Quick discovery of all active devices on a subnet
- **Performance monitoring**: Track latency to critical infrastructure

## License

MIT
