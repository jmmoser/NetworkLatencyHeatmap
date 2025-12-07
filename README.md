# Local Network Latency Heatmap Scanner

A fast network scanner that discovers hosts on your local network and measures their latency, displaying results as a visual heatmap.

## Features

- **Two-phase scanning**: Fast discovery phase followed by accurate latency measurement
- **Visual heatmap**: Color-coded latency display to quickly identify slow devices
- **Concurrent scanning**: Uses separate sender/receiver threads for maximum throughput
- **Large subnet support**: Can scan /16 networks (65k+ hosts) efficiently

## Requirements

- macOS (uses raw ICMP sockets)
- Root privileges (sudo) for raw socket access
- Zig 0.15+

## Building

```bash
zig build
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
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-d <ms>` | Discovery timeout in milliseconds | 1000 |
| `-p <count>` | Number of pings per host for latency measurement | 3 |
| `-t <ms>` | Timeout per ping in latency phase | 1000 |
| `-h, --help` | Show help message | |

## How It Works

1. **Phase 1: Discovery**
   - Blasts ICMP echo requests to all IPs in the subnet
   - Waits for the discovery timeout to collect responses
   - Records which hosts are alive

2. **Phase 2: Latency Measurement**
   - For each discovered host, sends multiple pings
   - Records minimum latency for each host
   - Displays results with color-coded heatmap

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
║       Local Network Latency Heatmap Scanner                  ║
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
