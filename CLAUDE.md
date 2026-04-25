# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Network Traffic Monitor is a C++ application for capturing and analyzing network traffic, grouping activity by domain names. It monitors DNS queries (UDP port 53) and HTTP/HTTPS traffic (TCP ports 80, 443, 8080), extracting domain names and displaying aggregated statistics.

## Architecture

### Two Program Variants

The project contains two similar but differently-featured programs:

1. **network_monitor** (basic)
   - Core functionality: packet capture, domain extraction, statistics display
   - ~7 KB binary
   - Console-only output, domain/bytes/packets summary
   - Best for: quick debugging, simple monitoring

2. **network_monitor_advanced** (full-featured)
   - All basic features plus:
   - JSON report export with timestamp
   - Per-packet logging (last 1000 packets)
   - IP address tracking per domain
   - Detailed metadata (src/dst IP, port, protocol)
   - ~12 KB binary
   - Best for: security analysis, long-term monitoring, automation

Both programs share similar packet capture and domain extraction logic. Code reuse is intentional—they're slightly different builds for different use cases, not separate abstractions.

### Core Packet Processing Pipeline

```
pcap_loop (capture packets)
  → packet_handler callback
    → Parse ethernet header (skip 14 bytes)
    → Parse IP header, validate IPv4
    → Route to protocol handler (UDP or TCP)
      → UDP:53 → extract_domain_from_dns()
      → TCP:80/443/8080 → extract_domain_from_http()
    → Update domain_stats map
    → (Advanced only) Log to packet_log vector
```

### Data Structures

- **domain_stats**: `std::map<std::string, DomainStats>` — aggregated per-domain statistics
- **packet_log**: `std::vector<PacketInfo>` — detailed packet history (advanced only, limited to ~1000 entries)
- **DomainStats**: bytes_in, bytes_out, packets, last_seen timestamp, IPs list
- **PacketInfo**: domain, src/dst IP, port, protocol type, bytes, timestamp

## Build & Run Commands

### Compile Both Programs
```bash
make                    # Recommended: uses Makefile
# or
./build.sh              # Auto-checks dependencies, installs if needed
```

Clean build:
```bash
make clean && make
```

Manual compile (if Makefile not available):
```bash
clang++ -std=c++17 -Wall -Wextra -o network_monitor network_monitor.cpp -lpcap
clang++ -std=c++17 -Wall -Wextra -o network_monitor_advanced network_monitor_advanced.cpp -lpcap
```

### Run Programs

Basic monitor (choose interface interactively or specify):
```bash
sudo ./network_monitor          # Interactive interface selection
sudo ./network_monitor en0      # Specific interface (macOS)
sudo ./network_monitor eth0     # Specific interface (Linux)
```

Advanced monitor with JSON export:
```bash
sudo ./network_monitor_advanced
# Generates: traffic_report_YYYY-MM-DD_HH-MM-SS.json
```

Run and capture output:
```bash
sudo ./network_monitor en0 2>&1 | tee output.txt
```

### Test & Verification

Manual integration test:
```bash
# Terminal 1
sudo ./network_monitor en0

# Terminal 2 (generate traffic)
curl https://www.google.com
curl https://www.github.com
open https://www.example.com

# Terminal 1 (stop with Ctrl+C)
# Should display statistics showing captured domains
```

Verify JSON output (advanced):
```bash
sudo ./network_monitor_advanced
# Stop with Ctrl+C
cat traffic_report_*.json | jq '.domains | keys'
```

## Key Code Patterns & Libraries

### libpcap Usage
- **pcap_findalldevs()** — list available network interfaces
- **pcap_open_live()** — open device for live packet capture
- **pcap_compile()** — compile BPF filter string
- **pcap_setfilter()** — apply filter to reduce noise
- **pcap_loop()** — blocking loop that calls callback on each packet

Requires `-lpcap` linker flag. Provides raw packet access but NOT encrypted content (HTTPS payloads are encrypted).

### Protocol Parsing

**DNS (UDP port 53)**
- DNS format: label-length pairs followed by 0x00 terminator
- Example: `\x06google\x03com\x00` = "google.com"
- Only queries captured, responses ignored
- Function: `extract_domain_from_dns()` — walks label structure, builds domain string

**HTTP/HTTPS (TCP ports 80/443/8080)**
- Extract "Host:" header from HTTP request
- For HTTPS, SNI or Host header visible before encryption
- Function: `extract_domain_from_http()` — finds "Host: " substring, parses until \r\n, strips port if present
- Limitation: Encrypted TLS payload invisible, only SNI/Host header available

### Packet Structure (Wire Format)
```
Ethernet (14 bytes) → IP header (20 bytes) → UDP/TCP → Payload
[14 byte offset]    [parse version/protocol]  [parse port] [domain/HTTP]
```

Header sizes:
- Ethernet: 14 bytes (skip before IP)
- IP: minimum 20 bytes (ip_hl = IP header length in 32-bit words)
- UDP: 8 bytes (skip before DNS payload)
- TCP: variable (th_off = TCP header length in 32-bit words)

## Important Design Decisions

1. **Two separate programs instead of flags/options**
   - Different feature sets warrant different binaries rather than runtime flags
   - Both are lean; combining would bloat the basic use case

2. **In-memory statistics only**
   - No database backend—simple, portable, no dependencies beyond libpcap
   - Packet log limited to ~1000 entries (advanced) to bound memory

3. **BPF filtering at kernel level**
   - Filter applied during capture (not post-processing) for efficiency
   - Reduces noise and packet processing load
   - Default: `"udp port 53 or tcp port 80 or tcp port 443 or tcp port 8080"`
   - User can customize by editing `filter_str` variable and recompiling

4. **No encrypted payload inspection**
   - HTTPS content encrypted; only SNI/Host header visible
   - By design—no TLS interception, respects privacy
   - DNS-over-HTTPS (DoH) not supported (would need port 443 + TLS parsing)

5. **Root/sudo required**
   - Packet capture is a privileged operation on modern systems
   - No workaround in this code; ChmodBPF (macOS) or capabilities (Linux) for privilege elevation

## Common Development Tasks

### Add Support for New Protocol

Edit packet_handler() to detect new protocol, write parser function. Example: QUIC (UDP 443):

1. Add condition in UDP branch for port 443
2. Write `extract_domain_from_quic()` to parse QUIC Initial packet SNI
3. Update BPF filter: add `or udp port 443`
4. Compile and test

See DEVELOPMENT.md for detailed QUIC example.

### Add New Export Format (CSV, SQLite, etc.)

1. Write export function (e.g., `export_csv()`)
2. Call from main() after statistics collected
3. Format domain_stats or packet_log as needed

Example in DEVELOPMENT.md shows CSV export.

### Optimize for High-Traffic Environment

- Use `std::unordered_map` instead of `std::map` (O(1) vs O(log n))
- Increase snapshot length: `pcap_open_live(..., 262144, ...)`
- Tighten BPF filter to reduce packet count
- Consider thread-based processing (separate capture/processing threads)

### Modify BPF Filter

Edit `filter_str` in source, recompile. Common filters:
```cpp
"udp port 53"                      // DNS only
"tcp port 443"                     // HTTPS only
"(tcp or udp) port 53"            // Both TCP/UDP DNS
"host 8.8.8.8"                    // Specific IP
"dst net 192.168.0.0/16"          // Destination network
```

Reference: https://www.tcpdump.org/papers/sniffing-faq.html

## Important Gotchas & Limitations

1. **HTTPS is encrypted**
   - Can extract domain from SNI or Host header in plaintext TLS ClientHello
   - Encrypted payload (actual HTTP request/response) is invisible
   - DoH (DNS over HTTPS) appears as HTTPS traffic, domain not extracted

2. **Root privilege required**
   - Without sudo, pcap_open_live() fails with permission error
   - On macOS, can use ChmodBPF to run without sudo (not built-in)

3. **Interface selection**
   - Loopback (lo0) only sees local traffic
   - Wi-Fi (en0) or ethernet (eth0) needed for system-wide monitoring
   - Virtual interfaces (docker0, utun0) show only that network's traffic

4. **Fragmented packets**
   - IP fragmentation may break packet parsing
   - Reassembly not implemented; fragmented packets likely dropped/malformed

5. **Snapshot length vs. buffer**
   - `BUFSIZ` (usually 65535) is max packet size captured
   - Larger snapshots = more memory, slower processing
   - Increase only if needed for large packets or high traffic

6. **BPF filter is compile-time**
   - Cannot change filter at runtime without restarting capture
   - Recompile binary to change ports/protocols

7. **DNS over HTTPS (DoH) not captured**
   - Appears as regular HTTPS traffic on port 443
   - Domain not extracted (TLS payload encrypted)
   - Solution: monitor system DNS config; DoH is opt-in

## Testing & Debugging

### Generate Test Traffic
```bash
# Trigger DNS lookups
nslookup google.com
dig github.com

# HTTP traffic
curl http://example.com

# HTTPS traffic
curl https://www.wikipedia.org

# Monitor while generating:
sudo ./network_monitor en0 &
# ... run above commands ...
# kill %1 or Ctrl+C
```

### Inspect Packets with tcpdump (Validation)
```bash
# Show DNS traffic
sudo tcpdump -i en0 -n "udp port 53" -A | head -20

# Show HTTPS traffic with Host header
sudo tcpdump -i en0 -n "tcp port 443" -A | grep -i host

# Compare with our monitor output
```

### JSON Analysis (Advanced)
```bash
# View full report
cat traffic_report_*.json | jq '.'

# Top 10 domains by bytes
cat traffic_report_*.json | jq '.domains | to_entries | sort_by(.value.bytes) | reverse | .[0:10]'

# All DNS packets
cat traffic_report_*.json | jq '.packets[] | select(.protocol == "DNS")'

# Count unique domains
cat traffic_report_*.json | jq '.domains | length'
```

## Dependencies

- **libpcap** (required) — packet capture library
  - macOS: `brew install libpcap`
  - Linux (Ubuntu): `sudo apt-get install libpcap-dev`
  - Linux (CentOS): `sudo yum install libpcap-devel`

- **C++17 compiler** (required) — clang++ (preferred) or g++
  - macOS: Xcode Command Line Tools (`xcode-select --install`)
  - Linux: build-essential package

- **jq** (optional) — for JSON analysis
  - macOS: `brew install jq`
  - Linux: `sudo apt-get install jq`

## Documentation Structure

- **README.md** — Feature overview, quick start, basic troubleshooting
- **INSTALL.md** — Step-by-step installation for each platform
- **GETTING_STARTED.md** — Complete setup, usage, output explanation
- **QUICK_REFERENCE.md** — Command cheat sheet, printable reference card
- **EXAMPLES.md** — 15 real-world use cases (browser, Docker, gaming, security, etc.)
- **DEVELOPMENT.md** — Technical deep-dive, extending the code, testing
- **INDEX.md** — Project structure and file cross-reference

User-facing docs assume readers will start with README → INSTALL → GETTING_STARTED → EXAMPLES for their use case. DEVELOPMENT is for extending/modifying code. QUICK_REFERENCE is for experienced users.

## Code Style Notes

- Variables: `snake_case`
- Functions: `snake_case`
- Structs: `PascalCase`
- Comments: Only explain WHY (not WHAT); code should be self-documenting
- No multi-line docstrings; inline comments max 1 line
- Prefer clarity over brevity
- Avoid over-engineering for hypothetical future needs

## Future Enhancement Ideas (Not Implemented)

- Protocol: QUIC (UDP 443), DoH (TLS + DNS parsing)
- Output: SQLite database, CSV export, Prometheus metrics
- Performance: Multi-threaded capture/processing, ring buffer for high traffic
- UI: Web dashboard with real-time updates
- Features: IP geolocation, ASN lookup, suspicious domain detection

See DEVELOPMENT.md for code patterns and examples.
