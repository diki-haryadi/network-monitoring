# Network Monitor - Project Index

Ringkasan lengkap file-file dalam project.

## 📁 Project Structure

```
network-monitoring/
├── network_monitor.cpp              # Basic monitor program
├── network_monitor_advanced.cpp     # Advanced with JSON export
├── Makefile                         # Build automation
├── build.sh                         # Build script (alternative)
│
├── README.md                        # Overview & quick start
├── GETTING_STARTED.md               # Detailed setup guide
├── EXAMPLES.md                      # Real-world use cases
├── DEVELOPMENT.md                   # Technical documentation
├── INDEX.md                         # This file
│
├── traffic_report_*.json            # Generated reports (after run)
└── *.log                           # Generated logs
```

## 📄 File Descriptions

### Source Code

#### `network_monitor.cpp` (7 KB)
**Basic network monitoring program**

- ✅ DNS packet capture (UDP port 53)
- ✅ HTTP/HTTPS traffic monitoring (TCP port 80, 443, 8080)
- ✅ Domain grouping by name
- ✅ Statistics display (domains sorted by bytes)
- ❌ No file output
- ❌ No detailed packet log

**Best for**: Quick network debugging, simple monitoring

**Key Functions**:
- `extract_domain_from_dns()` - Parse DNS queries
- `extract_domain_from_http()` - Parse HTTP Host header
- `packet_handler()` - Main packet processing
- `print_stats()` - Display statistics

#### `network_monitor_advanced.cpp` (12 KB)
**Advanced monitoring with JSON export**

- ✅ Semua fitur basic
- ✅ JSON report export
- ✅ Per-packet logging (last 1000 packets)
- ✅ IP tracking per domain
- ✅ Timestamp untuk setiap activity
- ✅ Structured data output

**Best for**: Security analysis, long-term monitoring, data collection

**Key Functions**:
- `get_timestamp()` - Format timestamp
- `export_json()` - Export ke JSON format
- `print_console_stats()` - Enhanced console output
- Plus semua functions dari basic version

### Build Files

#### `Makefile`
Build automation dengan make command.

**Usage**:
```bash
make              # Compile both programs
make clean        # Remove binaries
make run          # Run basic monitor with sudo
```

**Compiler Settings**:
- Language: C++17
- Warnings: -Wall -Wextra
- Library: libpcap

#### `build.sh`
Bash script untuk automated build dengan dependency check.

**Features**:
- Check libpcap installation
- Auto-install libpcap jika needed
- Compile both programs
- Show usage instructions

**Usage**:
```bash
chmod +x build.sh
./build.sh
```

### Documentation

#### `README.md` (3 KB)
**Overview dan Quick Start**

- Project features overview
- System requirements
- Compilation instructions
- Basic usage examples
- Output format explanation
- Troubleshooting guide

**When to read**: First time setup

#### `GETTING_STARTED.md` (8 KB)
**Complete Setup & Usage Guide**

- Prerequisites & installation
- Quick start 3-step guide
- Program comparison
- Use cases
- Output examples
- Troubleshooting detailed
- Security notes
- Tips & tricks

**When to read**: Learning how to use properly

#### `EXAMPLES.md` (10 KB)
**Real-World Examples & Scripts**

- 15 detailed use case examples:
  - Browser monitoring
  - Docker containers
  - Mobile devices
  - Gaming servers
  - Security monitoring
  - Performance analysis
  - DNS leak detection
  - VPN monitoring
  - System updates
  - Malware detection
  - API monitoring
  - Streaming services
  - Automation scripts
  - Packet analysis
  - Performance profiling

**When to read**: Need practical examples

#### `DEVELOPMENT.md` (12 KB)
**Technical Documentation for Developers**

- Architecture flowchart
- Data structures detail
- Key functions explanation
- Protocol parsing guide
- Adding new protocols (QUIC example)
- Adding new export formats (CSV example)
- Optimization tips
- Testing strategies
- Code style guide
- Debugging techniques
- Compilation options
- References

**When to read**: Want to extend/modify code

#### `INDEX.md` (This file)
**Project structure & file guide**

---

## 🎯 Quick Reference

### Compilation

```bash
# Option 1: Using Makefile (recommended)
make

# Option 2: Using build script
./build.sh

# Option 3: Manual
clang++ -std=c++17 -Wall -Wextra -o network_monitor network_monitor.cpp -lpcap
clang++ -std=c++17 -Wall -Wextra -o network_monitor_advanced network_monitor_advanced.cpp -lpcap
```

### Running

```bash
# Basic monitor
sudo ./network_monitor

# Specify interface
sudo ./network_monitor en0

# Advanced with JSON
sudo ./network_monitor_advanced

# Save output to file
sudo ./network_monitor 2>&1 | tee output.txt

# Run in background
nohup sudo ./network_monitor en0 > monitor.log 2>&1 &
```

### Analysis

```bash
# View JSON report
cat traffic_report_*.json | jq '.'

# Top domains by bytes
cat traffic_report_*.json | jq '.domains | to_entries | sort_by(.value.bytes) | reverse | .[0:5]'

# All captured packets
cat traffic_report_*.json | jq '.packets[]'

# DNS queries only
cat traffic_report_*.json | jq '.packets[] | select(.protocol == "DNS")'

# Group by IP
cat traffic_report_*.json | jq '.packets | group_by(.dst_ip)'
```

---

## 🔍 Finding Information

### "How do I...?"

| Question | File | Section |
|----------|------|---------|
| ...compile the code? | README.md | Compilation |
| ...run the monitor? | GETTING_STARTED.md | Quick Start |
| ...use specific interface? | EXAMPLES.md | Contoh 3 |
| ...export to JSON? | GETTING_STARTED.md | Advanced Monitor JSON Export |
| ...analyze traffic? | EXAMPLES.md | Contoh 13-15 |
| ...add QUIC support? | DEVELOPMENT.md | Adding New Protocol Support |
| ...optimize performance? | DEVELOPMENT.md | Optimization Tips |
| ...fix permission error? | GETTING_STARTED.md | Troubleshooting |

### By Use Case

| Use Case | Best Doc | Program |
|----------|----------|---------|
| Quick debugging | README.md | basic |
| Security monitoring | EXAMPLES.md (Contoh 5) | advanced |
| API analysis | EXAMPLES.md (Contoh 11) | advanced |
| Continuous monitoring | GETTING_STARTED.md | advanced |
| Development/extension | DEVELOPMENT.md | either |

---

## 📊 Statistics Provided

### Basic Monitor
Per-domain statistics:
- Total packets received
- Total bytes received
- Last activity timestamp

### Advanced Monitor
Same as basic, plus:
- IP addresses associated
- Detailed packet log
- Timestamp untuk setiap packet
- Protocol type (DNS/HTTP/HTTPS)
- Source IP, Destination IP
- Port number

---

## 🔧 Customization

Common modifications:

1. **Change BPF filter**: Edit `filter_str` variable
2. **Change ports monitored**: Edit TCP/UDP port checks
3. **Add new protocol**: See DEVELOPMENT.md
4. **Change statistics display**: Modify `print_stats()` function
5. **Add new export format**: See DEVELOPMENT.md

---

## 📦 Dependencies

### Required
- **libpcap** - Packet capture library
  - macOS: `brew install libpcap`
  - Linux: `sudo apt-get install libpcap-dev`

### Optional
- **jq** - JSON query processor (untuk analyze results)
  - macOS: `brew install jq`
  - Linux: `sudo apt-get install jq`

---

## 🚀 Getting Started in 3 Steps

1. **Compile**
   ```bash
   ./build.sh
   # atau
   make
   ```

2. **Run**
   ```bash
   sudo ./network_monitor en0
   # atau untuk advanced
   sudo ./network_monitor_advanced
   ```

3. **View Results**
   ```bash
   # Console output saat stop (Ctrl+C)
   # JSON files di current directory (advanced only)
   cat traffic_report_*.json | jq '.domains | keys'
   ```

---

## 💡 Tips

- Read **README.md** first untuk overview
- Read **GETTING_STARTED.md** untuk setup
- Browse **EXAMPLES.md** untuk inspiration
- Check **DEVELOPMENT.md** untuk technical details
- Use **INDEX.md** ini untuk quick navigation

---

## ❓ FAQ

**Q: Do I need sudo?**  
A: Yes, packet capture requires root privileges.

**Q: What interfaces can I monitor?**  
A: Any active network interface (en0, eth0, wlan0, etc.). Use `ifconfig` or `ip link` to list.

**Q: Can I monitor HTTPS traffic?**  
A: Domain names yes (from SNI/Host header), but encrypted content no.

**Q: How much disk space needed?**  
A: Advanced monitor logs last 1000 packets in JSON, ~100-500 KB per report.

**Q: Can I run multiple monitors?**  
A: Yes, on different interfaces or ports.

**Q: Is this safe to run?**  
A: Yes, read-only monitoring. No packets modified or sent.

**Q: Performance impact?**  
A: Minimal - uses efficient packet filtering (BPF).

---

## 📞 Support

- Check troubleshooting section in GETTING_STARTED.md
- Review relevant EXAMPLES.md for similar use cases
- See DEVELOPMENT.md for technical issues
- Run `man pcap` for libpcap documentation

---

**Last Updated**: April 2026  
**Version**: 1.0  
**License**: MIT
