# Development Guide - Network Monitor

Dokumentasi teknis untuk developers yang ingin extend atau modify program.

## 📐 Arsitektur

### Program Flow

```
┌─────────────────────────────────────┐
│ List Network Interfaces             │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│ Open Device dengan pcap_open_live   │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│ Compile BPF Filter                  │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│ Capture Packets (pcap_loop)         │
└──────────────────┬──────────────────┘
                   │
    ┌──────────────┴──────────────┐
    │                             │
    ▼                             ▼
┌──────────────┐          ┌──────────────┐
│ packet_handler          │ Parse Layers │
└──────┬───────┘          └──────────────┘
       │
       ├─ IP Layer (skip ethernet header)
       │
       ├─ Protocol Check (TCP/UDP)
       │
       ├─ If UDP:53 → Parse DNS
       │
       └─ If TCP:80/443 → Parse HTTP Host
           │
           ▼
       Update Statistics Map
           │
           ▼
       Log Packets (advanced only)

                   │
                   ▼ (Ctrl+C)
┌─────────────────────────────────────┐
│ Print Statistics                    │
└──────────────────┬──────────────────┘
                   │
                   ▼
┌─────────────────────────────────────┐
│ Export JSON (advanced only)         │
└─────────────────────────────────────┘
```

## 🏗️ Data Structures

### DomainStats
```cpp
struct DomainStats {
    std::string domain;              // Domain name
    uint64_t bytes_in = 0;          // Total bytes received
    uint64_t bytes_out = 0;         // Total bytes sent
    uint64_t packets = 0;           // Total packets
    std::string last_seen;          // Last activity timestamp
    std::vector<std::string> ips;   // Associated IPs (advanced)
};
```

### PacketInfo (Advanced Only)
```cpp
struct PacketInfo {
    std::string domain;             // Domain name
    std::string src_ip;             // Source IP
    std::string dst_ip;             // Destination IP
    uint16_t port;                  // Port number
    std::string protocol;           // Protocol (DNS/HTTP/HTTPS)
    uint64_t bytes;                 // Packet size
    std::string timestamp;          // When captured
};
```

## 🔧 Key Functions

### `extract_domain_from_dns()`
**Purpose**: Parse DNS query format dan extract domain name

**Input**:
- `data`: DNS packet payload (after UDP header)
- `len`: Length of DNS data

**Output**: Domain string (e.g., "google.com")

**DNS Format**:
```
Offset  Length  Content
0       2       Transaction ID
2       2       Flags
4       2       Questions
6       2       Answer RRs
...
12      ?       Questions Section
        
Questions Section Format:
┌──────────┬──────────┐
│ Q Name   │ Q Type   │
│ (domain) │ (2 bytes)│
└──────────┴──────────┘

Domain Name Format:
[length byte][label chars]...[0x00]

Example: "google.com"
0x06 + 'google' + 0x03 + 'com' + 0x00
  6        +  'google'  +  3    +  'com'  + null
```

### `extract_domain_from_http()`
**Purpose**: Parse HTTP Host header dari captured traffic

**Input**:
- `data`: TCP payload (HTTP content)
- `len`: Length of payload

**Output**: Domain string (from "Host:" header)

**HTTP Format**:
```
GET / HTTP/1.1\r\n
Host: www.google.com:443\r\n
User-Agent: ...\r\n
...
```

**Algorithm**:
1. Find "Host: " substring
2. Extract sampai "\r\n"
3. Remove port jika ada (`:` separator)

### `packet_handler()`
**Purpose**: Callback untuk setiap packet yang ditangkap

**Parameters**:
- `user_data`: Custom data (unused)
- `pkthdr`: Packet header dari libpcap
- `packet`: Raw packet data

**Processing**:
1. Skip Ethernet header (14 bytes)
2. Cast ke IP header
3. Check IP version (IPv4 only)
4. Route ke UDP atau TCP handler
5. Update statistics

## 🔌 Adding New Protocol Support

### Contoh: Menambah QUIC (UDP port 443)

1. **Extend packet_handler()** di bagian UDP:

```cpp
if (ip_header->ip_p == IPPROTO_UDP) {
    struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl * 4));
    int udp_port = ntohs(udp_header->uh_dport);

    // Existing DNS code
    if (udp_port == 53 || ntohs(udp_header->uh_sport) == 53) {
        // DNS handling
    }
    
    // NEW: QUIC support
    else if (udp_port == 443) {
        const u_char* quic_data = packet + 14 + (ip_header->ip_hl * 4) + 8;
        int quic_len = pkthdr->len - 14 - (ip_header->ip_hl * 4) - 8;
        domain = extract_domain_from_quic(quic_data, quic_len);
        protocol = "QUIC";
        is_valid = true;
    }
}
```

2. **Implement parser**:

```cpp
std::string extract_domain_from_quic(const u_char* data, int len) {
    // QUIC packet structure:
    // [1 byte flags][4 bytes version][variable CID]...[payload]
    // 
    // SNI (Server Name Indication) ada di Initial packet
    // Need to parse TLS ClientHello dalam QUIC packet
    
    if (len < 1200) return "";  // QUIC initial packets minimal 1200 bytes
    
    // Parse SNI dari TLS ClientHello
    // This is complex, requires TLS parsing
    // Simplified version shown
    
    return "";  // Implement based on QUIC spec RFC 9000
}
```

3. **Update BPF filter**:

```cpp
std::string filter_str = "udp port 53 or tcp port 80 or tcp port 443 or tcp port 8080 or udp port 443";
```

4. **Compile dan test**:

```bash
clang++ -std=c++17 -Wall -Wextra -o network_monitor_quic network_monitor_quic.cpp -lpcap
sudo ./network_monitor_quic en0
```

## 📊 Adding New Export Format

### Contoh: Export ke CSV

1. **Add CSV export function**:

```cpp
void export_csv(const std::string& filename) {
    std::ofstream file(filename);
    
    // Header
    file << "Domain,Packets,Bytes,IPs,LastSeen\n";
    
    // Data rows
    for (const auto& [domain, stats] : domain_stats) {
        file << domain << ","
             << stats.packets << ","
             << stats.bytes_in << ","
             << stats.ips.size() << ","
             << stats.last_seen << "\n";
    }
    
    file.close();
}
```

2. **Call dari main()**:

```cpp
// Setelah print_console_stats()
std::string csv_filename = "traffic_report_" + timestamp + ".csv";
export_csv(csv_filename);
```

3. **Use dengan Excel/Google Sheets**:

```bash
open traffic_report_*.csv  # Opens in default app
# atau
cat traffic_report_*.csv | column -t -s,
```

## 🎯 Optimization Tips

### 1. Reduce Memory Usage

**Before**:
```cpp
std::vector<PacketInfo> packet_log;  // Store semua packets
// For 1 hour monitoring: ~MB memory
```

**After**:
```cpp
// Store hanya summary statistics
std::map<std::string, DomainStats> domain_stats;
// Much smaller memory footprint
```

### 2. Faster Packet Processing

**Use `std::unordered_map` instead of `std::map`**:
```cpp
// Before
std::map<std::string, DomainStats> domain_stats;

// After
std::unordered_map<std::string, DomainStats> domain_stats;
// O(1) average lookup vs O(log n)
```

### 3. Thread-Safe Monitoring

```cpp
#include <thread>
#include <queue>
#include <mutex>

std::queue<PacketInfo> packet_queue;
std::mutex queue_mutex;

// Packet capture thread
void capture_thread() {
    pcap_loop(handle, -1, packet_handler, nullptr);
}

// Processing thread
void process_thread() {
    while (running) {
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            while (!packet_queue.empty()) {
                auto pkt = packet_queue.front();
                packet_queue.pop();
                // Process packet
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}
```

## 🧪 Testing

### Unit Tests

```cpp
// test_dns_parser.cpp
#include <cassert>

void test_extract_domain() {
    // Example DNS query for "google.com"
    u_char dns_packet[] = {
        // DNS header
        0x00, 0x01,  // ID
        0x01, 0x00,  // Flags
        0x00, 0x01,  // Questions
        0x00, 0x00,  // Answers
        0x00, 0x00,  // Authority
        0x00, 0x00,  // Additional
        // Query
        0x06, 'g', 'o', 'o', 'g', 'l', 'e',  // "google"
        0x03, 'c', 'o', 'm',                 // "com"
        0x00,                                 // null terminator
        0x00, 0x01,                          // Type A
        0x00, 0x01                           // Class IN
    };
    
    std::string domain = extract_domain_from_dns(dns_packet, sizeof(dns_packet));
    assert(domain == "google.com");
    
    std::cout << "✓ DNS parser test passed" << std::endl;
}
```

### Integration Tests

```bash
# Test dengan real interface
sudo ./network_monitor en0 &
MONITOR_PID=$!

# Generate network traffic
curl https://www.example.com

# Stop after 5 seconds
sleep 5
kill $MONITOR_PID

# Verify output contains "example.com"
```

## 📝 Code Style

### Naming Conventions

```cpp
// Variables: snake_case
std::string src_ip;
uint64_t bytes_in;
bool is_outgoing;

// Functions: snake_case
void extract_domain_from_dns();
void packet_handler();

// Classes/Structs: PascalCase
struct DomainStats { };
struct PacketInfo { };

// Constants: UPPER_SNAKE_CASE
#define DNS_PORT 53
const int ETHERNET_HEADER_SIZE = 14;
```

### Comments

```cpp
// Good: Explains WHY
if (label_len > 63) return "";  // DNS labels max 63 bytes per RFC 1035

// Bad: Explains WHAT (code already shows this)
label_len = data[offset];  // Read label length

// Good: Documents edge case
// QUIC packets require minimum 1200 bytes for initial packets
if (len < 1200) return "";

// Bad: Redundant
domain = "";  // Clear domain
```

## 🔍 Debugging

### Enable Verbose Logging

```cpp
#define VERBOSE_LOGGING 1

#if VERBOSE_LOGGING
std::cout << "[DEBUG] Processing packet from " << src_ip 
          << " to " << dst_ip << std::endl;
#endif
```

### Check Packet Contents

```cpp
void dump_packet_hex(const u_char* data, int len) {
    for (int i = 0; i < len && i < 64; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
}
```

### Validate BPF Filter

```bash
# Test filter syntax
tcpdump -i en0 -n "udp port 53 or tcp port 80 or tcp port 443" -c 1

# List packets matching filter
tcpdump -i en0 -n "tcp port 443" | head -5
```

## 🚀 Compilation Options

### Release Build (Optimized)
```bash
clang++ -std=c++17 -O3 -DNDEBUG -o network_monitor network_monitor.cpp -lpcap
```

### Debug Build
```bash
clang++ -std=c++17 -g -O0 -DDEBUG -o network_monitor network_monitor.cpp -lpcap
gdb ./network_monitor
```

### With Address Sanitizer (Find Memory Leaks)
```bash
clang++ -std=c++17 -fsanitize=address -fno-omit-frame-pointer -o network_monitor network_monitor.cpp -lpcap
sudo ./network_monitor
```

## 📚 References

- **libpcap**: https://www.tcpdump.org/
- **BPF Syntax**: https://www.tcpdump.org/papers/sniffing-faq.html
- **DNS RFC**: https://tools.ietf.org/html/rfc1035
- **HTTP RFC**: https://tools.ietf.org/html/rfc7230
- **IPv4 Header**: https://tools.ietf.org/html/rfc791

---

**Last Updated**: April 2026  
**Version**: 1.0
