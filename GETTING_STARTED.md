# Getting Started dengan Network Monitor

Panduan lengkap untuk setup dan menggunakan Network Traffic Monitor.

## 📋 Prasyarat

- macOS 10.14+ atau Linux
- C++17 compatible compiler (clang++, g++)
- libpcap library
- Administrator/sudo access (untuk packet capture)

## 🚀 Quick Start

### 1. Build Aplikasi

```bash
# Chmod executable
chmod +x build.sh

# Build both programs
./build.sh
```

Atau manual:
```bash
clang++ -std=c++17 -Wall -Wextra -o network_monitor network_monitor.cpp -lpcap
clang++ -std=c++17 -Wall -Wextra -o network_monitor_advanced network_monitor_advanced.cpp -lpcap
```

### 2. Run Program

#### Basic Monitor
```bash
sudo ./network_monitor

# Atau specify interface
sudo ./network_monitor en0
```

#### Advanced Monitor (dengan JSON export)
```bash
sudo ./network_monitor_advanced
```

### 3. Stop Monitoring
Tekan `Ctrl+C` untuk stop dan lihat statistik.

## 📊 Program Comparison

| Feature | Basic | Advanced |
|---------|-------|----------|
| DNS Monitoring | ✅ | ✅ |
| HTTP/HTTPS Monitoring | ✅ | ✅ |
| Domain Grouping | ✅ | ✅ |
| Console Statistics | ✅ | ✅ |
| JSON Export | ❌ | ✅ |
| Packet Log | ❌ | ✅ (last 1000) |
| IP Tracking | ❌ | ✅ |
| File Size | ~7KB | ~12KB |

## 🎯 Use Cases

### 1. Network Debugging
```bash
sudo ./network_monitor en0
# Lihat domain mana saja yang diakses
```

### 2. Monitor Aplikasi Spesifik
```bash
sudo ./network_monitor_advanced
# Keluarkan ke traffic_report_*.json
# Analyze yang diakses aplikasi tertentu
```

### 3. Security Monitoring
```bash
sudo ./network_monitor | tee traffic.log
# Monitor aktivitas network, save ke file
```

### 4. Performance Analysis
```bash
sudo ./network_monitor_advanced
# Analyze mana domain yang paling banyak traffic
```

## 📝 Output Examples

### Basic Monitor Output
```
========== NETWORK STATISTICS ==========
Domain                                  Packets         Bytes          
----------------------------------------------------------------------
api.github.com                          245             156234         
www.google.com                          189             89234          
cdn.jsdelivr.net                        123             67234          
www.wikipedia.org                       98              45123          
----------------------------------------------------------------------
```

### Advanced Monitor JSON Export
```json
{
  "timestamp": "2024-04-26 14:32:45",
  "total_packets": 5234,
  "domains": {
    "api.github.com": {
      "packets": 245,
      "bytes": 156234,
      "ips_count": 3,
      "ips": ["140.82.113.4", "140.82.113.5"],
      "last_seen": "2024-04-26 14:32:44"
    }
  },
  "packets": [
    {
      "timestamp": "2024-04-26 14:32:15",
      "domain": "api.github.com",
      "protocol": "HTTPS",
      "src_ip": "192.168.1.100",
      "dst_ip": "140.82.113.4",
      "port": 443,
      "bytes": 512
    }
  ]
}
```

## 🔧 Troubleshooting

### Error: "Permission denied"
```bash
# macOS: Gunakan sudo
sudo ./network_monitor

# Linux: Juga gunakan sudo
sudo ./network_monitor
```

### Error: "No such device"
Interface tidak ditemukan. Check available interfaces:
```bash
# macOS
ifconfig

# Linux
ip link show
```

### Error: "libpcap not found"
Install libpcap:
```bash
# macOS
brew install libpcap

# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

### Program tidak capture traffic
1. Pastikan sudo digunakan
2. Check interface dengan benar (bukan loopback)
3. Pastikan interface aktif (connected)

```bash
# Test interface connectivity
ping -c 1 8.8.8.8
```

## 🎓 Understanding Output

### DNS Query
```
Domain: google.com
Protocol: DNS
Port: 53 (DNS server)
```

### HTTP Request
```
Domain: www.example.com (dari Host header)
Protocol: HTTP
Port: 80
```

### HTTPS Request
```
Domain: api.github.com (dari SNI/Host header)
Protocol: HTTPS
Port: 443
```

## 📈 Advanced Topics

### Custom BPF Filter

Edit source code untuk filter specific traffic:

```cpp
// Hanya DNS
std::string filter_str = "udp port 53";

// Hanya HTTPS
std::string filter_str = "tcp port 443";

// Specific host
std::string filter_str = "host 8.8.8.8";

// Multiple conditions
std::string filter_str = "(tcp port 80 or tcp port 443) and dst net 192.168.0.0/16";
```

Compile ulang setelah edit.

### Increase Capture Buffer

```cpp
// Default: BUFSIZ (usually 65535)
pcap_open_live(device.c_str(), 65535, 1, 1000, errbuf);

// Increase untuk high traffic
pcap_open_live(device.c_str(), 262144, 1, 1000, errbuf);
```

### Real-time Parsing

Advanced program bisa modify untuk real-time parsing:

```cpp
// Ubah dari pcap_loop menjadi pcap_next dalam loop
while (running) {
    const u_char* packet = pcap_next(handle, &header);
    if (packet != nullptr) {
        packet_handler(nullptr, &header, packet);
    }
}
```

## 🔒 Security Notes

1. **Root Access**: Program memerlukan root karena packet capture
2. **Local Only**: Hanya capture traffic dari interface lokal
3. **No Encryption**: Encrypted traffic (HTTPS) hanya bisa lihat domain dari SNI
4. **Privacy**: Jangan share logs yang contain PII

## 📚 Referensi

- [libpcap Tutorial](https://www.tcpdump.org/papers/sniffing-faq.html)
- [BPF Syntax](https://www.tcpdump.org/papers/sniffing-faq.html#filter-syntax)
- [DNS Query Format](https://tools.ietf.org/html/rfc1035)
- [HTTP Host Header](https://tools.ietf.org/html/rfc7230#section-5.4)

## 🐛 Known Limitations

1. **HTTPS Payload**: Tidak bisa parse HTTP headers di HTTPS (encrypted)
   - Hanya bisa extract domain dari SNI saat TLS handshake
   - HTTP/2 dan HTTP/3 mungkin tidak terdeteksi dengan baik

2. **DNS over HTTPS (DoH)**: Tidak supported
   - DNS queries via HTTPS port 443 tidak terdeteksi

3. **Performance**: 
   - High traffic environments mungkin drop packets
   - Increase buffer size dan snapshot length untuk improve

4. **Fragmented Packets**:
   - Packets yang di-fragment mungkin tidak di-parse dengan benar

## 💡 Tips & Tricks

### Monitor dengan realtime grep
```bash
sudo ./network_monitor | tail -f | grep "example.com"
```

### Capture ke file dan analyze later
```bash
sudo ./network_monitor_advanced > traffic.txt 2>&1
cat traffic_report_*.json | jq '.domains | keys'
```

### Export statistics ke CSV
```bash
# Manual: extract dari JSON dan convert ke CSV
cat traffic_report_*.json | jq -r '.domains | to_entries[] | [.key, .value.packets, .value.bytes] | @csv'
```

### Monitor specific application
```bash
# Terminal 1: Monitor network
sudo ./network_monitor en0

# Terminal 2: Start aplikasi yang ingin dimonitor
./aplikasi_saya
```

---

**Last Updated**: April 2026  
**Version**: 1.0  
**License**: MIT
