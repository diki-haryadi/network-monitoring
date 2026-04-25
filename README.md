# Network Traffic Monitor

Program C++ untuk memonitor traffic internet (masuk dan keluar) dengan grouping berdasarkan nama domain.

## Fitur

- ✅ Capture DNS requests untuk identify domain names
- ✅ Monitor HTTP/HTTPS traffic (port 80, 443, 8080)
- ✅ Group statistics by domain
- ✅ Display total bytes dan packets per domain
- ✅ Real-time monitoring dengan Ctrl+C untuk stop

## Requirements

### macOS
```bash
# libpcap sudah tersedia di macOS
# Jika belum, install via Homebrew:
brew install libpcap
```

### Linux
```bash
sudo apt-get install libpcap-dev  # Ubuntu/Debian
sudo yum install libpcap-devel    # RHEL/CentOS
```

## Compilation

### Menggunakan Makefile (recommended)
```bash
make clean
make
```

### Manual compilation
```bash
clang++ -std=c++17 -Wall -Wextra -o network_monitor network_monitor.cpp -lpcap
```

## Usage

### MacOS (memerlukan root/sudo)
```bash
sudo ./network_monitor
# atau specify interface
sudo ./network_monitor en0
```

### Linux (memerlukan root/sudo)
```bash
sudo ./network_monitor
# atau specify interface
sudo ./network_monitor eth0
```

### Interactive Mode
Jika tidak specify interface, program akan list available interfaces:

```
=== Network Traffic Monitor ===

Available network interfaces:
1. lo0 (Loopback)
2. en0 (Wi-Fi)
3. en1 (Ethernet)

Enter interface number (default 1): 2
Monitoring on interface: en0
Press Ctrl+C to stop and show statistics
```

## Output

Setelah Ctrl+C, program menampilkan statistik:

```
========== NETWORK STATISTICS ==========
Domain                                  Packets         Bytes          
----------------------------------------------------------------------
www.google.com                          245             156234         
api.github.com                          189             89234          
www.amazon.com                          123             67234          
cdn.example.com                         98              45123          
----------------------------------------------------------------------
```

## How It Works

1. **DNS Monitoring**: Menangkap UDP port 53 untuk extract domain names dari DNS requests
2. **HTTP Monitoring**: Menangkap TCP port 80/443/8080 untuk extract Host header dari HTTP requests
3. **Filtering**: Menggunakan BPF (Berkeley Packet Filter) untuk efficient packet filtering
4. **Grouping**: Aggregate statistics berdasarkan domain name
5. **Statistics**: Track total bytes dan packets per domain

## Technical Details

- **Ethernet Header**: Skip 14 bytes
- **IP Header**: Parse source/destination IP
- **DNS Query**: Extract domain dari DNS packet format
- **HTTP Header**: Parse Host header untuk HTTPS traffic
- **Protocol Support**: 
  - DNS (UDP port 53)
  - HTTP (TCP port 80)
  - HTTPS (TCP port 443)
  - Custom HTTP (TCP port 8080)

## Limitations

1. HTTPS payload tidak bisa di-parse (encrypted), hanya bisa dari SNI atau Host header
2. Memerlukan root/sudo privilege untuk packet capture
3. DNS over HTTPS (DoH) tidak supported
4. Hanya capture traffic dari device network interface

## Advanced Usage

### Filter specific traffic only
Edit filter_str di network_monitor.cpp:

```cpp
// Only DNS
std::string filter_str = "udp port 53";

// Only HTTPS
std::string filter_str = "tcp port 443";

// Custom network
std::string filter_str = "host 192.168.1.0/24";
```

### Increase buffer for high traffic
```cpp
pcap_open_live(device.c_str(), 65535, 1, 1000, errbuf);  // Larger buffer
```

## Troubleshooting

### Permission denied
```bash
# Pada macOS, gunakan ChmodBPF untuk tanpa sudo
# Atau gunakan sudo setiap kali run
sudo ./network_monitor
```

### Interface not found
```bash
# List semua interface
ifconfig          # macOS/Linux
ipconfig          # Windows (gunakan Npcap)
```

### Filter syntax error
Gunakan valid BPF syntax:
- `tcp port 80`
- `udp port 53`
- `host 8.8.8.8`
- `net 192.168.0.0/16`

## Example Scripts

### Monitor dan save ke file
```bash
sudo ./network_monitor 2>&1 | tee traffic.log
```

### Monitor specific interface
```bash
sudo ./network_monitor en0
```

### Monitor dengan grep
```bash
sudo ./network_monitor en0 | grep "google.com"
```

## License

MIT License

## Contributing

Contributions welcome! Silakan submit pull requests atau issues.
