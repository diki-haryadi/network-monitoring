# Network Monitor - Contoh Penggunaan

Kumpulan contoh real-world penggunaan Network Monitor.

## 🔍 Contoh 1: Monitor Aktivitas Browser

```bash
# Terminal 1: Mulai monitoring
sudo ./network_monitor en0

# Terminal 2: Buka browser dan akses website
open https://www.google.com
open https://www.github.com

# Terminal 1: Tekan Ctrl+C untuk stop
# Output:
# api.google.com          245 packets    156234 bytes
# www.github.com          189 packets     89234 bytes
# cdn.jsdelivr.net        123 packets     67234 bytes
```

## 🚀 Contoh 2: Monitor Aplikasi Docker

```bash
# Terminal 1: Monitor dengan advanced
sudo ./network_monitor_advanced eth0

# Terminal 2: Start Docker container
docker run -it ubuntu /bin/bash
apt-get update    # Akan terlihat download DNS requests

# Terminal 1: Ctrl+C, lihat report JSON
cat traffic_report_*.json | jq '.domains | keys'
# Output:
# [
#   "archive.ubuntu.com",
#   "api.github.com",
#   "cdn.example.com",
#   ...
# ]
```

## 📱 Contoh 3: Monitor Mobile Device via Network

```bash
# Lihat connected devices
arp -a | grep -i "192.168.1"

# Monitor traffic dari device tertentu (substitute IP)
# Edit network_monitor.cpp, ubah filter jadi:
# std::string filter_str = "host 192.168.1.105";

sudo ./network_monitor en0
# Akan show semua traffic dari device 192.168.1.105
```

## 🎮 Contoh 4: Monitor Game Server Connections

```bash
# Monitor gaming traffic
sudo ./network_monitor en0

# Terminal 2: Jalankan game
./my-game

# Lihat:
# game-server.example.com    1234 packets  5MB
# matchmaking.example.com     856 packets  2MB
# analytics.example.com       256 packets  1MB
```

## 🔐 Contoh 5: Security Monitoring

```bash
# Continuous monitoring dan logging
nohup sudo ./network_monitor_advanced en0 > network_monitor.log 2>&1 &

# Setelah beberapa jam/hari, analyze
ls -la traffic_report_*.json | head -5

# Check untuk unusual domains
cat traffic_report_*.json | jq '.domains | keys' | grep -i ".ru\|.cn\|.tk"

# Alert jika ada domain aneh
cat traffic_report_*.json | jq '.domains | keys' | wc -l
# Jika jumlah unique domains sangat banyak, ada yang tidak normal
```

## 📊 Contoh 6: Performance Analysis

```bash
# Collect data untuk analisis
for i in {1..10}; do
  echo "Monitoring... ($i/10)"
  timeout 60 sudo ./network_monitor_advanced en0 > /dev/null 2>&1
  sleep 5
done

# Analyze all reports
echo "Top 10 Domains by Bytes:"
for f in traffic_report_*.json; do
  cat "$f"
done | jq -s 'map(.domains) | add | to_entries | sort_by(.value.bytes) | reverse | .[0:10] | map({domain: .key, bytes: .value.bytes})'
```

## 🔗 Contoh 7: Find DNS Leaks

```bash
# Monitor untuk find unencrypted DNS queries
sudo ./network_monitor_advanced en0

# Check hasil:
cat traffic_report_*.json | jq '.packets[] | select(.protocol == "DNS")'

# Jika banyak DNS queries ke ISP DNS (bukan 8.8.8.8/1.1.1.1), mungkin ada DNS leak

# Contoh:
# {
#   "domain": "ads.example.com",
#   "protocol": "DNS",
#   "dst_ip": "192.168.1.1",   # ISP DNS, bukan encrypted!
#   "port": 53
# }
```

## 🌐 Contoh 8: Monitor VPN Traffic

```bash
# Check sebelum dan sesudah connect VPN

# BEFORE VPN:
sudo ./network_monitor_advanced en0
# Catat domains yang diakses

# Connect ke VPN
networksetup -connectpppoeservice "My VPN"

# AFTER VPN:
sudo ./network_monitor_advanced en0
# Catat domains lagi

# Compare:
# - Sebelum: DNS requests visible to ISP
# - Sesudah: DNS requests encrypted via VPN
```

## 🐳 Contoh 9: Monitor Network During Updates

```bash
# Monitor macOS update process
sudo ./network_monitor_advanced en0

# Terminal 2: Trigger update
softwareupdate -ia

# Analisis:
cat traffic_report_*.json | jq '.domains | keys' | grep -i "apple\|update\|cdn"

# Lihat mana servers Apple yang digunakan
```

## 🚨 Contoh 10: Detect Malware Activity

```bash
# Collect baseline
echo "=== Baseline ===
sudo ./network_monitor_advanced en0
# No suspicious activity

# Baseline domains
cat traffic_report_*baseline*.json | jq '.domains | keys' > baseline_domains.txt

# Later, setelah install software baru
echo "=== After Install ===
sudo ./network_monitor_advanced en0

# New domains
cat traffic_report_*after*.json | jq '.domains | keys' > after_domains.txt

# Find differences
comm -13 baseline_domains.txt after_domains.txt
# Akan show domain baru yang di-access
```

## 📈 Contoh 11: API Server Monitoring

```bash
# Monitor API calls
sudo ./network_monitor_advanced en0

# Jalankan API tests
pytest tests/api_tests.py

# Analyze API traffic
cat traffic_report_*.json | jq '.domains[] | select(.domain == "api.example.com")' 

# Lihat:
# - Berapa banyak API calls
# - Total data transfer
# - Response time (dari packet timing)
```

## 🎬 Contoh 12: Streaming Service Analysis

```bash
# Monitor streaming
sudo ./network_monitor_advanced en0

# Terminal 2: Start streaming
open https://www.youtube.com
# or
open https://www.netflix.com

# Check CDN usage
cat traffic_report_*.json | jq '.domains | keys' | grep -i "cdn\|akamai\|cloudflare"

# Analyze:
# - Mana CDN yang digunakan
# - Berapa bandwidth yang dikonsumsi
# - Quality/bitrate estimate dari data rate
```

## 💻 Contoh 13: Script Automation

### Continuous Monitoring Script

```bash
#!/bin/bash
# continuous_monitor.sh

LOG_DIR="./traffic_logs"
mkdir -p "$LOG_DIR"

while true; do
  echo "Starting network monitor at $(date)"
  
  timeout 300 sudo ./network_monitor_advanced en0 > "$LOG_DIR/monitor_$(date +%s).log" 2>&1
  
  # Keep only last 24 hours
  find "$LOG_DIR" -name "*.json" -mtime +1 -delete
  
  echo "Sleeping for 5 minutes..."
  sleep 300
done
```

### JSON Analysis Script

```bash
#!/bin/bash
# analyze_traffic.sh

echo "=== Network Traffic Summary ==="
echo "Report Date: $(date)"
echo

echo "=== Top 10 Domains by Traffic ==="
for f in traffic_report_*.json; do
  cat "$f"
done | jq -s 'map(.domains) | add | to_entries | sort_by(.value.bytes) | reverse | .[0:10]' | jq '.[] | "\(.key): \(.value.bytes) bytes"'

echo
echo "=== Unique Domains ==="
for f in traffic_report_*.json; do
  cat "$f"
done | jq -s 'map(.domains) | add | length'

echo
echo "=== Protocol Distribution ==="
for f in traffic_report_*.json; do
  cat "$f"
done | jq -s 'map(.packets[]) | group_by(.protocol) | map({protocol: .[0].protocol, count: length})'
```

## 🔍 Contoh 14: Packet-Level Analysis

```bash
# Untuk detailed analysis, export JSON dan process dengan jq

# Show hanya HTTPS traffic
cat traffic_report_*.json | jq '.packets[] | select(.protocol == "HTTPS")'

# Count traffic per port
cat traffic_report_*.json | jq '.packets | group_by(.port) | map({port: .[0].port, count: length})'

# Timeline analysis (packets per hour)
cat traffic_report_*.json | jq '.packets[] | .timestamp' | cut -d: -f1 | sort | uniq -c
```

## ⚡ Contoh 15: Performance Profiling

```bash
# Monitor aplikasi Go/Python dan lihat DNS overhead

# Sebelum optimization:
sudo ./network_monitor_advanced lo0  # loopback untuk local
./app_version_1

# Lihat DNS lookups dan latency

# Setelah optimization (caching):
./app_version_2

# Compare:
# Version 1: 1000 DNS queries, 5MB data
# Version 2: 10 DNS queries, 50KB data
# 100x improvement!
```

---

## Tips Menggunakan Contoh Ini

1. **Adapt to your environment**: Ubah interface (en0 → eth0) dan IP addresses sesuai setup
2. **Combine scripts**: Mix contoh-contoh untuk use case spesifik
3. **Automate analysis**: Gunakan jq, grep, awk untuk process results
4. **Schedule jobs**: Gunakan cron untuk periodic monitoring

## Safety Reminders

- ✅ Gunakan sudo untuk packet capture
- ✅ Hati-hati dengan monitoring di production
- ✅ Respek privacy - jangan share raw logs dengan PII
- ✅ Clean up old report files untuk save disk space

---

**Last Updated**: April 2026
