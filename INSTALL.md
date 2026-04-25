# Installation Guide

Panduan step-by-step untuk install dan setup Network Monitor.

## 📋 System Requirements

### Minimum
- **macOS** 10.14+ atau **Linux** (Ubuntu 18.04+, CentOS 7+)
- **2 GB RAM**
- **100 MB disk space** (program + reports)
- **C++ compiler** (clang++ atau g++)
- **libpcap** library

### Recommended
- **macOS** 12+ atau **Linux** dengan recent kernel
- **4 GB+ RAM**
- **1 GB disk space**
- **Internet connection** untuk dependency download

---

## 🖥️ Platform-Specific Installation

### macOS (Recommended)

#### 1. Install Homebrew (jika belum)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### 2. Install libpcap
```bash
brew install libpcap
```

#### 3. Verify installation
```bash
pcap-config --version
# Should output: 1.X.X
```

#### 4. Get source code
```bash
cd ~/Downloads
git clone https://github.com/yourusername/network-monitoring.git
# atau download ZIP dan extract
cd network-monitoring
```

#### 5. Compile
```bash
./build.sh
# atau
make
```

#### 6. Test
```bash
sudo ./network_monitor en0
# Buka browser, akses website
# Tekan Ctrl+C
# Harus menampilkan statistics
```

---

### Linux - Ubuntu/Debian

#### 1. Update package manager
```bash
sudo apt-get update
```

#### 2. Install dependencies
```bash
sudo apt-get install -y \
  build-essential \
  libpcap-dev \
  curl \
  git
```

#### 3. Verify libpcap
```bash
dpkg -l | grep libpcap
# Should show libpcap version
```

#### 4. Get source code
```bash
cd ~/Downloads
git clone https://github.com/yourusername/network-monitoring.git
# atau download ZIP
cd network-monitoring
```

#### 5. Compile
```bash
./build.sh
# atau
make
```

#### 6. Test
```bash
sudo ./network_monitor eth0
# Generate traffic, Ctrl+C
# Harus menampilkan statistics
```

---

### Linux - CentOS/RHEL

#### 1. Install dependencies
```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y libpcap-devel curl git
```

#### 2. Verify libpcap
```bash
pkg-config --modversion libpcap
```

#### 3. Get source code
```bash
cd ~/Downloads
git clone https://github.com/yourusername/network-monitoring.git
cd network-monitoring
```

#### 4. Compile
```bash
./build.sh
# atau
make
```

#### 5. Test
```bash
sudo ./network_monitor eth0
```

---

## 🔧 Manual Compilation

### Option A: Using Makefile

```bash
# Clean previous builds
make clean

# Compile both programs
make

# Result:
# - network_monitor (executable)
# - network_monitor_advanced (executable)
```

### Option B: Using build.sh

```bash
# Make executable
chmod +x build.sh

# Run
./build.sh

# Auto-checks dan installs dependencies
# Compiles both programs
```

### Option C: Manual Commands

```bash
# Basic
clang++ -std=c++17 -Wall -Wextra -o network_monitor network_monitor.cpp -lpcap

# Advanced
clang++ -std=c++17 -Wall -Wextra -o network_monitor_advanced network_monitor_advanced.cpp -lpcap

# With optimization
clang++ -std=c++17 -O3 -Wall -Wextra -o network_monitor network_monitor.cpp -lpcap
```

---

## 🧪 Verification Steps

### 1. Check Compiler
```bash
clang++ --version
# Should show: Apple clang version X.X.X or clang version X.X.X
```

### 2. Check libpcap
```bash
pcap-config --version
# macOS example: 1.10.1
```

**If not found**, install:
```bash
# macOS
brew install libpcap

# Ubuntu
sudo apt-get install libpcap-dev

# CentOS
sudo yum install libpcap-devel
```

### 3. Check Network Interface
```bash
# macOS
ifconfig

# Linux
ip link show

# Should see active interfaces like en0, eth0, wlan0
```

### 4. Verify Compilation
```bash
# Check if files exist
ls -la network_monitor*

# Should show:
# -rwxr-xr-x  network_monitor
# -rwxr-xr-x  network_monitor_advanced
```

### 5. Test Run
```bash
# Run basic monitor
sudo ./network_monitor

# Should show menu of interfaces
# Select one (or auto-selects 1st)
# Should say "Monitoring on interface..."

# Open browser, access website
# Tekan Ctrl+C
# Should show statistics with domains
```

---

## 🐛 Troubleshooting Installation

### Issue: "libpcap not found"

**macOS**:
```bash
brew install libpcap
brew link libpcap --force
```

**Ubuntu**:
```bash
sudo apt-get install libpcap-dev
```

**CentOS**:
```bash
sudo yum install libpcap-devel
```

### Issue: "Command not found: clang++"

**macOS** (install Xcode):
```bash
xcode-select --install
```

**Linux** (install build tools):
```bash
# Ubuntu
sudo apt-get install build-essential

# CentOS
sudo yum groupinstall "Development Tools"
```

### Issue: "Permission denied" when running

**Solution**: Use sudo
```bash
sudo ./network_monitor en0
```

Or enable ChmodBPF (macOS only):
```bash
# Allow without sudo
brew install chmodbpf
# Restart terminal
```

### Issue: "No such device"

**Check available interfaces**:
```bash
ifconfig              # macOS
ip link show          # Linux
```

**Use correct interface**:
```bash
sudo ./network_monitor en0    # macOS
sudo ./network_monitor eth0   # Linux
```

### Issue: Compilation fails with undefined reference

**Make sure libpcap is linked**:
```bash
# This should work:
clang++ -std=c++17 -o network_monitor network_monitor.cpp -lpcap

# If not, specify path explicitly:
clang++ -std=c++17 -o network_monitor network_monitor.cpp -I/usr/local/include -L/usr/local/lib -lpcap
```

---

## 🚀 Quick Installation Summary

### For the Impatient (3 Steps)

#### Step 1: Install Dependencies
```bash
# macOS
brew install libpcap

# Ubuntu
sudo apt-get update && sudo apt-get install -y libpcap-dev

# CentOS
sudo yum install -y libpcap-devel
```

#### Step 2: Compile
```bash
./build.sh
# atau: make
```

#### Step 3: Run
```bash
sudo ./network_monitor en0
# Stop dengan Ctrl+C untuk melihat hasil
```

---

## 📦 All Dependencies

### Required
| Package | macOS | Ubuntu | CentOS |
|---------|-------|--------|--------|
| libpcap | `brew install libpcap` | `apt-get install libpcap-dev` | `yum install libpcap-devel` |
| C++ Compiler | Xcode/clang | build-essential | Development Tools |

### Optional (untuk analysis)
| Package | macOS | Ubuntu | CentOS |
|---------|-------|--------|--------|
| jq (JSON) | `brew install jq` | `apt-get install jq` | `yum install jq` |
| git | `brew install git` | `apt-get install git` | `yum install git` |

---

## 🎯 Post-Installation

### 1. Verify Everything Works
```bash
# Terminal 1
sudo ./network_monitor en0

# Terminal 2 (new terminal)
# Generate traffic
curl https://www.google.com
curl https://www.github.com

# Terminal 1
# Tekan Ctrl+C

# Should show:
# google.com        XX packets    XXXXX bytes
# github.com        XX packets    XXXXX bytes
```

### 2. (Optional) Install Analysis Tools
```bash
# macOS
brew install jq

# Ubuntu
sudo apt-get install jq

# Then use:
cat traffic_report_*.json | jq '.domains | keys'
```

### 3. Create Alias (Optional)
```bash
# Add to ~/.zshrc atau ~/.bashrc:
alias netmon='sudo /path/to/network_monitor en0'
alias netmon-adv='sudo /path/to/network_monitor_advanced en0'

# Reload shell:
source ~/.zshrc  # atau ~/.bashrc
```

### 4. Read Documentation
```bash
# Quick start
less QUICK_REFERENCE.md

# Full guide
less GETTING_STARTED.md

# Examples
less EXAMPLES.md
```

---

## 🆘 Getting Help

### Check Documentation
1. **QUICK_REFERENCE.md** - Fast answers
2. **GETTING_STARTED.md** - Troubleshooting section
3. **EXAMPLES.md** - Real-world examples
4. **DEVELOPMENT.md** - Technical details

### Manual Pages
```bash
man pcap           # libpcap documentation
man tcpdump        # Similar tool (reference)
man ifconfig       # Network interfaces
```

### Online Resources
- libpcap: https://www.tcpdump.org/
- BPF syntax: https://www.tcpdump.org/papers/sniffing-faq.html
- DNS RFC: https://tools.ietf.org/html/rfc1035

---

## 📝 Installation Checklist

Before you start using the monitor:

- [ ] libpcap installed (`brew install libpcap`)
- [ ] C++ compiler available (`clang++ --version`)
- [ ] Code compiled successfully (`./build.sh`)
- [ ] Executables created (`ls -la network_monitor*`)
- [ ] Network interface identified (`ifconfig`)
- [ ] Test run successful (`sudo ./network_monitor en0`)
- [ ] Documentation read (at least QUICK_REFERENCE.md)
- [ ] jq installed (optional, untuk analysis)

---

## 🎓 Next Steps

1. **Read QUICK_REFERENCE.md** untuk basic commands
2. **Run GETTING_STARTED.md** untuk setup walkthrough  
3. **Check EXAMPLES.md** untuk use cases
4. **Start monitoring!**

---

## 💬 Common Questions

**Q: Do I need to install every dependency?**  
A: Only libpcap is required. Other tools (jq, git) are optional.

**Q: Can I install without homebrew?**  
A: Yes, install libpcap from source atau use system package manager.

**Q: Do I need to compile every time?**  
A: No, compile once. Binaries (network_monitor, network_monitor_advanced) work without recompiling.

**Q: What if installation fails?**  
A: Check error message carefully, follow troubleshooting section, atau review relevant documentation.

**Q: Can I run on Windows?**  
A: Need WinPcap/Npcap (not included). Linux/macOS recommended.

---

**Last Updated**: April 2026  
**Version**: 1.0
