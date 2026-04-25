#!/bin/bash

# Build script untuk Network Monitor

echo "=== Network Monitor Build Script ==="
echo

# Check if libpcap is installed
if ! command -v pcap-config &> /dev/null; then
    echo "⚠️  libpcap not found. Installing..."

    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if ! command -v brew &> /dev/null; then
            echo "Homebrew not found. Please install Homebrew first:"
            echo "https://brew.sh"
            exit 1
        fi
        brew install libpcap
    elif [[ "$OSTYPE" == "linux"* ]]; then
        # Linux
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y libpcap-dev
        elif command -v yum &> /dev/null; then
            sudo yum install -y libpcap-devel
        else
            echo "Unable to determine package manager. Please install libpcap-dev manually."
            exit 1
        fi
    fi
fi

echo "✅ Building network_monitor..."
clang++ -std=c++17 -Wall -Wextra -o network_monitor network_monitor.cpp -lpcap

if [ $? -eq 0 ]; then
    echo "✅ network_monitor compiled successfully"
else
    echo "❌ Failed to compile network_monitor"
    exit 1
fi

echo
echo "✅ Building network_monitor_advanced..."
clang++ -std=c++17 -Wall -Wextra -o network_monitor_advanced network_monitor_advanced.cpp -lpcap

if [ $? -eq 0 ]; then
    echo "✅ network_monitor_advanced compiled successfully"
else
    echo "❌ Failed to compile network_monitor_advanced"
    exit 1
fi

echo
echo "=== Build Complete ==="
echo "Usage:"
echo "  sudo ./network_monitor                    # Basic monitor"
echo "  sudo ./network_monitor eth0               # Monitor specific interface"
echo "  sudo ./network_monitor_advanced           # Advanced with JSON export"
echo
