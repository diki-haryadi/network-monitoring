CXX      = clang++
CXXFLAGS = -std=c++17 -Wall -Wextra
LDFLAGS  = -lpcap

TARGET          = network_monitor
TARGET_ADVANCED = network_monitor_advanced
TARGET_BURP     = network_monitor_burp
SRC             = network_monitor.cpp
SRC_ADVANCED    = network_monitor_advanced.cpp
SRC_BURP        = network_monitor_burp.cpp

all: $(TARGET) $(TARGET_ADVANCED) $(TARGET_BURP)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(TARGET_ADVANCED): $(SRC_ADVANCED)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(TARGET_BURP): $(SRC_BURP)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_ADVANCED) $(TARGET_BURP)

run: $(TARGET)
	sudo ./$(TARGET)

run-advanced: $(TARGET_ADVANCED)
	sudo ./$(TARGET_ADVANCED)

run-burp: $(TARGET_BURP)
	sudo ./$(TARGET_BURP)

.PHONY: all clean run run-advanced run-burp
