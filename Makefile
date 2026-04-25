CXX      = clang++
CXXFLAGS = -std=c++17 -Wall -Wextra
LDFLAGS  = -lpcap

TARGET          = network_monitor
TARGET_ADVANCED = network_monitor_advanced
SRC             = network_monitor.cpp
SRC_ADVANCED    = network_monitor_advanced.cpp

all: $(TARGET) $(TARGET_ADVANCED)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(TARGET_ADVANCED): $(SRC_ADVANCED)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) $(TARGET_ADVANCED)

run: $(TARGET)
	sudo ./$(TARGET)

run-advanced: $(TARGET_ADVANCED)
	sudo ./$(TARGET_ADVANCED)

.PHONY: all clean run run-advanced
