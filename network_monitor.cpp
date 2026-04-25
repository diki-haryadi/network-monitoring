#include <iostream>
#include <map>
#include <string>
#include <cstring>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <atomic>
#include <csignal>

struct DomainStats {
    std::string domain;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    std::string last_seen;
};

std::atomic<pcap_t*> g_handle{nullptr};

void signal_handler(int sig) {
    (void)sig;
    pcap_t* h = g_handle.load();
    if (h) pcap_breakloop(h);
}

std::map<std::string, DomainStats> domain_stats;

// Parse DNS request untuk extract domain name
std::string extract_domain_from_dns(const u_char* data, int len) {
    if (len < 12) return "";

    // Skip DNS header (12 bytes)
    int offset = 12;
    std::string domain;

    while (offset < len && data[offset] != 0) {
        uint8_t label_len = data[offset];
        offset++;

        if (label_len > 63) return "";

        for (int i = 0; i < label_len && offset < len; i++) {
            domain += static_cast<char>(data[offset++]);
        }

        if (offset < len && data[offset] != 0) {
            domain += ".";
        }
    }

    return domain;
}

// Extract domain dari HTTP Host header
std::string extract_domain_from_http(const u_char* data, int len) {
    std::string payload(reinterpret_cast<const char*>(data), len);
    size_t host_pos = payload.find("Host: ");

    if (host_pos != std::string::npos) {
        size_t start = host_pos + 6;
        size_t end = payload.find("\r\n", start);
        if (end != std::string::npos) {
            std::string host = payload.substr(start, end - start);
            // Remove port if exists
            size_t colon_pos = host.find(':');
            if (colon_pos != std::string::npos) {
                host = host.substr(0, colon_pos);
            }
            return host;
        }
    }
    return "";
}

// Callback untuk setiap packet yang ditangkap
void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr,
                    const u_char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14); // Skip ethernet header

    if (ip_header->ip_v != 4) return;

    std::string domain;
    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);
    bool is_outgoing = true;

    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        int udp_port = ntohs(udp_header->uh_dport);

        // DNS over UDP (port 53)
        if (udp_port == 53 || ntohs(udp_header->uh_sport) == 53) {
            const u_char* dns_data = packet + 14 + (ip_header->ip_hl * 4) + 8;
            int dns_len = pkthdr->len - 14 - (ip_header->ip_hl * 4) - 8;
            domain = extract_domain_from_dns(dns_data, dns_len);
            is_outgoing = (udp_port == 53);
        }
    }
    else if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        int tcp_port = ntohs(tcp_header->th_dport);

        // HTTP (port 80) atau HTTPS (port 443)
        if (tcp_port == 80 || tcp_port == 443 || tcp_port == 8080) {
            const u_char* http_data = packet + 14 + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
            int http_len = pkthdr->len - 14 - (ip_header->ip_hl * 4) - (tcp_header->th_off * 4);

            if (http_len > 0 && (http_data[0] == 'G' || http_data[0] == 'P' || http_data[0] == 'H')) {
                domain = extract_domain_from_http(http_data, http_len);
                is_outgoing = true;
            }
        }
    }

    if (!domain.empty()) {
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::string timestamp = std::ctime(&time_t_now);
        timestamp.pop_back(); // Remove newline

        if (domain_stats.find(domain) == domain_stats.end()) {
            domain_stats[domain].domain = domain;
        }

        domain_stats[domain].last_seen = timestamp;
        domain_stats[domain].bytes_in += pkthdr->len;
        domain_stats[domain].packets_in++;
    }
}

void print_stats() {
    std::cout << "\n========== NETWORK STATISTICS ==========" << std::endl;
    std::cout << std::left << std::setw(40) << "Domain"
              << std::setw(15) << "Packets"
              << std::setw(15) << "Bytes" << std::endl;
    std::cout << std::string(70, '-') << std::endl;

    // Sort by bytes
    std::vector<std::pair<std::string, DomainStats>> sorted_stats(
        domain_stats.begin(), domain_stats.end()
    );
    std::sort(sorted_stats.begin(), sorted_stats.end(),
        [](const auto& a, const auto& b) {
            return a.second.bytes_in > b.second.bytes_in;
        }
    );

    for (const auto& [domain, stats] : sorted_stats) {
        std::cout << std::left << std::setw(40) << domain
                  << std::setw(15) << stats.packets_in
                  << std::setw(15) << stats.bytes_in << std::endl;
    }
    std::cout << std::string(70, '-') << std::endl;
}

int main(int argc, char* argv[]) {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];

    std::cout << "=== Network Traffic Monitor ===" << std::endl;

    // Get list of devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

    // Select network interface
    std::string device;
    if (argc > 1) {
        device = argv[1];
    } else {
        std::cout << "\nAvailable network interfaces:" << std::endl;
        int i = 0;
        for (d = alldevs; d != nullptr; d = d->next) {
            std::cout << ++i << ". " << d->name;
            if (d->description) {
                std::cout << " (" << d->description << ")";
            }
            std::cout << std::endl;
        }

        std::cout << "\nEnter interface number or name (default 1): ";
        std::string input;
        std::getline(std::cin, input);

        if (input.empty()) {
            // Default to first interface
            device = alldevs->name;
        } else {
            // Try to parse as number first
            try {
                int choice = std::stoi(input);
                i = 0;
                for (d = alldevs; d != nullptr && i < choice - 1; d = d->next) {
                    i++;
                }
                if (d != nullptr) {
                    device = d->name;
                } else {
                    std::cerr << "Invalid interface number" << std::endl;
                    return 1;
                }
            } catch (const std::invalid_argument&) {
                // Not a number, treat as interface name
                bool found = false;
                for (d = alldevs; d != nullptr; d = d->next) {
                    if (input == d->name) {
                        device = d->name;
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    std::cerr << "Interface not found: " << input << std::endl;
                    return 1;
                }
            }
        }
    }

    std::cout << "Monitoring on interface: " << device << std::endl;
    std::cout << "Press Ctrl+C to stop and show statistics" << std::endl;

    // Open device
    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    signal(SIGINT, signal_handler);
    g_handle.store(handle);

    // Filter untuk DNS dan HTTP/HTTPS
    std::string filter_str = "udp port 53 or tcp port 80 or tcp port 443 or tcp port 8080";
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_str.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    // Start capturing
    pcap_loop(handle, -1, packet_handler, nullptr);

    // Print statistics
    print_stats();

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
