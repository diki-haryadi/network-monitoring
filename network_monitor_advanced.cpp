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
#include <fstream>
#include <sstream>
#include <thread>
#include <mutex>
#include <csignal>

volatile bool running = true;
std::mutex stats_mutex;

struct PacketInfo {
    std::string domain;
    std::string src_ip;
    std::string dst_ip;
    uint16_t port;
    std::string protocol;
    uint64_t bytes;
    std::string timestamp;
};

struct DomainStats {
    std::string domain;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    uint64_t packets = 0;
    std::string last_seen;
    std::vector<std::string> ips;
};

std::map<std::string, DomainStats> domain_stats;
std::vector<PacketInfo> packet_log;

void signal_handler(int sig) {
    running = false;
}

std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t_now), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string extract_domain_from_dns(const u_char* data, int len) {
    if (len < 12) return "";

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

std::string extract_domain_from_http(const u_char* data, int len) {
    std::string payload(reinterpret_cast<const char*>(data), len);
    size_t host_pos = payload.find("Host: ");

    if (host_pos != std::string::npos) {
        size_t start = host_pos + 6;
        size_t end = payload.find("\r\n", start);
        if (end != std::string::npos) {
            std::string host = payload.substr(start, end - start);
            size_t colon_pos = host.find(':');
            if (colon_pos != std::string::npos) {
                host = host.substr(0, colon_pos);
            }
            return host;
        }
    }
    return "";
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr,
                    const u_char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14);

    if (ip_header->ip_v != 4) return;

    std::string domain;
    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);
    std::string protocol;
    uint16_t port = 0;
    bool is_valid = false;

    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        port = ntohs(udp_header->uh_dport);

        if (port == 53 || ntohs(udp_header->uh_sport) == 53) {
            const u_char* dns_data = packet + 14 + (ip_header->ip_hl * 4) + 8;
            int dns_len = pkthdr->len - 14 - (ip_header->ip_hl * 4) - 8;
            domain = extract_domain_from_dns(dns_data, dns_len);
            protocol = "DNS";
            is_valid = true;
        }
    }
    else if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        port = ntohs(tcp_header->th_dport);

        if (port == 80 || port == 443 || port == 8080) {
            const u_char* http_data = packet + 14 + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4);
            int http_len = pkthdr->len - 14 - (ip_header->ip_hl * 4) - (tcp_header->th_off * 4);

            if (http_len > 0 && (http_data[0] == 'G' || http_data[0] == 'P' || http_data[0] == 'H')) {
                domain = extract_domain_from_http(http_data, http_len);
                protocol = (port == 443) ? "HTTPS" : "HTTP";
                is_valid = true;
            }
        }
    }

    if (!domain.empty() && is_valid) {
        std::lock_guard<std::mutex> lock(stats_mutex);

        std::string timestamp = get_timestamp();

        if (domain_stats.find(domain) == domain_stats.end()) {
            domain_stats[domain].domain = domain;
        }

        domain_stats[domain].last_seen = timestamp;
        domain_stats[domain].bytes_in += pkthdr->len;
        domain_stats[domain].packets++;

        if (std::find(domain_stats[domain].ips.begin(),
                     domain_stats[domain].ips.end(), dst_ip) ==
            domain_stats[domain].ips.end()) {
            domain_stats[domain].ips.push_back(dst_ip);
        }

        PacketInfo info;
        info.domain = domain;
        info.src_ip = src_ip;
        info.dst_ip = dst_ip;
        info.port = port;
        info.protocol = protocol;
        info.bytes = pkthdr->len;
        info.timestamp = timestamp;

        packet_log.push_back(info);
    }
}

void print_console_stats() {
    std::cout << "\n\n========== NETWORK STATISTICS ==========" << std::endl;
    std::cout << std::left << std::setw(40) << "Domain"
              << std::setw(12) << "Packets"
              << std::setw(15) << "Bytes"
              << std::setw(12) << "IPs" << std::endl;
    std::cout << std::string(85, '-') << std::endl;

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
                  << std::setw(12) << stats.packets
                  << std::setw(15) << stats.bytes_in
                  << std::setw(12) << stats.ips.size() << std::endl;
    }
    std::cout << std::string(85, '-') << std::endl;
}

void export_json(const std::string& filename) {
    std::ofstream file(filename);

    file << "{\n";
    file << "  \"timestamp\": \"" << get_timestamp() << "\",\n";
    file << "  \"total_packets\": " << packet_log.size() << ",\n";
    file << "  \"domains\": {\n";

    std::vector<std::pair<std::string, DomainStats>> sorted_stats(
        domain_stats.begin(), domain_stats.end()
    );
    std::sort(sorted_stats.begin(), sorted_stats.end(),
        [](const auto& a, const auto& b) {
            return a.second.bytes_in > b.second.bytes_in;
        }
    );

    for (size_t i = 0; i < sorted_stats.size(); i++) {
        const auto& [domain, stats] = sorted_stats[i];

        file << "    \"" << domain << "\": {\n";
        file << "      \"packets\": " << stats.packets << ",\n";
        file << "      \"bytes\": " << stats.bytes_in << ",\n";
        file << "      \"ips_count\": " << stats.ips.size() << ",\n";
        file << "      \"ips\": [";

        for (size_t j = 0; j < stats.ips.size(); j++) {
            file << "\"" << stats.ips[j] << "\"";
            if (j < stats.ips.size() - 1) file << ", ";
        }

        file << "],\n";
        file << "      \"last_seen\": \"" << stats.last_seen << "\"\n";
        file << "    }";

        if (i < sorted_stats.size() - 1) file << ",";
        file << "\n";
    }

    file << "  },\n";
    file << "  \"packets\": [\n";

    // Limit log to last 1000 packets
    size_t start_idx = packet_log.size() > 1000 ? packet_log.size() - 1000 : 0;

    for (size_t i = start_idx; i < packet_log.size(); i++) {
        const auto& pkt = packet_log[i];

        file << "    {\n";
        file << "      \"timestamp\": \"" << pkt.timestamp << "\",\n";
        file << "      \"domain\": \"" << pkt.domain << "\",\n";
        file << "      \"protocol\": \"" << pkt.protocol << "\",\n";
        file << "      \"src_ip\": \"" << pkt.src_ip << "\",\n";
        file << "      \"dst_ip\": \"" << pkt.dst_ip << "\",\n";
        file << "      \"port\": " << pkt.port << ",\n";
        file << "      \"bytes\": " << pkt.bytes << "\n";
        file << "    }";

        if (i < packet_log.size() - 1) file << ",";
        file << "\n";
    }

    file << "  ]\n";
    file << "}\n";

    file.close();
    std::cout << "Report saved to: " << filename << std::endl;
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);

    pcap_if_t* alldevs;
    pcap_if_t* d;
    char errbuf[PCAP_ERRBUF_SIZE];

    std::cout << "=== Advanced Network Traffic Monitor ===" << std::endl;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
        return 1;
    }

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

        std::cout << "\nEnter interface number (default 1): ";
        std::string input;
        std::getline(std::cin, input);

        int choice = input.empty() ? 1 : std::stoi(input);
        i = 0;
        for (d = alldevs; d != nullptr && i < choice - 1; d = d->next) {
            i++;
        }

        if (d != nullptr) {
            device = d->name;
        } else {
            std::cerr << "Invalid choice" << std::endl;
            return 1;
        }
    }

    std::cout << "Monitoring on interface: " << device << std::endl;
    std::cout << "Press Ctrl+C to stop and generate report" << std::endl;

    pcap_t* handle = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

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

    std::cout << std::endl;
    pcap_loop(handle, -1, packet_handler, nullptr);

    print_console_stats();

    // Export reports
    std::string timestamp = get_timestamp();
    std::replace(timestamp.begin(), timestamp.end(), ' ', '_');
    std::replace(timestamp.begin(), timestamp.end(), ':', '-');

    std::string json_filename = "traffic_report_" + timestamp + ".json";
    export_json(json_filename);

    pcap_freecode(&fp);
    pcap_close(handle);
    pcap_freealldevs(alldevs);

    return 0;
}
