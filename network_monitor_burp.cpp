#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <cstring>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>
#include <mutex>
#include <atomic>
#include <csignal>
#include <ctime>

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

struct HttpHeader {
    std::string name;
    std::string value;
};

struct HttpRequest {
    std::string method;
    std::string uri;
    std::string version;
    std::string host;
    std::vector<HttpHeader> headers;
    std::string body_preview;
    std::string timestamp;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
};

struct HttpResponse {
    std::string version;
    int status_code = 0;
    std::string status_text;
    std::vector<HttpHeader> headers;
    std::string body_preview;
    uint64_t content_length = 0;
    std::string content_type;
    std::string timestamp;
};

struct HttpSession {
    uint32_t id = 0;
    std::string conn_key;
    HttpRequest request;
    HttpResponse response;
    bool has_response = false;
    bool is_https = false;
    std::string tls_sni;
    uint64_t total_bytes = 0;
};

struct DomainStats {
    std::string domain;
    uint64_t bytes_in = 0;
    uint64_t bytes_out = 0;
    uint64_t packets_in = 0;
    uint64_t packets_out = 0;
    std::string last_seen;
};

struct TcpStream {
    std::string buffer;
    std::chrono::steady_clock::time_point last_seen;
    bool request_captured = false;
    uint32_t session_id = 0;
};

std::atomic<bool> running{true};
std::atomic<pcap_t*> g_handle{nullptr};
std::mutex stats_mutex;
std::map<std::string, DomainStats> domain_stats;
std::vector<HttpSession> http_sessions;
std::map<std::string, TcpStream> tcp_streams;
std::map<std::string, std::string> tls_sni_map;
std::atomic<uint32_t> session_counter{0};

std::string get_timestamp() {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string format_bytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    double size = bytes;
    int unit = 0;
    while (size >= 1024 && unit < 3) {
        size /= 1024;
        unit++;
    }
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(1) << size << " " << units[unit];
    return oss.str();
}

std::string json_escape(const std::string& s) {
    std::string result;
    for (char c : s) {
        if (c == '"') result += "\\\"";
        else if (c == '\\') result += "\\\\";
        else if (c == '\n') result += "\\n";
        else if (c == '\r') result += "\\r";
        else if (c == '\t') result += "\\t";
        else if (c < 32) result += "\\u00" + std::string(1, "0123456789abcdef"[c >> 4]) + std::string(1, "0123456789abcdef"[c & 0xf]);
        else result += c;
    }
    return result;
}

std::string make_conn_key(const std::string& src_ip, uint16_t sport,
                          const std::string& dst_ip, uint16_t dport) {
    std::ostringstream oss;
    oss << src_ip << ":" << sport << "->" << dst_ip << ":" << dport;
    return oss.str();
}

std::string reverse_conn_key(const std::string& key) {
    size_t arrow = key.find("->");
    if (arrow == std::string::npos) return "";
    std::string src_part = key.substr(0, arrow);
    std::string dst_part = key.substr(arrow + 2);
    return dst_part + "->" + src_part;
}

std::string extract_tls_sni(const u_char* data, int len) {
    if (len < 45) return "";
    if (data[0] != 0x16 || data[1] != 0x03) return "";
    if (data[5] != 0x01) return "";

    int offset = 9;
    if (offset + 34 > len) return "";
    offset += 34;

    if (offset + 1 > len) return "";
    int session_id_len = data[offset++];
    offset += session_id_len;

    if (offset + 2 > len) return "";
    int cipher_suites_len = (data[offset] << 8) | data[offset + 1];
    offset += 2 + cipher_suites_len;

    if (offset + 1 > len) return "";
    int compression_len = data[offset++];
    offset += compression_len;

    if (offset + 2 > len) return "";
    int extensions_len = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    int ext_end = offset + extensions_len;

    while (offset + 4 <= ext_end && offset + 4 <= len) {
        int ext_type = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        int ext_len = (data[offset] << 8) | data[offset + 1];
        offset += 2;

        if (ext_type == 0x0000) {
            if (offset + 2 > len) return "";
            offset += 2;
            if (offset + 3 > len) return "";
            int name_type = data[offset++];
            int name_len = (data[offset] << 8) | data[offset + 1];
            offset += 2;
            if (name_type != 0 || offset + name_len > len) return "";
            return std::string((const char*)data + offset, name_len);
        }
        offset += ext_len;
    }
    return "";
}

std::string extract_domain_from_dns(const u_char* data, int len) {
    if (len < 13) return "";
    int offset = 12;
    std::string domain;
    while (offset < len) {
        int label_len = data[offset];
        if (label_len == 0) break;
        if (label_len > 63) return "";
        offset++;
        if (offset + label_len > len) return "";
        if (!domain.empty()) domain += ".";
        domain += std::string((const char*)data + offset, label_len);
        offset += label_len;
    }
    return domain;
}

bool is_http_request(const std::string& buf) {
    const char* methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
                            "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "};
    for (const char* m : methods) {
        if (buf.find(m) == 0) return true;
    }
    return false;
}

bool is_http_response(const std::string& buf) {
    if (buf.size() >= 7 && buf.substr(0, 7) == "HTTP/1.") return true;
    if (buf.size() >= 7 && buf.substr(0, 7) == "HTTP/2") return true;
    return false;
}

bool has_complete_headers(const std::string& buf) {
    return buf.find("\r\n\r\n") != std::string::npos;
}

std::string get_header_value(const std::string& buf, const std::string& header_name) {
    size_t headers_end = buf.find("\r\n\r\n");
    if (headers_end == std::string::npos) headers_end = buf.size();

    std::string lower_name = header_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    lower_name += ": ";

    size_t pos = 0;
    while ((pos = buf.find(lower_name, pos)) != std::string::npos && pos < headers_end) {
        pos += lower_name.size();
        size_t end = buf.find("\r\n", pos);
        if (end == std::string::npos) end = buf.size();
        std::string value = buf.substr(pos, end - pos);
        size_t colon = value.find(':');
        if (colon != std::string::npos) value = value.substr(colon + 1);
        while (!value.empty() && value[0] == ' ') value = value.substr(1);
        return value;
    }
    return "";
}

HttpRequest parse_http_request(const std::string& buf) {
    HttpRequest req;
    req.timestamp = get_timestamp();

    size_t line_end = buf.find("\r\n");
    if (line_end == std::string::npos) line_end = buf.find("\n");
    if (line_end == std::string::npos) return req;

    std::string request_line = buf.substr(0, line_end);
    size_t first_space = request_line.find(' ');
    size_t second_space = request_line.find(' ', first_space + 1);

    if (first_space != std::string::npos && second_space != std::string::npos) {
        req.method = request_line.substr(0, first_space);
        req.uri = request_line.substr(first_space + 1, second_space - first_space - 1);
        req.version = request_line.substr(second_space + 1);
    }

    req.host = get_header_value(buf, "host");

    size_t headers_end = buf.find("\r\n\r\n");
    if (headers_end == std::string::npos) headers_end = buf.find("\n\n");
    if (headers_end != std::string::npos) {
        size_t body_start = headers_end + 4;
        if (body_start > buf.size()) body_start = buf.size();
        size_t preview_len = std::min(size_t(512), buf.size() - body_start);
        req.body_preview = buf.substr(body_start, preview_len);
    }

    return req;
}

HttpResponse parse_http_response(const std::string& buf) {
    HttpResponse resp;
    resp.timestamp = get_timestamp();

    size_t line_end = buf.find("\r\n");
    if (line_end == std::string::npos) line_end = buf.find("\n");
    if (line_end == std::string::npos) return resp;

    std::string status_line = buf.substr(0, line_end);
    size_t first_space = status_line.find(' ');
    if (first_space != std::string::npos) {
        resp.version = status_line.substr(0, first_space);
        size_t second_space = status_line.find(' ', first_space + 1);
        if (second_space != std::string::npos) {
            resp.status_code = std::stoi(status_line.substr(first_space + 1, second_space - first_space - 1));
            resp.status_text = status_line.substr(second_space + 1);
        }
    }

    std::string cl_str = get_header_value(buf, "content-length");
    if (!cl_str.empty()) {
        try { resp.content_length = std::stoll(cl_str); } catch (...) {}
    }
    resp.content_type = get_header_value(buf, "content-type");

    size_t headers_end = buf.find("\r\n\r\n");
    if (headers_end == std::string::npos) headers_end = buf.find("\n\n");
    if (headers_end != std::string::npos) {
        size_t body_start = headers_end + 4;
        if (body_start > buf.size()) body_start = buf.size();
        size_t preview_len = std::min(size_t(512), buf.size() - body_start);
        resp.body_preview = buf.substr(body_start, preview_len);
    }

    return resp;
}

void update_domain_stats(const std::string& domain, const std::string& protocol,
                         const std::string& src_ip, const std::string& dst_ip,
                         bool is_outgoing, uint64_t bytes) {
    (void)protocol; (void)src_ip; (void)dst_ip;
    if (domain.empty()) return;
    auto& stats = domain_stats[domain];
    stats.domain = domain;
    stats.last_seen = get_timestamp();
    if (is_outgoing) {
        stats.bytes_out += bytes;
        stats.packets_out++;
    } else {
        stats.bytes_in += bytes;
        stats.packets_in++;
    }
}

void process_tcp_payload(const std::string& conn_key, const std::string& payload,
                         bool is_https, uint16_t dst_port) {
    auto& stream = tcp_streams[conn_key];
    stream.last_seen = std::chrono::steady_clock::now();

    if (stream.buffer.size() < 65536) {
        stream.buffer += payload;
    }

    if (!stream.request_captured && is_http_request(stream.buffer) && has_complete_headers(stream.buffer)) {
        HttpRequest req = parse_http_request(stream.buffer);

        if (tls_sni_map.count(conn_key)) {
            req.host = tls_sni_map[conn_key];
        }

        HttpSession session;
        session.id = ++session_counter;
        session.conn_key = conn_key;
        session.request = req;
        session.is_https = is_https;
        if (tls_sni_map.count(conn_key)) {
            session.tls_sni = tls_sni_map[conn_key];
        }

        if (http_sessions.size() >= 500) {
            http_sessions.erase(http_sessions.begin());
        }
        http_sessions.push_back(session);
        stream.request_captured = true;
        stream.session_id = session.id;

        std::string domain = req.host;
        std::string proto = is_https ? "HTTPS" : "HTTP";
        update_domain_stats(domain, proto, req.src_ip, req.dst_ip, (dst_port != 80 && dst_port != 443 && dst_port != 8080), stream.buffer.size());
    }

    if (is_http_response(stream.buffer) && has_complete_headers(stream.buffer)) {
        std::string rev_key = reverse_conn_key(conn_key);
        for (auto it = http_sessions.rbegin(); it != http_sessions.rend(); ++it) {
            if (it->conn_key == rev_key && !it->has_response) {
                it->response = parse_http_response(stream.buffer);
                it->has_response = true;
                it->total_bytes += stream.buffer.size();
                break;
            }
        }
    }
}

void cleanup_stale_streams() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = tcp_streams.begin(); it != tcp_streams.end();) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_seen).count();
        if (age > 30) {
            it = tcp_streams.erase(it);
        } else {
            ++it;
        }
    }
}

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    (void)user_data;
    if (pkthdr->caplen < 34) return;

    struct ip* ip_header = (struct ip*)(packet + 14);
    if (ip_header->ip_v != 4) return;

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_header->ip_src, src_ip_str, sizeof(src_ip_str));
    inet_ntop(AF_INET, &ip_header->ip_dst, dst_ip_str, sizeof(dst_ip_str));

    std::string src_ip(src_ip_str);
    std::string dst_ip(dst_ip_str);

    if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)(packet + 14 + ip_header->ip_hl * 4);
        uint16_t dport = ntohs(udp->uh_dport);
        uint16_t sport = ntohs(udp->uh_sport);

        if (dport == 53 || sport == 53) {
            const u_char* dns_data = packet + 14 + ip_header->ip_hl * 4 + 8;
            int dns_len = pkthdr->caplen - (14 + ip_header->ip_hl * 4 + 8);
            std::string domain = extract_domain_from_dns(dns_data, dns_len);

            std::lock_guard<std::mutex> lock(stats_mutex);
            update_domain_stats(domain, "DNS", src_ip, dst_ip, dport != 53, pkthdr->len);
        }
    } else if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4);
        uint16_t dport = ntohs(tcp->th_dport);
        uint16_t sport = ntohs(tcp->th_sport);

        bool is_https = (dport == 443 || sport == 443);

        if (is_https && pkthdr->caplen > 14 + ip_header->ip_hl * 4 + tcp->th_off * 4 + 5) {
            const u_char* tcp_payload = packet + 14 + ip_header->ip_hl * 4 + tcp->th_off * 4;
            int payload_len = pkthdr->caplen - (14 + ip_header->ip_hl * 4 + tcp->th_off * 4);

            if (tcp_payload[0] == 0x16 && tcp_payload[1] == 0x03) {
                std::string sni = extract_tls_sni(tcp_payload, payload_len);
                if (!sni.empty()) {
                    std::string conn_key = make_conn_key(src_ip, sport, dst_ip, dport);
                    tls_sni_map[conn_key] = sni;

                    std::lock_guard<std::mutex> lock(stats_mutex);
                    update_domain_stats(sni, "HTTPS", src_ip, dst_ip, dport != 443, pkthdr->len);
                }
            }
        }

        if (dport == 80 || dport == 443 || dport == 8080 || sport == 80 || sport == 443 || sport == 8080) {
            const u_char* tcp_payload = packet + 14 + ip_header->ip_hl * 4 + tcp->th_off * 4;
            int payload_len = pkthdr->caplen - (14 + ip_header->ip_hl * 4 + tcp->th_off * 4);

            if (payload_len > 0) {
                std::string conn_key = make_conn_key(src_ip, sport, dst_ip, dport);
                std::string payload_str((const char*)tcp_payload, payload_len);

                std::lock_guard<std::mutex> lock(stats_mutex);
                process_tcp_payload(conn_key, payload_str, is_https, dport);
            }
        }
    }
}

void render_live_table() {
    std::lock_guard<std::mutex> lock(stats_mutex);

    std::cout << "\033[?25l\033[H\033[2J";
    std::cout << "Network Monitor — Burp View\n\n";

    std::cout << "DOMAIN STATS\n";
    std::cout << std::string(95, '-') << "\n";
    std::cout << std::left << std::setw(35) << "Domain" << std::setw(8) << "Proto"
              << std::setw(13) << "Bytes In" << std::setw(13) << "Bytes Out"
              << std::setw(8) << "Pkts" << std::setw(5) << "IPs" << "\n";

    std::vector<std::pair<std::string, DomainStats>> sorted(domain_stats.begin(), domain_stats.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return (a.second.bytes_in + a.second.bytes_out) > (b.second.bytes_in + b.second.bytes_out); });

    for (const auto& [_, stats] : sorted) {
        std::string domain_trunc = stats.domain;
        if (domain_trunc.size() > 34) domain_trunc = domain_trunc.substr(0, 31) + "~";
        std::cout << std::left << std::setw(35) << domain_trunc << std::setw(8) << ""
                  << std::setw(13) << format_bytes(stats.bytes_in) << std::setw(13) << format_bytes(stats.bytes_out)
                  << std::setw(8) << (stats.packets_in + stats.packets_out) << std::setw(5) << "1" << "\n";
    }

    std::cout << "\nHTTP SESSIONS (last 10)\n";
    std::cout << std::string(95, '-') << "\n";
    std::cout << std::left << std::setw(4) << "#" << std::setw(8) << "Method"
              << std::setw(28) << "Host" << std::setw(32) << "Path"
              << std::setw(7) << "Status" << std::setw(8) << "Size" << "\n";

    size_t start = http_sessions.size() > 10 ? http_sessions.size() - 10 : 0;
    for (size_t i = start; i < http_sessions.size(); ++i) {
        const auto& sess = http_sessions[i];
        std::string host_trunc = sess.request.host;
        if (host_trunc.size() > 27) host_trunc = host_trunc.substr(0, 24) + "~";
        std::string path_trunc = sess.request.uri;
        if (path_trunc.size() > 31) path_trunc = path_trunc.substr(0, 28) + "~";
        std::string status = sess.has_response ? std::to_string(sess.response.status_code) : "—";

        std::cout << std::left << std::setw(4) << sess.id << std::setw(8) << sess.request.method
                  << std::setw(28) << host_trunc << std::setw(32) << path_trunc
                  << std::setw(7) << status << std::setw(8) << format_bytes(sess.total_bytes) << "\n";
    }

    std::cout << std::flush;
    std::cout << "\033[?25h";
}

void display_thread_func() {
    while (running) {
        render_live_table();
        for (int i = 0; i < 10 && running; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void maintenance_thread_func() {
    while (running) {
        for (int i = 0; i < 50 && running; ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::lock_guard<std::mutex> lock(stats_mutex);
        cleanup_stale_streams();
    }
}

std::string build_sessions_json() {
    std::ostringstream oss;
    oss << "{\"sessions\":[";
    bool first = true;
    for (const auto& sess : http_sessions) {
        if (!first) oss << ",";
        first = false;
        oss << "{\"id\":" << sess.id << ",\"method\":\"" << json_escape(sess.request.method)
            << "\",\"host\":\"" << json_escape(sess.request.host) << "\",\"uri\":\"" << json_escape(sess.request.uri)
            << "\",\"status\":" << (sess.has_response ? sess.response.status_code : 0)
            << ",\"size\":" << sess.total_bytes << ",\"https\":" << (sess.is_https ? "true" : "false") << "}";
    }
    oss << "]}";
    return oss.str();
}

std::string build_stats_json() {
    std::ostringstream oss;
    oss << "{\"domains\":{";
    bool first = true;
    for (const auto& [_, stats] : domain_stats) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << json_escape(stats.domain) << "\":{\"bytes_in\":" << stats.bytes_in
            << ",\"bytes_out\":" << stats.bytes_out << ",\"packets\":" << (stats.packets_in + stats.packets_out) << "}";
    }
    oss << "}}";
    return oss.str();
}

std::string build_html_ui() {
    return R"HTML(<!DOCTYPE html>
<html>
<head>
    <title>Network Monitor — Burp View</title>
    <style>
        body { font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 1em; }
        h1, h2 { color: #00d4ff; }
        h2 { border-bottom: 1px solid #333; padding-bottom: 0.5em; }
        table { border-collapse: collapse; width: 100%; margin: 1em 0; }
        th { background: #16213e; color: #00d4ff; padding: 8px 12px; text-align: left; }
        td { padding: 6px 12px; border-bottom: 1px solid #222; }
        tr:hover { background: #0f3460; }
        .expand-row { background: #0d2137; }
        .expand-row pre { white-space: pre-wrap; word-break: break-all; color: #a8e6cf; margin: 0; }
        button { background: #0f3460; color: #00d4ff; border: 1px solid #00d4ff; padding: 6px 12px; cursor: pointer; border-radius: 3px; margin-right: 5px; }
        button:hover { background: #16213e; }
        .method-GET { color: #69db7c; font-weight: bold; }
        .method-POST { color: #ffa94d; font-weight: bold; }
        .status-2 { color: #69db7c; }
        .status-4 { color: #ff6b6b; }
        .status-5 { color: #ff8787; }
    </style>
</head>
<body>
    <h1>Network Monitor — Burp View</h1>
    <div>
        <button onclick="location.reload()">Refresh</button>
        <button onclick="exportJSON()">Export JSON</button>
        <span id="status"></span>
    </div>

    <h2>Domain Stats</h2>
    <table id="stats-table">
        <thead>
            <tr><th>Domain</th><th>Bytes In</th><th>Bytes Out</th><th>Packets</th></tr>
        </thead>
        <tbody id="stats-body"></tbody>
    </table>

    <h2>HTTP Sessions</h2>
    <table id="sessions-table">
        <thead>
            <tr><th>#</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Size</th></tr>
        </thead>
        <tbody id="sessions-body"></tbody>
    </table>

    <script>
        const POLL_MS = 2000;

        async function refreshSessions() {
            try {
                const r = await fetch('/api/sessions');
                const data = await r.json();
                const tbody = document.getElementById('sessions-body');
                tbody.innerHTML = '';
                (data.sessions || []).forEach(s => {
                    const tr = document.createElement('tr');
                    const method_class = s.method === 'GET' ? 'method-GET' : s.method === 'POST' ? 'method-POST' : '';
                    const status_class = s.status >= 200 && s.status < 300 ? 'status-2' : s.status >= 400 && s.status < 500 ? 'status-4' : s.status >= 500 ? 'status-5' : '';
                    tr.innerHTML = '<td>' + s.id + '</td><td class="' + method_class + '">' + s.method + '</td><td>' + s.host + '</td><td>' + s.uri.substring(0, 30) + '</td><td class="' + status_class + '">' + (s.status || '—') + '</td><td>' + s.size + '</td>';
                    tr.style.cursor = 'pointer';
                    tbody.appendChild(tr);
                });
            } catch (e) { console.error(e); }
        }

        async function refreshStats() {
            try {
                const r = await fetch('/api/stats');
                const data = await r.json();
                const tbody = document.getElementById('stats-body');
                tbody.innerHTML = '';
                Object.entries(data.domains || {}).forEach(([domain, stats]) => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = '<td>' + domain + '</td><td>' + stats.bytes_in + '</td><td>' + stats.bytes_out + '</td><td>' + stats.packets + '</td>';
                    tbody.appendChild(tr);
                });
            } catch (e) { console.error(e); }
        }

        function exportJSON() {
            window.location.href = '/export';
        }

        refreshSessions();
        refreshStats();
        setInterval(refreshSessions, POLL_MS);
        setInterval(refreshStats, POLL_MS);
    </script>
</body>
</html>)HTML";
}

void handle_web_client(int client_fd) {
    char buffer[2048];
    int read_len = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
    if (read_len <= 0) {
        close(client_fd);
        return;
    }
    buffer[read_len] = '\0';

    std::string request(buffer);
    std::string path = "/";
    size_t space1 = request.find(' ');
    if (space1 != std::string::npos) {
        size_t space2 = request.find(' ', space1 + 1);
        if (space2 != std::string::npos) {
            path = request.substr(space1 + 1, space2 - space1 - 1);
        }
    }

    std::string response;
    if (path == "/") {
        std::string html = build_html_ui();
        response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " + std::to_string(html.size()) + "\r\n\r\n" + html;
    } else if (path == "/api/sessions") {
        std::lock_guard<std::mutex> lock(stats_mutex);
        std::string json = build_sessions_json();
        response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(json.size()) + "\r\n\r\n" + json;
    } else if (path == "/api/stats") {
        std::lock_guard<std::mutex> lock(stats_mutex);
        std::string json = build_stats_json();
        response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + std::to_string(json.size()) + "\r\n\r\n" + json;
    } else {
        response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    }

    send(client_fd, response.c_str(), response.size(), 0);
    close(client_fd);
}

void web_server_thread_func() {
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        std::cerr << "Failed to create socket\n";
        return;
    }

    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(listen_fd);
        return;
    }

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(8888);

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listen_fd);
        return;
    }

    if (listen(listen_fd, 5) < 0) {
        close(listen_fd);
        return;
    }

    fcntl(listen_fd, F_SETFL, O_NONBLOCK);

    std::cerr << "Web UI running at http://localhost:8888\n";

    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(listen_fd + 1, &readfds, nullptr, nullptr, &tv);
        if (sel <= 0) continue;

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_fd >= 0) {
            std::thread(&handle_web_client, client_fd).detach();
        }
    }

    close(listen_fd);
}

void signal_handler(int sig) {
    (void)sig;
    running = false;
    pcap_t* handle = g_handle.load();
    if (handle) pcap_breakloop(handle);
}

void print_console_stats() {
    std::cout << "\n\nFinal Statistics:\n";
    std::cout << std::string(95, '-') << "\n";
    std::cout << std::left << std::setw(40) << "Domain" << std::setw(12) << "Packets"
              << std::setw(15) << "Bytes" << "\n";

    std::vector<std::pair<std::string, DomainStats>> sorted(domain_stats.begin(), domain_stats.end());
    std::sort(sorted.begin(), sorted.end(),
              [](const auto& a, const auto& b) { return (a.second.bytes_in + a.second.bytes_out) > (b.second.bytes_in + b.second.bytes_out); });

    for (const auto& [_, stats] : sorted) {
        std::cout << std::left << std::setw(40) << stats.domain << std::setw(12) << (stats.packets_in + stats.packets_out)
                  << std::setw(15) << format_bytes(stats.bytes_in + stats.bytes_out) << "\n";
    }
}

void export_json(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) return;

    file << "{\"timestamp\":\"" << get_timestamp() << "\",\"total_packets\":" << 0 << ",\"domains\":{";
    bool first = true;
    for (const auto& [_, stats] : domain_stats) {
        if (!first) file << ",";
        first = false;
        file << "\"" << json_escape(stats.domain) << "\":{\"packets\":" << (stats.packets_in + stats.packets_out)
             << ",\"bytes\":" << (stats.bytes_in + stats.bytes_out) << ",\"ips_count\":1,\"ips\":[],\"last_seen\":\""
             << stats.last_seen << "\"}";
    }
    file << "},\"http_sessions\":[";
    first = true;
    for (const auto& sess : http_sessions) {
        if (!first) file << ",";
        first = false;
        file << "{\"id\":" << sess.id << ",\"method\":\"" << json_escape(sess.request.method) << "\",\"uri\":\""
             << json_escape(sess.request.uri) << "\",\"host\":\"" << json_escape(sess.request.host)
             << "\",\"https\":" << (sess.is_https ? "true" : "false");
        if (sess.has_response) {
            file << ",\"status_code\":" << sess.response.status_code << ",\"status_text\":\""
                 << json_escape(sess.response.status_text) << "\"";
        }
        file << ",\"total_bytes\":" << sess.total_bytes << "}";
    }
    file << "]}";
    file.close();
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "pcap_findalldevs: " << errbuf << "\n";
        return 1;
    }

    std::string device;
    if (argc > 1) {
        device = argv[1];
    } else {
        std::cout << "Available interfaces:\n";
        int i = 0;
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            std::cout << i++ << ": " << d->name << "\n";
        }
        int choice = 0;
        std::cout << "Select interface [0]: ";
        std::cin >> choice;

        i = 0;
        for (pcap_if_t* d = alldevs; d; d = d->next, ++i) {
            if (i == choice) {
                device = d->name;
                break;
            }
        }
    }

    if (device.empty()) {
        std::cerr << "No device selected\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_t* handle = pcap_open_live(device.c_str(), 65535, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live: " << errbuf << "\n";
        pcap_freealldevs(alldevs);
        return 1;
    }

    g_handle = handle;

    struct bpf_program fp;
    const char* filter_str = "udp port 53 or tcp port 80 or tcp port 443 or tcp port 8080";
    if (pcap_compile(handle, &fp, filter_str, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "pcap_compile: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap_setfilter: " << pcap_geterr(handle) << "\n";
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_freealldevs(alldevs);

    std::thread display_thread(display_thread_func);
    std::thread web_thread(web_server_thread_func);
    std::thread maint_thread(maintenance_thread_func);

    pcap_loop(handle, -1, packet_handler, nullptr);

    running = false;
    display_thread.join();
    web_thread.join();
    maint_thread.join();

    std::cout << "\033[H\033[2J";
    print_console_stats();

    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::ostringstream oss;
    oss << "traffic_report_" << std::put_time(&tm, "%Y-%m-%d_%H-%M-%S") << ".json";
    export_json(oss.str());

    std::cout << "Report saved to: " << oss.str() << "\n";

    pcap_close(handle);
    return 0;
}
