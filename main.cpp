#include <iostream>
#include <pcap.h>
#include <string>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>
#include "aho_corasick.h"
#include "stream_tracker.h"
#include <fstream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <arpa/inet.h>

AhoCorasick ac;
StreamTracker tracker;

void inspect_payload(const u_char *payload, int len) {
    ac.search(payload, len);
}

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // 1. Grab the log file pointer passed from pcap_loop
    std::ofstream* log_file = reinterpret_cast<std::ofstream*>(user_data);

    struct ether_header *eth_header = (struct ether_header *)packet;

    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        if (ip_header->ip_p == IPPROTO_TCP) {
            unsigned int ip_header_len = ip_header->ip_hl * 4;
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
            unsigned int tcp_header_len = tcp_header->th_off * 4;

            // 1. Build the Connection Key
            ConnectionKey key;
            key.src_ip = ip_header->ip_src.s_addr;
            key.dst_ip = ip_header->ip_dst.s_addr;
            key.src_port = tcp_header->th_sport; 
            key.dst_port = tcp_header->th_dport;

            // 2. Check for TCP Teardown Flags (FIN or RST)
            // If the connection is closing, delete the buffer to free RAM and skip scanning.
            if ((tcp_header->th_flags & TH_FIN) || (tcp_header->th_flags & TH_RST)) {
                tracker.close_connection(key);
                return; // Packet handled, move on
            }

            unsigned int total_headers_size = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
            const u_char* payload = packet + total_headers_size;
            int payload_len = ntohs(ip_header->ip_len) - (ip_header_len + tcp_header_len);

            if (payload_len > 0) { 
                tracker.add_payload(key, payload, payload_len);
                const std::vector<unsigned char>& assembled_stream = tracker.get_stream(key);

                int old_alert_count = ac.alert_count;
                std::vector<AlertMatch> results = ac.search(assembled_stream.data(), assembled_stream.size());

                // 3. If we found malware, log ALL the data points as JSON
                if (!results.empty()) {
                    // Get current timestamp and format it as ISO 8601 (Standard JSON time)
                    auto now = std::chrono::system_clock::now();
                    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
                    
                    // Safely convert IPs to strings using inet_ntop (Enterprise standard)
                    struct in_addr src_addr, dst_addr;
                    src_addr.s_addr = key.src_ip;
                    dst_addr.s_addr = key.dst_ip;
                    char src_ip_str[INET_ADDRSTRLEN];
                    char dst_ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);

                    for (const AlertMatch& match : results) {
                        std::cout << "[!] NIDS ALERT Triggered. Writing JSON to log..." << std::endl;

                        // Write structured JSON to the .log file
                        *log_file << "{"
                                  << "\t\"timestamp\":\"" << std::put_time(std::gmtime(&now_time), "%Y-%m-%dT%H:%M:%SZ") << "\",\n"
                                  << "\t\"event_type\":\"alert\",\n"
                                  << "\t\"src_ip\":\"" << src_ip_str << "\",\n"
                                  << "\t\"src_port\":" << ntohs(key.src_port) << ",\n"
                                  << "\t\"dest_ip\":\"" << dst_ip_str << "\",\n"
                                  << "\t\"dest_port\":" << ntohs(key.dst_port) << ",\n"
                                  << "\t\"protocol\":\"TCP\",\n"
                                  << "\t\"packet_length\":" << pkthdr->len << ",\n"
                                  << "\t\"alert\":{\n"
                                  << "\t\t\"signature\":\"" << match.signature << "\",\n"
                                  << "\t\t\"offset\":" << match.offset << "\n"
                                  << "\t}\n"
                                  << "}\n";
                        
                        // Force write to disk immediately
                        log_file->flush(); 
                    }
                }

                if (ac.alert_count > old_alert_count) {
                    tracker.active_streams[key].buffer.clear();
                }
            }

            // 3. Lazy Garbage Collection
            // Since we are running in a fast packet loop, we don't want to sweep the map every single packet.
            // A simple hack: Only run the heavy sweeper occasionally (e.g., arbitrarily checking every time the clock hits a 0 second).
            // In an enterprise system, this runs on a separate background thread.
            static auto last_prune = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_prune).count() > 10) {
                tracker.prune_stale_connections(60); // Drop connections idle > 60s
                last_prune = now;
            }
        }
    }
}

int main() {
    // init signatures
    ac.insert("eval(base64_decode");
    ac.insert("UNION SELECT");
    ac.insert("../etc/passwd");
    ac.build_failure_links();

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;

    if (pcap_findalldevs(&interfaces, error_buffer) == -1) {
        std::cerr << "Error finding devices: " << error_buffer << std::endl;
        return 1;
    }

    const char* dev_name = "lo";
    std::cout << "Opening device: " << dev_name << " ...\n";
    std::cout << "Opened " << dev_name << " in promiscuous mode.\n";

    /*
     * pcap_open_live parameters:
     * 1. Device name
     * 2. Snaplen: Max bytes to capture per packet (65535 is standard for "all")
     * 3. Promiscuous: 1 (True) or 0 (False)
     * 4. Timeout: 1000 (ms)
     * 5. Error buffer
     */
    pcap_t* handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, error_buffer);

    if (handle == nullptr) {
        std::cerr << "Could not open device " << dev_name << ": " << error_buffer << std::endl;
        pcap_freealldevs(interfaces);
        return 2;
    }

    struct bpf_program fp;
    const char* filter_exp = "tcp dst port 8080";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Could not parse filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
        return 2;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Could not install filter " << filter_exp << ": " << pcap_geterr(handle) << std::endl;
    }

    std::cout << "BPF Filter applied: " << filter_exp << std::endl;

    std::ofstream log_file("dpi_alerts.jsonl", std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "Fatal: could not open dpi_alerts.log\n";
        return 3;
    }

    std::cout << "Logging alerts to: dpi_alerts.log\n";
    std::cout << "Sniffing " << dev_name << "... Press Ctrl+C to stop.\n";

    pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(&log_file));

    pcap_close(handle);
    pcap_freealldevs(interfaces);
    return 0;
}