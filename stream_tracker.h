#pragma once
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <chrono>

struct ConnectionKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    bool operator==(const ConnectionKey& other) const {
        return src_ip == other.src_ip &&
               dst_ip == other.dst_ip &&
               src_port == other.src_port &&
               dst_port == other.dst_port;
    }
};

struct KeyHasher {
    std::size_t operator()(const ConnectionKey& k) const {
        return std::hash<uint32_t>()(k.src_ip) ^
               std::hash<uint32_t>()(k.dst_ip) ^
               std::hash<uint16_t>()(k.src_port) ^
               std::hash<uint16_t>()(k.dst_port);
    }
};

struct StreamData {
    std::vector<unsigned char> buffer;
    std::chrono::steady_clock::time_point last_activity;
};

class StreamTracker {
public:
    std::unordered_map<ConnectionKey, StreamData, KeyHasher> active_streams;

    void add_payload(const ConnectionKey& key, const unsigned char* payload, int len) {
        active_streams[key].buffer.insert(active_streams[key].buffer.end(), payload, payload + len);
        active_streams[key].last_activity = std::chrono::steady_clock::now();
    }

    const std::vector<unsigned char>& get_stream(const ConnectionKey& key) {
        return active_streams[key].buffer;
    }

    // gracefully delete connections
    void close_connection(const ConnectionKey& key) {
        active_streams.erase(key);
    }

    // garbage collection
    void prune_stale_connections(int timeout_seconds = 60) {
        auto now = std::chrono::steady_clock::now();
        for (auto it = active_streams.begin(); it != active_streams.end();) {
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity).count();
            if (duration > timeout_seconds) {
                it = active_streams.erase(it);
            } else {
                ++it;
            }
        }
    }
};