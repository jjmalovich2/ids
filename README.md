# L7-NIDS: Layer 7 Network Intrusion Detection System

A high-performance, custom-built C++ Network Intrusion Detection System (NIDS) designed to capture, reassemble, and inspect real-time network traffic for malicious payloads. Built from the ground up, this project demonstrates the core architecture used by enterprise-grade security tools like Snort and Suricata.

## 🚀 Key Features

* **Raw Packet Capture:** Hooks directly into the network interface using `libpcap` to sniff live traffic.
* **Kernel-Level Filtering (BPF):** Utilizes Berkeley Packet Filters (`tcp dst port 8080`) to drop irrelevant packets at the kernel level, saving CPU cycles.
* **TCP Stream Reassembly:** Defeats packet-fragmentation evasion techniques by tracking the 4-Tuple state (Source IP, Dest IP, Source Port, Dest Port) and reassembling segmented payloads.
* **High-Speed Pattern Matching:** Implements the **Aho-Corasick Finite State Machine**, allowing simultaneous $O(n)$ scanning of thousands of malware signatures without performance degradation.
* **Memory Management & Anti-DoS:** Features a custom Garbage Collector and TCP flag monitor (FIN/RST) to gracefully delete idle connection buffers, preventing memory exhaustion attacks (e.g., Slowloris).
* **Enterprise-Ready Logging:** Outputs structured **JSON Lines (JSONL)** logs, automatically resolving IPs and packaging alert metadata for immediate ingestion by SIEMs like Splunk or Elasticsearch.

## 🧠 Architecture Pipeline

1.  **Capture:** `libpcap` sniffs raw Ethernet frames from the wire.
2.  **Filter:** The OS Kernel applies the BPF, only passing relevant traffic to the NIDS.
3.  **Dissect:** C-struct pointer math strips away Ethernet, IP, and TCP headers to isolate the application-layer payload.
4.  **Reassemble:** The `StreamTracker` buffers the payload, handling out-of-order execution and fragmentation.
5.  **Match:** The assembled stream is passed through the `AhoCorasick` engine to detect malicious signatures.
6.  **Log:** Matches are formatted with timestamps and IP conversions, then flushed to `dpi_alerts.jsonl`.

## 🛠️ Prerequisites

* Linux Operating System (Ubuntu/Debian recommended)
* `g++` compiler
* `libpcap` development headers
    ```bash
    sudo apt update
    sudo apt install build-essential libpcap-dev
    ```

## 📦 Installation & Build

1. Clone the repository and navigate to the directory.
2. Build the project using the provided `Makefile`:
    ```bash
    make
    ```
    *Note: The Makefile automatically applies `setcap cap_net_raw,cap_net_admin=eip` so you can run the IDS without full root/sudo privileges.*

## 🚦 Usage

Start the NIDS:
```bash
./ids
```

You should see output indicating the capture interface and BPF filter:
```txt
Opening device: lo ...
Opened lo in promiscuous mode.
BPF Filter applied: tcp dst port 8080
Sniffing lo... Press Ctrl+C to stop.
```

## Testing the Engine
In a separate terminal, start a dummy web server:
```bash
python3 -m http.server 8080
```

Fire a malicious payload at the server using `curl`:
```bash
curl '[http://127.0.0.1:8080/?test=eval](http://127.0.0.1:8080/?test=eval)(base64_decode'
```

## Viewing the Logs
The IDS will generate a SIEM-ready log file named `dpi_alerts.jsonl`. You can view it using `cat` or parse it dynamically with `jq`:
```bash
cat dpi_alerts.jsonl | jq '.'
```

### Example Log Output
```json
{
  "timestamp": "2026-05-11T19:07:14Z",
  "event_type": "alert",
  "src_ip": "127.0.0.1",
  "src_port": 48212,
  "dest_ip": "127.0.0.1",
  "dest_port": 8080,
  "protocol": "TCP",
  "packet_length": 134,
  "alert": {
    "signature": "eval(base64_decode",
    "offset": 11
  }
}
```

## Evasion Testing
To prove the TCP Stream Reassembly works, use the included Python testing script (`dos.py`) to fragment an attack across multiple packets:
```python
import socket, time
for i in range(100):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 8080))
    s.send(b"GET /?test=eval(")
    print(f"[{i}] Sent 1st package")
    s.send(b"base64_decode HTTP/1.1\r\n\r\n")
    print(f"[{i}] Sent 2nd package")
    s.close()
```

## File Structure
* `main.cpp` - The core application loop, PCAP configuration, and protocol dissector.
* `aho_corasick.h` & `.cpp` - The Trie and failure-link logic for the high-speed pattern matching engine.
* `stream_tracker.h` - State management, connection buffering, and garbage collection.
* `Makefile` - Build instructions and capability setting.