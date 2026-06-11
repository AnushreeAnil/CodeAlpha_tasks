# Task 1 — Basic Network Sniffer

**CodeAlpha Cybersecurity Internship**

A Python-based network packet sniffer that captures and analyzes live network traffic in real time.

---

## 📌 Objective

Build a tool that captures network packets and displays useful information such as:

- Source and destination IP addresses
- Protocol type (HTTPS, HTTP, DNS, TCP, UDP, ICMP)
- Port numbers
- Packet size
- Payload preview

---

## 🛠️ Tools & Libraries

| Tool                        | Purpose                       |
| --------------------------- | ----------------------------- |
| Python 3.x                  | Core programming language     |
| [Scapy](https://scapy.net/) | Packet capture and analysis   |
| [Npcap](https://npcap.com/) | Windows packet capture driver |

---

## ⚙️ Setup & Installation

### Prerequisites

1. **Install Npcap** → [npcap.com/#download](https://npcap.com/#download)
   - During install, enable ✅ _"WinPcap API-compatible Mode"_
2. **Install Scapy**
   ```bash
   pip install scapy
   ```

### Running the Sniffer

> ⚠️ Must be run as **Administrator** on Windows

```bash
python network_sniffer.py
```

---

## 🔧 Configuration

Inside `network_sniffer.py`, you can tweak these settings at the top:

```python
PACKET_COUNT = 50       # Number of packets to capture (0 = infinite)
SAVE_TO_FILE = True     # Save output to a log file
LOG_FILE     = "captured_packets.txt"
FILTER       = ""       # BPF filter e.g. "tcp", "udp port 53", "" = all
```

---

## 📊 Sample Output

```
======================================================================
  CodeAlpha Task 1 — Network Sniffer
======================================================================
  Capturing 50 packets  |  Filter: 'none (all traffic)'
  Saving to: captured_packets.txt

     #  Time       Proto    Source IP          Dest IP            Size
----------------------------------------------------------------------
[   1] 21:13:21  [HTTPS ]  192.168.31.239   → 172.66.0.163        55 bytes
          Ports: 53624 → 443
[   2] 21:13:21  [TCP   ]  172.66.0.163     → 192.168.31.239       66 bytes
          Ports: 443 → 53624
[   3] 21:13:21  [DNS   ]  192.168.31.217   → 224.0.0.251          93 bytes
          Ports: 5353 → 5353  Payload: ..milink-1403391506.local
[   5] 21:13:22  [UDP   ]  192.168.31.11    → 192.168.31.255       86 bytes
          Ports: 59123 → 5775  Payload: beacon:RNOSBGJNX083488:0:false:0:1:SV=181048

[✓] Log saved to: captured_packets.txt
[✓] Total packets captured: 50
```

---

## 🔍 What the Output Reveals

| Packet                                   | Meaning                                                         |
| ---------------------------------------- | --------------------------------------------------------------- |
| `192.168.31.239 → 172.66.0.163` port 443 | Local PC connecting to Cloudflare over HTTPS                    |
| `192.168.31.217 → 224.0.0.251` DNS       | mDNS multicast — Xiaomi/Mi device doing local network discovery |
| UDP beacon `RNOSBGJNX083488`             | Smart device broadcasting presence on local network             |

---

## 📁 Project Structure

```
Task1_NetworkSniffer/
├── network_sniffer.py       # Main sniffer script
├── captured_packets.txt     # Sample capture log
└── README.md                # This file
```

---

## 💡 Key Learnings

- How network packets are structured (IP, TCP, UDP, DNS layers)
- How data flows through a network at the packet level
- How to use Scapy for live packet capture and protocol inspection
- How to identify devices and services from raw network traffic
- Difference between protocols: TCP (reliable), UDP (fast/connectionless), DNS (name resolution)

---

## ⚠️ Disclaimer

This tool is built for **educational purposes only** as part of the CodeAlpha Cybersecurity Internship. Only use it on networks you own or have explicit permission to monitor.
