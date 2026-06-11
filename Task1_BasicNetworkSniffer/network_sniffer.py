"""
CodeAlpha Internship - Task 1: Basic Network Sniffer
Author: [Your Name]
Description: Captures and analyzes live network packets using Scapy.
             Displays source/destination IPs, protocols, and payload info.

Requirements:
  - Python 3.x
  - Scapy: pip install scapy
  - Npcap: https://npcap.com/#download (install with WinPcap compatibility mode)
  - Run this script as Administrator on Windows
"""

from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from datetime import datetime
import os
import sys

# ─────────────────────────────────────────────
# CONFIGURATION — tweak these as you like
# ─────────────────────────────────────────────
PACKET_COUNT   = 50          # How many packets to capture (0 = infinite)
SAVE_TO_FILE   = True        # Save output to a log file?
LOG_FILE       = "captured_packets.txt"
FILTER         = ""          # BPF filter string e.g. "tcp", "udp port 53", "" = all
# ─────────────────────────────────────────────


def get_protocol_name(packet):
    """Return a human-readable protocol label."""
    if packet.haslayer(TCP):
        port = packet[TCP].dport or packet[TCP].sport
        if port == 80:   return "HTTP"
        if port == 443:  return "HTTPS"
        if port == 22:   return "SSH"
        if port == 21:   return "FTP"
        if port == 25:   return "SMTP"
        return "TCP"
    elif packet.haslayer(UDP):
        if packet.haslayer(DNS): return "DNS"
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def get_payload_preview(packet):
    """Extract a short, readable preview of the payload (if any)."""
    try:
        if packet.haslayer(TCP):
            raw = bytes(packet[TCP].payload)
        elif packet.haslayer(UDP):
            raw = bytes(packet[UDP].payload)
        else:
            return ""
        if not raw:
            return ""
        # Decode printable ASCII only
        preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in raw[:60])
        return f"  Payload: {preview.strip()[:60]}"
    except Exception:
        return ""


def format_packet(packet, index):
    """Build a formatted string for one packet."""
    timestamp = datetime.now().strftime("%H:%M:%S")

    if not packet.haslayer(IP):
        return None   # Skip non-IP packets (ARP, etc.)

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    protocol = get_protocol_name(packet)
    size     = len(packet)

    # Port info (TCP/UDP only)
    ports = ""
    if packet.haslayer(TCP):
        ports = f"  Ports: {packet[TCP].sport} → {packet[TCP].dport}"
    elif packet.haslayer(UDP):
        ports = f"  Ports: {packet[UDP].sport} → {packet[UDP].dport}"

    payload = get_payload_preview(packet)

    line = (
        f"[{index:>4}] {timestamp}  [{protocol:<6}]  "
        f"{src_ip:<16} → {dst_ip:<16}  {size:>5} bytes"
        f"\n        {ports}{payload}"
    )
    return line


# ─────────────────────────────────────────────
# Log file setup
# ─────────────────────────────────────────────
log_handle = None
if SAVE_TO_FILE:
    log_handle = open(LOG_FILE, "w", encoding="utf-8")
    log_handle.write(f"=== Network Sniffer Log — {datetime.now()} ===\n\n")

packet_index = [0]   # mutable counter accessible inside callback


def packet_callback(packet):
    """Called by Scapy for every captured packet."""
    packet_index[0] += 1
    line = format_packet(packet, packet_index[0])

    if line:
        print(line)
        if log_handle:
            log_handle.write(line + "\n")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  CodeAlpha Task 1 — Network Sniffer")
    print("=" * 70)
    print(f"  Capturing {'∞' if PACKET_COUNT == 0 else PACKET_COUNT} packets"
          f"  |  Filter: '{FILTER or 'none (all traffic)'}'")
    if SAVE_TO_FILE:
        print(f"  Saving to: {LOG_FILE}")
    print("  Press Ctrl+C to stop early.\n")
    print(f"{'#':>6}  {'Time':<10} {'Proto':<8} {'Source IP':<18} {'Dest IP':<18} {'Size'}")
    print("-" * 70)

    try:
        sniff(
            prn=packet_callback,
            count=PACKET_COUNT,
            filter=FILTER,
            store=False         # Don't store packets in memory — saves RAM
        )
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        print("\nTroubleshooting tips:")
        print("  1. Did you install Npcap? → https://npcap.com/#download")
        print("  2. Are you running this script as Administrator?")
        print("  3. Right-click your terminal → 'Run as administrator', then retry.")
    finally:
        if log_handle:
            log_handle.close()
            print(f"\n[✓] Log saved to: {LOG_FILE}")
        print(f"[✓] Total packets captured: {packet_index[0]}")


if __name__ == "__main__":
    main()
