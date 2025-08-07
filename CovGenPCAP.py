from scapy.all import Ether, IP, TCP, sendp, wrpcap
from random import randint, choice
from datetime import datetime
import os
import logging
from termcolor import colored


# Signature block with creator information and file details
CREATOR_TAG = """
Created by: Ashley Smith
Team 6 // CS4463
Date: 2025
File: CovGenPCAP.py
"""

# 🌈 Fancy rainbow title because... why not?
def rainbow_banner(text):
    colors = ['red', 'yellow', 'green', 'cyan', 'blue', 'magenta']
    rainbow_text = ""

    for i, char in enumerate(text):
        color = colors[i % len(colors)]
        rainbow_text += colored(char, color)

    return rainbow_text + "\n"


# Suppressing Scapy runtime warnings specifically for live packet sending
# Uncomment if needed for real-time sending and ensure logging is imported
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def pattern_fixed_ttl_and_seq():
    """Generate a covert pattern with fixed TTL and TCP sequence number, and incremental IP ID."""
    packets = []
    for i in range(10):
        pkt = Ether()/IP(dst="192.168.1.195", ttl=123, id=40000+i)/TCP(sport=1234, dport=80, seq=999999)
        packets.append(pkt)
    return packets

def pattern_fixed_seq_only():
    """Generate a covert pattern with varied IP IDs and a fixed TCP sequence number."""
    packets = []
    for i in range(10):
        pkt = Ether()/IP(dst="192.168.1.195", ttl=64, id=randint(10000, 20000))/TCP(sport=1234, dport=80, seq=888888)
        packets.append(pkt)
    return packets

def pattern_incremental_ids():
    """Generate a covert pattern simulating timing-based channels with increasing IP IDs."""
    packets = []
    for i in range(10):
        pkt = Ether()/IP(dst="192.168.1.195", ttl=64, id=10000+i)/TCP(sport=1234, dport=80, seq=randint(1000, 5000))
        packets.append(pkt)
    return packets

def pattern_binary_ttl():
    """Generate a covert pattern encoding binary data using the TTL field (even/odd)."""
    packets = []
    for bit in [0, 1, 1, 0, 1, 0, 0, 1]:  # Simulate binary: 01101001
        ttl = 120 if bit == 0 else 121  # 120 for '0', 121 for '1'
        pkt = Ether()/IP(dst="192.168.1.195", ttl=ttl, id=randint(10000, 20000))/TCP(sport=1234, dport=80, seq=randint(2000, 7000))
        packets.append(pkt)
    return packets

def pattern_repeating_ports():
    """Generate a covert pattern signaling bits using repeated source ports."""
    packets = []
    for _ in range(5):
        port = choice([4321, 4322])  # 4321 represents '0', 4322 represents '1'
        pkt = Ether()/IP(dst="192.168.1.195", ttl=64, id=randint(30000, 40000))/TCP(sport=port, dport=80, seq=randint(5000, 15000))
        packets.append(pkt)
    return packets

def pattern_variable_size():
    """Generate a covert pattern using payload size to encode bits."""
    packets = []
    for bit in [1, 0, 1, 1, 0]:  # Simulate "10110"
        size = 100 if bit == 0 else 200
        payload = bytes([0] * size)  # Create a payload of specified size
        pkt = Ether()/IP(dst="192.168.1.195", ttl=64, id=randint(3000, 4000))/TCP(sport=1234, dport=80)/payload
        packets.append(pkt)
    return packets

def save_pcap(packets, label):
    """Save generated packets to a PCAP file with a timestamped filename."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"covert_{label}_{timestamp}.pcap"
    wrpcap(filename, packets)  # Write packets to PCAP file
    print(f"✅ Saved: {filename}")
    return filename

def log_pattern(label, description):
    """Log a description of the packet pattern to a text file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"covert_{label}_description_{timestamp}.txt", "w") as f:
        f.write(description)
    print(f"📝 Description saved for {label}")

def main():
    print(rainbow_banner("Generate Covert PCAP"))
    print(colored(CREATOR_TAG, "blue"))

    """Main function to generate and save different covert patterns."""
    patterns = {
        "fixed_ttl_seq": (pattern_fixed_ttl_and_seq, "Fixed TTL and SEQ with incremental IP ID."),
        "fixed_seq": (pattern_fixed_seq_only, "Varied IP ID with fixed TCP SEQ."),
        "incremental_ids": (pattern_incremental_ids, "Incrementing IP IDs to simulate timing channels."),
        "binary_ttl": (pattern_binary_ttl, "TTL field encodes binary data via even/odd."),
        "repeating_ports": (pattern_repeating_ports, "Source ports 4321/4322 repeat to encode bits."),
        "variable_size": (pattern_variable_size, "Payload size encodes bits with large/small packets.")
    }

    for label, (pattern_func, description) in patterns.items():
        packets = pattern_func()  # Generate packets with specified pattern
        filename = save_pcap(packets, label)  # Save generated packets to PCAP
        log_pattern(label, description)  # Log pattern description

if __name__ == "__main__":
    main()  # Run the main function to execute the script
