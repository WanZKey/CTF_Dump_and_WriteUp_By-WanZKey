#!/usr/bin/env python3
from scapy.all import rdpcap, TCP, Raw

def solve():
    packets = rdpcap("mitm_chaos.pcap")
    print("[*] Searching for the Rogue Agent's secret...")
    
    for packet in packets:
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Cari request POST
            if "POST" in payload:
                print("-" * 40)
                print("[+] Found POST Request!")
                print(payload)
                print("-" * 40)

if __name__ == "__main__":
    solve()
