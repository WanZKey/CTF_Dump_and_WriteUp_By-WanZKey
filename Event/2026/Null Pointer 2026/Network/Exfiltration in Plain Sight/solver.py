#!/usr/bin/env python3
from scapy.all import rdpcap, ICMP, Raw

def solve():
    packets = rdpcap("icmp_leak.pcap")
    flag = ""
    
    for packet in packets:
        if packet.haslayer(ICMP) and packet.haslayer(Raw):
            if packet[ICMP].type == 8: # Echo Request
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Kita skip alphabet sequence padding
                if payload.startswith("abcdef") or payload.startswith("xyzabc"):
                    continue
                
                # Ambil karakter pertama dari setiap payload yang bukan padding
                flag += payload[0]
                
    print(f"[*] Found Flag: {flag}")

if __name__ == "__main__":
    solve()
