#!/usr/bin/env python3
from scapy.all import rdpcap, UDP, DNS

def solve():
    packets = rdpcap("beacon_challenge.pcap")
    
    print("[*] Checking Port 5555...")
    for packet in packets:
        if packet.haslayer(UDP) and (packet[UDP].dport == 5555 or packet[UDP].sport == 5555):
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                print(f"[+] Data from Port 5555: {payload}")

    print("\n[*] Checking MDNS (Port 5353) Transaction IDs...")
    mdns_chars = []
    seen_ids = set()
    
    for packet in packets:
        if packet.haslayer(UDP) and packet[UDP].dport == 5353:
            # MDNS header starts with Transaction ID (2 bytes)
            # Wireshark says "Unknown operation (12) 0x7374"
            # 0x7374 is the Transaction ID field
            if packet.haslayer(DNS):
                tx_id = packet[DNS].id
                # Kita ambil ID yang unik saja untuk melihat urutan flag
                if tx_id not in seen_ids:
                    seen_ids.add(tx_id)
                    # Convert 16-bit ID to 2 chars
                    char1 = chr((tx_id >> 8) & 0xff)
                    char2 = chr(tx_id & 0xff)
                    mdns_chars.append(char1 + char2)
    
    print(f"[+] Reconstructed from MDNS: {''.join(mdns_chars)}")

if __name__ == "__main__":
    solve()
