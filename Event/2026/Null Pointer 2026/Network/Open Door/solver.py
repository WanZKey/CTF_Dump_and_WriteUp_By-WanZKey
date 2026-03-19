#!/usr/bin/env python3
from scapy.all import rdpcap, TCP, Raw

def solve():
    packets = rdpcap("noisy_challenge.pcap")
    telnet_data = b""
    
    # Filter traffic ke/dari port 23 (Telnet)
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            if packet[TCP].dport == 23 or packet[TCP].sport == 23:
                telnet_data += packet[Raw].load
                
    print("[*] Reconstructed Telnet Session:")
    # Clean up telnet options (byte yang diawali \xff) biar enak dibaca
    cleaned_data = "".join([chr(b) for b in telnet_data if 32 <= b <= 126 or b == 10 or b == 13])
    print(cleaned_data)

if __name__ == "__main__":
    solve()
