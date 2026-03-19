#!/usr/bin/env python3
from scapy.all import rdpcap, ICMP, Raw

def extract_icmp_payload(pcap_file):
    print("[*] Reading pcap file...")
    packets = rdpcap(pcap_file)
    extracted_data = b""
    
    for packet in packets:
        # Cek apakah packet memiliki layer ICMP dan punya Raw payload
        if packet.haslayer(ICMP) and packet.haslayer(Raw):
            # Filter hanya ICMP Echo Request (type 8)
            if packet[ICMP].type == 8:
                payload = packet[Raw].load
                extracted_data += payload
                
    print("[+] Extraction Complete!\n")
    print("[*] Raw Extracted Data:")
    print(extracted_data)
    
    # Coba decode ke utf-8 dengan ignore error jika ada byte sampah
    print("\n[*] Decoded String (UTF-8):")
    try:
        print(extracted_data.decode('utf-8', errors='ignore'))
    except Exception as e:
        print(f"Error decoding: {e}")

if __name__ == "__main__":
    pcap_path = "icmp_leak.pcap"
    extract_icmp_payload(pcap_path)
