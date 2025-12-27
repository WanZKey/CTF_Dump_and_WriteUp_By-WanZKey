from scapy.all import *
import binascii

# Nama file pcap
pcap_file = "exfil.pcap"

# List untuk menyimpan urutan data agar tidak duplikat
extracted_hex = []

def analyze_packet(pkt):
    # Filter hanya paket DNS Query
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        query_name = pkt[DNS].qd.qname.decode('utf-8')
        
        # Kita hanya peduli pada domain roguedns
        if "roguedns.serverstation" in query_name:
            # Ambil bagian paling depan (subdomain hex)
            # Format: [HEX].challenge.roguedns.serverstation.
            parts = query_name.split('.')
            hex_part = parts[0]
            
            # Cek validitas hex (hanya angka 0-9 dan a-f)
            # dan hindari duplikat berurutan (retransmission)
            if all(c in string.hexdigits for c in hex_part):
                if len(extracted_hex) == 0 or extracted_hex[-1] != hex_part:
                    extracted_hex.append(hex_part)
                    print(f"[+] Found chunk: {hex_part}")

print("Reading PCAP and extracting Hex chunks...")
packets = rdpcap(pcap_file)

for pkt in packets:
    analyze_packet(pkt)

# Gabungkan semua hex
full_hex = "".join(extracted_hex)
print(f"\n[!] Full Hex Stream: {full_hex}")

# Decode ke ASCII
try:
    flag = binascii.unhexlify(full_hex).decode('utf-8', errors='ignore')
    print(f"\n[🎉] FLAG FOUND:\n{flag}")
except Exception as e:
    print(f"\n[!] Error decoding: {e}")
