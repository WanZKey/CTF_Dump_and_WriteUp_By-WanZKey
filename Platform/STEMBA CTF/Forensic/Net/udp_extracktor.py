from scapy.all import rdpcap, UDP
import base64

# Load file PCAP
packets = rdpcap("suspicious.pcap")

# Ambil payload dari semua paket UDP
udp_payloads = []

for pkt in packets:
    if pkt.haslayer(UDP):
        raw = bytes(pkt[UDP].payload)
        if raw:  # jika ada payload
            udp_payloads.append(raw.hex())  # simpan dalam hex string

# Gabungkan semua hex dan decode ke ASCII
hex_string = ''.join(udp_payloads)
ascii_string = bytes.fromhex(hex_string).decode()

print("[+] Data hex digabung:", hex_string)
print("[+] Hasil ASCII     :", ascii_string)

# Coba decode sebagai base64
try:
    decoded = base64.b64decode(ascii_string)
    print("[+] Hasil Base64 Decode:", decoded.decode())
except:
    print("[!] Base64 decode gagal atau hasil bukan teks!")
    print("[+] Raw bytes:", decoded)
