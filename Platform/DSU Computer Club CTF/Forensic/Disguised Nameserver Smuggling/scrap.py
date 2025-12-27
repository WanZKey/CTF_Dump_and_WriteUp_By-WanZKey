from scapy.all import *
import binascii

# Ganti dengan nama file pcap kamu
pcap_file = "exfil.pcap"

# List untuk menampung potongan data
exfiltrated_data = []

def analyze_packet(pkt):
    # Kita cari paket DNS Query (QR=0)
    if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
        query_name = pkt[DNS].qd.qname.decode('utf-8')
        
        # Hapus root dot di akhir jika ada (example.com.)
        if query_name.endswith('.'):
            query_name = query_name[:-1]
            
        # Asumsi format: [DATA].example.com
        # Kita ambil bagian subdomainnya saja
        subdomain = query_name.split('.')[0]
        
        # Hindari duplikat jika request dikirim ulang
        if subdomain not in exfiltrated_data:
            exfiltrated_data.append(subdomain)
            print(f"[+] Found chunk: {subdomain}")

print("Reading PCAP...")
packets = rdpcap(pcap_file)

print("Extracting DNS queries...")
for pkt in packets:
    analyze_packet(pkt)

# Gabungkan semua potongan
full_string = "".join(exfiltrated_data)
print(f"\n[!] Raw String: {full_string}")

# Coba decode (Biasanya Hex atau Base64)
try:
    # Coba Hex decode
    print(f"[!] Decoded (Hex): {binascii.unhexlify(full_string)}")
except:
    print("[-] Not Hex encoded or incomplete.")

try:
    # Coba Base64 decode
    import base64
    print(f"[!] Decoded (Base64): {base64.b64decode(full_string)}")
except:
    print("[-] Not Base64 encoded.")
