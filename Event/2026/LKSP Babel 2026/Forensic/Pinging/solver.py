#!/usr/bin/env python3
import subprocess
import binascii
import base64
import re

def solve():
    # Menjalankan tshark untuk mengekstrak raw hex data dari paket ICMP
    tshark_cmd = ['tshark', '-r', 'snippet.pcap', '-Y', 'icmp', '-T', 'fields', '-e', 'data']
    result = subprocess.run(tshark_cmd, capture_output=True, text=True)

    # Menghilangkan newline dari output tshark agar menyatu menjadi satu string hex
    hex_data = result.stdout.replace('\n', '').strip()

    if not hex_data:
        print("[!] Tidak ada data ICMP yang ditemukan.")
        return

    # Mengubah nilai hex menjadi string ASCII
    ascii_text = binascii.unhexlify(hex_data).decode('utf-8')

    # Mencari pola Base64 di dalam command echo menggunakan Regular Expression
    b64_match = re.search(r'echo "(.*?)"', ascii_text)
    
    if b64_match:
        b64_string = b64_match.group(1)
        # Mendekode string Base64 untuk mendapatkan flag
        flag = base64.b64decode(b64_string).decode('utf-8')
        print(f"Flag : {flag}")
    else:
        print("[!] Teks Base64 tidak ditemukan di dalam payload ICMP.")

if __name__ == '__main__':
    solve()
