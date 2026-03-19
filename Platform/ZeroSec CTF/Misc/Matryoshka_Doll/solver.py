#!/usr/bin/env python3
import base64

def solve():
    print("[*] Memulai proses decoding Matryoshka Doll...")
    
    with open("chall.txt", "r") as f:
        data = f.read().strip()

    layer = 0
    while True:
        try:
            # Mencoba decode base64
            decoded_bytes = base64.b64decode(data)
            decoded_str = decoded_bytes.decode('utf-8')
            
            # Jika berhasil, timpa data lama dengan yang baru
            data = decoded_str
            layer += 1
            
        except Exception:
            # Looping akan otomatis berhenti (exception) ketika data sudah bukan base64 valid
            # (misalnya saat flag dengan format namactf{...} muncul)
            break

    print(f"[+] Selesai! Berhasil mengupas {layer} lapis encoding.")
    print(f"\n[+] Flag: {data}")

if __name__ == "__main__":
    solve()
