#!/usr/bin/env python3
import os
import random
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def solve():
    try:
        # Load file attachment dalam format raw bytes
        with open("news.bin", "rb") as f:
            ct = f.read()
            
        # Mengambil informasi kapan file tersebut diunduh/dibuat di OS lokal
        file_mtime = int(os.path.getmtime("news.bin"))
        print(f"[*] File news.bin timestamp (epoch): {file_mtime}")
        print("[*] Melakukan brute-force PRNG seed (rentang pencarian +/- 24 jam)...")
        
        # Brute-force dengan rentang 86400 detik (24 jam) ke belakang dan ke depan
        for seed in range(file_mtime - 86400, file_mtime + 86400):
            # Inisialisasi ulang state PRNG dengan seed yang diuji
            random.seed(seed)
            
            # Generate key dan iv dengan urutan yang persis sama seperti server
            key = random.randbytes(AES.block_size)
            iv = random.randbytes(AES.block_size)
            
            # Setup cipher AES
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            try:
                # Decrypt dan hilangkan padding
                pt_padded = cipher.decrypt(ct)
                pt_b64 = unpad(pt_padded, AES.block_size)
                
                # Decode Base64 ke string
                flag = base64.b64decode(pt_b64).decode('utf-8')
                
                # Cek jika format flag valid
                if "VuwCTF{" in flag:
                    print("\n[*] CRACKED!")
                    print(f"[*] Server Timestamp Seed : {seed}")
                    print(f"[*] Flag : {flag}")
                    return
            except Exception:
                # Jika unpad atau decode gagal, berarti seed salah. Lanjut iterasi.
                continue
                
        print("\n[!] Gagal menemukan seed. Jika file diunduh sudah sangat lama, cobalah unduh ulang news.bin lalu langsung jalankan solver ini.")
        
    except FileNotFoundError:
        print("[!] File news.bin tidak ditemukan. Pastikan ada di direktori yang sama.")
    except Exception as e:
        print(f"[!] Terjadi error: {e}")

if __name__ == '__main__':
    solve()
