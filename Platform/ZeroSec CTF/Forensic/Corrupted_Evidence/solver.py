#!/usr/bin/env python3
def solve():
    print("[*] Fixing corrupted PNG header...")
    try:
        with open("chall.png", "rb") as f:
            data = bytearray(f.read())
        
        # PNG Magic Bytes: 89 50 4E 47 0D 0A 1A 0A
        magic_bytes = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
        
        # Replace the first 8 bytes
        data[:8] = magic_bytes
        
        with open("fixed_chall.png", "wb") as f:
            f.write(data)
            
        print("[+] File successfully fixed and saved as 'fixed_chall.png'!")
        print("[*] Buka file 'fixed_chall.png' untuk melihat flagnya.")
        
    except FileNotFoundError:
        print("[-] File chall.png tidak ditemukan. Pastikan file ada di direktori yang sama.")

if __name__ == "__main__":
    solve()
