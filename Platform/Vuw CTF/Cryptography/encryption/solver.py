#!/usr/bin/env python3
import base64

def solve():
    try:
        with open("challenge.txt", "r") as f:
            encoded_text = f.read().strip()
            
        print(f"[*] Encoded Text : {encoded_text}")
        
        # Proses decoding base64
        decoded_bytes = base64.b64decode(encoded_text)
        decoded_text = decoded_bytes.decode('utf-8')
        
        print(f"[*] Decoded Text : {decoded_text}")
        
    except FileNotFoundError:
        print("[!] File challenge.txt tidak ditemukan.")
    except Exception as e:
        print(f"[!] Terjadi kesalahan: {e}")

if __name__ == '__main__':
    solve()
