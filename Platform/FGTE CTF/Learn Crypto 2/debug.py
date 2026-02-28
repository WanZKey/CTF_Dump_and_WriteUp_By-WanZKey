#!/usr/bin/env python3
import base64
import base92

def solve():
    print("[*] Starting Debug Solver...")

    try:
        # 1. Baca ct.txt
        with open("ct.txt", "r") as f:
            content = f.read().strip()
            
        # 2. Decode Layer 1 (Base64)
        print("[*] Layer 1: Decoding Base64...")
        l1_bytes = base64.b64decode(content)
        l1_str = l1_bytes.decode('utf-8', errors='ignore')
        
        # Ambil Payload (Baris 1)
        payload_b64 = l1_str.split('\n')[0].strip()
        print(f"    [D] Payload L1 ditemukan.")

        # 3. Decode Layer 2 (Base64 lagi)
        print("[*] Layer 2: Decoding Base64 again...")
        # PENTING: Jangan di-decode ke utf-8 dulu! Biarkan jadi bytes.
        l2_bytes = base64.b64decode(payload_b64)
        
        print(f"    [D] Tipe Data Input Base92: {type(l2_bytes)}") 
        # Seharusnya <class 'bytes'>
        
        print(f"    [D] Preview Bytes: {l2_bytes[:20]}") 
        # Seharusnya terlihat seperti b';m]2r6bQ...'

        # 4. Decode Layer 3 (Base92)
        print("[*] Layer 3: Decoding Base92...")
        
        # Masukkan bytes langsung ke base92.decode
        l3_output = base92.decode(l2_bytes)
        
        print("\n" + "="*20 + " HASIL DECODE " + "="*20)
        
        # Cek tipe hasil, kalau bytes kita decode ke string buat baca
        if isinstance(l3_output, bytes):
            try:
                print(f"[TEXT]: {l3_output.decode('utf-8')}")
            except:
                print(f"[HEX]: {l3_output.hex()}")
                print("[!] Hasil berupa binary/raw bytes.")
        else:
            print(f"[TEXT]: {l3_output}")
            
        print("="*54 + "\n")

    except Exception as e:
        print(f"[-] Error di langkah debug: {e}")

if __name__ == "__main__":
    solve()
