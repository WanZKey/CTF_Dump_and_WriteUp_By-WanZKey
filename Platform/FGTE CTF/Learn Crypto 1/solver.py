#!/usr/bin/env python3
import base64
import codecs
import re

def xor_decrypt(data, key):
    key_bytes = key.encode()
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key_bytes[i % len(key_bytes)])
    return result

def solve():
    print("[*] Starting Final Solver...")
    
    try:
        # 1. Baca CT
        with open("ct.txt", "r") as f:
            content = f.read().strip()
            
        # 2. Decode Layer 1 (Base64) & Layer 2 (Base32)
        print("[*] Decoding Layer 1 (B64) -> Layer 2 (B32)...")
        l1 = base64.b64decode(content).decode('utf-8', errors='ignore')
        
        # Ambil string Base32 (biasanya baris pertama jika ada sampah lain)
        b32_str = l1.split()[0] 
        l2 = base64.b32decode(b32_str).decode('utf-8')
        
        # l2 sekarang adalah "V0dIZ..."
        print(f"    [>] Layer 2 Output: {l2[:20]}...")

        # 3. Decode Layer 3 (Base64 wrapper)
        # Ini yang terlewat sebelumnya. V0dIZ... harus di-decode dulu
        print("[*] Decoding Layer 3 (Base64 Wrapper)...")
        l3_decoded = base64.b64decode(l2).decode('utf-8')
        
        lines = l3_decoded.strip().split('\n')
        target_cipher_rot = lines[0].strip() # "WGHg..."
        hint_rot13 = lines[1].strip()        # "Grenxuve..."
        
        print(f"    [>] Target Cipher : {target_cipher_rot}")
        print(f"    [>] Hint          : {hint_rot13}")

        # 4. Parse Hint
        hint_plain = codecs.decode(hint_rot13, 'rot_13')
        key_match = re.search(r'"(.*?)"', hint_plain)
        key = key_match.group(1) if key_match else "cryptoisfun"
        print(f"    [+] Key           : {key}")

        # 5. Apply ROT13 to Target Cipher
        # Hint bilang "ROT13", dan ini berlaku untuk Cipher-nya juga sebelum di-decode
        print("[*] Applying ROT13 to Target Cipher...")
        cipher_rot13 = codecs.decode(target_cipher_rot, 'rot_13')
        print(f"    [>] Cipher (ROT13): {cipher_rot13}")

        # 6. Decode Base64 Final & XOR
        print(f"[*] Decoding Base64 & XOR with '{key}'...")
        cipher_bytes = base64.b64decode(cipher_rot13)
        decrypted = xor_decrypt(cipher_bytes, key)
        flag = decrypted.decode('utf-8')

        print("\n" + "="*50)
        print(f"SOLVED FLAG: {flag}")
        print("="*50 + "\n")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
