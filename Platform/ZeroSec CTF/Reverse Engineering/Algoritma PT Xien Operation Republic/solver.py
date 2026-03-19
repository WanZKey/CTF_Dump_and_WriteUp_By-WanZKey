#!/usr/bin/env python3
import base64

def main():
    # Variabel dari source code Java
    ch_owowow = "SAEBMwdeOBUQJ1kHXzYJV0gNJyRdAjYMFUg"
    key = "xiilingxi"
    
    # Base64 butuh padding kelipatan 4
    padding_needed = (4 - len(ch_owowow) % 4) % 4
    ch_owowow += "=" * padding_needed
    
    # Decode Base64
    decoded_target = base64.b64decode(ch_owowow)
    
    # Proses XOR Decryption
    decrypted_message = ""
    for i in range(len(decoded_target)):
        target_char = decoded_target[i]
        key_char = ord(key[i % len(key)])
        decrypted_message += chr(target_char ^ key_char)
        
    # Formatting Flag
    flag = f"ZeroSec{{{decrypted_message}}}"
    
    print("[*] Proses Decryption Selesai!")
    print(f"[*] Pesan Asli : {decrypted_message}")
    print(f"[*] Flag       : {flag}")

if __name__ == "__main__":
    main()
