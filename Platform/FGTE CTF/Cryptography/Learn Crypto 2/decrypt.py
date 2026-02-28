#!/usr/bin/env python3
import base64

def vigenere_decrypt(ciphertext, key):
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext_int = [ord(i) for i in ciphertext]
    plaintext = ''
    
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            # Tentukan offset (A=65 atau a=97)
            offset = 65 if char.isupper() else 97
            key_char = key[key_index % key_length]
            key_offset = 65 if key_char.isupper() else 97
            
            # Rumus Decrypt Vigenere: P = (C - K) mod 26
            val = (ord(char) - offset) - (ord(key_char) - key_offset)
            val = (val % 26) + offset
            plaintext += chr(val)
            key_index += 1
        else:
            # Karakter non-huruf (angka, simbol) tidak diubah
            plaintext += char
            
    return plaintext

def solve():
    print("[*] Decoding Final Flag...")
    
    # 1. Base64 hasil Caesar shift 10
    final_b64 = "SFhSVHtEc21oX1EzNGxhMXB4X0FncmQ3MF9PMzFjeCF9"
    
    # 2. Decode ke String
    cipher_text = base64.b64decode(final_b64).decode('utf-8')
    print(f"    [>] Ciphertext Vigenere: {cipher_text}")
    
    # 3. Vigenere Decrypt
    key = "cryptoisfun"
    print(f"    [>] Key                : {key}")
    
    flag = vigenere_decrypt(cipher_text, key)
    
    print("\n" + "="*50)
    print(f"SOLVED FLAG: {flag}")
    print("="*50 + "\n")

if __name__ == "__main__":
    solve()
