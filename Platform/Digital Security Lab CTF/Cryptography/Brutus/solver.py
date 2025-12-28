#!/usr/bin/env python3
import string

def custom_caesar_decrypt(ciphertext, shift):
    plaintext = ""
    
    for char in ciphertext:
        # 1. Handle Huruf (A-Z dan a-z)
        if char.isalpha():
            ascii_base = ord('A') if char.isupper() else ord('a')
            # Rumus Decrypt: (Char - Base - Shift) % 26 + Base
            decoded = chr((ord(char) - ascii_base - shift) % 26 + ascii_base)
            plaintext += decoded
            
        # 2. Handle Angka (0-9) -> Ini yang tidak dilakukan decoder biasa
        elif char.isdigit():
            digit = int(char)
            # Rumus Decrypt Angka: (Digit - Shift) % 10
            # Contoh: (0 - 7) % 10 = 3
            decoded = str((digit - shift) % 10)
            plaintext += decoded
            
        # 3. Handle Simbol ({, }, _)
        else:
            plaintext += char
            
    return plaintext

# Setup
ciphertext = "KZB{04_4b_iyba0}"
shift_key = 7  # K (11) -> D (4) adalah selisih 7

# Eksekusi
print(f"[*] Ciphertext : {ciphertext}")
print(f"[*] Shift Key  : {shift_key}")

flag = custom_caesar_decrypt(ciphertext, shift_key)

print(f"\n[+] FLAG       : {flag}")
