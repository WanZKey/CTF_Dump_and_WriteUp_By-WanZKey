#!/usr/bin/env python3
from Crypto.Cipher import Blowfish

ciphertext = bytes.fromhex("8ef84c40db955fdd9e6e5cb1884ce4a2e891e7c5783af02339e7177078909bf7")
key = b"cruootttt"

# Blowfish CBC, IV = 8 null bytes
cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=b'\x00' * 8)
raw = cipher.decrypt(ciphertext)

# Block pertama corrupt (IV tidak diketahui), ambil dari byte ke-8 dst
flag = raw[8:].rstrip(b'\x00').decode('ascii')

print(f"Flag: {flag}")
