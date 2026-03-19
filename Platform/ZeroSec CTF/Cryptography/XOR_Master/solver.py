#!/usr/bin/env python3
with open("chall.bin", "rb") as f:
    data = f.read()

for key in range(256):
    decrypted = bytes([b ^ key for b in data])
    try:
        text = decrypted.decode('ascii')
        if text.startswith('ZeroSec'):
            print(f"Key found: {key} (0x{key:02x})")
            print(f"Decrypted: {text}")
    except:
        pass
