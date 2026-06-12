#!/usr/bin/env python3
def rc4(data, key):
    # KSA (Key-Scheduling Algorithm)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA (Pseudo-Random Generation Algorithm)
    out = bytearray()
    i = 0
    j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
        
    return out

# List 'kd' dan nilai 'm' dari hasil decompile
kd = [91, 92, 85, 86, 85, 82, 91, 26, 69, 84, 3, 26, 5, 7, 5, 1]
m = 55

# Rebuild the key using XOR
key = bytes([x ^ m for x in kd])
print(f"[*] Derived Key: {key.decode()}")

# Baca file flag.enc
with open("flag.enc", "rb") as f:
    encrypted_data = f.read()

# Decrypt
decrypted_data = rc4(encrypted_data, key)
print(f"[*] Flag: {decrypted_data.decode()}")
