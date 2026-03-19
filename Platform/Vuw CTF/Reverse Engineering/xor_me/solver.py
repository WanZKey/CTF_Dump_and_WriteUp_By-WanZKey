#!/usr/bin/env python3
ciphertext = "|_]i~lQEYIKXuBKYuHOODuREXONW\n"
key = 0x2A # atau 42 dalam desimal

flag = ""
for char in ciphertext:
    # Ubah karakter ke integer, XOR dengan key, lalu kembalikan ke karakter
    flag += chr(ord(char) ^ key)

print("Decrypted Flag:", flag)
