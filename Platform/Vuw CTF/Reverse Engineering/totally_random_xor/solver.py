#!/usr/bin/env python3

# Nilai array v5 (ciphertext) yang diambil dari IDA Pro
v5 = [
    352217015, 918588263, 499345217, 513054014, 248820239, 2113718786, 
    109687931, 205974930, 2049711889, 1893967997, 972265870, 400263502, 
    1638661205, 1623839542, 843216766, 392333987, 394727461
]

# Deretan nilai rand() yang diekstrak secara berurutan dari output ltrace
rand_vals = [
    352217057, 918588210, 499345174, 513054021, 248820349, 2113718833, 
    109687829, 205975030, 2049711996, 1893967906, 972265918, 400263484, 
    1638661130, 1623839576, 843216717, 392334071, 394727512
]

flag = ""

# Melakukan perulangan untuk meng-XOR ciphertext dengan angka 'random'
for i in range(len(v5)):
    # Hasil XOR dikonversi dari integer ke karakter ASCII
    flag += chr(v5[i] ^ rand_vals[i])

print(f"Decrypted Flag: {flag}")
