from pwn import *
import binascii

# Convert hex ke bytes
cipher = bytes.fromhex('d16b248fc086c001f8e61af5f0d6f5e107066c53501d0f0c')

# Fungsi untuk mencoba dekripsi
def try_decrypt(key_sequence):
    flag = ''
    for i in range(len(cipher)):
        flag += chr(cipher[i] ^ key_sequence[i])
    return flag

# Kita perlu mencari pattern dari PRNG
# Biasanya PRNG sederhana menggunakan operasi matematika seperti:
# - Linear Congruential Generator (LCG)
# - Multiply-with-carry
# - Xorshift

# Contoh implementasi decrypt dengan LCG
def lcg(seed, a, c, m, length):
    numbers = []
    x = seed
    for _ in range(length):
        x = (a * x + c) % m
        numbers.append(x & 0xFF)  # Ambil byte terakhir saja
    return numbers

# Coba beberapa parameter umum LCG
seeds = [0x1337, 0xdeadbeef, 0x13371337]
multipliers = [1103515245, 134775813, 1664525]
increments = [12345, 1, 1013904223] 
modulus = [2**32, 2**31, 2**16]

for seed in seeds:
    for a in multipliers:
        for c in increments:
            for m in modulus:
                key_sequence = lcg(seed, a, c, m, len(cipher))
                possible_flag = try_decrypt(key_sequence)
                if 'bronco' in possible_flag.lower():  # Asumsi flag mengandung 'bronco'
                    print(f"Found potential flag: {possible_flag}")
                    print(f"Parameters: seed={seed}, a={a}, c={c}, m={m}")
