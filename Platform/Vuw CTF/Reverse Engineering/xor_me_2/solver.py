#!/usr/bin/env python3

# Nilai dari variabel v11 di decompiler
v11 = [12, 111, 63, 40, 4, 49, 98, 73, 47, 95, 41, 103, 90, 46, 
       44, 30, 90, 90, 14, 51, 16, 33, 31, 22, 20, 68, 79, 113]

# Nilai dari variabel v12 di decompiler
v12 = [74, 6, 56, 27, 80, 21, 25, 6, 68, 4, 56, 11, 5, 59, 
       39, 65, 25, 26, 35, 57, 92, 62, 34, 54, 32, 50, 22, 12]

flag = ""

# Melakukan perulangan sebanyak 14 kali karena 1 perulangan mengekstrak 2 karakter
for i in range(14):
    # Penjumlahan elemen indeks genap
    flag += chr(v11[2*i] + v12[2*i])
    # Penjumlahan elemen indeks ganjil
    flag += chr(v11[2*i + 1] + v12[2*i + 1])

print(f"Decrypted Flag: {flag}")
