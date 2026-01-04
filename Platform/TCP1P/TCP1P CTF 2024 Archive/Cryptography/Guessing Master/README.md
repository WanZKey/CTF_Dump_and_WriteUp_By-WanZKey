# WriteUp: Guessing Master

## Overview

* **Judul:** Guessing Master
* **Kategori:** Cryptography
* **Poin:** 1000 pts
* **Deskripsi:** just guess it
* **Author:** Agoyy

## Informasi Attachment & Struktur Direktori

Berikut adalah informasi file yang diberikan dan struktur direktorinya:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/TCP1P/TCP1P CTF 2024 Archive/Guessing Master]
└─$ file guessingmaster_guessingmaster-dist.zip
guessingmaster_guessingmaster-dist.zip: Zip archive data, at least v2.0 to extract, compression method=deflate

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/TCP1P/TCP1P CTF 2024 Archive/Guessing Master]
└─$ unzip guessingmaster_guessingmaster-dist.zip
Archive:  guessingmaster_guessingmaster-dist.zip
  inflating: output.txt
  inflating: chall.py

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/TCP1P/TCP1P CTF 2024 Archive/Guessing Master]
└─$ tree
.
├── chall.py
├── guessingmaster_guessingmaster-dist.zip
└── output.txt

1 directory, 3 files

```

## Proses Penyelesaian

### 1. Analisis Source Code

Langkah pertama adalah membaca source code `chall.py` untuk memahami logika enkripsi.

```python
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/TCP1P/TCP1P CTF 2024 Archive/Guessing Master]
└─$ cat chall.py
import math
import os
from Crypto.Random import random

def bin2hex(binary):
    return hex(int(binary,2))[2:]

def hex2bin(msg):
    return bin(int(msg, 16))[2:]

# ... (potongan kode fungsi helper Hamming Code: count_bit, flip_bit, add_bit) ...

def random_flip(binary):
    binary = binary[::-1]
    length = len(binary) + count_bit(len(binary)) + 1
    encoded = ""
    # ... (Proses encoding Hamming Code) ...
    rand = random.randrange(0, len(encoded))
    flipped = flip_bit(encoded, rand)
    return flipped[::-1], rand

def main():
    flag = open("flag.txt", "rb").read()
    binarys = hex2bin(flag.hex())
    output = []
    for binary in binarys:
        temp = hex2bin(os.urandom(16).hex())
        encoded, rand = random_flip(temp)
        if int(binary):
            output.append([bin2hex(encoded), rand])
        else:
            output.append([bin2hex(encoded), random.randrange(0, len(encoded))])
    print(output)

if __name__ == "__main__":
    main()

```

### 2. Temuan Analisis

1. **Mekanisme Enkripsi**: Script mengimplementasikan **Hamming Code**. Fungsi `random_flip` menyisipkan parity bit, lalu sengaja melakukan *flip* (merusak) 1 bit pada posisi random (`rand`).
2. **Leak**:
* Jika bit flag adalah `1`, script menyimpan `[encoded_string, rand]` dimana `rand` adalah posisi error yang **sebenarnya**.
* Jika bit flag adalah `0`, script menyimpan `[encoded_string, fake_rand]` dimana `fake_rand` adalah angka random yang **salah**.


3. **Kelemahan**: Karena Hamming Code didesain untuk *Error Correction*, kita bisa menghitung ulang posisi error yang sebenarnya (Syndrome) dari string yang rusak. Jika posisi hasil hitungan kita sama dengan angka yang diberikan soal, maka bit flagnya `1`. Jika beda, maka `0`.
4. **Isu Leading Zero**: Fungsi `hex2bin` menggunakan `bin(int(msg, 16))[2:]`. Jika byte pertama flag (misal 'T' = `0x54` = `01010100`) diawali dengan bit `0`, fungsi `bin()` akan menghapusnya. Ini menyebabkan pergeseran urutan bit (misalignment) saat mendekode. Kita perlu menambahkan padding `0` di awal hasil recovery.

### Script Solver

Berikut adalah script `solver.py` untuk mendekode flag:

```python
import ast

def solve():
    # Membaca output.txt
    try:
        with open('output.txt', 'r') as f:
            data = ast.literal_eval(f.read())
    except FileNotFoundError:
        print("[-] File output.txt tidak ditemukan.")
        return

    print(f"[+] Loaded {len(data)} entries from output.txt")
    
    recovered_bits = ""

    for item in data:
        hex_str = item[0]
        given_idx = item[1]

        # Konversi hex ke binary string terbalik (sesuai logika chall.py)
        val = int(hex_str, 16)
        bin_str = bin(val)[2:][::-1]

        # Hitung Hamming Syndrome (Posisi Error Sebenarnya)
        calculated_error_pos = 0
        for idx, bit in enumerate(bin_str):
            if bit == '1':
                # Posisi Hamming adalah 1-based
                calculated_error_pos ^= (idx + 1)
        
        # Konversi ke 0-based index
        real_idx = calculated_error_pos - 1

        # Bandingkan real_idx dengan given_idx
        if real_idx == given_idx:
            recovered_bits += "1"
        else:
            recovered_bits += "0"

    # Fix Alignment: Tambahkan padding 0 di depan jika jumlah bit tidak kelipatan 8
    # Ini menangani leading zero yang hilang oleh fungsi bin() Python
    pad_length = 8 - (len(recovered_bits) % 8)
    if pad_length != 8:
        recovered_bits = "0" * pad_length + recovered_bits
        print(f"[+] Added {pad_length} bit(s) padding to fix alignment.")

    # Konversi bits ke String
    flag = ""
    for i in range(0, len(recovered_bits), 8):
        byte = recovered_bits[i:i+8]
        flag += chr(int(byte, 2))

    print(f"[+] Recovered Flag: {flag}")

if __name__ == "__main__":
    solve()

```

## Output Terminal

Berikut adalah hasil eksekusi solver yang berhasil mendapatkan flag:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/TCP1P/TCP1P CTF 2024 Archive/Guessing Master]
└─$ python3 solver.py
[+] Loaded 303 entries from output.txt
[+] Added 1 bit(s) padding to fix alignment.
[+] Recovered Flag: TCP1P{now_you_are_the_guessing_master}

```

## Flag
 
`TCP1P{now_you_are_the_guessing_master}`


