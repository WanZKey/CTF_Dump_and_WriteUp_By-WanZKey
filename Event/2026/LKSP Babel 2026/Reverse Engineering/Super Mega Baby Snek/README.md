# WriteUp - SuperMegaBabySnek

## Overview

* **Name:** SuperMegaBabySnek
* **Category:** Reverse Engineering
* **Point:** 500
* **Author:** Aseng
* **Desc:** Just a very very baby simple encryptor, this one is a warmup instead of ez zz
* **URL:** Local Attachment (SuperMegaBabySnek.zip)

## Reconnaissance

```text
Archive:  SuperMegaBabySnek.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     2418  2026-06-11 00:13   chall.cpython-311.pyc
       34  2026-06-11 00:17   flag.enc
---------                     -------
     2452                     2 files

```

```python
# Source Generated with Decompyle++
# File: chall.cpython-311.pyc (Python 3.11)

from pathlib import Path
ye = Path('flag.txt')
out = Path('flag.enc')
m = 55
kd = [
    91,
    92,
    85,
    86,
    85,
    82,
    91,
    26,
    69,
    84,
    3,
    26,
    5,
    7,
    5,
    1]

def _get_key():
Unsupported opcode: RETURN_GENERATOR (109)
    return (lambda .0: pass# WARNING: Decompyle incomplete
)(kd())


def wud(data, key):
Warning: block stack is not empty!
    s = list(range(256))
    j = 0
    for i in range(256):
        j = j + s[i] + key[i % len(key)] & 255
        s[i], s[j] = s[j], s[i]
        out = bytearray()
        i = 0
        j = 0
        for byte in data:
            i = i + 1 & 255
            j = j + s[i] & 255
            s[i], s[j] = s[j], s[i]
            k = s[s[i] + s[j] & 255]
            out.append(byte ^ k)
            return bytes(out)


def main():
    if not ye.exists():
        raise SystemExit('no flag.txt')
    flag = ye.read_bytes().strip()
    encrypted = wud(flag, _get_key())
    out.write_bytes(encrypted)

if __name__ == '__main__':
    main()
    return None

```

## Step by Step Solution

### 1. Ekstraksi dan Analisis Bytecode Python

**Analisis pycdc Output:** File utama merupakan *compiled Python bytecode* berformat `.pyc` untuk versi CPython 3.11. Hasil *decompile* menggunakan alat `pycdc` menunjukkan beberapa bagian yang tidak dapat dikonversi kembali dengan sempurna (seperti `RETURN_GENERATOR`), namun alur logika dan variabel utama berhasil terbaca.

### 2. Pemulihan Kunci Enkripsi via XOR Array

**Hidden Key Generation:** Pada fungsi `_get_key()`, logika pembuatan kunci disembunyikan dalam *generator* yang rusak. Namun, terdapat konstanta `m = 55` dan array integer `kd`. Melakukan operasi XOR antara setiap nilai di dalam array `kd` dengan nilai `m` akan mengembalikan kunci asli berupa string *plaintext*.

```bash
# Ilustrasi logika XOR
[91^55, 92^55, 85^55, ...] -> "lkbabel-rc4-2026"

```

### 3. Identifikasi RC4 Symmetric Cipher

**KSA dan PRGA Algorithm:** Fungsi `wud(data, key)` berisi logika manipulasi list sepanjang 256 elemen. Logika inisialisasi ini identik dengan *Key-Scheduling Algorithm* (KSA) yang dilanjutkan dengan operasi XOR byte-per-byte dalam *Pseudo-Random Generation Algorithm* (PRGA). Ini mengonfirmasi bahwa algoritma enkripsinya adalah RC4. Mengingat sifat RC4 yang merupakan *symmetric stream cipher*, fungsi enkripsi dan dekripsi adalah sama persis.

### 4. Eksekusi Skrip Dekripsi Simetris

**Symmetric Decryption:** Menggunakan kunci `lkbabel-rc4-2026` yang ditemukan pada langkah kedua, skrip dekripsi ditulis menggunakan pustaka RC4 kustom yang bersih dari kesalahan *indentation* *decompiler*, dan diterapkan langsung untuk membaca *ciphertext* dari file `flag.enc`.

## Script Solver

```python
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

def main():
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

if __name__ == '__main__':
    main()

```

## Output Terminal Solver

```bash
$ ./solver.py
[*] Derived Key: lkbabel-rc4-2026
[*] Flag: LKS{all_that_l3ft_is_0nly_memo...}

```

## Flag

`LKS{all_that_l3ft_is_0nly_memo...}`
