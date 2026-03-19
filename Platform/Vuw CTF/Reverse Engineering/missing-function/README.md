# WriteUp - missing-function

## Overview
- **Judul:** missing-function
- **Kategori:** Reverse Engineering
- **Poin:** 300
- **Author:** leastinformednerd
- **Release:** VuwCTF 2025
- **Deskripsi:** I'm trying to find out how this program verifies the flag but I can't find the function it's calling anywhere!

## Informasi Attachment
```text
…anZKey  ～  ~../Reverse Engineering/missing-function 󱎫 0s 󱑎 14.36
 󰋑  ▶  file flag_verifier
flag_verifier: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=37484ceec34e3f82f947c2c1e8240326225187a0, for GNU/Linux 3.2.0, stripped

…anZKey  ～  ~../Reverse Engineering/missing-function 󱎫 0s 󱑎 14.36
 󰋑  ▶  checksec --file=flag_verifier
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/missing-function/flag_verifier'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

## Proses Penyelesaian

Sesuai dengan deskripsi *challenge*, program ini menyembunyikan fungsi utamanya. Saat kita melakukan analisis dinamis dengan `ltrace`, terlihat ada pemanggilan fungsi `mmap(nil, 2048, 0b111, 0x22, -1, 0)`. Parameter `0b111` ekuivalen dengan `PROT_READ | PROT_WRITE | PROT_EXEC` (hak akses membaca, menulis, dan mengeksekusi memori). Ini adalah indikasi kuat bahwa program mengalokasikan *executable memory* secara dinamis pada saat *runtime*.

### Analisis Decompile (IDA Pro)

Berdasarkan hasil dekompilasi pada fungsi `main`, kita dapat mengonfirmasi asumsi tersebut:
```c
  v10 = mmap(0LL, 0x800uLL, 7, 34, -1, 0LL); // Mengalokasikan executable memory
  // ...
  *v10 = *(_QWORD *)sub_4020;
  v5[255] = *((_QWORD *)sub_4020 + 255);
  qmemcpy(..., sub_4020, ...); // Menyalin instruksi fungsi sub_4020 ke memori yang baru
  // ...
  if ( ((unsigned __int8 (__fastcall *)(char *, _QWORD))v10)(lineptr, (unsigned int)(v6 - 1)) ) // Mengeksekusi memori tersebut sebagai fungsi
```
Program menyalin kode *assembly* dari fungsi `sub_4020` ke blok memori yang baru dialokasikan, lalu mengeksekusi blok memori tersebut dengan mem-*passing* *input* pengguna dan panjang stringnya. Oleh karena itu, logika verifikasi *flag* yang sebenarnya berada di dalam `sub_4020`.

Menganalisis `sub_4020`:
```c
  if ( a2 != 29 )
    return 0LL;
  v5 = 0x9FF8E6A5C0D784D5LL;
  v6[0] = 0xECC29CFAD3AEEDCFLL;
  *(_QWORD *)((char *)v6 + 5) = 0xC6AEE0C99DECC29CLL;
  *(_QWORD *)((char *)&v6[1] + 5) = 0x8CEDCF98F7C39FF6LL;
  v8 = 0;
  v3 = -3709;
  v4 = -96;
  for ( i = 0; i <= 28; ++i )
  {
    if ( (*((_BYTE *)&v3 + v8) ^ *((_BYTE *)&v6[-1] + i)) != *(_BYTE *)(i + a1) )
      return 0LL;
    if ( ++v8 == 3 )
      v8 = 0;
  }
```

Terdapat beberapa poin penting:
1. **Pengecekan Panjang:** Program mengharuskan panjang *input* persis 29 karakter.
2. **Kunci XOR (Key):** Kunci disimpan dalam variabel `v3` (16-bit) dan `v4` (8-bit). Jika direpresentasikan dalam bentuk *byte array* (*little-endian*):
   - `v3` = `-3709` -> `0xF183` -> `[0x83, 0xF1]`
   - `v4` = `-96` -> `0xA0` -> `[0xA0]`
   - *Key Array*: `[0x83, 0xF1, 0xA0]` (Panjang 3 *byte*).
3. **Ciphertext:** Program melakukan *overlapping memory assignment* pada variabel `v5` dan `v6` untuk menyembunyikan susunan *array ciphertext*. Jika kita ekstrak nilainya per *byte* secara *little-endian*, kita akan mendapatkan urutan 29 *byte* *ciphertext* rahasia.
4. **Validasi:** Program melakukan iterasi untuk membandingkan `input[i] == ciphertext[i] ^ key[i % 3]`.

Karena operasi XOR bersifat dua arah, kita bisa mengekstrak nilai *ciphertext* dan *key*, lalu meng-XOR-kan keduanya untuk mendapatkan *flag* (plaintext) secara langsung.

### Script Solver

```python
#!/usr/bin/env python3

# Array ciphertext 29 byte hasil ekstraksi memori (little-endian)
ciphertext = [
    0xD5, 0x84, 0xD7, 0xC0, 0xA5, 0xE6, 0xF8, 0x9F,
    0xCF, 0xED, 0xAE, 0xD3, 0xFA, 0x9C, 0xC2, 0xEC,
    0x9D, 0xC9, 0xE0, 0xAE, 0xC6, 0xF6, 0x9F, 0xC3,
    0xF7, 0x98, 0xCF, 0xED, 0x8C
]

# Kunci XOR 3 byte
key = [0x83, 0xF1, 0xA0]

flag = ""

# Lakukan dekripsi
for i in range(len(ciphertext)):
    flag += chr(ciphertext[i] ^ key[i % 3])

print(f"Decrypted Flag: {flag}")
```

### Output Terminal Solver

```text
 󰋑  ▶  ./solver.py
Decrypted Flag: VuwCTF{non_symbolic_function}
```

## Flag

```text
VuwCTF{non_symbolic_function}
```
