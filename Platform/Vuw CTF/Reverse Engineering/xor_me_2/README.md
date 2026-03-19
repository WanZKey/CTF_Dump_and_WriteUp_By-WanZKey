# WriteUp - xor_me_2

## Overview
- **Judul:** xor_me_2
- **Kategori:** Reverse Engineering
- **Poin:** 250
- **Author:** Aterlone
- **Release:** Reverse Engineering Meetup
- **Deskripsi:** Oscar has been encrypted again using XOR. It’s said that the technique is more complex. Your task is to decrypt the hidden message and bring him back to earth.

## Informasi Attachment
```text
 WanZKey  ～  ~../Reverse Engineering/xor_me_2 󱎫 0s 󱑎 14.23
 󰋑  ▶  file xor_me_2
xor_me_2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9092bc26bba565007bf0b69aecf3bba2c7b5accf, for GNU/Linux 4.4.0, not stripped

 WanZKey  ～  ~../Reverse Engineering/xor_me_2 󱎫 0s 󱑎 14.23
 󰋑  ▶  checksec --file=xor_me_2
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/xor_me_2/xor_me_2'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

## Proses Penyelesaian

Langkah pertama adalah melakukan *dynamic analysis* ringan. Saat program `xor_me_2` dijalankan, program mencetak deretan teks *gibberish* (*ciphertext*): `P@ZBKxe\VnCIt`ZkSwP=␦\nE&nK`.

Melalui perintah `ltrace`, kita dapat melihat bahwa program mencetak *ciphertext* tersebut karakter demi karakter menggunakan fungsi `putchar()`. Ini menandakan bahwa *binary* ini bertindak sebagai mesin enkripsinya (*encrypter*).

### Analisis Decompile (IDA Pro)

Dari hasil *decompile* fungsi `main`, kita menemukan dua *array* bertipe *integer* (`v11` dan `v12`). Bagian terpenting dari logika program ini berada di blok perulangan (*looping*) pertama:

```c
for ( i = 0; i <= 13; ++i )
{
  v7 = v11[2 * i];
  v8 = v12[2 * i];
  *((_BYTE *)&v12[34] + i + 2) = 2 * (v8 & v7) + (v7 ^ v8);
  v9 = v11[2 * i + 1];
  v10 = v12[2 * i + 1];
  *((_BYTE *)&v12[31] + i) = 2 * (v10 & v9) + (v9 ^ v10);
}
```

Meskipun soal menyebutkan "teknik XOR yang lebih kompleks", program sebenarnya menggunakan teknik *obfuscation* (pengaburan kode) matematika *bitwise*. Potongan rumus `2 * (A & B) + (A ^ B)` secara logika matematis komputer sama persis dengan operasi penjumlahan biasa, yaitu **`A + B`**.

Program mengekstrak nilai dari indeks genap dan ganjil dari kedua *array* tersebut, lalu menjumlahkannya. Hasil dari penjumlahan ini (yang disimpan sementara di memori) **adalah *flag* murni (plaintext) yang kita cari**. 

Perulangan `j` dan `k` selanjutnya yang menggunakan operasi XOR hanyalah manipulasi tambahan untuk menghasilkan *ciphertext* acak di terminal dan mengecoh analisis. Oleh karena itu, kita cukup menjumlahkan elemen `v11` dan `v12` yang bersesuaian untuk mendapatkan *flag*.

### Script Solver

Berikut adalah *script* Python untuk mereplikasi ekstraksi data dan menjumlahkan elemen-elemen dari kedua *array* (berdasarkan indeks genap dan ganjil) untuk menyusun kembali pesannya.

```python
#!/usr/bin/env python3

# Nilai array v11 dari hasil decompile
v11 = [12, 111, 63, 40, 4, 49, 98, 73, 47, 95, 41, 103, 90, 46, 
       44, 30, 90, 90, 14, 51, 16, 33, 31, 22, 20, 68, 79, 113]

# Nilai array v12 dari hasil decompile
v12 = [74, 6, 56, 27, 80, 21, 25, 6, 68, 4, 56, 11, 5, 59, 
       39, 65, 25, 26, 35, 57, 92, 62, 34, 54, 32, 50, 22, 12]

flag = ""

# Loop sebanyak 14 kali (karena tiap iterasi memproses 2 karakter: genap & ganjil)
for i in range(14):
    # Penjumlahan elemen indeks genap
    flag += chr(v11[2*i] + v12[2*i])
    # Penjumlahan elemen indeks ganjil
    flag += chr(v11[2*i + 1] + v12[2*i + 1])

print(f"Decrypted Flag: {flag}")
```

### Output Terminal

```text
 󰋑  ▶  ./solver.py
Decrypted Flag: VuwCTF{Oscar_iS_st1ll_AL4ve}
```

## Flag

```text
VuwCTF{Oscar_iS_st1ll_AL4ve}
```
