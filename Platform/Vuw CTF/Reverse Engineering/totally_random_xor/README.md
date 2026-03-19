# WriteUp - totally_random_xor

## Overview
- **Judul:** totally_random_xor
- **Kategori:** Reverse Engineering
- **Poin:** 200
- **Author:** Aterlone
- **Release:** Reverse Engineering Meetup
- **Deskripsi:** A new "state-of-the-art" random number generator service has been launched. It proudly claims to be cryptographically secure—but is it really? Flag format is VUW{}. Sorry, I made this before we actually decided on a flag format.

## Informasi Attachment
```text
 WanZKey  ～  ~../Reverse Engineering/totally_random_xor 󱎫 0s 󱑎 14.26
 󰋑  ▶  file totally_random_xor
totally_random_xor: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8756a41defac234ca651ae7682f916455c49a5e5, for GNU/Linux 4.4.0, stripped

 WanZKey  ～  ~../Reverse Engineering/totally_random_xor 󱎫 0s 󱑎 14.27
 󰋑  ▶  checksec --file=totally_random_xor
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/totally_random_xor/totally_random_xor'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

## Proses Penyelesaian

Berdasarkan deskripsi soal, program ini mengklaim memiliki *random number generator* (RNG) yang aman secara kriptografi. Namun, analisis dinamis dan statis membuktikan sebaliknya.

Saat mengeksekusi *binary* dengan `ltrace`, terlihat jelas urutan pemanggilan fungsi dari *library* sistem:
```text
srand(3735928559)                                  = <void>
rand()                                             = 352217057
rand()                                             = 918588210
rand()                                             = 499345174
...
```

### Analisis Decompile (IDA Pro)

Hasil *decompile* dari fungsi `main` memperlihatkan logika internal program:
```c
  sub_1159(3735928559LL, a2, a3); // Ini memanggil srand(3735928559)
  v5[0] = 352217015;
  v5[1] = 918588263;
  // ... inisialisasi v5 ...
  for ( i = 0; i <= 16; ++i )
    v5[i] ^= rand();
```

Terdapat kelemahan fatal pada implementasi RNG program ini, yaitu penggunaan nilai *seed* yang bersifat *hardcoded* dan statis (`3735928559`). Karena *seed* selalu sama di setiap eksekusi, fungsi `rand()` akan selalu menghasilkan deretan angka *pseudo-random* yang deterministik dan identik.

Program kemudian menggunakan nilai keluaran dari `rand()` tersebut sebagai *key* (kunci) untuk melakukan operasi XOR terhadap elemen-elemen di *array* `v5` (yang berperan sebagai *ciphertext*). Karena kita sudah mengantongi nilai *ciphertext* dari hasil *decompile* IDA Pro, serta urutan kunci acaknya dari tangkapan `ltrace`, kita dapat melakukan operasi XOR ulang secara manual untuk mengekstrak kode ASCII aslinya (*plaintext*).

### Script Solver

```python
#!/usr/bin/env python3

# Nilai array v5 (ciphertext) yang diambil dari decompile IDA Pro
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

# Melakukan perulangan untuk meng-XOR ciphertext dengan deretan angka 'random'
for i in range(len(v5)):
    # Hasil XOR dikonversi kembali dari bentuk integer ke karakter string
    flag += chr(v5[i] ^ rand_vals[i])

print(f"Decrypted Flag: {flag}")
```

### Output Terminal Solver

```text
 󰋑  ▶  ./solver.py
Decrypted Flag: VUW{r3ndm_0r_n3T}
```

## Flag

```text
VUW{r3ndm_0r_n3T}
```
