# WriteUp - xor_me

## Overview
- **Judul:** xor_me
- **Kategori:** Reverse Engineering
- **Poin:** 150
- **Author:** Aterlone
- **Release:** Reverse Engineering Meetup
- **Deskripsi:** Oscar has been encrypted using XOR using the meaning of life. Your task is to decrypt the hidden message and bring him back to earth.

## Informasi Attachment
```text
 WanZKey  ～  ~../Reverse Engineering/xor_me 󱎫 0s 󱑎 14.14
 󰋑  ▶  file xor_me
xor_me: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1c54779f79c6a56c8e1e1c45f7d4e906cfbef24e, for GNU/Linux 3.2.0, stripped

 WanZKey  ～  ~../Reverse Engineering/xor_me 󱎫 0s 󱑎 14.14
 󰋑  ▶  checksec --file=xor_me
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/xor_me/xor_me'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

## Proses Penyelesaian

Langkah pertama yang dilakukan adalah menganalisis jenis *file* dan proteksi keamanan dari *binary* tersebut. Selanjutnya, program dijalankan secara normal dan dianalisis perilakunya menggunakan `ltrace` untuk melacak pemanggilan fungsi *library* (library calls) dari sistem.

```text
 WanZKey  ～  ~../Reverse Engineering/xor_me 󱎫 1s 󱑎 14.14
 󰋑  ▶  ./xor_me
Hello there.
Have you tried decompiling the program yet? I recommend using ghidra.

 WanZKey  ～  ~../Reverse Engineering/xor_me 󱎫 0s 󱑎 14.14
 󰋑  ▶  ltrace ./xor_me
puts("Hello there.\nHave you tried deco"...Hello there.
Have you tried decompiling the program yet? I recommend using ghidra.
) = 83
+++ exited (status 0) +++
```

Program hanya mencetak pesan statis yang menyarankan penggunaan *decompiler* dan tidak meminta interaksi *input* dari pengguna. Oleh karena itu, langkah berikutnya adalah melakukan *decompile* pada *binary* menggunakan IDA Pro untuk memeriksa alur kode yang tersembunyi.

### Informasi Decompile (IDA Pro)

**1. start**
```c
// positive sp value has been detected, the output may be wrong!
void __fastcall __noreturn start(__int64 a1, __int64 a2, void (*a3)(void))
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  char *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  _libc_start_main(main, v4, &retaddr, 0LL, 0LL, a3, &v5);
  __halt();
}
```

**2. main**
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int i; // [rsp+4h] [rbp-3Ch]
  _QWORD v5[6]; // [rsp+10h] [rbp-30h] BYREF

  v5[5] = __readfsqword(0x28u);
  qmemcpy(v5, "|_]i~lQEYIKXuBKYuHOODuREXONW\n", 29);
  for ( i = 0; i < 0x1D; ++i )
    *((_BYTE *)v5 + (int)i) ^= 0x2Au;
  puts("Hello there.\nHave you tried decompiling the program yet? I recommend using ghidra.");
  return 0LL;
}
```

Berdasarkan hasil analisis *decompile* pada fungsi `main`, program mengalokasikan memori untuk *ciphertext* `|_]i~lQEYIKXuBKYuHOODuREXONW\n` ke dalam variabel `v5`. Program lalu melakukan iterasi (*looping*) sebanyak 29 kali (0x1D) di mana setiap karakter dari *ciphertext* tersebut di-XOR (`^=`) dengan nilai `0x2Au` (42 dalam desimal). Angka 42 ini sesuai dengan petunjuk "the meaning of life" pada deskripsi soal.

Namun, nilai yang telah di-XOR tersebut hanya tersimpan di dalam memori dan program langsung mengeksekusi perintah `puts` untuk menampilkan teks pengecoh sebelum akhirnya keluar (`return 0LL`). Untuk mendapatkan nilai aslinya, kita harus mendekripsi *ciphertext* tersebut menggunakan *script* secara manual. 

### Script Solver

```python
#!/usr/bin/env python3

ciphertext = "|_]i~lQEYIKXuBKYuHOODuREXONW\n"
key = 0x2A

flag = ""
for char in ciphertext:
    flag += chr(ord(char) ^ key)

print(f"Decrypted Flag: {flag.strip()}")
```

### Output Terminal Solver

```text
 󰋑  ▶  ./solver.py
Decrypted Flag: VuwCTF{oscar_has_been_xored}
```

## Flag

```text
VuwCTF{oscar_has_been_xored}
```
