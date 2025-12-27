https://gemini.google.com/share/13fdfefc60ef
# WriteUp: One Time Check

## Challenge Information

* **Name:** One Time Check
* **Category:** Reverse Engineering
* **Points:** 500
* **Description:** In this challenge, you need to reverse-engineer the attached binary to find the accepted key.

## 1. Initial Analysis & Reconnaissance

Langkah pertama adalah melakukan identifikasi terhadap file binary yang diberikan untuk mengetahui arsitektur dan proteksi yang aktif.

### Basic File Information

Menggunakan perintah `file` untuk melihat tipe binary.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/One Time Check]
└─$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=4b7ab914737abf99c58beb5fb9a800beb5cbbb30, for GNU/Linux 4.4.0, not stripped

```

### Security Mitigation Check

Menggunakan `checksec` untuk melihat mitigasi keamanan.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/One Time Check]
└─$ checksec --file=chall
[*] '/home/wanzkey/Digital Security Lab CTF/Reverse Engineering/One Time Check/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       Canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No

```

**Analisis:** Binary adalah 64-bit ELF, **not stripped** (simbol fungsi masih ada, memudahkan debugging), dan PIE enabled (alamat memori acak).

## 2. Dynamic Analysis

Mencoba menjalankan program untuk memahami perilaku input dan outputnya.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/One Time Check]
└─$ ./chall
Enter the key: test
Try again!

```

Menggunakan `ltrace` untuk melacak library calls yang dipanggil program saat dijalankan.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/One Time Check]
└─$ ltrace ./chall
printf("Enter the key: ")                                 = 15
__isoc99_scanf(0x56e66d1e1014, 0x7ffdd1950d30, 0, 0Enter the key: test
)                      = 1
strlen("test")                                            = 4
puts("Try again!"Try again!
)                                        = 11
+++ exited (status 0) +++

```

**Analisis:** Program mengambil input menggunakan `scanf`, menghitung panjang string dengan `strlen`, lalu membandingkannya. Karena input salah, program mencetak "Try again!".

## 3. Reverse Engineering

Karena binary tidak di-strip, kita bisa melihat assembly code untuk fungsi `main` dan fungsi pengecekan lainnya.

### Disassembly (Objdump)

Melihat instruksi assembly untuk fungsi `main` dan `check_key`.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/One Time Check]
└─$ objdump -d chall | grep main
    1098:       48 8d 3d 56 01 00 00    lea    0x156(%rip),%rdi        # 11f5 <main>
    109f:       ff 15 1b 2f 00 00       call   *0x2f1b(%rip)        # 3fc0 <__libc_start_main@GLIBC_2.34>
00000000000011f5 <main>:
    1249:       75 11                   jne    125c <main+0x67>
    125a:       eb 0f                   jmp    126b <main+0x76>
    127d:       74 05                   je     1284 <main+0x8f>

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/One Time Check]
└─$ objdump -d chall | grep check_key
0000000000001179 <check_key>:
    1195:       74 07                   je     119e <check_key+0x25>
    119c:       eb 55                   jmp    11f3 <check_key+0x7a>
    11a5:       eb 41                   jmp    11e8 <check_key+0x6f>
    11db:       74 07                   je     11e4 <check_key+0x6b>
    11e2:       eb 0f                   jmp    11f3 <check_key+0x7a>
    11ec:       7e b9                   jle    11a7 <check_key+0x2e>
    1242:       e8 32 ff ff ff          call   1179 <check_key>

```

### Decompilation (IDA Pro)

Untuk memahami logika secara utuh, berikut adalah hasil decompile menggunakan IDA Pro.

#### 1. Fungsi `main`

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[72]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter the key: ");
  __isoc99_scanf("%64s", v4);
  if ( (unsigned int)check_key(v4) )
    puts("Try again!");
  else
    puts("That's it!");
  return 0;
}

```

**Logika:** Input pengguna disimpan di `v4`, lalu dikirim ke fungsi `check_key(v4)`. Jika return value `0` (false), kita menang ("That's it!").

#### 2. Fungsi `check_key`

```c
__int64 __fastcall check_key(const char *a1)
{
  int i; // [rsp+1Ch] [rbp-4h]

  if ( strlen(a1) != 33 )
    return 1LL;
  for ( i = 0; i <= 32; ++i )
  {
    if ( (key[i] ^ a1[i]) != enc_flag[i] )
      return 1LL;
  }
  return 0LL;
}

```

**Logika Pengecekan:**

1. Panjang input (`a1`) harus 33 karakter.
2. Melakukan loop dari `i = 0` sampai `32`.
3. Mengecek kondisi: `(key[i] ^ a1[i]) != enc_flag[i]`.
4. Jika kondisi di atas benar (tidak sama), fungsi return `1` (gagal).
5. Agar berhasil, persamaan `key[i] ^ a1[i] == enc_flag[i]` harus terpenuhi.

## 4. Solving Strategy

Berdasarkan analisis fungsi `check_key`, kita memiliki persamaan XOR:


Karena operasi XOR bersifat *reversible* (dapat dibalik), kita dapat mencari nilai `input` (flag) dengan rumus:


Variabel `key` dan `enc_flag` adalah variabel global yang tersimpan di dalam binary. Karena binary **not stripped**, kita dapat menggunakan `pwntools` untuk membaca nilai byte dari simbol `key` dan `enc_flag` tersebut tanpa harus menyalinnya secara manual dari Hex Editor.

### Solver Script (`solver.py`)

```python
from pwn import *

# Muat file binary
elf = ELF('./chall')

try:
    # Ambil alamat dari simbol 'key' dan 'enc_flag'
    key_addr = elf.symbols['key']
    enc_flag_addr = elf.symbols['enc_flag']

    # Baca data dari alamat tersebut sebanyak 33 byte (sesuai panjang loop/strlen)
    key_data = elf.read(key_addr, 33)
    enc_flag_data = elf.read(enc_flag_addr, 33)

    # Lakukan operasi XOR untuk mendapatkan flag asli
    # flag = key ^ enc_flag
    flag = xor(key_data, enc_flag_data)

    # Cetak hasil
    print(f"Flag found: {flag.decode('utf-8')}")

except Exception as e:
    print(f"Error: {e}")

```

## 5. Result

Menjalankan script solver di terminal untuk mendapatkan flag.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/One Time Check]
└─$ python3 solver.py
[*] '/home/wanzkey/Digital Security Lab CTF/Reverse Engineering/One Time Check/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       Canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No
Flag found: flag{x0r_is_inv3rt1ble_y0u_kn0w?}

```

**Flag:** `flag{x0r_is_inv3rt1ble_y0u_kn0w?}`
