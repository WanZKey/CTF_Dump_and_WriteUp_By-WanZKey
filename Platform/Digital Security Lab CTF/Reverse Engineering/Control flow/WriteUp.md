https://gemini.google.com/share/13fdfefc60ef
# WriteUp: Control Flow

## Challenge Information

* **Name:** Control flow
* **Category:** Reverse Engineering
* **Points:** 500
* **Description:** Melakukan reverse engineering pada binary untuk menemukan kunci yang valid.

## 1. Initial Analysis & Reconnaissance

Langkah pertama adalah melakukan identifikasi dasar terhadap file binary yang diberikan untuk mengetahui arsitektur, jenis file, dan proteksi keamanan yang diterapkan.

### Basic File Information

Menggunakan perintah `file` untuk melihat detail binary.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Control flow]
└─$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=fc29053dbfb98924b7b6fe38f80abcfcab349b0e, for GNU/Linux 4.4.0, not stripped

```

### Security Mitigation Check

Menggunakan `checksec` untuk memeriksa mitigasi keamanan.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Control flow]
└─$ checksec --file=chall
[*] '/home/wanzkey/Digital Security Lab CTF/Reverse Engineering/Control flow/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       Canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No

```

**Analisis:** Binary adalah format ELF 64-bit, **not stripped** (simbol fungsi masih ada), dan PIE enabled.

## 2. Dynamic Analysis

Kita mencoba menjalankan binary tersebut untuk memahami input yang diminta dan bagaimana program merespons.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Control flow]
└─$ ./chall
Enter the key: test
Try again!

```

### Tracing Library Calls (ltrace)

Kita menggunakan `ltrace` untuk melihat apakah ada fungsi library (seperti `strcmp`) yang digunakan untuk membandingkan input.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Control flow]
└─$ ltrace ./chall
printf("Enter the key: ")                                 = 15
__isoc99_scanf(0x5e2112921014, 0x7fff6a3b7b80, 0, 0Enter the key: test
)                      = 1
puts("Try again!"Try again!
)                                        = 11
+++ exited (status 0) +++

```

**Temuan:**
Berbeda dengan challenge "Key Guesser", `ltrace` di sini **tidak** menampilkan fungsi perbandingan string. Ini mengindikasikan bahwa validasi kunci dilakukan secara manual (misalnya karakter per karakter) di dalam logika program, bukan menggunakan library standar. Hal ini sesuai dengan nama challenge "Control flow".

## 3. Static Analysis & Reverse Engineering

Kita akan melihat kode assembly dan melakukan dekompilasi untuk mendapatkan logika program yang utuh.

### Disassembly (Objdump)

Melihat struktur assembly fungsi `main` dan `check_key`.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Control flow]
└─$ objdump -d chall | grep main
    1088:       48 8d 3d 12 03 00 00    lea    0x312(%rip),%rdi        # 13a1 <main>
    108f:       ff 15 2b 2f 00 00       call   *0x2f2b(%rip)        # 3fc0 <__libc_start_main@GLIBC_2.34>
00000000000013a1 <main>:
    13f5:       75 11                   jne    1408 <main+0x67>
    1406:       eb 0f                   jmp    1417 <main+0x76>
    1429:       74 05                   je     1430 <main+0x8f>

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Control flow]
└─$ objdump -d chall | grep check_key
0000000000001169 <check_key>:
    117a:       74 0a                   je     1186 <check_key+0x1d>
    1181:       e9 19 02 00 00          jmp    139f <check_key+0x236>
    1193:       74 0a                   je     119f <check_key+0x36>
    119a:       e9 00 02 00 00          jmp    139f <check_key+0x236>
    11ac:       74 0a                   je     11b8 <check_key+0x4f>
    11b3:       e9 e7 01 00 00          jmp    139f <check_key+0x236>
    11c5:       74 0a                   je     11d1 <check_key+0x68>
    11cc:       e9 ce 01 00 00          jmp    139f <check_key+0x236>
    11de:       74 0a                   je     11ea <check_key+0x81>
    11e5:       e9 b5 01 00 00          jmp    139f <check_key+0x236>
    11f7:       74 0a                   je     1203 <check_key+0x9a>
    11fe:       e9 9c 01 00 00          jmp    139f <check_key+0x236>
    1210:       74 0a                   je     121c <check_key+0xb3>
    1217:       e9 83 01 00 00          jmp    139f <check_key+0x236>
    1229:       74 0a                   je     1235 <check_key+0xcc>
    1230:       e9 6a 01 00 00          jmp    139f <check_key+0x236>
    1242:       74 0a                   je     124e <check_key+0xe5>
    1249:       e9 51 01 00 00          jmp    139f <check_key+0x236>
    125b:       74 0a                   je     1267 <check_key+0xfe>
    1262:       e9 38 01 00 00          jmp    139f <check_key+0x236>
    1274:       74 0a                   je     1280 <check_key+0x117>
    127b:       e9 1f 01 00 00          jmp    139f <check_key+0x236>
    128d:       74 0a                   je     1299 <check_key+0x130>
    1294:       e9 06 01 00 00          jmp    139f <check_key+0x236>
    12a6:       74 0a                   je     12b2 <check_key+0x149>
    12ad:       e9 ed 00 00 00          jmp    139f <check_key+0x236>
    12bf:       74 0a                   je     12cb <check_key+0x162>
    12c6:       e9 d4 00 00 00          jmp    139f <check_key+0x236>
    12d8:       74 0a                   je     12e4 <check_key+0x17b>
    12df:       e9 bb 00 00 00          jmp    139f <check_key+0x236>
    12f1:       74 0a                   je     12fd <check_key+0x194>
    12f8:       e9 a2 00 00 00          jmp    139f <check_key+0x236>
    130a:       74 0a                   je     1316 <check_key+0x1ad>
    1311:       e9 89 00 00 00          jmp    139f <check_key+0x236>
    1323:       74 07                   je     132c <check_key+0x1c3>
    132a:       eb 73                   jmp    139f <check_key+0x236>
    1339:       74 07                   je     1342 <check_key+0x1d9>
    1340:       eb 5d                   jmp    139f <check_key+0x236>
    134f:       74 07                   je     1358 <check_key+0x1ef>
    1356:       eb 47                   jmp    139f <check_key+0x236>
    1365:       74 07                   je     136e <check_key+0x205>
    136c:       eb 31                   jmp    139f <check_key+0x236>
    137b:       74 07                   je     1384 <check_key+0x21b>
    1382:       eb 1b                   jmp    139f <check_key+0x236>
    1391:       74 07                   je     139a <check_key+0x231>
    1398:       eb 05                   jmp    139f <check_key+0x236>
    13ee:       e8 76 fd ff ff          call   1169 <check_key>

```

Output `objdump` pada `check_key` menunjukkan struktur percabangan yang sangat panjang (banyak instruksi `je` dan `jmp`), mengonfirmasi bahwa setiap karakter dicek satu per satu.

### Decompilation (IDA Pro)

Hasil dekompilasi dari IDA Pro memberikan logika yang jelas.

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

Program memanggil `check_key(v4)`. Jika return value **selain 0** (True), maka gagal. Jika **0** (False), maka sukses ("That's it!").

#### 2. Fungsi `check_key`

```c
_BOOL8 __fastcall check_key(_BYTE *a1)
{
  if ( *a1 != 102 )
    return 1LL;
  if ( a1[1] != 108 )
    return 1LL;
  if ( a1[2] != 97 )
    return 1LL;
  if ( a1[3] != 103 )
    return 1LL;
  if ( a1[4] != 123 )
    return 1LL;
  if ( a1[5] != 51 )
    return 1LL;
  if ( a1[6] != 97 )
    return 1LL;
  if ( a1[7] != 115 )
    return 1LL;
  if ( a1[8] != 121 )
    return 1LL;
  if ( a1[9] != 95 )
    return 1LL;
  if ( a1[10] != 99 )
    return 1LL;
  if ( a1[11] != 48 )
    return 1LL;
  if ( a1[12] != 110 )
    return 1LL;
  if ( a1[13] != 116 )
    return 1LL;
  if ( a1[14] != 114 )
    return 1LL;
  if ( a1[15] != 48 )
    return 1LL;
  if ( a1[16] != 108 )
    return 1LL;
  if ( a1[17] != 95 )
    return 1LL;
  if ( a1[18] != 102 )
    return 1LL;
  if ( a1[19] != 108 )
    return 1LL;
  if ( a1[20] != 48 )
    return 1LL;
  if ( a1[21] == 119 )
    return a1[22] != 125;
  return 1LL;
}

```

**Analisis Logika:**
Fungsi memeriksa setiap indeks array input `a1` terhadap nilai integer tertentu. Nilai integer tersebut adalah representasi **Desimal dari ASCII Character**.
Contoh:

* `a1[0]` harus `102` ('f')
* `a1[1]` harus `108` ('l')
* dan seterusnya.

## 4. Solving Strategy

Strateginya adalah mengumpulkan semua angka desimal tersebut dan mengonversinya kembali menjadi karakter ASCII untuk membentuk flag.

### Solver Script (`solver.py`)

Berikut adalah script Python untuk mendekode urutan angka tersebut.

```python
# Nilai desimal yang diambil dari hasil dekompilasi IDA Pro
# Urutan: a1[0], a1[1], a1[2], ..., a1[22]

decimal_chars = [
    102, 108, 97, 103, 123,  # flag{
    51, 97, 115, 121, 95,    # 3asy_
    99, 48, 110, 116, 114,   # c0ntr
    48, 108, 95,             # 0l_
    102, 108, 48, 119, 125   # fl0w}
]

# Konversi List Angka ke String (ASCII)
flag = "".join([chr(x) for x in decimal_chars])

print(f"Flag Found: {flag}")

```

## 5. Result

Menjalankan script solver untuk mendapatkan flag:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Control flow]
└─$ python3 solver.py
Flag Found: flag{3asy_c0ntr0l_fl0w}

```

Melakukan verifikasi flag pada binary:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Control flow]
└─$ ./chall
Enter the key: flag{3asy_c0ntr0l_fl0w}
That's it!

```

**Flag:** `flag{3asy_c0ntr0l_fl0w}`
