https://gemini.google.com/share/13fdfefc60ef
# WriteUp: Key Guesser

## Challenge Information

* **Name:** Key guesser
* **Category:** Reverse Engineering
* **Points:** 500
* **Description:** In this challenge, you need to reverse-engineer the attached binary to find the accepted key.

## 1. Initial Analysis & Reconnaissance

Langkah pertama adalah melakukan identifikasi dasar terhadap file binary yang diberikan untuk mengetahui arsitektur, jenis file, dan proteksi keamanan yang diterapkan.

### Basic File Information

Menggunakan perintah `file` untuk melihat detail binary.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Key guesser]
└─$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7cbb5e79f1d3919c2d7df713341237fa4805ad7c, for GNU/Linux 4.4.0, not stripped

```

### Security Mitigation Check

Menggunakan `checksec` untuk memeriksa mitigasi keamanan.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Key guesser]
└─$ checksec --file=chall
[*] '/home/wanzkey/Digital Security Lab CTF/Reverse Engineering/Key guesser/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       Canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No

```

**Analisis:**
Binary ini adalah ELF 64-bit dan **not stripped**. Status "not stripped" berarti simbol-simbol (seperti nama fungsi) masih ada di dalam binary, yang akan sangat memudahkan proses reverse engineering.

## 2. Dynamic Analysis

Kita mencoba menjalankan binary tersebut untuk memahami input yang diminta dan bagaimana program merespons input yang salah.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Key guesser]
└─$ ./chall
Enter the key: test
Try again!

```

### Tracing Library Calls (ltrace)

Selanjutnya, kita menggunakan `ltrace` untuk melacak pemanggilan fungsi library (library calls) saat program berjalan. Ini berguna untuk melihat fungsi perbandingan string.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Key guesser]
└─$ ltrace ./chall
printf("Enter the key: ")                                 = 15
__isoc99_scanf(0x57b0376d2018, 0x7ffdbca5e0c0, 0, 0Enter the key: test
)                      = 1
strcmp("test", "flag{c0mpil4t1on_is_n0t_3ncrypt1"...)     = 14
puts("Try again!"Try again!
)                                        = 11
+++ exited (status 0) +++

```

**Temuan:**
Output `ltrace` menunjukkan bahwa input kita ("test") dibandingkan menggunakan fungsi `strcmp` dengan sebuah string yang dimulai dengan `flag{...`. Namun, output tersebut terpotong (`...`). Kita perlu melakukan analisis statis untuk melihat string lengkapnya.

## 3. Static Analysis & Reverse Engineering

Kita akan melihat kode assembly dan melakukan dekompilasi untuk mendapatkan logika program yang utuh.

### Disassembly (Objdump)

Melihat struktur assembly fungsi `main`.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Key guesser]
└─$ objdump -d chall | grep main
    1098:       48 8d 3d da 00 00 00    lea    0xda(%rip),%rdi        # 1179 <main>
    109f:       ff 15 1b 2f 00 00       call   *0x2f1b(%rip)        # 3fc0 <__libc_start_main@GLIBC_2.34>
0000000000001179 <main>:
    11d7:       75 11                   jne    11ea <main+0x71>
    11e8:       eb 0f                   jmp    11f9 <main+0x80>
    120b:       74 05                   je     1212 <main+0x99>

```

### Decompilation (IDA Pro)

Berikut adalah hasil dekompilasi fungsi `main` menggunakan IDA Pro:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s1[72]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter the key: ");
  __isoc99_scanf("%64s", s1);
  if ( !strcmp(s1, "flag{c0mpil4t1on_is_n0t_3ncrypt1on}") )
    puts("That's it!");
  else
    puts("Try again!");
  return 0;
}

```

**Analisis Logika:**

1. Program meminta input string dari user dan menyimpannya ke variabel `s1`.
2. Input tersebut langsung dibandingkan menggunakan `strcmp` dengan string hardcoded: `"flag{c0mpil4t1on_is_n0t_3ncrypt1on}"`.
3. Jika hasil `strcmp` adalah 0 (cocok), program mencetak "That's it!".
4. Ini mengkonfirmasi bahwa string tersebut adalah flag yang valid.

## 4. Solving Strategy

Berdasarkan analisis di atas, flag tersimpan dalam bentuk *plaintext* (teks jelas) di dalam binary. Kita bisa langsung mengambilnya.

**Flag:** `flag{c0mpil4t1on_is_n0t_3ncrypt1on}`

### Solver Script (`solver.py`)

Berikut adalah script Python menggunakan `pwntools` untuk melakukan koneksi ke binary dan mengirimkan flag secara otomatis:

```python
from pwn import *

# Set log level
context.log_level = 'info'

# Start process
io = process('./chall')

# Flag yang ditemukan dari IDA Pro
key = "flag{c0mpil4t1on_is_n0t_3ncrypt1on}"

# Tunggu sampai program meminta input
io.recvuntil(b"Enter the key: ")

# Kirim flag
io.sendline(key.encode())

# Terima respon
output = io.recvline().decode().strip()
print(f"Server Response: {output}")

if "That's it!" in output:
    print("[+] Flag accepted!")
else:
    print("[-] Flag rejected.")

io.close()

```

## 5. Verification

Melakukan verifikasi manual dengan memasukkan flag yang ditemukan ke dalam program.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Reverse Engineering/Key guesser]
└─$ ./chall
Enter the key: flag{c0mpil4t1on_is_n0t_3ncrypt1on}
That's it!

```


