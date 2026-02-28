# WriteUp - bayi ahh gedebe

## Overview

* **Judul:** bayi ahh gedebe
* **Kategori:** Reverse Engineering
* **Poin:** 50
* **Deskripsi:** Bisakah kamu yang hebat mencari tahu apa isi register eax di akhir fungsi main? Formatnya FGTE{n}, di mana n adalah isi register eax dalam basis desimal. Jika jawabannya adalah 0x11, maka flag-nya adalah FGTE{17}.
* **Author:** nuts3424

## Attachment

* **Direktori:** `~../Reverse/bayi ahh gedebe`
* **File:** `debug0_a`

## Proses Penyelesaian

### 1. Reconnaissance

Langkah pertama adalah melakukan identifikasi file binary `debug0_a` untuk mengetahui arsitektur dan proteksinya.

```bash
WanZKey  ～  ~../Reverse/bayi ahh gedebe 󱎫 0s 󱑎 17.01
 󰋑  ▶  file debug0_a
debug0_a: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=1bbb247653531231b899594d165bb642abf5c731, for GNU/Linux 3.2.0, not stripped

WanZKey  ～  ~../Reverse/bayi ahh gedebe 󱎫 0s 󱑎 17.01
 󰋑  ▶  checksec --file=debug0_a
[*] '/home/wanzkey/ARIAF CTF 2025/Reverse/bayi ahh gedebe/debug0_a'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       No canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No

```

Selanjutnya, mencoba menjalankan binary tersebut dan menggunakan `ltrace` untuk melihat *exit status* atau *library call*.

```bash
WanZKey  ～  ~../Reverse/bayi ahh gedebe 󱎫 0s 󱑎 17.01
 󰋑  ▶  ./debug0_a

WanZKey  ～  ~../Reverse/bayi ahh gedebe 󱎫 0s 󱑎 17.01
 󰋑  ▶  ltrace ./debug0_a
+++ exited (status 147) +++

```

Program langsung berhenti dengan status **147**. Perlu diketahui bahwa di Linux, *exit status* hanya mengambil 8-bit terakhir (modulo 256) dari nilai return fungsi `main`.

### 2. Static Analysis (IDA Pro)

Untuk mengetahui nilai asli register `eax` sebelum program berhenti, dilakukan dekompilasi menggunakan IDA Pro. Register `eax` pada arsitektur x86/x64 digunakan untuk menyimpan nilai kembalian (*return value*) dari sebuah fungsi.

**Assembly Listing (`main`):**

```asm
; int __fastcall main(int argc, const char **argv, const char **envp)
public main
main proc near

var_10= qword ptr -10h
var_4= dword ptr -4

; __unwind {
push    rbp
mov     rbp, rsp
mov     [rbp+var_4], edi
mov     [rbp+var_10], rsi
mov     eax, 8793h      ; <--- Nilai return (EAX) di-set ke 0x8793
pop     rbp
retn
; } // starts at 1129
main endp

```

**Pseudocode (`main`):**

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  return 34707;
}

```

Dari kode assembly, terlihat instruksi `mov eax, 8793h`. Ini berarti nilai `eax` pada akhir fungsi `main` adalah **0x8793**.

### 3. Solving

Deskripsi soal meminta nilai `eax` dalam basis desimal.

* Nilai Hex: `0x8793`
* Konversi ke Desimal: `34707`

Verifikasi dengan `ltrace`:
`34707 % 256 = 147`.
Ini sesuai dengan output `ltrace` sebelumnya (`status 147`), mengonfirmasi bahwa nilai aslinya adalah 34707.

### 4. Solver Script & Output

Script Python sederhana digunakan untuk mengonfirmasi konversi dan mencetak flag sesuai format.

```python
# Solver untuk menghitung nilai desimal dari Hex EAX
eax_hex = 0x8793

print(f"[*] Hex Value (EAX): {hex(eax_hex)}")
print(f"[*] Decimal Value  : {eax_hex}")
print(f"[+] Flag: FGTE{{{eax_hex}}}")

```

**Output Terminal:**

```bash
 󰋑  ▶  ./solver.py
[*] Hex Value (EAX): 0x8793
[*] Decimal Value  : 34707
[+] Flag: FGTE{34707}

```

## Flag

```
FGTE{34707}

```
