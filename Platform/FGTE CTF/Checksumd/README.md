# WriteUp: Checksumd

## Overview

* **Judul:** Checksumd
* **Kategori:** Reverse
* **Poin:** 100
* **Deskripsi:** Sebuah tool checksum sederhana dibuat menggunakan Golang untuk memverifikasi integritas sebuah file. Namun, file data.bin yang seharusnya valid telah dimodifikasi oleh seseorang, sehingga proses verifikasi selalu gagal. Bisakah kamu memperbaiki isi data.bin agar lolos proses verifikasi checksum?
* **Format:** FGTE{...}

## Attachment Information

**Files:**

* `checksumd`: ELF 64-bit LSB executable (Go binary)
* `data.bin`: ASCII text

**Struktur Direktori:**

```text
.
├── checksumd
└── data.bin

```

## Proses Penyelesaian

### 1. Reconnaissance

Melakukan identifikasi awal terhadap file binary dan file data yang diberikan menggunakan `file`, `checksec`, dan `xxd`.

```bash
file *
checksec --file=checksumd
xxd data.bin | head

```

**Output Terminal:**

```text
 WanZKey  ～  ~../Reverse/Checksumd 󱎫 0s 󱑎 13.11
 󰋑  ▶  file *
checksumd: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=k8CJY951aSq8lcz5iy7l/HE2qczOsZsQOpWRO_K4p/kBFsA-ZRO8AlvSp8KhBv/fkyPIv3HHuajmv_0Ed6u, stripped
data.bin:  ASCII text, with no line terminators

 WanZKey  ～  ~../Reverse/Checksumd 󱎫 0s 󱑎 13.13
 󰋑  ▶  checksec --file=checksumd
[*] '/home/wanzkey/ARIAF CTF 2025/Reverse/Checksumd/checksumd'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)

 WanZKey  ～  ~../Reverse/Checksumd 󱎫 0s 󱑎 13.13
 󰋑  ▶  xxd data.bin | head
00000000: 5858 5858 5858 5858 5858 5858 5858 5858  XXXXXXXXXXXXXXXX

```

### 2. Static Analysis (Strings)

Meskipun binary `checksumd` merupakan program Golang yang *stripped* (informasi simbol dihapus), seringkali string konstan (seperti flag atau pesan sukses) masih tersimpan dalam format *plain text* di dalam binary. Dilakukan pencarian string dengan filter format flag `FGTE`.

```bash
strings checksumd | grep "FGTE{"

```

**Output Terminal:**

```text
 WanZKey  ～  ~../Reverse/Checksumd 󱎫 0s 󱑎 13.13
 󰋑  ▶  strings checksumd | grep "FGTE{"
FGTE{c0de_y0ur_ch3cksum_succ3ssfully!}

```

Flag ditemukan secara langsung (hardcoded) di dalam binary tanpa perlu melakukan dekompilasi mendalam atau memperbaiki `data.bin`.

## Solver Script

```bash
strings checksumd | grep "FGTE"

```

**Output Solver:**

```text
FGTE{c0de_y0ur_ch3cksum_succ3ssfully!}

```

## Flag

```
FGTE{c0de_y0ur_ch3cksum_succ3ssfully!}

```
