# WriteUp - String_Theory

## Overview

**Title:** String_Theory
**Category:** N/A
**Points:** N/A
**Author:** N/A
**Description:** Kami menemukan file binary aneh yang tertinggal di server. Sepertinya program ini rusak dan tidak bisa dijalankan. Namun, intelijen kami yakin ada password rahasia yang tertulis di dalam kodenya ("hardcoded"). Jangan mencoba menjalankannya, cukup bedah isinya. Tugas: Temukan string yang bisa dibaca di dalam file ini.
**URL:** N/A

## Attachment Information

**File:** `chall_6925b1fb7f5e4_03e904c8.bin` (di-ubah namanya menjadi `chall.bin`)
**Directory Structure:**

```text
./
└── chall.bin

```

## Step-by-Step Solution

Langkah pertama adalah melakukan investigasi awal terhadap file attachment menggunakan `file` dan `exiftool` untuk mengetahui struktur dan metadatanya. Berikut adalah seluruh output terminal dari proses tersebut:

```bash
 󰋑  ▶  file chall.bin
chall.bin: ELF, unknown class 142

 󰋑  ▶  exiftool chall.bin
ExifTool Version Number         : 13.44
File Name                       : chall.bin
Directory                       : .
File Size                       : 2.1 MB
File Modification Date/Time     : 2025:11:25 20:41:15+07:00
File Access Date/Time           : 2026:02:21 12:10:23+07:00
File Inode Change Date/Time     : 2026:02:21 12:10:16+07:00
File Permissions                : -rw-r--r--
File Type                       : ELF executable
File Type Extension             :
MIME Type                       : application/octet-stream
CPU Architecture                : Unknown (142)
CPU Byte Order                  : Unknown (198)
Object File Type                : Unknown (59292)
CPU Type                        : Unknown (47235)

```

Berdasarkan analisa output di atas, file `chall.bin` terdeteksi sebagai file ELF executable, namun memiliki *class*, *byte order*, dan arsitektur CPU yang tidak diketahui (rusak/corrupted). Hal ini sejalan dengan deskripsi soal yang menyatakan bahwa program rusak dan tidak bisa dijalankan.

Karena instruksinya adalah membedah isi file untuk mencari password yang *hardcoded*, penyelesaian dilakukan dengan mengekstrak teks (human-readable string) dari dalam file binary. Alat bantu `strings` sangat cocok digunakan di sini, dan outputnya disaring menggunakan `grep` untuk langsung mencari kata kunci flag.

## Solver Script & Terminal Output

Proses ekstraksi string sekaligus pencarian flag dieksekusi melalui perintah terminal berikut:

```bash
 󰋑  ▶  strings chall.bin | grep "Zero"
 -- CONFIDENTIAL STRING START -- ZeroSec{grep_strings_is_your_friend} -- CONFIDENTIAL STRING END --

```

## Flag

`ZeroSec{grep_strings_is_your_friend}`
