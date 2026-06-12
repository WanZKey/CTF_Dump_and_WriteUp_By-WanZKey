# WriteUp - Pinging

## Overview

* **Name:** Pinging
* **Category:** Forensics
* **Point:** 500
* **Author:** Aseng
* **Desc:** My buddy sends me something inside that ICMP Protocol data, can you parse and help me figure out what's the message?
* **URL:** Local Attachment (snippet.pcap)

## Reconnaissance

```text
$ file snippet.pcap
snippet.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)

$ exiftool snippet.pcap
ExifTool Version Number         : 13.50
File Name                       : snippet.pcap
Directory                       : .
File Size                       : 6.0 kB
File Modification Date/Time     : 2026:06:11 11:32:32+07:00
File Access Date/Time           : 2026:06:11 17:59:48+07:00
File Inode Change Date/Time     : 2026:06:11 17:09:00+07:00
File Permissions                : -rw-r--r--
File Type                       : PCAP
File Type Extension             : pcap
MIME Type                       : application/vnd.tcpdump.pcap
PCAP Version                    : PCAP 2.4
Byte Order                      : Little-endian (Intel, II)
Link Type                       : BSD Loopback
Time Stamp                      : 2024:05:31 23:08:37.250000+07:00

```

## Step by Step Solution

### 1. Analisis Hierarki Protokol Jaringan

**Recon Protocol:** Menggunakan utilitas `tshark` via *command line* untuk melihat distribusi hierarki protokol pada *file capture*. Analisis mengonfirmasi bahwa 100% *traffic* di dalam file pcap tersebut berwujud protokol ICMP.

```bash
$ tshark -r snippet.pcap -q -z io,phs

===================================================================
Protocol Hierarchy Statistics
Filter:

frame                                    frames:102 bytes:4386
  eth                                    frames:102 bytes:4386
    ip                                   frames:102 bytes:4386
      icmp                               frames:102 bytes:4386
===================================================================

```

### 2. Penarikan Data Terselubung

**Ekstrak Data ICMP:** Mengetahui bahwa informasi disembunyikan di dalam *payload* ICMP, *filter* spesifik diterapkan pada `tshark` untuk mengisolasi paket ICMP dan mengekstrak *field* data secara langsung. Output yang dihasilkan berupa deretan karakter heksadesimal tunggal per baris.

```bash
$ tshark -r snippet.pcap -Y "icmp" -T fields -e data
65
63
68
6f
...

```

### 3. Konversi dan Dekode Teks

**Ekstrak Data ICMP & Decode:** Deretan nilai heksadesimal tersebut kemudian disatukan menggunakan perintah `tr -d '\n'` untuk menghilangkan garis baru (*newline*), lalu di-*reverse* menjadi *string* ASCII menggunakan `xxd -r -p`. Hasil dekode ini mengungkap sebuah perintah Linux untuk melakukan dekode *string* Base64 yang akan menghasilkan *flag*.

```bash
$ tshark -r snippet.pcap -Y "icmp" -T fields -e data | tr -d '\n' | xxd -r -p
echo "TEtTe2JhYnlfSUNNUF9idXRfbm90X2V4ZmlsX21vcmVsaWtlX3RyYW5zZmVyX2ZsNGc/P30=" | base64 -d > flag.txt

```

Data Base64 `TEtTe2JhYnlfSUNNUF9idXRfbm90X2V4ZmlsX21vcmVsaWtlX3RyYW5zZmVyX2ZsNGc/P30=` kemudian didekode untuk mendapatkan *flag* akhir secara utuh.

## Script Solver

```python
#!/usr/bin/env python3
import subprocess
import binascii
import base64
import re

def solve():
    # Menjalankan tshark untuk mengekstrak raw hex data dari paket ICMP
    tshark_cmd = ['tshark', '-r', 'snippet.pcap', '-Y', 'icmp', '-T', 'fields', '-e', 'data']
    result = subprocess.run(tshark_cmd, capture_output=True, text=True)

    # Menghilangkan newline dari output tshark agar menyatu menjadi satu string hex
    hex_data = result.stdout.replace('\n', '').strip()

    if not hex_data:
        print("[!] Tidak ada data ICMP yang ditemukan.")
        return

    # Mengubah nilai hex menjadi string ASCII
    ascii_text = binascii.unhexlify(hex_data).decode('utf-8')

    # Mencari pola Base64 di dalam command echo menggunakan Regular Expression
    b64_match = re.search(r'echo "(.*?)"', ascii_text)
    
    if b64_match:
        b64_string = b64_match.group(1)
        # Mendekode string Base64 untuk mendapatkan flag
        flag = base64.b64decode(b64_string).decode('utf-8')
        print(f"Flag : {flag}")
    else:
        print("[!] Teks Base64 tidak ditemukan di dalam payload ICMP.")

if __name__ == '__main__':
    solve()

```

## Output Terminal Solver

```bash
$ ./solver.py
Flag : LKS{baby_ICMP_but_not_exfil_morelike_transfer_fl4g??}

```

## Flag

`LKS{baby_ICMP_but_not_exfil_morelike_transfer_fl4g??}`
