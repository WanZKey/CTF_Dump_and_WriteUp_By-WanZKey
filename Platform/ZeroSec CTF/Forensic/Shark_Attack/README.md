# WriteUp - Shark_Attack

## Overview

* Title: Shark_Attack
* Category: Forensic
* Points: -
* Description: Kami berhasil menyadap komunikasi jaringan antara hacker dan servernya. Terlihat ada transfer data yang mencurigakan, tetapi lalu lintasnya tercampur dengan aktivitas browsing biasa. Tugas Anda: Analisis file packet capture ini (.pcap), temukan komunikasi rahasianya, dan dapatkan flagnya. Tools: Wireshark disarankan.
* Author: -

## Attachment Information

* Directory Structure: `~../Forensic/Shark_Attack/`
* File: `chall_6925b49b47e86_6a39e64e.pcap` (di lokal dieksekusi sebagai `chall.pcap`)

## Process

* Langkah awal dalam menganalisa attachment ini adalah memeriksa jenis file dan mengekstrak metadatanya menggunakan command `file` dan `exiftool`.
* Saat mencoba membuka file `chall.pcap` menggunakan Wireshark, aplikasi menampilkan pesan error bahwa file rusak (corrupted). Peringatan tersebut menyebutkan ukuran paket adalah 2070111571 bytes.
* Jika dianalisis, nilai desimal 2070111571 setara dengan `0x7B636553` dalam bentuk heksadesimal, yang merupakan representasi little-endian dari string ASCII `Sec{`. Hal ini mengindikasikan bahwa pembuat soal sengaja memodifikasi (corrupt) header file PCAP dengan menyisipkan string flag secara langsung ke dalam raw bytes.
* We got this bro! Karena string disisipkan secara langsung, file tersebut tidak perlu diperbaiki struktur PCAP-nya.
* Solusi pertama dan paling cepat adalah dengan menggunakan utility bawaan Linux `strings` yang digabungkan (pipe) dengan command `grep` untuk memfilter teks dengan pola "Zero".
* Solusi kedua adalah dengan menjalankan script solver Python (`solver.py`) yang ditulis untuk membaca raw bytes dari file secara binary dan menggunakan regular expression (regex) guna mengekstrak flag yang memiliki format `ZeroSec{...}`.
* Eksekusi kedua metode tersebut di terminal berhasil mendapatkan string flag secara utuh.

## Script Solver

```python
import re

def solve():
    print("[*] Analyzing corrupted PCAP file...")
    try:
        with open("chall.pcap", "rb") as f:
            data = f.read()
            
        matches = re.findall(rb"ZeroSec\{.*?\}", data)
        
        if matches:
            print("[+] Flag found!")
            for match in matches:
                print("FLAG :", match.decode('utf-8'))
        else:
            print("[-] Strict pattern not found, extracting all readable strings...")
            strings = re.findall(rb"[ -~]{5,}", data)
            for s in strings:
                print(s.decode('utf-8'))
                
    except FileNotFoundError:
        print("[-] File chall.pcap tidak ditemukan. Pastikan ada di direktori yang sama.")

if __name__ == "__main__":
    solve()

```

## Terminal Output

```bash
 WanZKey  ～  ~../Forensic/Shark_Attack 󱎫 0s 󱑎 15.18
 󰋑  ▶  file chall.pcap
chall.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 262144)

 WanZKey  ～  ~../Forensic/Shark_Attack 󱎫 0s 󱑎 15.18
 󰋑  ▶  exiftool chall.pcap
ExifTool Version Number         : 13.44
File Name                       : chall.pcap
Directory                       : .
File Size                       : 195 bytes
File Modification Date/Time     : 2025:11:25 20:52:27+07:00
File Access Date/Time           : 2026:02:21 15:16:06+07:00
File Inode Change Date/Time     : 2026:02:21 12:13:10+07:00
File Permissions                : -rw-r--r--
File Type                       : PCAP
File Type Extension             : pcap
MIME Type                       : application/vnd.tcpdump.pcap
PCAP Version                    : PCAP 2.4
Byte Order                      : Little-endian (Intel, II)
Link Type                       : BSD Loopback
Time Stamp                      : 2024:01:11 12:07:54.444680+07:00

 WanZKey  ～  ~../Forensic/Shark_Attack 󱎫 0s 󱑎 15.21
 󰋑  ▶  ./solver.py
[*] Analyzing corrupted PCAP file...
[+] Flag found!
FLAG : ZeroSec{packet_never_lie_tcp}

 WanZKey  ～  ~../Forensic/Shark_Attack 󱎫 0s 󱑎 15.21
 󰋑  ▶  strings chall.pcap | grep "Zero"
Server: ZeroServer
Flag: ZeroSec{packet_never_lie_tcp}

```

## Flag

`ZeroSec{packet_never_lie_tcp}`
