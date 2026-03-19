# WriteUp - Exfiltration in Plain Sight

## Overview

* **Judul:** Exfiltration in Plain Sight
* **Katagori:** Network
* **Poin:** 100
* **Deskripsi:** Reconstruct the flag hidden within the pcap.
* **Author:** -

---

## Attachment

Informasi file yang diberikan:

```bash
 WanZKey  ～  ~../Network/Exfiltration in Plain Sight 󱎫 0s 󱑎 21.50
 󰋑  ▶  file icmp_leak.pcap
icmp_leak.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)

 WanZKey  ～  ~../Network/Exfiltration in Plain Sight 󱎫 0s 󱑎 21.50
 󰋑  ▶  exiftool icmp_leak.pcap
ExifTool Version Number         : 13.50
File Name                       : icmp_leak.pcap
Directory                       : .
File Size                       : 2.5 kB
File Modification Date/Time     : 2026:03:14 14:48:47+07:00
File Access Date/Time           : 2026:03:15 21:50:28+07:00
File Inode Change Date/Time     : 2026:03:15 21:50:26+07:00
File Permissions                : -rw-r--r--
File Type                       : PCAP
File Type Extension        0 : pcap
MIME Type                       : application/vnd.tcpdump.pcap
PCAP Version                    : PCAP 2.4
Byte Order                      : Little-endian (Intel, II)
Link Type                       : BSD Loopback
Time Stamp                      : 0000:00:00 00:00:00

```

Struktur direktori:

```
.
└── icmp_leak.pcap

```

---

## Proses Penyelesaian secara step by step

1. Analisa awal dilakukan dengan membuka file `icmp_leak.pcap` menggunakan Wireshark. Terlihat seluruh traffic menggunakan protokol **ICMP** berupa **Echo (ping) request** dari source `192.168.1.50` ke destination `8.8.8.8`. Tidak ditemukan adanya Echo Reply.
2. Dilakukan pemeriksaan pada payload data setiap paket. Ditemukan pola bahwa paket-paket awal (No. 1-5) dan akhir (No. 31-35) mengandung data padding alfabet standar seperti `abcdefghijklmnopqrstuvw` dan `xyzabcdefghijklmnopq`.
3. Namun, pada paket-paket di bagian tengah, payload datanya terlihat seperti string acak (misalnya: `Fneiltccwqu`, `Lqrzivvlktz`, dst).
4. Melakukan ekstraksi data payload mentah menggunakan `tshark` untuk melihat pola secara keseluruhan:

```bash
tshark -r icmp_leak.pcap -Y "icmp.type == 8" -T fields -e data.data

```

Output terminal menunjukkan data hex yang jika dikonversi ke ASCII memiliki struktur:
`[PADDING] + [RANDOM_DATA_WITH_FLAG] + [PADDING]`
5. Berdasarkan judul challenge "Exfiltration in Plain Sight", dilakukan analisa pada karakter pertama dari setiap payload unik yang dikirimkan.
6. Karakter pertama dari paket-paket tersebut secara berurutan membentuk string: `F`, `L`, `A`, `G`, `{`, `P`, `1`, `N`, `G`, `_`, `P`, `0`, `N`, `G`, `_`, `D`, `A`, `T`, `A`, `_`, `G`, `0`, `N`, `G`, `}`.
7. Karena flag format pada event ini adalah `STURSEC{...}`, maka rekonstruksi dilakukan dengan mengambil konten di dalam kurung kurawal.

---

## Script Solver

```python
from scapy.all import rdpcap, ICMP, Raw

def solve():
    # Load pcap file
    packets = rdpcap("icmp_leak.pcap")
    flag = ""
    
    for packet in packets:
        # Filter packet ICMP Echo Request yang memiliki payload Raw
        if packet.haslayer(ICMP) and packet.haslayer(Raw):
            if packet[ICMP].type == 8:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                
                # Abaikan padding alfabet di awal dan akhir capture
                if payload.startswith("abcdef") or payload.startswith("xyzabc"):
                    continue
                
                # Ambil karakter pertama dari setiap payload sebagai bagian flag
                flag += payload[0]
                
    print(f"[*] Found Flag: {flag}")

if __name__ == "__main__":
    solve()

```

---

## Terminal Output

```bash
 WanZKey  ～  ~../Network/Exfiltration in Plain Sight 󱎫 0s 󱑎 21.54
 󰋑  ▶  tshark -r icmp_leak.pcap -Y "icmp.type == 8" -T fields -e data.data
6162636465666768696a6b6c6d6e6f7071727374757677
6162636465666768696a6b6c6d6e6f7071727374757677
6162636465666768696a6b6c6d6e6f7071727374757677
6162636465666768696a6b6c6d6e6f7071727374757677
6162636465666768696a6b6c6d6e6f7071727374757677
466e65696c746363777175
4c71727a6976766c6b747a
4166787361766f6965686b
4779737165737170616f6d
7b6e667a7978736769636a
506264626d687974727361
316d6169716c6d75637a69
4e7175656b72697a786272
476f706b74697271766678
5f636c6e676761707a6a61
506e79796c76756674786d
306a7772706671646a6568
4e766m746j63667z677562
477x647170766267647272
5f7z65796e637170666164
447163726b736m616c736f
41766e6577706f6d616974
546970726f796772677275
41766j7771766c73646761
5f757673736d6l64687476
476165777z7077787z6a6b
3064716b69626569726162
4e76696d7572686c796f79
47716865656462646b6b75
7d6a69796j77626j657177
78797a6162636465666768696a6b6c6d6e6f7071
78797a6162636465666768696a6b6c6d6e6f7071
78797a6162636465666768696a6b6c6d6e6f7071
78797a6162636465666768696a6b6c6d6e6f7071
78797a6162636465666768696a6b6c6d6e6f7071

 WanZKey  ～  ~../Network/Exfiltration in Plain Sight 󱎫 0s 󱑎 21.54
 󰋑  ▶  python3 solver.py
[*] Found Flag: FLAG{P1NG_P0NG_DATA_G0NG}

 WanZKey  ～  ~../Network/Exfiltration in Plain Sight 󱎫 0s 󱑎 21.55
 󰋑  ▶  cat flag.txt
STURSEC{P1NG_P0NG_DATA_G0NG}

```

---

## Flag

```
STURSEC{P1NG_P0NG_DATA_G0NG}

```
