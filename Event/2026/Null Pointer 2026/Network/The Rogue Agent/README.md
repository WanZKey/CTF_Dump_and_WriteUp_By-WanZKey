# WriteUp - The Rogue Agent

## Overview

* **Judul:** The Rogue Agent
* **Katagori:** Network
* **Poin:** 150
* **Deskripsi:** A "live" environment where a client (bot) is trying to send a secret to a server. However, the server’s ARP table is unprotected.
* **Author:** -

---

## Attachment

Informasi file yang diberikan:

```bash
 WanZKey  ～  ~../Network/The Rogue Agent 󱎫 0s 󱑎 22.07
 󰋑  ▶  file mitm_chaos.pcap
mitm_chaos.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)

 WanZKey  ～  ~../Network/The Rogue Agent 󱎫 0s 󱑎 22.07
 󰋑  ▶  exiftool mitm_chaos.pcap
ExifTool Version Number         : 13.50
File Name                       : mitm_chaos.pcap
Directory                       : .
File Size                       : 8.4 kB
File Modification Date/Time     : 2026:03:14 14:50:38+07:00
File Access Date/Time           : 2026:03:15 22:07:09+07:00
File Inode Change Date/Time     : 2026:03:15 22:07:07+07:00
File Permissions                : -rw-r--r--
File Type                       : PCAP
File Type Extension             : pcap
MIME Type                       : application/vnd.tcpdump.pcap
PCAP Version                    : PCAP 2.4
Byte Order                      : Little-endian (Intel, II)
Link Type                       : BSD Loopback
Time Stamp                      : 0000:00:00 00:00:00

```

Struktur direktori:

```
.
└── mitm_chaos.pcap

```

---

## Proses Penyelesaian secara step by step

1. Analisa traffic pada `mitm_chaos.pcap` menggunakan Wireshark menunjukkan adanya aktivitas **ARP Poisoning**. Hal ini teridentifikasi pada paket 64, 66, 69, dan 70, di mana dua alamat IP berbeda (`192.168.1.10` dan `192.168.1.50`) diklaim memiliki MAC address yang sama, yaitu `66:66:66:66:66:66`.
2. Kondisi ini menandakan adanya serangan **Man-in-the-Middle (MitM)** di mana penyerang ("Rogue Agent") mencegat traffic antara client dan server.
3. Melalui observasi pada packet list, ditemukan sebuah HTTP request mencurigakan pada **Packet 91** dengan metode **POST** ke endpoint `/api/login`.
4. Dilakukan pemeriksaan mendalam pada Frame 91 menggunakan `tshark`. Ditemukan bahwa source IP `192.168.1.50` mengirimkan data ke destination `192.168.1.10`, namun paket Ethernet diarahkan ke MAC address penyerang (`66:66:66:66:66:66`).
5. Karena pcap ini dipenuhi dengan traffic SSDP ("Chaos"), dibuat sebuah script Python menggunakan library `scapy` untuk memfilter dan mengekstrak isi payload dari setiap paket yang mengandung metode POST secara otomatis.
6. Berdasarkan hasil eksekusi script, ditemukan body dari request POST tersebut yang berisi parameter `secret` dengan nilai flag.

---

## Script Solver

```python
#!/usr/bin/env python3
from scapy.all import rdpcap, TCP, Raw

def solve():
    # Membaca file pcap mitm_chaos
    packets = rdpcap("mitm_chaos.pcap")
    print("[*] Searching for the Rogue Agent's secret...")

    for packet in packets:
        # Mencari paket yang memiliki layer Raw (payload data)
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                # Filter hanya paket dengan HTTP request method POST
                if "POST" in payload:
                    print("-" * 40)
                    print("[+] Found POST Request!")
                    print(payload)
                    print("-" * 40)
            except:
                continue

if __name__ == "__main__":
    solve()

```

---

## Terminal Output

```bash
 WanZKey  ～  ~../Network/The Rogue Agent 󱎫 0s 󱑎 22.08
 󰋑  ▶  tshark -r mitm_chaos.pcap -Y "http.request.method == POST" -V
Frame 91: Packet, 115 bytes on wire (920 bits), 115 bytes captured (920 bits)
    ...
Ethernet II, Src: CIMSYS_33:44:55 (00:11:22:33:44:55), Dst: 66:66:66:66:66:66 (66:66:66:66:66:66)
    ...
Internet Protocol Version 4, Src: 192.168.1.50, Dst: 192.168.1.10
    ...
Transmission Control Protocol, Src Port: 54321, Dst Port: 80, Seq: 1, Ack: 1, Len: 61
    ...
Hypertext Transfer Protocol
    POST /api/login HTTP/1.1\r\n
        Request Method: POST
        Request URI: /api/login
        Request Version: HTTP/1.1

 WanZKey  ～  ~../Network/The Rogue Agent 󱎫 0s 󱑎 22.09
 󰋑  ▶  ./check-post-req.py
[*] Searching for the Rogue Agent's secret...
----------------------------------------
[+] Found POST Request!
POST /api/login HTTP/1.1

secret=FLAG{D3T3CT_TH3_MAC_SH1FT}
----------------------------------------

 WanZKey  ～  ~../Network/The Rogue Agent 󱎫 0s 󱑎 22.10
 󰋑  ▶  cat flag.txt
STURSEC{D3T3CT_TH3_MAC_SH1FT}

```

---

## Flag

```
STURSEC{D3T3CT_TH3_MAC_SH1FT}

```
