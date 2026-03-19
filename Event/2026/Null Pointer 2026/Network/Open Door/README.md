# WriteUp - Open Door

## Overview

* **Judul:** Open Door
* **Katagori:** Network
* **Poin:** 100
* **Deskripsi:** Protocol Analysis / Cleartext Credentials
* **Author:** -

---

## Attachment

Informasi file yang diberikan:

```bash
 WanZKey  ～  ~../Network/Open Door 󱎫 0s 󱑎 22.00
 󰋑  ▶  file noisy_challenge.pcap
enoisy_challenge.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)

 WanZKey  ～  ~../Network/Open Door 󱎫 0s 󱑎 22.00
 󰋑  ▶  exiftool noisy_challenge.pcap
wExifTool Version Number         : 13.50
File Name                       : noisy_challenge.pcap
Directory                       : .
File Size                       : 2.7 kB
File Modification Date/Time     : 2026:03:14 14:25:22+07:00
File Access Date/Time           : 2026:03:15 22:00:30+07:00
File Inode Change Date/Time     : 2026:03:15 22:00:28+07:00
File Permissions                : -rw-r--r--
File Type                       : PCAP
File Type Extension             : pcap
MIME Type                       : application/vnd.tcpdump.pcap
PCAP Version                    : PCAP 2.4
Byte Order                      : Little-endian (Intel, II)
Link Type                       : BSD Loopback
Time Stamp            2026:03:12 23:49:09.024012+07:00

```

Struktur direktori:

```
.
└── noisy_challenge.pcap

```

---

## Proses Penyelesaian secara step by step

1. Analisa traffic dilakukan menggunakan Wireshark pada file `noisy_challenge.pcap`.
2. Ditemukan beberapa jenis protokol dalam capture tersebut, termasuk ARP, DNS, SSL/TLS (port 443), dan TELNET (port 23).
3. Berdasarkan deskripsi "Cleartext Credentials", fokus dialihkan ke protokol **TELNET** karena Telnet tidak mengenkripsi data yang dikirimkan melalui jaringan.
4. Traffic Telnet terjadi antara host `192.168.1.15` dan `10.0.0.5`.
5. Dilakukan rekonstruksi TCP stream menggunakan `tshark` dengan perintah:
```bash
tshark -r noisy_challenge.pcap -z follow,tcp,ascii,1

```


6. Hasil rekonstruksi menunjukkan adanya interaksi login di mana user memasukkan username `operator` dan password `GHOST_IN_THE_SHELL_99`.
7. Karena Telnet mengirimkan karakter satu per satu, penggunaan script otomasi membantu memastikan seluruh karakter dalam password terbaca dengan benar.
8. Password yang ditemukan `GHOST_IN_THE_SHELL_99` merupakan isi dari flag.

---

## Script Solver

```python
from scapy.all import rdpcap, TCP, Raw

def solve():
    # Membaca file pcap
    packets = rdpcap("noisy_challenge.pcap")
    telnet_data = b""
    
    # Filter traffic ke/dari port 23 (Telnet)
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            # Port 23 adalah port standar untuk Telnet
            if packet[TCP].dport == 23 or packet[TCP].sport == 23:
                telnet_data += packet[Raw].load
                
    print("[*] Reconstructed Telnet Session:")
    # Membersihkan opsi Telnet (byte kontrol) dan menyusun karakter yang dapat dibaca
    cleaned_data = "".join([chr(b) for b in telnet_data if 32 <= b <= 126 or b == 10 or b == 13])
    print(cleaned_data)

if __name__ == "__main__":
    solve()

```

---

## Terminal Output

```bash
 WanZKey  ～  ~../Network/Open Door 󱎫 0s 󱑎 22.04
 󰋑  ▶  tshark -r noisy_challenge.pcap -z follow,tcp,ascii,1
===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 1
Node 0: 192.168.1.15:49152
Node 1: 10.0.0.5:23
        6
User:
10
operator

        6
Pass:
===================================================================

 WanZKey  ～  ~../Network/Open Door 󱎫 0s 󱑎 22.04
 󰋑  ▶  ./solver.py
[*] Reconstructed Telnet Session:
User: operator
Pass: GHOST_IN_THE_SHELL_99

 WanZKey  ～  ~../Network/Open Door 󱎫 0s 󱑎 22.05
 󰋑  ▶  cat flag.txt
STURSEC{GHOST_IN_THE_SHELL_99}

```

---

## Flag

```
STURSEC{GHOST_IN_THE_SHELL_99}

```
