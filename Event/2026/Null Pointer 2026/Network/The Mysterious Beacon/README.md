# WriteUp - The Mysterious Beacon

## Overview

* **Judul:** The Mysterious Beacon
* **Katagori:** Network
* **Poin:** 150
* **Deskripsi:** Identify the port the "beacon" is coming from and capture the flag.
* **Author:** -

---

## Attachment

Informasi file yang diberikan:

```bash
 WanZKey  ～  ~../Network/The Mysterious Beacon 󱎫 0s 󱑎 22.16
 󰋑  ▶  file beacon_challenge.pcap
beacon_challenge.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Ethernet, capture length 65535)

 WanZKey  ～  ~../Network/The Mysterious Beacon 󱎫 0s 󱑎 22.16
 󰋑  ▶  exiftool beacon_challenge.pcap
ExifTool Version Number         : 13.50
File Name                       : beacon_challenge.pcap
Directory                       : .
File Size      0 0 0 0 0 0 0 0 0: 13 kB
File Modification Date/Time     : 2026:03:14 14:47:12+07:00
File Access Date/Time           : 2026:03:15 20:42:57+07:00
File Inode Change Date/Time     : 2026:03:15 20:42:32+07:00
File Permissions                : -rw-r--r--
File Type                       : PCAP
File Type Extension        0 : pcap
MIME Type                       : application/vnd.tcpdump.pcap
PCAP Version                    : PCAP 2.4
Byte Order                      : Little-endian (Intel, II)
Link Type                       : BSD Loopback
Time Stamp      0 0 0 0 0 0 0 0 : 0000:00:00 00:00:00

```

Struktur direktori:

```
.
└── beacon_challenge.pcap

```

---

## Proses Penyelesaian secara step by step

1. Analisa file `beacon_challenge.pcap` menggunakan Wireshark menunjukkan adanya banjir traffic mDNS (port 5353) dari source `192.168.1.5` yang ditandai sebagai **Malformed Packet**.
2. Paket-paket mDNS tersebut memiliki anomali pada Transaction ID `0x7374` (string "st") dan opcode `12` yang tidak standar.
3. Selain traffic mDNS, ditemukan sebuah paket UDP tunggal pada **Packet 136** yang dikirimkan dari `192.168.1.10` ke alamat broadcast `192.168.1.255` melalui **port 5555**.
4. Berdasarkan instruksi untuk mencari asal "beacon", dilakukan ekstraksi payload pada port 5555 karena polanya berbeda dari noise mDNS di sekitarnya.
5. Menggunakan script Python dengan library `scapy`, dilakukan pembacaan payload pada port 5555 dan juga inspeksi pada Transaction ID mDNS.
6. Hasil eksekusi menunjukkan port 5555 mengirimkan payload string `FLAG{B3ACON_L0CAT3D_SUCC3SS}` secara konsisten.
7. Flag kemudian disesuaikan dengan format prefix `STURSEC{...}`.

---

## Script Solver

```python
from scapy.all import rdpcap, UDP, DNS

def solve():
    # Membaca file pcap
    packets = rdpcap("beacon_challenge.pcap")
    
    print("[*] Checking Port 5555...")
    for packet in packets:
        # Filter paket UDP pada port 5555
        if packet.haslayer(UDP) and (packet[UDP].dport == 5555 or packet[UDP].sport == 5555):
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                print(f"[+] Data from Port 5555: {payload}")

    print("\n[*] Checking MDNS (Port 5353) Transaction IDs...")
    mdns_chars = []
    seen_ids = set()
    
    for packet in packets:
        if packet.haslayer(UDP) and packet[UDP].dport == 5353:
            # MDNS header dimulai dengan Transaction ID (2 bytes)
            if packet.haslayer(DNS):
                tx_id = packet[DNS].id
                if tx_id not in seen_ids:
                    seen_ids.add(tx_id)
                    # Konversi 16-bit ID menjadi 2 karakter ASCII
                    char1 = chr((tx_id >> 8) & 0xff)
                    char2 = chr(tx_id & 0xff)
                    mdns_chars.append(char1 + char2)
    
    print(f"[+] Reconstructed from MDNS: {''.join(mdns_chars)}")

if __name__ == "__main__":
    solve()

```

---

## Terminal Output

```bash
 WanZKey  ～  ~../Network/The Mysterious Beacon 󱎫 0s 󱑎 22.18
 󰋑  ▶  ./solver.py
[*] Checking Port 5555...
[+] Data from Port 5555: b'FLAG{B3ACON_L0CAT3D_SUCC3SS}'
[+] Data from Port 5555: b'FLAG{B3ACON_L0CAT3D_SUCC3SS}'

[*] Checking MDNS (Port 5353) Transaction IDs...
[+] Reconstructed from MDNS: st

 WanZKey  ～  ~../Network/The Mysterious Beacon 󱎫 0s 󱑎 22.19
 󰋑  ▶  cat flag.txt
STURSEC{B3ACON_L0CAT3D_SUCC3SS}

```

---

## Flag

```
STURSEC{B3ACON_L0CAT3D_SUCC3SS}

```
