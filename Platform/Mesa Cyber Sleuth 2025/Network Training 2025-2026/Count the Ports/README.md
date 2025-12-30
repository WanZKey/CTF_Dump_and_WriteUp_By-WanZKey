# Writeup: Count the Ports

## Overview

* **Judul:** Count the Ports
* **Kategori:** Network Reconnaissance / Scanning
* **Poin:** 70
* **Deskripsi:** How many ports are shown at the ip address 172.31.7.221?
* **Author:** Arcane Security

## Proses Penyelesaian

### 1. Analisis Target

Tantangan ini meminta kita untuk menghitung jumlah port yang **ditampilkan** (shown) oleh hasil scanning pada alamat IP `172.31.7.221`.

### 2. Scanning dengan Nmap

Perintah yang digunakan adalah `nmap` dengan flag `-sVC` (gabungan `-sV` untuk versi dan `-sC` untuk script default) serta `-Pn` untuk melewati host discovery.

Berikut adalah output terminal dari proses scanning:

```bash
node@d312f343d3f4:~$ nmap -sVC 172.31.7.221 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-30 11:07 UTC
Nmap scan report for ip-172-31-7-221.us-west-1.compute.internal (172.31.7.221)
Host is up (0.00055s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE  SERVICE VERSION
21/tcp    closed ftp
80/tcp    closed http
3306/tcp  closed mysql

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.69 seconds
node@d312f343d3f4:~$ 

```

### 3. Analisis Hasil

Dari output di atas, Nmap memberitahukan bahwa ada 997 port yang tidak ditampilkan (*Not shown: 997 filtered tcp ports*). Port yang ditampilkan secara eksplisit dalam daftar adalah:

1. **21/tcp** (closed)
2. **80/tcp** (closed)
3. **3306/tcp** (closed)

Total ada **3** port yang ditampilkan dalam hasil scan.

## Script Solver / Command

```bash
nmap -sVC 172.31.7.221 -Pn

```

## Flag

3
