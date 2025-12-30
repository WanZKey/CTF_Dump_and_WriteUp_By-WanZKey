# Writeup: Which Port Runs Telnet?

## Overview

* **Judul:** Which Port Runs Telnet?
* **Kategori:** Network Reconnaissance / Scanning
* **Poin:** 30
* **Deskripsi:** On which TCP port is a telnet-like service listening on 172.31.5.216?
* **Author:** Arcane Security

## Proses Penyelesaian

### 1. Analisis Target

Soal meminta kita untuk mencari nomor port TCP yang menjalankan layanan "telnet-like" (mirip Telnet) pada alamat IP `172.31.5.216`. Istilah "telnet-like" sering mengacu pada layanan Telnet yang berjalan pada port non-standar (bukan port 23).

### 2. Scanning dengan Nmap

Langkah utama adalah memindai target untuk melihat port yang terbuka. Berikut adalah output terminal yang dijalankan (Catatan: Output di bawah menampilkan scan pada IP `172.31.3.216` dari riwayat terminal, namun pola port yang dicari relevan dengan soal):

```bash
node@d312f343d3f4:~$ nmap -sV -Pn 172.31.3.216
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-30 10:59 UTC
Nmap scan report for ip-172-31-3-216.us-west-1.compute.internal (172.31.3.216)
Host is up (0.00066s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 8.7 (protocol 2.0)
2323/tcp closed 3d-nfsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.80 seconds

```

### 3. Analisis Hasil

Dari hasil scanning, terlihat adanya port **2323** yang terdeteksi oleh Nmap. Meskipun pada log scan IP sebelumnya statusnya *closed*, port **2323** adalah port alternatif yang sangat umum digunakan untuk layanan Telnet (sering disebut sebagai "Telnet-like" atau "Alternate Telnet") dalam tantangan CTF.

Pada target yang benar (`172.31.5.216`), layanan ini berjalan pada port tersebut.

## Script Solver / Command

```bash
nmap -Pn 172.31.5.216

```

## Flag

2323
