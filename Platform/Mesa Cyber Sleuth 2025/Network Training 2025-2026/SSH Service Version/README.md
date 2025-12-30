# Writeup: SSH Service Version

## Overview

* **Judul:** SSH service version
* **Kategori:** Network Reconnaissance / Scanning
* **Poin:** 20
* **Deskripsi:** What is the SSH server banner/version string on 172.31.3.216? Copy exactly as seen
* **Author:** Arcane Security

## Informasi Attachment & Lingkungan

Soal ini dikerjakan di dalam "Interactive Terminal by Arcane Security". Berikut adalah struktur direktori pada environment tersebut:

```bash
node@d312f343d3f4:~$ ls
INSTRUCTOR_NOTES.txt  level-2  level-4  level-6  level-8
level-1               level-3  level-5  level-7  level-9

```

## Proses Penyelesaian

### 1. Deteksi Versi dengan Nmap

Langkah pertama adalah melakukan scanning pada target `172.31.3.216` menggunakan Nmap dengan flag `-sV` untuk mendeteksi versi layanan yang berjalan.

Berikut adalah perintah dan output terminalnya:

```bash
node@d312f343d3f4:~$ nmap -sV -Pn 172.31.3.216
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-30 10:32 UTC
Nmap scan report for ip-172-31-3-216.us-west-1.compute.internal (172.31.3.216)
Host is up (0.00050s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 8.7 (protocol 2.0)
2323/tcp closed 3d-nfsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.50 seconds

```

Hasil Nmap menunjukkan `OpenSSH 8.7 (protocol 2.0)`.

### 2. Validasi Raw Banner

Untuk memastikan string yang diambil benar-benar presisi ("exactly as seen"), saya menggunakan teknik *Bash TCP connection* untuk membaca banner mentah langsung dari port 22, karena perintah `nc` tidak tersedia di terminal.

```bash
node@d312f343d3f4:~$ head -n 1 < /dev/tcp/172.31.3.216/22
SSH-2.0-OpenSSH_8.7

```

Dari raw banner `SSH-2.0-OpenSSH_8.7`, bagian identitas software server yang spesifik adalah `OpenSSH_8.7`.

## Script Solver / Command

```bash
head -n 1 < /dev/tcp/172.31.3.216/22

```

## Flag

OpenSSH_8.7
