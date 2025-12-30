# Writeup: What SSH Port?

## Overview

* **Judul:** What SSH port?
* **Kategori:** Network Reconnaissance / Scanning
* **Poin:** 10
* **Deskripsi:** Scan 172.31.3.216 and tell me the TCP port number where an SSH service is listening. (One number only.)
* **Author:** Arcane Security

## Informasi Attachment & Lingkungan

Soal ini memberikan akses ke "Interactive Terminal by Arcane Security". Berikut adalah pengecekan awal struktur direktori pada environment tersebut:

```bash
node@d312f343d3f4:~$ ls
INSTRUCTOR_NOTES.txt  level-2  level-4  level-6  level-8
level-1               level-3  level-5  level-7  level-9

```

## Proses Penyelesaian

### 1. Analisis Target

Tujuan dari challenge ini adalah mencari nomor port TCP yang menjalankan layanan SSH pada alamat IP target: `172.31.3.216`.

### 2. Scanning Port dengan Nmap

Untuk mengetahui port yang terbuka dan layanan yang berjalan, saya menggunakan tools `nmap`. Flag `-Pn` digunakan untuk melewati tahap discovery (ping) dan mengasumsikan host dalam keadaan aktif (up), yang berguna jika target memblokir ICMP request.

Berikut adalah perintah yang dijalankan beserta output lengkap dari terminal:

```bash
node@d312f343d3f4:~$ nmap -Pn 172.31.3.216
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-30 10:29 UTC
Nmap scan report for ip-172-31-3-216.us-west-1.compute.internal (172.31.3.216)
Host is up (0.00074s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT      STATE  SERVICE
22/tcp    open   ssh
2323/tcp closed 3d-nfsd

Nmap done: 1 IP address (1 host up) scanned in 4.35 seconds
node@d312f343d3f4:~$ 

```

### 3. Analisis Hasil

Berdasarkan output scan nmap di atas:

```text
PORT      STATE  SERVICE
22/tcp    open   ssh

```

Terlihat bahwa layanan **ssh** berjalan pada port **22** dengan status *open*.

## Script Solver / Command

Tidak diperlukan script Python khusus untuk challenge ini, penyelesaian cukup menggunakan *one-liner command* berikut:

```bash
nmap -Pn 172.31.3.216

```

## Flag 

**22**
