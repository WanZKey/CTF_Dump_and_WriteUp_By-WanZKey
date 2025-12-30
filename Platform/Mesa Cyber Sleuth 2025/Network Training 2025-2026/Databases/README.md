# Writeup: Databases

## Overview

* **Judul:** Databases
* **Kategori:** Network Reconnaissance / Scanning
* **Poin:** 80
* **Deskripsi:** Which port at 172.31.7.221 seems to be hosting a database service?
* **Author:** Arcane Security

## Proses Penyelesaian

### 1. Analisis Target

Tantangan ini meminta kita untuk mengidentifikasi port yang menjalankan layanan database pada alamat IP `172.31.7.221`. Hint yang diberikan menyebutkan bahwa "MySql is a well known database service", yang mengarahkan kita untuk mencari port standar MySQL.

### 2. Scanning dengan Nmap

Kita menggunakan hasil scanning dari proses sebelumnya terhadap target yang sama. Perintah yang digunakan adalah `nmap` dengan flag `-sVC` (versi dan script default) dan `-Pn`.

Berikut adalah output terminal dari proses scanning:

```bash
node@d312f343d3f4:~$ nmap -sVC 172.31.7.221 -Pn
Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-30 11:08 UTC
Nmap scan report for ip-172-31-7-221.us-west-1.compute.internal (172.31.7.221)
Host is up (0.00066s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT      STATE  SERVICE VERSION
21/tcp    closed ftp
80/tcp    closed http
3306/tcp  closed mysql

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.87 seconds

```

### 3. Analisis Hasil

Dari output scan di atas, kita melihat daftar port yang terdeteksi:

```text
PORT      STATE  SERVICE VERSION
21/tcp    closed ftp
80/tcp    closed http
3306/tcp  closed mysql

```

Port **3306** teridentifikasi menjalankan layanan **mysql**, yang merupakan layanan database sesuai dengan deskripsi dan hint soal.

## Script Solver / Command

```bash
nmap -sVC 172.31.7.221 -Pn

```

## Flag

3306
