# Writeup: Port 8080

## Overview

* **Judul:** Port 8080
* **Kategori:** Network Reconnaissance / Scanning
* **Poin:** 40
* **Deskripsi:** What is the state of port 8080 on 172.31.5.98?
* **Author:** Arcane Security

## Proses Penyelesaian

### 1. Analisis Target

Tantangan ini meminta kita untuk menentukan **status** (state) dari port 8080 pada alamat IP `172.31.5.98`.

### 2. Scanning Port Spesifik dengan Nmap

Saya menggunakan `nmap` dengan flag `-p8080` untuk memindai port spesifik tersebut dan `-Pn` untuk melewati host discovery (ping).

Berikut adalah perintah yang dijalankan beserta output lengkap dari terminal:

```bash
node@d312f343d3f4:~$ nmap -p8080 172.31.5.98 -Pn

Starting Nmap 7.93 ( https://nmap.org ) at 2025-12-30 11:01 UTC
Nmap scan report for ip-172-31-5-98.us-west-1.compute.internal (172.31.5.98)
Host is up (0.00087s latency).

PORT      STATE  SERVICE
8080/tcp closed http-proxy

Nmap done: 1 IP address (1 host up) scanned in 0.04 seconds
node@d312f343d3f4:~$ 

```

### 3. Analisis Hasil

Berdasarkan output Nmap pada kolom **STATE**:

```text
PORT      STATE  SERVICE
8080/tcp closed http-proxy

```

Status port 8080 adalah **closed**.

## Script Solver / Command

```bash
nmap -p8080 172.31.5.98 -Pn

```

## Flag

closed
