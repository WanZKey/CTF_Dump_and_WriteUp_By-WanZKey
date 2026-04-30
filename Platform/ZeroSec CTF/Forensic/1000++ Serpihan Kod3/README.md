# WriteUp - 1000++ Serpihan Kod3

## Overview

* Title: 1000++ Serpihan Kod3
* Category: Forensic
* Points: -
* Description: Kemarin aku mendapatkan sebuah dokumen lama yang berisi 1000+ file QR tetapi aku bingung membaca nya karena aku harus me-scan nya tetapi aku pikir itu sangat membuang waktu untuk membacanya. Apakah kamu bisa membaca dan menyusun kata kata itu kembali sampai bisa di baca oleh manusia??
* Author: -

## Attachment Information

* Directory Structure: `~../Forensic/1000++ Serpihan Kod3/serpihankode/`
* File: `chall_69538d1f38099_a7e3974e.zip`

## Process

* We got this bro! Langkah pertama adalah mengekstrak file `chall.zip` yang berisi folder `serpihankode` dengan total 1254 gambar QR code di dalamnya.


* Karena melakukan scan manual satu per satu sangat tidak efisien, pengujian awal dilakukan menggunakan tool `zbarimg` pada beberapa sampel file (`00.png`, `01.png`, `11.png`) untuk memastikan QR code dapat dibaca lewat terminal.
* Sebuah script Python (`solver.py`) dibuat untuk mengotomatisasi proses pembacaan seluruh QR code menggunakan `zbarimg`. Script ini mengurutkan nama file secara numerik agar teks yang dihasilkan tersusun dengan benar.
* Hasil scan pertama menghasilkan string tunggal sepanjang 1254 karakter yang diawali dengan huruf 'P' berulang, mengindikasikan bahwa string tersebut adalah sebuah ASCII Art.
* Script kemudian dimodifikasi untuk memecah string 1254 karakter tersebut ke dalam beberapa dimensi baris dan kolom. Pada dimensi 66 Kolom x 19 Baris, sebuah pola teks yang dapat dibaca manusia muncul.
* Teks yang tercetak adalah `ZzzeEErRRoOOSsseEEcCC{k3r3n_B4t_lLLuWWwhHH_cCCuUUyYY!!!}`. Pembuat soal sengaja menambahkan padding (pengulangan karakter) untuk mempertahankan bentuk blok ASCII Art.
* Setelah karakter padding dihapus, didapatkan flag asli yang bersih.

## Script Solver

```python
import os
import re
import subprocess

def solve():
    folder = "serpihankode"
    cache_file = "scanned_full.txt"
    full_text = ""

    if os.path.exists(cache_file):
        print(f"[*] Ketemu file {cache_file}, membaca dari cache...")
        with open(cache_file, "r") as f:
            full_text = f.read()
    else:
        if not os.path.exists(folder):
            print("[-] Folder 'serpihankode' tidak ditemukan.")
            return
        
        files = [f for f in os.listdir(folder) if f.endswith('.png')]
        files.sort(key=lambda x: int(re.sub(r'\D', '', x)))
        
        print(f"[*] Melakukan scanning {len(files)} QR codes...")
        for f in files:
            filepath = os.path.join(folder, f)
            result = subprocess.run(['zbarimg', '-q', '--raw', filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if result.stdout:
                full_text += result.stdout.decode('utf-8').strip()
                
        with open(cache_file, "w") as f:
            f.write(full_text)
        print(f"[+] Scan selesai! Teks disimpan ke {cache_file}")

    print(f"\n[*] Total panjang karakter: {len(full_text)}")
    print("[*] Menyusun ulang menjadi ASCII Art...\n")
    
    print(f"==================================================")
    print(f"=== Dimensi: 66 Kolom x 19 Baris ===")
    print(f"==================================================\n")
    
    for i in range(19):
        baris_text = full_text[i*66 : (i+1)*66]
        print(baris_text)
    print("\n")

if __name__ == "__main__":
    solve()

```

## Terminal Output

```bash
 WanZKey  ～  ~../Forensic/1000++ Serpihan Kod3 󱎫 0s 󱑎 18.14
 󰋑  ▶  file chall.zip
chall.zip: Zip archive data, made by v3.0 UNIX, extract using at least v1.0, last modified Dec 30 2025 15:07:00, uncompressed size 0, method=store

 WanZKey  ～  ~../Forensic/1000++ Serpihan Kod3 󱎫 0s 󱑎 18.14
 󰋑  ▶  unzip chall.zip
Archive:  chall.zip
   creating: serpihankode/
 extracting: serpihankode/272.png
 extracting: serpihankode/251.png
 extracting: serpihankode/204.png
 ... [output truncated for brevity, extracted 1254 files] ...
 extracting: serpihankode/712.png

 WanZKey  ～  ~../Forensic/1000++ Serpihan Kod3 󱎫 2s 󱑎 18.17
 󰋑  ▶  zbarimg  serpihankode/00.png
Connection Error (Failed to connect to socket /run/dbus/system_bus_socket: No such file or directory)
Connection Null
QR-Code:P
scanned 1 barcode symbols from 1 images in 0.01 seconds

 WanZKey  ～  ~../Forensic/1000++ Serpihan Kod3 󱎫 0s 󱑎 18.18
 󰋑  ▶  zbarimg  serpihankode/01.png
Connection Error (Failed to connect to socket /run/dbus/system_bus_socket: No such file or directory)
Connection Null
QR-Code:P
scanned 1 barcode symbols from 1 images in 0.04 seconds

 WanZKey  ～  ~../Forensic/1000++ Serpihan Kod3 󱎫 0s 󱑎 18.18
 󰋑  ▶  zbarimg  serpihankode/11.png
Connection Error (Failed to connect to socket /run/dbus/system_bus_socket: No such file or directory)
Connection Null
QR-Code:P
scanned 1 barcode symbols from 1 images in 0.03 seconds

 WanZKey  ～  ~../Forensic/1000++ Serpihan Kod3 󱎫 0s 󱑎 18.25
 󰋑  ▶  ./solver.py
[*] Mengambil dan mengurutkan file...
[*] Scanning 1254 QR codes... We got this bro, tunggu bentar ya prosesnya agak lumayan!

[+] Scan selesai! Mengekstrak flag...

[-] Strict flag pattern gak ketemu langsung. Ini hasil gabungan 500 karakter pertamanya buat lu cek manual (siapa tau di-encode base64 dll):
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP

 WanZKey  ～  ~../Forensic/1000++ Serpihan Kod3 󱎫 0s 󱑎 18.30
 󰋑  ▶  ./solver.py
[*] Melakukan scanning 1254 QR codes dan menyimpan hasilnya...
[+] Scan selesai! Teks disimpan ke scanned_full.txt

[*] Total panjang karakter: 1254
[*] Menyusun ulang menjadi ASCII Art...

==================================================
=== Dimensi: 66 Kolom x 19 Baris ===
==================================================

PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP
PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPZzzeEErRRoOOSsseEEcCC{
k3r3n_B4t_lLLuWWwhHH_cCCuUUyYY!!!}AAAAAAAAAAAAAAAAAAAAADDDDDDDDDDd
dMMMMMMMMMMMMMMMMMmmjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjQQQQQQQQQ
QQQQQQQQQQQQQQQQQQQQQQQQQQQ9228964646464646=======================
====================@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@@@@@@@@$$$$$$$$$$$$$$$$$$$$$$$$$$^^^^^^^^^^^^^^^^^^^

```

## Flag

`ZeroSec{k3r3n_B4t_luwh_cuy!}`
