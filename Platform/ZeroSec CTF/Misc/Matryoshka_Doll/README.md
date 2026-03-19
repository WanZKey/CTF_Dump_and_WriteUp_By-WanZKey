# WriteUp - Matryoshka Doll

## Overview

* **Judul:** Matryoshka_Doll
* **Kategori:** MISC
* **Poin:** 100 PTS
* **Deskripsi:** Kami menemukan sebuah teks aneh. Kelihatannya seperti Base64 biasa, tapi setiap kali kami decode, hasilnya masih acak. Sepertinya si pembuat soal sangat paranoid dan membungkus pesannya berkali-kali seperti boneka Rusia. Jangan buang waktu melakukannya secara manual, jari Anda akan keriting. Gunakan Python! Tugas: Kupas lapisan encoding ini sampai ke intinya.
* **Author:** Unknown

## Informasi Attachment

* **File:** `chall_6925b66bef572_1ca77886.txt` (di-rename menjadi `chall.txt` di lokal).
* **Struktur Direktori:** `~../Misc/Matryoshka_Doll/`

## Proses Penyelesaian

1. Menganalisa informasi dan *hint* yang diberikan pada deskripsi soal. Deskripsi menyebutkan bahwa pesan dibungkus berkali-kali seperti "boneka Rusia" dan menyarankan penggunaan Python. Ini merupakan indikasi kuat adanya proses *nested encoding* (encoding yang berlapis-lapis), kemungkinan besar menggunakan Base64.
2. Melakukan inspeksi awal terhadap file attachment `chall.txt` di terminal menggunakan *command* `file` dan `exiftool`. Output menunjukkan bahwa file tersebut adalah file teks ASCII berukuran sekitar 62 kB yang hanya terdiri dari satu baris teks yang sangat panjang (62008 karakter) tanpa *line terminators*.
3. Membaca cuplikan isi file menggunakan *command* `cat`. Teks diawali dengan string `Vm0wd2...` dan diakhiri dengan `==`. Format ini merupakan *signature* klasik dari format *encoding* Base64.
4. Karena file berukuran cukup besar dan proses decoding perlu dilakukan berkali-kali, *decoding* secara manual tidak dimungkinkan. Oleh karena itu, dibuat sebuah *script solver* menggunakan bahasa pemrograman Python untuk mengotomatisasi proses tersebut.
5. *Script solver* (`solver.py`) dirancang menggunakan *library* `base64`. Script akan membaca isi file teks dan melakukan *looping* (perulangan) menggunakan blok `try-except` untuk terus melakukan proses `base64.b64decode()` secara berulang dan menimpa *variable* data lama dengan hasil *decode* yang baru.
6. Proses *looping* ini didesain agar otomatis berhenti (*break*) dan melemparkan *exception* ketika *decoder* menemui string yang bukan merupakan format Base64 yang valid (seperti tanda kurung kurawal `{` dan `}` yang biasa terdapat pada format *flag* CTF).
7. Menjalankan *script* `solver.py` di terminal. Script berhasil bekerja, mengupas lapisan Base64 sebanyak 25 kali secara otomatis, dan langsung mencetak *flag* yang tersembunyi di lapisan paling dasar.

## Script Solver

```python
import base64

def solve():
    print("[*] Memulai proses decoding Matryoshka Doll...")
    
    with open("chall.txt", "r") as f:
        data = f.read().strip()

    layer = 0
    while True:
        try:
            # Mencoba decode base64
            decoded_bytes = base64.b64decode(data)
            decoded_str = decoded_bytes.decode('utf-8')
            
            # Jika berhasil, timpa data lama dengan yang baru
            data = decoded_str
            layer += 1
            
        except Exception:
            # Looping akan otomatis berhenti (exception) ketika data sudah bukan base64 valid
            break

    print(f"[+] Selesai! Berhasil mengupas {layer} lapis encoding.")
    print(f"\n[+] Flag: {data}")

if __name__ == "__main__":
    solve()

```

## Output Terminal

```text
 WanZKey  ～  ~../Misc/Matryoshka_Doll 󱎫 0s 󱑎 13.07
 󰋑  ▶  file chall.txt
chall.txt: ASCII text, with very long lines (62008), with no line terminators

 󰋑  ▶  exiftool chall.txt
ExifTool Version Number         : 13.50
File Name                       : chall.txt
Directory                       : .
File Size                       : 62 kB
File Modification Date/Time     : 2026:03:09 13:07:47+07:00
File Access Date/Time           : 2026:03:09 13:07:49+07:00
File Inode Change Date/Time     : 2026:03:09 13:07:47+07:00
File Permissions                : -rw-r--r--
File Type                       : TXT
File Type Extension             : txt
MIME Type                       : text/plain
MIME Encoding                   : us-ascii
Newlines                        : (none)
Line Count                      : 1
Word Count                      : 1

 󰋑  ▶  cat chall.txt
Vm0wd2QyUXlVWGxWV0d4V1YwZDRWMVl3WkRSV01WbDNXa1JTVjAxV2JETlhhMUpUVmpBeFYySkVUbGhoTVVwVVZtcEJlRll5U2tWVWJHaG9UVlZ3VlZadGNFSmxSbGw1VTJ0V1ZXSkhhRzlVVmxaM1ZsWmFkR05GU214U2JHdzFWVEowVjFaWFNraGhSemxWVm14YU0xWnNXbUZrUjA1R1UyMTRVMkpIZHpGV1ZFb3dWakZhV0Z
.......................................................
........................................................
MnhUVFRKT00xWnRNWGRUTURWSFlrWmtWbUpyTlZsWmEyUlRWMVpzYzFWdVRtaFNiSEI0VmtkMFQxVnJNVmRTYWxKV1lrWktlbFpXV2xkV1ZURkZZWG93UFE9PQ==¶

 󰋑  ▶  ./solver.py
[*] Memulai proses decoding Matryoshka Doll...
[+] Selesai! Berhasil mengupas 25 lapis encoding.

[+] Flag: ZeroSec{scripting_is_necessary_for_survival}

```

## Flag

```text
ZeroSec{scripting_is_necessary_for_survival}

```
