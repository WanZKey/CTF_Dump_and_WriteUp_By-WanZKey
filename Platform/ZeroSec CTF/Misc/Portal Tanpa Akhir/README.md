# WriteUp - Portal Tanpa Akhir

## Overview

* **Judul:** Portal Tanpa Akhir
* **Kategori:** MISC
* **Poin:** 999 PTS
* **Deskripsi:** Aku tahu 9 lebih besar dari 8. Tapi bisakah kamu kembali ke masa lalu, dan meyakinkan semua orang bahwa 8 lebih besar dari 9? Sebelum kamu mencoba, dengarkan baik-baik pesanku: "Berpikirlah secara logika" & "Teliti" Kembali ke masa lalu hanya akan membuang waktumu. Sebagai pegangan, aku titipkan sepucuk pesan, yang harus kau simpan di dalam pikiranmu: `ZeroSec{T----_---A}` Jika kamu tetap bersikeras ingin kembali ke masa lalu. Silakan masuk ke Portal Pertama.
* **URL:** [https://xas-api.xo.je/Waktu/portal1.html](https://xas-api.xo.je/Waktu/portal1.html)
* **Author:** Unknown

## Informasi Attachment

* **File:** `hint.jpg` (Gambar meme bertuliskan "PIKIRKAN SECARA LOGIKA")
* **Struktur Direktori:** `~../Misc/Portal Tanpa Akhir/`

## Proses Penyelesaian

1. Mengunjungi URL Portal 1 (`https://xas-api.xo.je/Waktu/portal1.html`). Halaman ini memberikan peringatan awal untuk "berpikir dengan logika sebelum melangkah lebih jauh" dan menyertakan tombol untuk mengunduh gambar `hint.jpg` beserta *source code* yang berisi komentar jebakan ``.
2. Melakukan ekstraksi metadata dan analisa informasi pada file `hint.jpg` menggunakan berbagai *tools* di terminal (`file`, `identify`, `exiftool`, `binwalk`, `zsteg`, dan `strings`).
3. Dari hasil `exiftool` dan `strings`, ditemukan sebuah *Comment* yang mengarahkan ke URL Portal 2: `https://xas-api.xo.je/Waktu/portal2.html`. Ditemukan juga string cipher panjang yang saat di-*decode* menggunakan metode *decabit* menghasilkan `01150010100001000u00s0100`, yang mana ini terkonfirmasi sebagai *rabbit hole* (jebakan).
4. Mengakses URL Portal 2 menggunakan *script solver* Python (`solver.py`) untuk menganalisa *source code* secara langsung. *Source code* Portal 2 memberikan pesan bahwa kita "semakin tersesat" dan menuntun ke tautan Portal 3 (`portal3.html`).
5. Mengakses URL Portal 3 (`https://xas-api.xo.je/Waktu/portal3.html`). Halaman ini berisi ejekan dari *author* dan menampilkan sebuah kode Base64: `U2VwZXJ0aW55YSBrYXUgbWVsdXBha2FuIHNlc3VhdHUgZGkgcG9ydGFsIDEgY29iYSBjZWsga2VtYmFsaSBtZW5ndW5ha2FuIGxpbmsgaW5pCmh0dHBzOi8veGFzLWFwaS54by5qZS9XYWt0dS9wb3J0YWwxLmh0bWw=`. Selain itu, terdapat tombol "OPEN" yang mengarah ke `ngeyel.html` (halaman yang hanya berisi video *troll*/jebakan).
6. Melakukan *decode* string Base64 menggunakan *tool* `dcode`. Hasilnya adalah pesan: "Sepertinya kau melupakan sesuatu di portal 1 coba cek kembali mengunakan link ini [https://xas-api.xo.je/Waktu/portal1.html](https://xas-api.xo.je/Waktu/portal1.html)".
7. Sampai di titik ini, terkonfirmasi bahwa seluruh alur direktori `/Waktu/` dan portal 1 hingga 3 merupakan sebuah putaran tanpa akhir (*infinite loop*) yang memang sengaja dirancang untuk membuang-buang waktu *player*. Hal ini sangat sesuai dengan *hint* di deskripsi soal: "Kembali ke masa lalu hanya akan membuang waktumu".
8. Meninggalkan *rabbit hole* teknis dan fokus kembali pada pesan utama di deskripsi soal serta gambar `hint.jpg` yang secara eksplisit menyuruh: "PIKIRKAN SECARA LOGIKA".
9. Pertanyaan utama *author* di deskripsi adalah: *"bisakah kamu kembali ke masa lalu, dan meyakinkan semua orang bahwa 8 lebih besar dari 9?"*
10. Berdasarkan logika fundamental dan hukum alam/matematika, jawabannya sudah pasti **TIDAK BISA**.
11. Mencocokkan jawaban logika tersebut dengan kerangka *flag* yang telah diberikan: `ZeroSec{T----_---A}`.
12. Susunan kata "TIDAK BISA" memiliki kecocokan pola yang 100% sempurna:
* Kata pertama: **TIDAK** -> Diawali huruf `T` dengan sisa 4 huruf kosong (`T----`).
* Karakter pemisah: `_`.
* Kata kedua: **BISA** -> 3 huruf kosong diawali dengan `B-I-S` dan ditutup huruf `A` (`---A`).


13. Menyusun dan men-*submit* *flag* kapital sesuai instruksi *hint*: `ZeroSec{TIDAK_BISA}`.

## Script Solver

```python
import requests

def investigate_portal(url):
    print(f"[*] Hitting target: {url}")
    try:
        res = requests.get(url)
        print(f"[+] HTTP Status: {res.status_code}")
        print("\n[+] Source Code:\n")
        print(res.text)
    except Exception as e:
        print(f"[-] Error bro: {e}")

if __name__ == "__main__":
    target = "https://xas-api.xo.je/Waktu/portal2.html"
    investigate_portal(target)

```

## Output Terminal

```text
 WanZKey  ～  ~../Misc/Portal Tanpa Akhir 󱎫 0s 󱑎 13.15
 󰋑  ▶  file hint.jpg
hint.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "https://xas-api.xo.je/Waktu/portal2.html", baseline, precision 8, 556x551, components 3

 WanZKey  ～  ~../Misc/Portal Tanpa Akhir 󱎫 0s 󱑎 13.15
 󰋑  ▶  identify hint.jpg
hint.jpg JPEG 556x551 556x551+0+0 8-bit sRGB 25137B 0.000u 0:00.004

 WanZKey  ～  ~../Misc/Portal Tanpa Akhir 󱎫 0s 󱑎 13.15
 󰋑  ▶  exiftool hint.jpg
ExifTool Version Number         : 13.50
File Name                       : hint.jpg
Directory                       : .
File Size                       : 25 kB
File Modification Date/Time     : 2026:03:09 13:14:45+07:00
File Access Date/Time           : 2026:03:09 13:15:07+07:00
File Inode Change Date/Time     : 2026:03:09 13:15:06+07:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Comment                         : https://xas-api.xo.je/Waktu/portal2.html
Image Width                     : 556
Image Height                    : 551
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 556x551
Megapixels                      : 0.306

 WanZKey  ～  ~../Misc/Portal Tanpa Akhir 󱎫 0s 󱑎 13.15
 󰋑  ▶  binwalk hint.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01

 WanZKey  ～  ~../Misc/Portal Tanpa Akhir 󱎫 2s 󱑎 13.15
 󰋑  ▶  zsteg hint.jpg
[!] #<ZPNG::NotSupported: Unsupported header "\xFF\xD8\xFF\xE0\x00\x10JF" in #<File:hint.jpg>>

 󰋑  ▶  strings hint.jpg | head -n 10
JFIF
*https://xas-api.xo.je/Waktu/portal2.html
!1!%)+...
383-7(-.+
+-++++---+---+-+----+----+++-+-+----+-++--+-+--+--
"Qaq
#5BRU
$3Cbr
6DTcu
"2QaRq$4B

 󰋑  ▶  strings hint.jpg | tail -n 10
D@DD
D@DD
D@DD
D@DD
D@DD
D@DD
D@DD
D@DD
D@DD
D@DD

 󰋑  ▶  python3 solver.py
[*] Hitting target: https://xas-api.xo.je/Waktu/portal2.html
[+] HTTP Status: 200

[+] Source Code:

<!DOCTYPE html><html lang="id"><head>  <meta charset="UTF-8">  <title>Portal 1</title>
  <style>    * {      box-sizing: border-box;    }
    body {      margin: 0;      background: #000;      color: #fff;      font-family: "Courier New", Courier, monospace;      display: flex;      justify-content: center;      align-items: center;      height: 100vh;    }
    .box {      width: 520px;      padding: 32px;      border: 2px solid #ff0000;      box-shadow: 0 0 25px rgba(255, 0, 0, 0.8);      background: rgba(0, 0, 0, 0.85);    }
    h1 {      text-align: center;      color: #ff0000;      margin-bottom: 20px;      letter-spacing: 1px;    }/* Tidak ada apa apa disini sepertinya anda harus ke portal 3 */    code {      display: block;      color: #00ff99;      background: rgba(0, 255, 153, 0.08);      padding: 12px;      margin-bottom: 18px;      border-left: 4px solid #00ff99;    }
    p {      line-height: 1.6;      margin-bottom: 16px;    }
    .actions {      margin-top: 25px;      display: flex;      gap: 15px;      flex-wrap: wrap;    }
    a {      color: #00ff00;      border: 1px solid #00ff00;      padding: 10px 18px;      text-decoration: none;      transition: all 0.2s ease;    }
    a:hover {      background: #00ff00;      color: #000;      box-shadow: 0 0 10px #00ff00;    }  </style></head>
<body>  <div class="box">    <h1>PORTAL II</h1>
    <code>Selamat Datang di Portal Kedua Menuju Masa Lalu</code>
    <p>      Wah, ternyata kamu cukup keras kepala.      Bisa saja di portal berikutnya kamu akan semakin tersesat.      Namun karena kamu sudah sejauh ini,      aku akan menuntunmu menuju Portal Ketiga.      Silakan akses link di bawah ini.          </p>        <div class="actions">      <a href="portal3.html">Open</a>    </div></body></html>

 󰋑  ▶  dcode U2VwZXJ0aW55YSBrYXUgbWVsdXBha2FuIHNlc3VhdHUgZGkgcG9ydGFsIDEgY29iYSBjZWsga2VtYmFsaSBtZW5ndW5ha2FuIGxpbmsgaW5pCmh0dHBzOi8veGFzLWFwaS54by5qZS9XYWt0dS9wb3J0YWwxLmh0bWw=

              __                         __
            |/  |                    | / /
            |   | ___  ___  ___  ___|  (
            |   )|___)|    |   )|   )| |___ \   )
            |__/ |__  |__  |__/ |__/ | |     \_/
                                             /
            https://github.com/s0md3v/Decodify
[+] Decoded from Base64: Sepertinya kau melupakan sesuatu di portal 1 coba cek kembali mengunakan link ini
https://xas-api.xo.je/Waktu/portal1.html

```

## Flag

```text
ZeroSec{TIDAK_BISA}

```

---
