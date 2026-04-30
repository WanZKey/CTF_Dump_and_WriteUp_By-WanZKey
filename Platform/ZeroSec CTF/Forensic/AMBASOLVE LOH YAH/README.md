# WriteUp - AMBASOLVE LOH YAH

## Overview

* Title: AMBASOLVE LOH YAH
* Category: Forensic
* Points: -
* Description: Kemarin malam aku dikirim pesan aneh berupa gambar dari mas Rusdi, pas aku lihat ternyata ada pesan tersembunyi mas Amba yang sedang bolak balik menjerit tengah malam dan ternyata suara tersebut memiliki sebuah kalimat yang tampak aneh apakah kamu bisa membantu ku untuk memecahkan pesan rahasia mas Amba yang dikirim mas Rusdi ??
* Author: -

## Attachment Information

* Directory Structure: `~../Forensic/AMBASOLVE LOH YAH/`
* File: `chall_695340679717f_6be60616.zip`

## Process

* We got this bro! Langkah pertama adalah mengekstrak arsip `chall.zip` yang menghasilkan file bernama `ambasolve.png`.
* Pemeriksaan awal menggunakan `file`, `pngcheck`, dan `identify` menunjukkan bahwa `ambasolve.png` mengalami kerusakan atau memiliki header yang tidak valid.
* Inspeksi heksadesimal menggunakan `xxd` mengungkapkan anomali pada struktur file. Bagian awal file diawali dengan string `DNEI` (kebalikan dari chunk penutup `IEND`), sedangkan bagian akhir file berisi magic bytes PNG yang terbaca terbalik (`.GNP.`).
* Oh my bad! Seluruh susunan byte pada file ini ternyata sengaja di-reverse dari belakang ke depan oleh pembuat soal.
* Untuk mengembalikan gambar ke kondisi normal, script Python `solver.py` dieksekusi untuk membalik (reverse) seluruh raw bytes secara utuh. Output perbaikan disimpan sebagai `fixed_ambasolve.png`.
* Saat gambar perbaikan dibuka, isinya hanyalah gambar umpan (bait). Namun, analisis metadata menggunakan `exiftool` memberikan petunjuk penting berupa peringatan: `[minor] Trailer data after PNG IEND chunk`.
* Menggunakan tool `zsteg` untuk menelusuri data tersembunyi (extradata), ditemukan sebuah teks rahasia pada field `GtEXtComment` yang berisi angka desimal raksasa: `145261217193339700092274108114674177042872914472564540419893373`.
* Angka desimal tersebut adalah representasi *Long Integer* dari sebuah string ASCII.
* Script `decrypt.py` kemudian dieksekusi untuk mengonversi angka desimal tersebut kembali menjadi format bytes, yang berhasil mendekripsi flag secara sempurna.

## Script Solver

**`solver.py` (Reversing Bytes)**

```python
def solve():
    print("[*] Reversing file bytes...")
    try:
        with open("ambasolve.png", "rb") as f:
            data = f.read()
        
        reversed_data = data[::-1]
        
        with open("fixed_ambasolve.png", "wb") as f:
            f.write(reversed_data)
            
        print("[+] File successfully reversed and saved as 'fixed_ambasolve.png'!")
        print("[*] Buka file 'fixed_ambasolve.png' untuk melihat isinya.")
        
    except FileNotFoundError:
        print("[-] File ambasolve.png tidak ditemukan. Pastikan file ada di direktori yang sama.")

if __name__ == "__main__":
    solve()

```

**`decrypt.py` (Decimal to Text Decoder)**

```python
def solve():
    print("[*] Decrypting hidden comment data...")
    
    secret_decimal = 145261217193339700092274108114674177042872914472564540419893373
    
    try:
        flag_bytes = secret_decimal.to_bytes((secret_decimal.bit_length() + 7) // 8, 'big')
        flag = flag_bytes.decode('utf-8')
        
        print("[+] Message decoded successfully!")
        print("FLAG :", flag)
        
    except Exception as e:
        print("[-] Oops, something went wrong:", e)

if __name__ == "__main__":
    solve()

```

## Terminal Output

```bash
 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.28
 󰋑  ▶  file chall.zip
chall.zip: Zip archive data, made by v3.0 UNIX, extract using at least v2.0, last modified Dec 30 2025 09:36:44, uncompressed size 765957, method=deflate

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.28
 󰋑  ▶  unzip -l chall.zip
Archive:  chall.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   765957  2025-12-30 09:36   ambasolve.png
---------                     -------
   765957                     1 file

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.28
 󰋑  ▶  unzip chall.zip
Archive:  chall.zip
  inflating: ambasolve.png

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.28
 󰋑  ▶  fim ambasolve.png
^C¶
 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 3s 󱑎 15.28
 󰋑  ▶  file ambasolve.png
ambasolve.png: data

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.28
 󰋑  ▶  pngcheck ambasolve.png
ambasolve.png  this is neither a PNG or JNG image nor a MNG stream
ERROR: ambasolve.png

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.28
 󰋑  ▶  identify ambasolve.png
identify: improper image header `ambasolve.png' @ error/png.c/ReadPNGImage/3953.

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.28
 󰋑  ▶  exiftool ambasolve.png
ExifTool Version Number         : 13.44
File Name                       : ambasolve.png
Directory                       : .
File Size                       : 766 kB
File Modification Date/Time     : 2025:12:30 09:36:44+07:00
File Access Date/Time           : 2026:02:21 15:28:35+07:00
File Inode Change Date/Time     : 2026:02:21 15:28:32+07:00
File Permissions                : -rw-r--r--
Error                           : File format error

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.28
 󰋑  ▶  binwalk ambasolve.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------


 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 4s 󱑎 15.29
 󰋑  ▶  xxd ambasolve.png | head -n 10
00000000: 8260 42ae 444e 4549 0000 0000 aa16 01a3  .`B.DNEI........
00000010: bd06 a8fd 0b81 000c 0602 0018 0c04 0030  ...............0
00000020: 1808 0060 3010 00c0 6020 0180 c040 0301  ...`0...` ...@..
00000030: 8080 0603 0100 0c06 0200 180c 0400 3018  ..............0.
00000040: 0800 6030 1000 c060 2001 80c0 4003 0180  ..`0...` ...@...
00000050: 8006 0301 000c 0602 0018 0c04 0030 1808  .............0..
00000060: 0060 3010 00c0 6020 0180 c040 0301 8080  .`0...` ...@....
00000070: 0603 0100 0c06 0200 180c 0400 3018 0800  ............0...
00000080: 6030 1000 c060 2001 80c0 4003 0180 8006  `0...` ...@.....
00000090: 0301 000c 0602 0018 0c04 0030 1808 0060  ...........0...`

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.29
 󰋑  ▶  xxd ambasolve.png | tail -n 10
000baf70: 1e5f d76d d559 7dfe 57e7 ec79 a803 e378  ._.m.Y}.W..y...x
000baf80: 477b 733d a4ef 1dd3 cf38 2220 2227 de3d  G{s=.....8" "'.=
000baf90: d1e7 c8ee 8886 e675 d9b7 33ce 1a22 6bd9  .......u..3.."k.
000bafa0: 2fff bfe7 ff0a 3e14 2850 a142 1012 e127  /.....>.(P.B...'
000bafb0: 1671 4494 8ed7 1874 cce1 42a2 9048 c483  .qD....t..B..H..
000bafc0: f509 e9ad 4c5e 8ebd 977a 0af4 e752 76af  ....L^...z...Rv.
000bafd0: bf20 258f 3adc 9669 7dec 9c78 5441 4449  . %.:..i}..xTADI
000bafe0: dfa7 0b00 43c1 d3e8 0000 0006 0838 0400  ....C........8..
000baff0: 0080 0700 0052 4448 490d 0000 000a 1a0a  .....RDHI.......
000bb000: 0d47 4e50 89                             .GNP.

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.35
 󰋑  ▶  ./solver.py
[*] Reversing file bytes...
[+] File successfully reversed and saved as 'fixed_ambasolve.png'!
[*] Buka file 'fixed_ambasolve.png' untuk melihat isinya.

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.35
 󰋑  ▶  file fixed_ambasolve.png
fixed_ambasolve.png: PNG image data, 1920 x 1080, 8-bit/color RGBA, non-interlaced

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.35
 󰋑  ▶  exiftool fixed_ambasolve.png
ExifTool Version Number         : 13.44
File Name                       : fixed_ambasolve.png
Directory                       : .
File Size                       : 766 kB
File Modification Date/Time     : 2026:02:21 15:33:05+07:00
File Access Date/Time           : 2026:02:21 15:33:08+07:00
File Inode Change Date/Time     : 2026:02:21 15:33:05+07:00
File Permissions                : -rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 1920
Image Height                    : 1080
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 1920x1080
Megapixels                      : 2.1

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.36
 󰋑  ▶  xxd fixed_ambasolve.png | head -n 10
00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR
00000010: 0000 0780 0000 0438 0806 0000 00e8 d3c1  .......8........
00000020: 4300 0ba7 df49 4441 5478 9cec 7d69 96dc  C....IDATx..}i..
00000030: 3a8f 2520 bfaf 7652 e7f4 0a7a 97bd 8e5e  :.% ..vR...z...^
00000040: 4cad e909 f583 c448 90a2 42e1 cc74 18d7  L......H..B..t..
00000050: 8e94 4471 1627 e112 1042 a150 2814 3e0a  ..Dq.'...B.P(.>.
00000060: ffe7 bfff 2fd9 6b22 1ace 33b7 d975 e686  ..../.k"..3..u..
00000070: 88ee c8e7 d13d de27 2220 2238 cfd3 1def  .....=.'" "8....
00000080: a43d 737b 4778 e303 a879 ece7 57fe 7d59  .=s{Gx...y..W.}Y
00000090: d56d d75f 1e7f e677 e627 fa1d cb68 cbb1  .m._...w.'...h..

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.36
 󰋑  ▶  xxd fixed_ambasolve.png | tail -n 10
000baf70: 060c 0001 0306 8080 0103 40c0 8001 2060  ..........@... `
000baf80: c000 1030 6000 0818 3000 040c 1800 0206  ...0`...0.......
000baf90: 0c00 0103 0680 8001 0340 c080 0120 60c0  .........@... `.
000bafa0: 0010 3060 0008 1830 0004 0c18 0002 060c  ..0`...0........
000bafb0: 0001 0306 8080 0103 40c0 8001 2060 c000  ........@... `..
000bafc0: 1030 6000 0818 3000 040c 1800 0206 0c00  .0`...0.........
000bafd0: 0103 0680 8001 0340 c080 0120 60c0 0010  .......@... `...
000bafe0: 3060 0008 1830 0004 0c18 0002 060c 0081  0`...0..........
000baff0: 0bfd a806 bda3 0116 aa00 0000 0049 454e  .............IEN
000bb000: 44ae 4260 82                             D.B`.

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.36
 󰋑  ▶  zsteg fixed_ambasolve.png
[?] 2029 bytes of extra data after image end (IEND), offset = 0xba818
extradata:0         .. file: PNG image data, 640 x 480, 8-bit/color RGB, non-interlaced
    00000000: 89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|
    00000010: 00 00 02 80 00 00 01 e0  08 02 00 00 00 ba b3 4b  |...............K|
    00000020: b3 00 00 00 47 74 45 58  74 43 6f 6d 6d 65 6e 74  |....GtEXtComment|
    00000030: 00 31 34 35 32 36 31 32  31 37 31 39 33 33 33 39  |.145261217193339|
    00000040: 37 30 30 30 39 32 32 37  34 31 30 38 31 31 34 36  |7000922741081146|
    00000050: 37 34 31 37 37 30 34 32  38 37 32 39 31 34 34 37  |7417704287291447|
    00000060: 32 35 36 34 35 34 30 34  31 39 38 39 33 33 37 33  |2564540419893373|
    00000070: e9 8f 94 3e 00 00 07 61  49 44 41 54 78 9c ed d5  |...>...aIDATx...|
    00000080: 31 01 00 20 0c c0 30 c0  bf e7 e1 82 1e 24 0a fa  |1.. ..0......$..|
    00000090: 75 cf cc 02 00 de 3a 75  00 00 fc c8 80 01 20 60  |u.....:u...... `|
    000000a0: c0 00 10 30 60 00 08 18  30 00 04 0c 18 00 02 06  |...0`...0.......|
    000000b0: 0c 00 01 03 06 80 80 01  03 40 c0 80 01 20 60 c0  |.........@... `.|
    000000c0: 00 10 30 60 00 08 18 30  00 04 0c 18 00 02 06 0c  |..0`...0........|
    000000d0: 00 01 03 06 80 80 01 03  40 c0 80 01 20 60 c0 00  |........@... `..|
    000000e0: 10 30 60 00 08 18 30 00  04 0c 18 00 02 06 0c 00  |.0`...0.........|
    000000f0: 01 03 06 80 80 01 03 40  c0 80 01 20 60 c0 00 10  |.......@... `...|
b2,r,lsb,xy         .. text: "UUUUUUUUUP"
b2,b,lsb,xy         .. text: "lZP:NI9>T"
b4,r,lsb,xy         .. text: "wveUDD332\"#4DVgx"
b4,b,lsb,xy         .. text: "ffUTC3\"\""

 WanZKey  ～  ~../Forensic/AMBASOLVE LOH YAH 󱎫 0s 󱑎 15.42
 󰋑  ▶  ./decrypt.py
[*] Decrypting hidden comment data...
[+] Message decoded successfully!
FLAG : ZeroSec{m4s_amb4_t3rpec4h}

```

## Flag

`ZeroSec{m4s_amb4_t3rpec4h}`
