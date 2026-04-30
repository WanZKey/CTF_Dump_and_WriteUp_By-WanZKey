# WriteUp - Corrupted_Evidence

## Overview

* Title: Corrupted_Evidence
* Category: Forensic
* Points: -
* Description: Agen, kami memulihkan file gambar ini dari hard drive yang terbakar. Sistem operasi tidak bisa membukanya dan mengatakan "File format not supported". Tim teknis kami menduga bagian awal file (Header) hilang atau rusak. Bisakah Anda melakukan bedah digital (Hex Editing) untuk memperbaikinya dan melihat apa isinya? Status File: Rusak (Corrupted Header)
* Author: -

## Attachment Information

* Directory Structure: `~../Forensic/Corrupted_Evidence/`
* File: `chall_6925b39a59185_d6330ff9.png` (di lokal dieksekusi sebagai `chall.png`)

## Process

* We got this bro! Langkah awal untuk menyelesaikan challenge ini adalah dengan melakukan inspeksi pada file `chall.png` menggunakan tool bawaan seperti `file`, `pngcheck`, `identify`, `strings`, dan `xxd`.
* Berdasarkan output dari perintah `file`, sistem operasi hanya mengenali file tersebut sebagai raw `data`, bukan sebagai format gambar PNG yang sah.
* Hasil dari perintah `pngcheck` dan `identify` mengonfirmasi bahwa terdapat kerusakan atau ketidaksesuaian pada header gambar (improper image header).
* Analisis lanjutan menggunakan `xxd` menunjukkan bahwa 8 byte pertama bernilai `0000 0000 0000 0000`. Padahal, ketika menggunakan perintah `strings`, terlihat struktur standar (chunk) dari format PNG masih utuh di dalamnya, seperti `IHDR`, `IDATx`, dan `IEND`.
* Oh my bad! Ini berarti magic bytes (file signature) dari file PNG telah sengaja dihilangkan atau ditimpa dengan null bytes. File PNG yang valid harus selalu diawali dengan deretan hex `89 50 4E 47 0D 0A 1A 0A`.
* Untuk melakukan perbaikan (hex editing) secara presisi, sebuah script Python dibuat untuk membaca raw bytes dari file yang rusak, menimpa 8 byte pertamanya dengan magic bytes PNG yang valid, dan menyimpannya sebagai file baru.
* Eksekusi script `solver.py` berhasil memperbaiki file dan menghasilkan gambar baru dengan nama `fixed_chall.png`.
* Saat file `fixed_chall.png` dibuka di image viewer, gambar tersebut menampilkan teks yang merupakan flag dari challenge ini.

## Script Solver

```python
def solve():
    print("[*] Fixing corrupted PNG header...")
    try:
        with open("chall.png", "rb") as f:
            data = bytearray(f.read())
        
        # PNG Magic Bytes: 89 50 4E 47 0D 0A 1A 0A
        magic_bytes = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
        
        # Replace the first 8 bytes
        data[:8] = magic_bytes
        
        with open("fixed_chall.png", "wb") as f:
            f.write(data)
            
        print("[+] File successfully fixed and saved as 'fixed_chall.png'!")
        print("[*] Buka file 'fixed_chall.png' untuk melihat flagnya.")
        
    except FileNotFoundError:
        print("[-] File chall.png tidak ditemukan. Pastikan file ada di direktori yang sama.")

if __name__ == "__main__":
    solve()

```

## Terminal Output

```bash
 WanZKey  ～  ~../Forensic/Corrupted_Evidence 󱎫 0s 󱑎 15.23
 󰋑  ▶  file chall.png
chall.png: data

 WanZKey  ～  ~../Forensic/Corrupted_Evidence 󱎫 0s 󱑎 15.23
 󰋑  ▶  pngcheck chall.png
chall.png  this is neither a PNG or JNG image nor a MNG stream
ERROR: chall.png

 󰋑  ▶  identify chall.png
identify: improper image header `chall.png' @ error/png.c/ReadPNGImage/3953.

 WanZKey  ～  ~../Forensic/Corrupted_Evidence 󱎫 0s 󱑎 15.24
 󰋑  ▶  strings chall.png | head -n 10
IHDR
IDATx
yOcV
S9Xf
6]=V
-Iwww
=x9X
|i?e;
kuYc
O%w%

 WanZKey  ～  ~../Forensic/Corrupted_Evidence 󱎫 0s 󱑎 15.24
 󰋑  ▶  strings chall.png | tail -n 10
~e?i
xYDo
:q<|
qY>_F
<~9v
[}~C
{G_d{<
~J{7
se>?
IEND


 WanZKey  ～  ~../Forensic/Corrupted_Evidence 󱎫 0s 󱑎 15.24
 󰋑  ▶  xxd chall.png | head -n 10
00000000: 0000 0000 0000 0000 0000 000d 4948 4452  ............IHDR
00000010: 0000 0258 0000 0064 0802 0000 00d5 23d9  ...X...d......#.
00000020: 7400 0008 a149 4441 5478 9ced dc6d 8c5d  t....IDATx...m.]
00000030: 451d c7f1 3367 e63c ecf2 2001 9514 6b6c  E...3g.<.. ...kl
00000040: 1034 bcf2 01df 60d4 48b0 4f96 9a6a 218a  .4....`.H.O..j!.
00000050: 692a c6a2 85c6 486a 7da0 56ab 42d8 961a  i*....Hj}.V.B...
00000060: 45d3 b4b4 4053 a5da d84a 8b2d 8442 d117  E...@S...J.-.B..
00000070: 1865 8186 4883 be21 c417 50cb 0b9f 4aa4  .e..H..!..P...J.
00000080: e79c 9933 67cc dcbd db6e efbd fbd0 75d3  ...3g....n....u.
00000090: 7633 df4f 36cd dd3d 3373 fe67 9a9c dfce  v3.O6..=3s.g....

 WanZKey  ～  ~../Forensic/Corrupted_Evidence 󱎫 0s 󱑎 15.24
 󰋑  ▶  xxd chall.png | tail -n 10
00000840: d008 4200 40d0 0842 0040 d008 4200 40d0  ..B.@..B.@..B.@.
00000850: 0842 0040 d008 4200 40d0 0842 0040 d008  .B.@..B.@..B.@..
00000860: 4200 40d0 0842 0040 d008 4200 40d0 0842  B.@..B.@..B.@..B
00000870: 0040 d008 4200 40d0 0842 0040 d008 4200  .@..B.@..B.@..B.
00000880: 40d0 0842 0040 d008 4200 40d0 0842 0040  @..B.@..B.@..B.@
00000890: d008 4200 40d0 0842 0040 d008 4200 40d0  ..B.@..B.@..B.@.
000008a0: 0842 0040 d008 4200 40d0 0842 0040 d008  .B.@..B.@..B.@..
000008b0: 4200 40d0 0842 0040 d008 4200 40d0 0842  B.@..B.@..B.@..B
000008c0: 0040 14b2 ff01 55bb a77f 4145 810f 0000  .@....U...AE....
000008d0: 0000 4945 4e44 ae42 6082                 ..IEND.B`.

 󰋑  ▶  ./solver.py
[*] Fixing corrupted PNG header...
[+] File successfully fixed and saved as 'fixed_chall.png'!
[*] Buka file 'fixed_chall.png' untuk melihat flagnya.

```

## Flag

`ZeroSec{magic_bytes_fix_everything}`
