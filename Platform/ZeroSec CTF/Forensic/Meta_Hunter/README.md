# WriteUp - Meta_Hunter

## Overview

* Title: Meta_Hunter
* Category: Forensic
* Points: -
* Description: Gambar ini diambil dari lokasi persembunyian hacker. Namun, yang kami butuhkan bukan gambarnya, melainkan data yang tertinggal di dalamnya.
* Author: -

## Attachment Information

* Directory Structure: `~../Forensic/Meta_Hunter/`
* File: `chall_692555a224eda_72fc81a2.jpg` (di lokal dieksekusi sebagai `chall.jpg`)

## Process

* We got this bro! Langkah awal dalam menganalisa file gambar adalah dengan memeriksa jenis file beserta ringkasan metadata menggunakan tool bawaan `file`.
* Dari hasil eksekusi perintah `file` terhadap `chall.jpg`, string flag langsung terekspos pada bagian standar Exif di parameter `description`.
* Untuk memverifikasi temuan dan mengekstrak seluruh baris metadata secara menyeluruh, tool `exiftool` digunakan pada gambar tersebut.
* Output terminal dari `exiftool` dengan jelas menampilkan flag utuh pada field `Image Description`.

## Terminal Output

```bash
 WanZKey  ～  ~../Forensic/Meta_Hunter 󱎫 0s 󱑎 15.11
 󰋑  ▶  file chall.jpg
chall.jpg: JPEG image data, Exif standard: [TIFF image data, big-endian, direntries=1, description=ZeroSec{metadata_reveals_everything}], baseline, precision 8, 2560x1970, components 3

 WanZKey  ～  ~../Forensic/Meta_Hunter 󱎫 0s 󱑎 15.11
 󰋑  ▶  exiftool chall.jpg
ExifTool Version Number         : 13.44
File Name                       : chall.jpg
Directory                       : .
File Size                       : 505 kB
File Modification Date/Time     : 2025:11:25 14:07:14+07:00
File Access Date/Time           : 2026:02:21 12:13:33+07:00
File Inode Change Date/Time     : 2026:02:21 12:13:28+07:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : ZeroSec{metadata_reveals_everything}
Image Width                     : 2560
Image Height                    : 1970
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2560x1970
Megapixels                      : 5.0

```

## Flag

`ZeroSec{metadata_reveals_everything}`
