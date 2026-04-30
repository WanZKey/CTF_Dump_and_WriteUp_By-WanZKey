# WriteUp - Meta_Hunter_2

## Overview

* Title: Meta_Hunter_2
* Category: Forensic
* Points: -
* Description: Seorang informan mengirimkan foto pemandangan ini sebagai bukti lokasi pertemuan. Namun, dia bilang koordinatnya disembunyikan di dalam "jiwa" foto tersebut. Tugas: Jangan terkecoh dengan gambarnya. Periksa Metadata-nya.
* Author: -

## Attachment Information

* Directory Structure: `~../Forensic/Meta_Hunter_2/`
* File: `chall_6925b5aaa125b_878269fe.jpg` (di lokal dieksekusi sebagai `chall.jpg`)

## Process

* We got this bro! Sama seperti challenge sebelumnya, langkah pertama untuk menginvestigasi file ini adalah dengan menggunakan utility `file` untuk melihat detail tipe data dan ringkasan metadata Exif.
* Melalui output perintah `file chall.jpg`, kita bisa langsung melihat bahwa string flag disisipkan pada bagian parameter `description`.
* Untuk memastikan dan mengekstrak seluruh informasi tersembunyi dari "jiwa" foto tersebut, kita mengeksekusi tool `exiftool`.
* Hasil dari `exiftool` memvalidasi temuan awal kita, menampilkan flag secara utuh pada baris `Image Description`.

## Terminal Output

```bash
 WanZKey  ～  ~../Forensic/Meta_Hunter_2 󱎫 0s 󱑎 15.14
 󰋑  ▶  file chall.jpg
chall.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=1, description=ZeroSec{exif_data_reveals_secrets}], baseline, precision 8, 400x400, components 3

 WanZKey  ～  ~../Forensic/Meta_Hunter_2 󱎫 0s 󱑎 15.14
 󰋑  ▶  exiftool chall.jpg
ExifTool Version Number         : 13.44
File Name                       : chall.jpg
Directory                       : .
File Size                       : 3.8 kB
File Modification Date/Time     : 2025:11:25 20:56:58+07:00
File Access Date/Time           : 2026:02:21 12:14:19+07:00
File Inode Change Date/Time     : 2026:02:21 12:14:18+07:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Exif Byte Order                 : Big-endian (Motorola, MM)
Image Description               : ZeroSec{exif_data_reveals_secrets}
Image Width                     : 400
Image Height                    : 400
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 400x400
Megapixels                      : 0.160

```

## Flag

`ZeroSec{exif_data_reveals_secrets}`
