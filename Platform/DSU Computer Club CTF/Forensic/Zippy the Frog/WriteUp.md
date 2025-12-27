
---

# DSU CTF 2025: Zippy the Frog Writeup

**Category:** Forensics
**Points:** 125
**Author:** Iurii C.

## Deskripsi

> Hello, frogs are really cool creatures. Read up on them!

## Langkah Pengerjaan

### 1. Initial Reconnaissance

Langkah pertama adalah mengidentifikasi jenis file yang diberikan. Diberikan sebuah file bernama `zippy-the-frog.odt`. Kita memeriksa metadata dan tipe file tersebut.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog]
└─$ file zippy-the-frog.odt
zippy-the-frog.odt: Zip archive data, made by v2.0 UNIX, extract using at least v2.0, last modified Dec 04 2025 21:46:48, uncompressed size 0, method=store

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog]
└─$ exiftool zippy-the-frog.odt
ExifTool Version Number         : 13.36
File Name                       : zippy-the-frog.odt
Directory                       : .
File Size                       : 2.8 MB
File Modification Date/Time     : 2025:12:05 04:58:28+07:00
File Access Date/Time           : 2025:12:23 17:14:12+07:00
File Inode Change Date/Time     : 2025:12:23 17:14:09+07:00
File Permissions                : -rw-r--r--
File Type                       : ODT
File Type Extension             : odt
MIME Type                       : application/vnd.oasis.opendocument.text
Creation-date                   : 2025:12:04 15:46:39.349197349
Editing-duration                : P0D
Editing-cycles                  : 1
Generator                       : LibreOffice/25.8.3.2$Linux_X86_64 LibreOffice_project/580$Build-2
Document-statistic Table-count  : 0
Document-statistic Image-count  : 2
Document-statistic Object-count : 0
Document-statistic Page-count   : 3
Document-statistic Paragraph-count: 11
Document-statistic Word-count   : 557
Document-statistic Character-count: 3440
Document-statistic Non-whitespace-character-count: 2885
Preview PNG                     : (Binary data 35258 bytes, use -b option to extract)

```

File teridentifikasi sebagai dokumen **ODT (OpenDocument Text)**, yang pada dasarnya adalah arsip ZIP.

### 2. Ekstraksi File (Unzip)

Karena struktur ODT adalah ZIP, kita dapat melihat isinya dan mengekstraknya untuk menganalisis komponen internalnya (gambar, xml, dll).

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog]
└─$ unzip -l zippy-the-frog.odt
Archive:  zippy-the-frog.odt
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2025-12-05 10:46   Configurations2/
        0  2025-12-05 04:55   META-INF/
     1307  2025-12-05 10:46   META-INF/manifest.xml
        0  2025-12-05 04:55   Pictures/
   124150  2025-12-05 10:46   Pictures/100000000000078000000438F9D94128.png
  2671501  2025-12-05 10:46   Pictures/10000001000006400000047C6DEDFA93.png
        0  2025-12-05 04:55   Thumbnails/
    35258  2025-12-05 10:46   Thumbnails/thumbnail.png
     9772  2025-12-05 04:56   content.xml
      899  2025-12-05 10:46   manifest.rdf
      930  2025-12-05 10:46   meta.xml
       39  2025-12-05 10:46   mimetype
    14984  2025-12-05 10:46   settings.xml
    14011  2025-12-05 10:46   styles.xml
---------                     -------
  2872851                     14 files

```

Kita juga mencoba menggunakan `bkcrack` untuk memastikan tidak ada enkripsi zip legasi, lalu melakukan ekstraksi full.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog]
└─$ bkcrack -L zippy-the-frog.odt
bkcrack 1.8.0 - 2025-08-18
Archive: zippy-the-frog.odt
Index Encryption Compression CRC32    Uncompressed  Packed size Name
----- ---------- ----------- -------- ------------ ------------ ----------------
    0 None       Store       00000000            0            0 Configurations2/
    1 None       Store       00000000            0            0 META-INF/
    2 None       Deflate     525f787e         1307          347 META-INF/manifest.xml
    3 None       Store       00000000            0            0 Pictures/
    4 None       Deflate     43e05dd3       124150       118211 Pictures/100000000000078000000438F9D94128.png
    5 None       Deflate     1caf858c      2671501      2672316 Pictures/10000001000006400000047C6DEDFA93.png
    6 None       Store       00000000            0            0 Thumbnails/
    7 None       Deflate     c22b7ee8        35258        34673 Thumbnails/thumbnail.png
    8 None       Deflate     a5d62a12         9772         3059 content.xml
    9 None       Deflate     d268f7b4          899          262 manifest.rdf
   10 None       Deflate     58f7eb46          930          437 meta.xml
   11 None       Deflate     0c32c65e           39           41 mimetype
   12 None       Deflate     d4ad1d16        14984         2091 settings.xml
   13 None       Deflate     f2d6f7bd        14011         2550 styles.xml

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog]
└─$ unzip zippy-the-frog.odt
Archive:  zippy-the-frog.odt
   creating: Configurations2/
   creating: META-INF/
  inflating: META-INF/manifest.xml
   creating: Pictures/
  inflating: Pictures/100000000000078000000438F9D94128.png
  inflating: Pictures/10000001000006400000047C6DEDFA93.png
   creating: Thumbnails/
  inflating: Thumbnails/thumbnail.png
  inflating: content.xml
  inflating: manifest.rdf
  inflating: meta.xml
  inflating: mimetype
  inflating: settings.xml
  inflating: styles.xml

```

### 3. Analisis Gambar (Rabbit Hole)

Terdapat folder `Pictures/` yang berisi dua gambar. Kita melakukan analisis mendalam pada gambar yang berukuran lebih besar (`10000001000006400000047C6DEDFA93.png`) menggunakan berbagai tools steganografi.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog/Pictures]
└─$ ls
100000000000078000000438F9D94128.png  10000001000006400000047C6DEDFA93.png

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog/Pictures]
└─$ file 10000001000006400000047C6DEDFA93.png
10000001000006400000047C6DEDFA93.png: PNG image data, 1600 x 1148, 8-bit/color RGBA, non-interlaced

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog/Pictures]
└─$ exiftool 10000001000006400000047C6DEDFA93.png
ExifTool Version Number         : 13.36
...
MIME Type                       : image/png
Image Width                     : 1600
Image Height                    : 1148
...

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog/Pictures]
└─$ binwalk 10000001000006400000047C6DEDFA93.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1600 x 1148, 8-bit/color RGBA, non-interlaced
62            0x3E            Zlib compressed data, default compression

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog/Pictures]
└─$ zsteg 10000001000006400000047C6DEDFA93.png
imagedata           .. file: Tower/XP rel 3 object not stripped
b1,g,lsb,xy         .. text: "x>?%@g,1B"
...

```

Hasil analisis menunjukkan gambar ini kemungkinan besar hanya pengalih perhatian (red herring) atau aset dokumen biasa, karena tidak ditemukan data tersembunyi yang valid.

### 4. Menemukan Flag

Kita beralih ke gambar satunya yang bernama `100000000000078000000438F9D94128.png`.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog/Pictures]
└─$ file 100000000000078000000438F9D94128.png
100000000000078000000438F9D94128.png: PNG image data, 1920 x 1080, 8-bit/color RGB, non-interlaced

```

Kita membuka gambar tersebut menggunakan image viewer terminal `fim`:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Zippy the Frog/Pictures]
└─$ fim 100000000000078000000438F9D94128.png

```

Hasilnya, flag tertulis langsung di dalam gambar:

## Flag

`DSU{v3ry_c00l_z1ppy}`
