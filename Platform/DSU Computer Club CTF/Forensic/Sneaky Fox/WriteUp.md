# DSU CTF 2025: Sneaky Fox Writeup

**Category:** Forensics
**Points:** 75
**Author:** Jacob R.

## Deskripsi Challenge

> This fox might look innocent, but I think he's hiding something from us. I'm told some images might give you some more information about them if you look inside. See if you can find his secret.

## Langkah Pengerjaan

### 1. Identifikasi File

Langkah pertama adalah melakukan pengecekan dasar terhadap file yang diberikan untuk memastikan integritas dan tipe filenya menggunakan perintah `file`.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Sneaky Fox]
└─$ file sneaky_fox.jpeg
sneaky_fox.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, Exif Standard: [TIFF image data, big-endian, direntries=7, xresolution=98, yresolution=106, resolutionunit=1], baseline, precision 8, 185x272, components 3

```

### 2. Analisis Metadata (Exiftool)

Berdasarkan deskripsi soal *"look inside"*, hal ini sering kali mengacu pada metadata file. Kita menggunakan `exiftool` untuk melihat informasi tersembunyi di dalam header gambar.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Sneaky Fox]
└─$ exiftool sneaky_fox.jpeg
ExifTool Version Number         : 13.36
File Name                       : sneaky_fox.jpeg
Directory                       : .
File Size                       : 11 kB
File Modification Date/Time     : 2025:12:04 15:03:39+07:00
File Access Date/Time           : 2025:12:23 17:07:56+07:00
File Inode Change Date/Time     : 2025:12:23 17:07:54+07:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Exif Byte Order                 : Big-endian (Motorola, MM)
X Resolution                    : 1
Y Resolution                    : 1
Resolution Unit                 : None
Artist                          : Mr. Fox
Y Cb Cr Positioning             : Centered
Copyright                       : Sneaky Studios 2025
Exif Version                    : 0232
Components Configuration        : Y, Cb, Cr, -
User Comment                    : RFNVe3lvdV9kMWRudF9nM3RfZm94M2QhfQ==
Flashpix Version                : 0100
Color Space                     : Uncalibrated
XMP Toolkit                     : Image::ExifTool 12.00
Camera Model                    : Sneaky Foxster V3
Image Width                     : 185
Image Height                    : 272
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 185x272
Megapixels                      : 0.050

```

Ditemukan sebuah string yang mencurigakan pada field **User Comment**:
`RFNVe3lvdV9kMWRudF9nM3RfZm94M2QhfQ==`

### 3. Decoding Flag

String tersebut diakhiri dengan `==` yang merupakan ciri khas encoding Base64. Kita menggunakan tools `basecrack` untuk melakukan decoding string tersebut.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Sneaky Fox]
└─$ basecrack

██████╗  █████╗ ███████╗███████╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██████╔╝███████║███████╗█████╗  ██║     ██████╔╝███████║██║     █████╔╝
██╔══██╗██╔══██║╚════██║██╔══╝  ██║     ██╔══██╗██╔══██║██║     ██╔═██╗
██████╔╝██║  ██║███████║███████╗╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝ v4.0

                python basecrack.py -h [FOR HELP]

[>] Enter Encoded Base: RFNVe3lvdV9kMWRudF9nM3RfZm94M2QhfQ==

[>] Decoding as Base64: DSU{you_d1dnt_g3t_fox3d!}

[-] The Encoding Scheme Is Base64

```

## Flag

`DSU{you_d1dnt_g3t_fox3d!}`
