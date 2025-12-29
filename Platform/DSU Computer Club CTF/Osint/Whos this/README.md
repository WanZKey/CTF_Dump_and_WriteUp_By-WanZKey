# WriteUp: Who's this?

## Informasi Tantangan

* **Nama:** Who's this?
* **Kategori:** OSINT
* **Poin:** 25
* **Author:** Gwen V.
* **Deskripsi:**
> Who's this?
> Who's this guy?
> Submit the flag in the format DSU{Firstname_Lastname}
> This is a club activity for 9/25, but feel free to solve and get points on your own.


* **File:** `who.jpg`

## Langkah Penyelesaian

### 1. Identifikasi Awal File

Langkah pertama adalah memeriksa jenis file yang diberikan untuk memastikan integritasnya.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU Computer Club CTF/Osint/Whos this?]
└─$ file who.jpg
who.jpg: JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=0], baseline, precision 8, 260x260, components 3

```

### 2. Analisis Metadata (ExifTool)

Selanjutnya, kita memeriksa metadata gambar menggunakan `exiftool` untuk mencari informasi tersembunyi seperti komentar, lokasi GPS, atau nama pembuat.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU Computer Club CTF/Osint/Whos this?]
└─$ exiftool who.jpg
ExifTool Version Number         : 13.36
File Name                       : who.jpg
Directory                       : .
File Size                       : 3.7 kB
File Modification Date/Time     : 2024:09:26 06:47:54+07:00
File Access Date/Time           : 2025:12:29 15:12:27+07:00
File Inode Change Date/Time     : 2025:12:23 19:13:23+07:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Exif Byte Order                 : Little-endian (Intel, II)
Quality                         : 10%
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 260
Image Height                    : 260
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 260x260
Megapixels                      : 0.068

```

**Analisis:**

* Resolusi gambar sangat kecil (260x260).
* Kualitas gambar rendah (Quality: 10%).
* Tidak ditemukan flag atau petunjuk teks eksplisit dalam metadata.

### 3. Reverse Image Search (Pencarian Gambar Terbalik)

Karena metadata tidak memberikan petunjuk langsung, langkah selanjutnya adalah melakukan pencarian berdasarkan visual gambar (OSINT).

1. **Aksi:** Mengunggah `who.jpg` ke mesin pencari gambar (Google Lens/Images).
2. **Kata Kunci Tambahan:** Mengingat format flag diawali dengan `DSU` (kemungkinan *Dakota State University*), pencarian difokuskan pada staf atau fakultas universitas tersebut.
3. **Hasil:** Pencarian mencocokkan wajah pada gambar dengan **Tom Halverson**.
4. **Jabatan:** Dean of the Beacom College of Computer and Cyber Sciences di Dakota State University.

### 4. Penyusunan Flag

Format flag yang diminta adalah `DSU{Firstname_Lastname}`.

* **Firstname:** Tom
* **Lastname:** Halverson

Maka flagnya adalah:
`DSU{Tom_Halverson}`

## Flag

```text
DSU{Tom_Halverson}

```
