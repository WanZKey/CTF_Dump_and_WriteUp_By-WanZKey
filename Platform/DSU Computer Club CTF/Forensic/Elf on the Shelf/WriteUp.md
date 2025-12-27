# DSU CTF 2025: Elf on the Shelf Writeup

**Category:** Forensics
**Points:** 100
**Author:** Iurii C.

## Deskripsi Challenge

> I never watched the movie, but I do like this guy's haircut. I wanted to show it to my barber, but to my embarassment, I couldn't open the picture when I needed it! Help me recover it.

## Langkah Pengerjaan

### 1. Analisis Awal

Melakukan pengecekan jenis file. File terdeteksi hanya sebagai "data" dan `exiftool` melaporkan format error.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Elf on the Shelf]
└─$ file elf.jpg
elf.jpg: data

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Elf on the Shelf]
└─$ exiftool elf.jpg
...
Error                           : File format error

```

### 2. Analisis Hex (Magic Bytes)

Memeriksa header file menggunakan `xxd` untuk melihat apakah *Magic Bytes*-nya sesuai dengan standar JPEG.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Elf on the Shelf]
└─$ xxd elf.jpg | head -n 5
00000000: 6700 67e0 0010 4a46 4946 0001 0101 0048  g.g...JFIF.....H

```

* **Temuan:** 4 byte pertama adalah `67 00 67 e0`.
* **Seharusnya:** Header standar JPEG (JFIF) adalah `ff d8 ff e0`.

### 3. Perbaikan Header (Patching)

Kita memperbaiki 4 byte pertama file agar sesuai dengan signature JPEG menggunakan perintah `dd`.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Elf on the Shelf]
└─$ printf '\xff\xd8\xff\xe0' | dd of=elf.jpg bs=1 seek=0 count=4 conv=notrunc
4+0 records in
4+0 records out
4 bytes copied, 0.0203844 s, 0.2 kB/s

```

### 4. Verifikasi Hasil

Setelah di-patch, file diperiksa kembali untuk memastikan formatnya sudah valid.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/Elf on the Shelf]
└─$ file elf.jpg
elf.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, progressive, precision 8, 718x1024, components 3

```

Gambar berhasil dibuka dan flag terlihat tertulis di dalamnya.

## Flag

`DSU{t4mp3r3d_with_jp3g}`
