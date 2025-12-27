# DSU CTF 2025: All Hexed Out Writeup

**Category:** Forensics
**Points:** 125
**Author:** Jacob R.

## Deskripsi Challenge

> Spin the magic, cook the width, stir the height, and you get this broken image. Can you fix it? P.S. the secret numbers are 400 and 400, pretty sure you'll want to know those.

## Langkah Pengerjaan

### 1. Analisis Awal

File yang diberikan adalah `fix_it.png`. Saat dicek, file ini tidak terdeteksi sebagai gambar valid.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/All Hexed Out]
└─$ file fix_it.png
fix_it.png: data

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/All Hexed Out]
└─$ exiftool fix_it.png
Error                           : File format error

```

### 2. Inspeksi Hex (Header & Dimensi)

Kita menggunakan `xxd` untuk melihat byte awal file.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/All Hexed Out]
└─$ xxd fix_it.png | head -n 5
00000000: 4341 4e55 4649 583f 0000 000d 4948 4452  CANUFIX?....IHDR
00000010: 0000 012c 0000 00c8 ...

```

Ditemukan beberapa kejanggalan:

1. **Magic Bytes (Header):** Bernilai `43 41 4E 55 46 49 58 3F` (`CANUFIX?`). Ini harus diubah menjadi signature standar PNG (`89 50 4E 47 0D 0A 1A 0A`).
2. **Dimensi (IHDR Chunk):**
* **Width (Offset 16):** `00 00 01 2c` (Hex) = 300.
* **Height (Offset 20):** `00 00 00 c8` (Hex) = 200.
* Berdasarkan hint soal (*"secret numbers are 400 and 400"*), dimensi harus diubah menjadi 400x400.
* 400 dalam Hex = `0x00000190`.



### 3. Perbaikan File (Python Script)

Dibuat script Python sederhana untuk melakukan *patching* pada byte yang salah tersebut.

```python
import struct

filename = "fix_it.png"

# Signature PNG standar
png_signature = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'

# Dimensi Target (400x400) -> 0x0190
width = struct.pack('>I', 400)
height = struct.pack('>I', 400)

with open(filename, 'r+b') as f:
    print(f"[*] Fixing Magic Bytes at offset 0...")
    f.seek(0)
    f.write(png_signature)
    
    print(f"[*] Fixing Width to 400 at offset 16...")
    f.seek(16)
    f.write(width)
    
    print(f"[*] Fixing Height to 400 at offset 20...")
    f.seek(20)
    f.write(height)

print("[+] Selesai! Coba buka gambar fix_it.png sekarang.")

```

### 4. Hasil

Setelah script dijalankan, file berhasil dikenali sebagai PNG yang valid.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU CTF/Forensics/All Hexed Out]
└─$ file fix_it.png
fix_it.png: PNG image data, 400 x 400, 8-bit/color RGB, non-interlaced

```

Membuka gambar tersebut menampilkan flag.

## Flag

`DSU{can_we_fix_it_yes_we_can!}`
