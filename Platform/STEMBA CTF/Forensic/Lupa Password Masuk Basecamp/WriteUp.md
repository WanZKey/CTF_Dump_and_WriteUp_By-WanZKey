https://chatgpt.com/share/687e60dd-f6f4-8002-ad5e-3a0b477b620e
# Writeup CTF STEMBACTF - Lupa Password Masuk Basecamp (300pt)

**Kategori:** Forensik
**Author:** raffa

---

## Deskripsi

> Aku mau masuk basecamp, tapi aku lupa passwordnya, udah kusimpan di gambar, tapi kata adikku gambarnya terbelah karena XOR. Bisa bantu aku?

Kita diberi 3 file:

* `gmbr1.bmp`
* `gmbr2.bmp`
* `flag.zip`

---

## Langkah Penyelesaian

### 1. Melihat isi file

```bash
└─$ unzip chall.zip
  inflating: flag.zip
  inflating: gmbr2.bmp
  inflating: gmbr1.bmp

└─$ file gmbr1.bmp
gmbr1.bmp: PNG image data, 1088 x 256, 8-bit colormap, non-interlaced

└─$ file gmbr2.bmp
gmbr2.bmp: PNG image data, 1088 x 256, 8-bit colormap, non-interlaced
```

### 2. Analisis exiftool

```bash
└─$ exiftool gmbr1.bmp
File Type : PNG
Image Size : 1088x256

└─$ exiftool gmbr2.bmp
File Type : PNG
Image Size : 1088x256
```

### 3. Petunjuk soal: "gambar terbelah karena XOR"

Berarti kita harus melakukan XOR antar `gmbr1.bmp` dan `gmbr2.bmp` untuk mendapatkan gambarnya kembali.

---

## Script XOR Gambar

```python
# xor_images.py
with open("gmbr1.bmp", "rb") as f1, open("gmbr2.bmp", "rb") as f2:
    data1 = f1.read()
    data2 = f2.read()

# XOR byte per byte
xor_result = bytes([b1 ^ b2 for b1, b2 in zip(data1, data2)])

# Simpan hasil
with open("gabungan.png", "wb") as out:
    out.write(xor_result)

print("[+] XOR berhasil, disimpan sebagai gabungan.png")
```

### 4. Menjalankan script XOR

```bash
└─$ python3 xor_images.py
[+] XOR berhasil, disimpan sebagai gabungan.png
```

### 5. Melihat isi gabungan.png

Hasil gambar menampilkan teks:

```
Lup4P4ssBasecamp
```

---

### 6. Ekstrak flag.zip dengan password hasil gambar

```bash
└─$ unzip flag.zip
[flag.zip] flag.txt password: Lup4P4ssBasecamp
  inflating: flag.txt
```

### 7. Lihat isi flag.txt

```bash
└─$ xxd flag.txt | head
00000000: k5wcu 5d3hi 6fjjj dp2fl ifqfs e3xul 6yxio rzd7  ...]
```

Terlihat seperti base32 ciphertext.

---

## Decode Base32 Berulang

Setelah analisis lebih dalam, ditemukan bahwa data pada `flag.txt` merupakan **base32 encoded string sebanyak 14x**.

---

## Script Decode Base32 (14x)

```python
# decoder.py
import base64

with open("flag.txt", "rb") as f:
    data = f.read()

for i in range(14):
    try:
        data = base64.b32decode(data)
        print(f"[+] Iterasi ke-{i+1}: berhasil decode")
    except Exception as e:
        print(f"[!] Gagal decode pada iterasi ke-{i+1}: {e}")
        break

try:
    hasil_akhir = data.decode()
    print("\n[+] Hasil akhir decoding:")
    print(hasil_akhir)
except UnicodeDecodeError:
    print("\n[!] Tidak bisa decode ke UTF-8.")
```

### Output Script:

```bash
└─$ python3 decoder.py
[+] Iterasi ke-1: berhasil decode
[+] Iterasi ke-2: berhasil decode
[+] Iterasi ke-3: berhasil decode
[+] Iterasi ke-4: berhasil decode
[+] Iterasi ke-5: berhasil decode
[+] Iterasi ke-6: berhasil decode
[+] Iterasi ke-7: berhasil decode
[+] Iterasi ke-8: berhasil decode
[+] Iterasi ke-9: berhasil decode
[+] Iterasi ke-10: berhasil decode
[+] Iterasi ke-11: berhasil decode
[+] Iterasi ke-12: berhasil decode
[+] Iterasi ke-13: berhasil decode
[+] Iterasi ke-14: berhasil decode

[+] Hasil akhir decoding:
STEMBACTF{0ooppss_4r3_y0u_luCky_0r_ju5t_g00d_4t_1t}
```

---

## 🏁 Flag:

```
STEMBACTF{0ooppss_4r3_y0u_luCky_0r_ju5t_g00d_4t_1t}
```

---

## ✅ Summary:

* XOR dua gambar → dapat password zip
* Ekstrak zip → dapat flag.txt
* Decode base32 sebanyak 14x → dapat flag


