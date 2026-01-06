https://chatgpt.com/share/687e57ec-5dfc-8002-a2df-e751de7aa0c3
# 🧊 STEMBACTF 2024 - File Snowwinterr (150 pts)

## 📁 Deskripsi Soal

Diberikan sebuah file gambar JPEG bernama `winterrrrrrr.jpg`. Soal memberikan clue:

> "Diberi surat dari orang yang tak dikenal, setelah dicek ada sebuah file yang bisa dilihat dan datanya aneh bisa dibaca tapi tidak beraturan, ternyata datanya diencrypt di tahun 58 & 45."

Tugas kita adalah mencari flag tersembunyi dalam file tersebut.

---

## 🧪 Analisis File

### 1. Cek Tipe File

```bash
$ file winterrrrrrr.jpg
winterrrrrrr.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, comment: "3YzANECFqv,72CZZA6S6L84"
```

📌 Terlihat ada **komentar tersembunyi** pada metadata JPEG:

```
Comment: 3YzANECFqv,72CZZA6S6L84
```

### 2. Periksa Metadata Lengkap

```bash
$ exiftool winterrrrrrr.jpg
...
Comment                         : 3YzANECFqv,72CZZA6S6L84
...
```

### 3. Petunjuk Soal: "diencrypt di tahun 58 & 45"

Interpretasi:

* Base58 dan Base45 encoding.

---

## 🔓 Proses Dekripsi

### ✨ Pisahkan String

Dari comment:

```
3YzANECFqv,72CZZA6S6L84
```

Dipisahkan menjadi:

* Base58 encoded: `3YzANECFqv`
* Base45 encoded: `72CZZA6S6L84`

### 🧮 Decode Base58

```python
>>> import base58
>>> base58.b58decode("3YzANECFqv")
b'CTF_1tu'
```

Hasil: `CTF_1tu`

### 🧮 Decode Base45

```python
>>> import base45
>>> base45.b45decode("72CZZA6S6L84")
b'_MUd4h!!'
```

Hasil: `_MUd4h!!`

### 🧩 Gabungkan Hasil

```
CTF_1tu + _MUd4h!! = CTF_1tu_MUd4h!!
```

---

## 🏁 Flag

```
STEMBACTF{CTF_1tu_MUd4h!!}
```

---

## ✅ Kesimpulan

Dengan memanfaatkan clue "tahun 58 dan 45", kita berhasil mengidentifikasi penggunaan Base58 dan Base45 encoding pada metadata JPEG. Setelah didekode, dua bagian tersebut digabungkan menjadi flag akhir.

Challenge ini melatih pemahaman tentang metadata, encoding, dan pengenalan pola dalam challenge forensik.
