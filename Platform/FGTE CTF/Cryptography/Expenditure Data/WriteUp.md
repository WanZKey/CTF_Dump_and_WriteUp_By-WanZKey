
# Writeup: Expenditure Data

## Informasi Challenge

* **Event:** ARIAF CTF 2025
* **Kategori:** Cryptography / Steganography
* **Poin:** 290
* **Hint:** "Spam bukan selalu spam"
* **File:** `expense.txt`

## Analisis

Challenge memberikan sebuah file `expense.txt` berisi data pengeluaran bulanan yang terlihat seperti file CSV biasa. Namun, hint **"Spam bukan selalu spam"** merupakan petunjuk kuat yang mengarah ke **Spam Mimic**, sebuah layanan steganografi klasik yang dapat menyembunyikan pesan di dalam teks yang terlihat seperti spam atau data acak.

Isi file tersebut sesuai dengan format yang dihasilkan oleh fitur **Spreadsheet** dari Spam Mimic, di mana pesan disembunyikan dalam nilai-nilai angka dan kategori pengeluaran palsu.

## Langkah Penyelesaian

1. **Identifikasi Tools**
Berdasarkan hint dan format data (Spreadsheet/CSV), tools yang tepat untuk digunakan adalah **Spam Mimic Spreadsheet Decoder**.
* **URL:** `https://www.spammimic.com/spreadsheet.php`


2. **Proses Decoding**
* Buka file `expense.txt` dan salin seluruh isinya.
* Buka situs Spam Mimic pada bagian **Decode**.
* Paste isi `expense.txt` ke dalam kolom input.
* Klik tombol **Decode**.


3. **Hasil**
Setelah proses decode selesai, pesan asli yang tersembunyi di balik angka-angka pengeluaran tersebut ditampilkan.
Output dari decoder:
```text
FGTE{D4ta_P3n9eluaran_yang_w3eeiiird!}

```



## Flag

```text
FGTE{D4ta_P3n9eluaran_yang_w3eeiiird!}

```
