https://g.co/gemini/share/88c995f9f92d

````markdown
# Write-Up CTF: Activation (Reverse)

Selamat atas keberhasilanmu menyelesaikan challenge reverse engineering ini. Berikut adalah write-up lengkap yang merinci setiap langkah dari analisis awal hingga penemuan flag.

## Informasi Challenge
| Kategori | Deskripsi |
| :--- | :--- |
| Reverse Engineering | Sebuah aplikasi aktivasi yang memerlukan username dan lisensi yang benar untuk mengungkapkan rahasia (flag). |

---

## 1. Analisis Awal
Challenge ini menyediakan sebuah file executable Windows bernama `activator.exe`. Langkah pertama adalah mengidentifikasi jenis file ini.

```bash
$ file activator.exe
activator.exe: PE32 executable for MS Windows ... Intel i386 Mono/.Net assembly ...
````

Output dari perintah `file` menunjukkan bahwa ini adalah **.NET Assembly**. Ini adalah petunjuk kunci, karena aplikasi .NET dapat didekompilasi kembali ke kode sumber (biasanya C\#) yang sangat mudah dibaca, berbeda dengan *native binary* dari C++. Untuk tugas ini, kita akan menggunakan decompiler .NET seperti **dnSpy**.

## 2\. Analisis Statis - Dekompilasi Kode

Dengan membuka `activator.exe` di dnSpy, kita dapat melihat seluruh struktur kode program. Titik awal analisis kita adalah fungsi `Main`, yang merupakan *entry point* dari aplikasi.

### Alur Program Utama

Fungsi `Main` mengungkapkan logika validasi program:

1.  Program menerima dua argumen dari command line: `username` dan `license`.
2.  Program memanggil `GetEmbeddedUsername()` untuk mendapatkan username yang seharusnya. Input dari pengguna kemudian dibandingkan dengan username ini.
3.  Jika username cocok, program memanggil `ExpectedLicense(username)` untuk menghasilkan lisensi yang benar. Lisensi ini dibandingkan dengan input dari pengguna.
4.  Jika lisensi juga cocok, program memanggil `DeriveKeyFromLicense(license)` untuk membuat sebuah kunci dekripsi.
5.  Terakhir, kunci ini digunakan oleh fungsi `DecryptBlob(key)` untuk mendekripsi data terenkripsi yang berisi flag.

Tugas kita adalah mereplikasi alur ini untuk menghasilkan flag.

## 3\. Mereplikasi Logika Kriptografi

Kita akan membedah setiap fungsi penting untuk merekonstruksi proses dari awal hingga akhir.

### Langkah 1: Menemukan Username yang Valid

Fungsi `GetEmbeddedUsername` membaca data dari variabel `userChunks`, menggabungkannya, dan melakukan decode Base64.

  - **`userChunks`**: `{"UkFOSQ=="}`
  - **Proses**: `Base64Decode("UkFOSQ==")`
  - **Hasil**: `RANI`

Username yang harus digunakan adalah **`RANI`**.

### Langkah 2: Menemukan Cryptographic Salt

Beberapa fungsi kriptografi dalam program ini menggunakan *salt* yang didapat dari fungsi `GetSalt`.

  - **`saltChunks`**: `{"c2FsdF9w", "YXJ0XzFf", "ZnJvbV9j", "cmU="}`
  - **Digabungkan**: `"c2FsdF9wYXJ0XzFfZnJvbV9jcmU="`
  - **Proses**: `Base64Decode(...)`
  - **Hasil**: `salt_part_1_from_cre`

Salt ini akan digunakan dalam pembuatan lisensi dan kunci dekripsi.

### Langkah 3: Menghasilkan Lisensi

Fungsi `ExpectedLicense` menggunakan algoritma **HMACSHA256**.

  - **Key**: Salt dari Langkah 2 (`salt_part_1_from_cre`).
  - **Pesan**: Username dari Langkah 1 (`RANI`).
  - **Proses**: Menghitung `HMAC-SHA256` dari pesan menggunakan key tersebut, lalu mengambil **8 byte pertama** dari hash dan mengubahnya menjadi string Heksadesimal.

### Langkah 4: Mendapatkan Kunci Dekripsi

Setelah mendapatkan lisensi yang valid, fungsi `DeriveKeyFromLicense` membuat kunci dekripsi.

  - **Data**: Lisensi valid (dari Langkah 3) digabungkan dengan representasi Base64 dari salt.
  - **Proses**: Data gabungan tersebut di-hash menggunakan **SHA256**.
  - **Hasil**: **16 byte pertama** dari hash SHA256 diambil sebagai kunci dekripsi AES-128.

### Langkah 5: Mendekripsi Flag

Fungsi `DecryptBlob` adalah langkah terakhir. Fungsi ini mendekripsi `encryptedBlob` menggunakan **AES-128** dalam mode **CBC**.

  - **Key**: Kunci 16-byte dari Langkah 4.
  - **IV (Initialization Vector)**: 16 byte pertama dari `encryptedBlob`.
  - **Ciphertext**: Sisa dari `encryptedBlob` (setelah 16 byte pertama).

## 4\. Skrip Solver

Berdasarkan analisis di atas, kita dapat membuat skrip Python untuk mengotomatiskan seluruh proses.

**`solver.py`**:

```python
import base64
import hmac
import hashlib
from Crypto.Cipher import AES

# Variabel statis dari dekompilasi
user_chunks = ["UkFOSQ=="]
salt_chunks = ["c2FsdF9w", "YXJ0XzFf", "ZnJvbV9j", "cmU="]
encrypted_blob = bytes([
    167, 164, 179, 68, 122, 43, 220, 205, 221, 237, 252, 140, 94, 60, 228, 168,
    158, 24, 12, 211, 42, 196, 123, 129, 112, 31, 108, 142, 85, 169, 138, 71,
    23, 244, 193, 140, 102, 155, 201, 244, 183, 5, 176, 49, 163, 24, 215, 196,
    212, 215, 159, 80, 85, 221, 12, 234, 16, 7, 169, 163, 172, 218, 85, 246
])

# Langkah 1: Mendapatkan username
username_b64 = "".join(user_chunks)
username = base64.b64decode(username_b64).decode('utf-8')
print(f"[*] Username ditemukan: {username}")

# Langkah 2: Mendapatkan salt
salt_b64 = "".join(salt_chunks)
salt = base64.b64decode(salt_b64)
print(f"[*] Salt ditemukan: {salt.decode('utf-8')}")

# Langkah 3: Menghasilkan lisensi
h = hmac.new(salt, username.encode('utf-8'), hashlib.sha256)
license_key = h.digest()[:8].hex().upper()
print(f"[+] Lisensi yang valid: {license_key}")

# Langkah 4: Mendapatkan kunci dekripsi (AES key)
data_to_hash = license_key.encode('utf-8') + base64.b64encode(salt)
aes_key = hashlib.sha256(data_to_hash).digest()[:16]
print(f"[*] Kunci AES (16 bytes): {aes_key.hex()}")

# Langkah 5: Mendekripsi flag
iv = encrypted_blob[:16]
ciphertext = encrypted_blob[16:]
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
decrypted_bytes = cipher.decrypt(ciphertext)

# Hapus padding PKCS7
padding_len = decrypted_bytes[-1]
flag = decrypted_bytes[:-padding_len].decode('utf-8')

print("\n" + "="*40)
print(f"🚩 FLAG: {flag}")
print("="*40)
```

## 5\. Mendapatkan Flag

Menjalankan skrip solver akan memberikan kita semua informasi yang dibutuhkan dan, pada akhirnya, flag itu sendiri.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Reverse/activation]
└─$ python3 solve.py
[*] Username ditemukan: RANI
[*] Salt ditemukan: salt_part_1_from_cre
[+] Lisensi yang valid: 0905E413DDF6D48B
[*] Kunci AES (16 bytes): ab5ca2c49a6e6f4425eb73d97f603242

========================================
🚩 FLAG: FGTE{L!c3n$3_4cTiv@t10n_7xY9_b2Q8R5s}
========================================
```

Flag-nya adalah **`FGTE{L!c3n$3_4cTiv@t10n_7xY9_b2Q8R5s}`**.

## Kesimpulan

Challenge ini adalah contoh klasik dari reverse engineering pada aplikasi .NET yang melibatkan beberapa lapisan kriptografi. Kunci keberhasilannya adalah memahami alur validasi program secara keseluruhan, kemudian dengan sabar mereplikasi setiap langkah—mulai dari decoding data statis hingga merekonstruksi algoritma hashing dan dekripsi—untuk akhirnya mengungkap rahasia yang tersembunyi.

```
```
