https://gemini.google.com/share/f3818452508e
# WriteUp: Crypto 2 - CBC Bit Flipping Attack

## Informasi Tantangan

* **Nama Challenge:** Crypto 2
* **Kategori:** Cryptography
* **Platform:** Practice Digital Security Lab (Unipi)
* **Poin:** 500

## Deskripsi

Tantangan ini menyajikan layanan enkripsi AES dalam mode **CBC (Cipher Block Chaining)**.
Terdapat dua fitur utama:

1. **Enkripsi:** Menerima input `username`, membuat struktur JSON `{"user": username, "access_time": ...}`, lalu mengenkripsinya. Sistem menolak input jika `username` adalah "admin".
2. **Dekripsi:** Menerima `token` (ciphertext) dan `iv`. Jika hasil dekripsi mengandung `"user": "admin"`, server akan memberikan flag.

Tujuannya adalah memanipulasi ciphertext atau IV agar server membaca user sebagai "admin".

## Analisis Kerentanan (CBC Bit Flipping)

Dalam mode AES-CBC, proses dekripsi untuk blok pertama bergantung pada **Initialization Vector (IV)**.

Rumus matematika dekripsi blok pertama () adalah:


Dimana:

*  = Plaintext blok pertama.
*  = Hasil dekripsi blok cipher pertama dengan Kunci.
*  = Initialization Vector.
*  = Operasi XOR.

**Celah Keamanan:**
Server mengizinkan pengguna untuk mengirimkan **IV** sendiri pada endpoint `/api/decrypt_message/`. Ini memungkinkan serangan **Bit Flipping**.

Jika kita memodifikasi 1 byte pada IV (misal pada indeks ), maka 1 byte pada posisi yang sama di Plaintext hasil dekripsi juga akan berubah sesuai rumus:

Ini berarti kita bisa mengubah karakter tertentu pada Plaintext tanpa mengetahui kuncinya.

## Strategi Eksploitasi

### 1. Payload Awal

Kita tidak bisa mengenkripsi "admin" secara langsung. Kita akan mengenkripsi username yang sangat mirip, yaitu "**bdmin**".

* Target: `admin` (Hex: `61`)
* Fake: `bdmin` (Hex: `62`)
* Perbedaan hanya 1 bit/karakter.

### 2. Menentukan Target Byte

Struktur JSON yang dibuat Python secara default (`json.dumps`) memiliki spasi setelah separator:

```json
{"user": "bdmin", "access_time": ...}

```

Mari kita hitung posisi karakter 'b' pada string tersebut:

| Char | `{` | `"` | `u` | `s` | `e` | `r` | `"` | `:` | `     ` | `"` | **`b`** |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Index** | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | **10** |

Target kita adalah **Byte ke-10** (Index 10) dari IV.

### 3. Kalkulasi XOR

Kita ingin mengubah huruf 'b' menjadi 'a'.


## Solver Script

Berikut adalah script Python yang digunakan untuk melakukan serangan tersebut secara otomatis:

```python
import requests
import json

# Konfigurasi
URL = "http://practice-digitalsecuritylab.di.unipi.it:11002/api/"

def solve():
    print("[*] Memulai serangan CBC Bit Flipping...")

    # LANGKAH 1: Dapatkan Token & IV untuk "bdmin"
    # Kita gunakan "bdmin" karena panjangnya sama dengan "admin"
    s = requests.Session()
    res = s.post(URL + "get_encrypted_message/", json={"user": "bdmin"})
    data = res.json()
    
    token = data['token']
    iv_original_hex = data['iv']
    iv_original = bytes.fromhex(iv_original_hex)
    
    print(f"[+] Token didapat: {token[:10]}...")
    print(f"[+] IV Asli: {iv_original_hex}")

    # LANGKAH 2: Manipulasi IV (Bit Flipping)
    # Kita ubah byte ke-10 untuk mengubah 'b' menjadi 'a'
    # Posisi 10 didapat dari struktur: {"user": "bdmin"
    
    iv_list = list(iv_original)
    
    # Logic: New_IV_Byte = Old_IV_Byte XOR 'b' XOR 'a'
    # 'b' (0x62) XOR 'a' (0x61) = 0x03
    iv_list[10] = iv_list[10] ^ ord('b') ^ ord('a')
    
    iv_modified_hex = bytes(iv_list).hex()
    print(f"[+] IV Modifikasi: {iv_modified_hex}")

    # LANGKAH 3: Kirim Token Asli + IV Palsu
    payload = {
        "token": token,
        "iv": iv_modified_hex
    }
    
    res_dec = s.post(URL + "decrypt_message/", json=payload)
    print("\n[+] Respon Server:")
    print(json.dumps(res_dec.json(), indent=2))

if __name__ == "__main__":
    solve()

```

## Output Terminal

Berikut adalah hasil eksekusi dari script di atas yang berhasil mendapatkan flag:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Cryptography/Crypto 2]
└─$ python3 solver.py
[*] Memulai serangan CBC Bit Flipping...
[+] Token didapat: 1294053033...
[+] IV Asli: 46a7f85ab8bfa1d00a822ca5d34f0727
[+] IV Modifikasi: 46a7f85ab8bfa1d00a822fa5d34f0727

[+] Respon Server:
{
  "flag": "TRT{9e6f87a77d29a43c}",
  "msg": "Welcome admin!"
}

```

## Kesimpulan

Serangan berhasil. Server mendekripsi pesan menggunakan IV yang dimodifikasi, mengubah karakter "b" pada plaintext menjadi "a", sehingga JSON dibaca sebagai user "admin".

**Flag:** `TRT{9e6f87a77d29a43c}`
