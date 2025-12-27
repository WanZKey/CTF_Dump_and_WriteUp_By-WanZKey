https://gemini.google.com/share/f3818452508e
# WriteUp: Crypto 1

## Informasi Tantangan

* **Nama Challenge:** Crypto 1
* **Kategori:** Cryptography
* **Platform:** Practice Digital Security Lab (Unipi)
* **Poin:** 500

## Deskripsi

Tantangan ini menyediakan layanan enkripsi AES dalam mode **CTR (Counter)**. Layanan menerima input username, menyisipkannya ke dalam struktur JSON bersama dengan flag, lalu mengembalikan ciphertext dalam format heksadesimal.

Tujuan utama adalah mendekripsi ciphertext untuk mendapatkan flag.

## Analisis Source Code

Kode sumber Python yang diberikan adalah sebagai berikut:

```python
import os
from flask import Flask, request
import json
from Crypto.Cipher import AES

app = Flask(__name__, static_url_path="")

# VULNERABILITAS UTAMA DI SINI
KEY = os.urandom(16)
NONCE = os.urandom(8)

@app.route("/api/get_encrypted_message/", methods=["GET", "POST"])
def get_encrypted_message():
    try:
        username = request.json["user"]
        # Format Plaintext
        token = json.dumps({"user": username, "flag": os.environ["FLAG"]})
        
        # Enkripsi
        enc_token = AES.new(KEY, AES.MODE_CTR, nonce=NONCE).encrypt(token.encode())
        return {"token": enc_token.hex(), "nonce": NONCE.hex()}
    except Exception as e:
        return {"error": str(e)}

```

### Identifikasi Kerentanan: Nonce Reuse

Dalam mode AES-CTR, enkripsi bekerja seperti *Stream Cipher*. Blok cipher menghasilkan *keystream* yang kemudian di-XOR dengan plaintext untuk menghasilkan ciphertext.

Persamaan matematisnya adalah:


Keystream dihasilkan berdasarkan **Key**, **Nonce**, dan **Counter**. Dalam kode di atas, `KEY` dan `NONCE` diinisialisasi secara global di luar fungsi route. Artinya, selama server berjalan, **Key dan Nonce tidak pernah berubah**.

Jika Nonce dan Key digunakan kembali (Nonce Reuse), maka urutan keystream yang dihasilkan akan selalu sama untuk setiap request.

Ini memungkinkan serangan **Known Plaintext Attack (KPA)**. Jika kita bisa menebak atau mengontrol sebagian dari plaintext (), kita bisa memulihkan Keystream dan menggunakannya untuk mendekripsi pesan lain.

## Strategi Penyelesaian

1. **Kontrol Plaintext:** Kita bisa mengontrol input `username`. Struktur JSON target adalah:
`{"user": "<INPUT_KITA>", "flag": "<FLAG_RAHASIA>"}`
2. **Dapatkan Keystream:**
* Kirim username yang sangat panjang (misal: huruf 'A' sebanyak 150 kali).
* Kita tahu persis bentuk plaintext awal: `{"user": "AAAAA...", "flag": "`
* Lakukan operasi XOR antara Ciphertext yang diterima dengan Plaintext buatan kita.
* Hasilnya adalah **Keystream**.


3. **Dekripsi Flag:**
* Kirim username pendek (misal: "a").
* Posisi byte flag sekarang akan bergeser maju ke posisi yang keystream-nya sudah kita ketahui.
* Lakukan XOR antara Ciphertext baru dengan Keystream yang didapat sebelumnya.



## Solver Script

Berikut adalah script dieksploitasi yang digunakan untuk menyelesaikan tantangan:

```python
import requests
import json
from pwn import xor

# URL Target
URL = "http://practice-digitalsecuritylab.di.unipi.it:11001/api/get_encrypted_message/"

def get_encrypted_token(username):
    """Mengambil ciphertext dalam bentuk bytes dari server"""
    try:
        data = {"user": username}
        response = requests.post(URL, json=data)
        if response.status_code == 200:
            return bytes.fromhex(response.json()['token'])
        else:
            print(f"[-] Error: {response.status_code}")
            exit()
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        exit()

def solve():
    print("[*] Memulai serangan Nonce Reuse...")

    # LANGKAH 1: Dapatkan Keystream menggunakan Known Plaintext
    # Kita kirim username panjang untuk meng-cover panjang flag
    dummy_input = "A" * 150
    ciphertext_long = get_encrypted_token(dummy_input)

    # Kita rekonstruksi plaintext yang pasti terbentuk di server
    # Format: {"user": "AAAA...", "flag": "
    # Catatan: json.dumps menambahkan spasi setelah separator secara default (': ', ', ')
    known_part = json.dumps({"user": dummy_input, "flag": ""})
    
    # Ambil bagian prefix sampai sebelum nilai flag dimulai
    # String: {"user": "AAAA...AAAA", "flag": "
    prefix_str = f'{{"user": "{dummy_input}", "flag": "'
    known_bytes = prefix_str.encode()

    # Recover Keystream
    # Keystream = Ciphertext XOR Plaintext
    # Kita hanya bisa recover keystream sepanjang known_bytes
    keystream = xor(ciphertext_long[:len(known_bytes)], known_bytes)
    
    print(f"[+] Keystream recovered ({len(keystream)} bytes)")

    # LANGKAH 2: Dekripsi Flag
    # Kirim username pendek agar posisi flag masuk ke area keystream yang sudah diketahui
    short_input = "a"
    ciphertext_short = get_encrypted_token(short_input)

    # Decrypt
    # Plaintext = Ciphertext XOR Keystream
    decrypted_data = xor(ciphertext_short, keystream[:len(ciphertext_short)])

    print("\n[+] Hasil Dekripsi:")
    try:
        print(decrypted_data.decode())
    except UnicodeDecodeError:
        print(decrypted_data)

if __name__ == "__main__":
    solve()

```

## Eksekusi dan Hasil

Menjalankan script solver di terminal:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Cryptography/Crypto 1]
└─$ python3 solver.py
[+] Keystream recovered (172 bytes)

[+] Hasil Dekripsi:
{"user": "a", "flag": "TRT{a1ed095ec5ea3e37}"}

```

## Kesimpulan

Bendera (Flag) berhasil didapatkan dengan memanfaatkan penggunaan ulang Nonce dan Key pada implementasi AES-CTR.

**Flag:** `TRT{a1ed095ec5ea3e37}`
