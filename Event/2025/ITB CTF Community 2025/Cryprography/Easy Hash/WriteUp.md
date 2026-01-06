https://gemini.google.com/share/c5896da64015
### Analisis Kerentanan

1.  **Mekanisme Token:** Server menggunakan token yang diformat sebagai `key1=val1:::key2=val2...` dan ditandatangani dengan "HMAC" buatan sendiri.
2.  **HMAC yang Rentan:** Fungsi `get_hmac` menggunakan `sha256(KEY + data)`. Ini adalah konstruksi klasik yang rentan terhadap **Hash Length Extension Attack**. Jika kita tahu `hash(secret || message)` dan panjang `secret`, kita dapat menghitung `hash(secret || message || padding || extra_message)` tanpa mengetahui `secret`.
3.  **Panjang Kunci (Secret):** Script memberi tahu kita panjang `KEY` secara eksplisit: `KEY = os.urandom(32)`. Jadi, panjang kuncinya adalah 32 byte.
4.  **Tujuan (Request Secret):** Untuk mendapatkan *flag*, kita harus memanggil fungsi `request_secret` (pilihan 3) dengan token yang valid di mana `user_data["authorized"] == "true"`.
5.  **Masalah:** Saat mendaftar, server selalu memberikan token dengan `authorized="false"`.
6.  **Bocoran Flag (Leak):** Jika kita berhasil lolos cek `authorized == "true"`, server akan:
      * Mengambil `user_id` dari token kita dan mengubahnya dari string biner ke integer: `user_id = int(user_data["user_id"], 2)`.
      * Menghitung tiga hash dari tiga potong *flag* yang berdekatan:
          * `enc1 = H(FLAG[user_id : user_id + 3])`
          * `enc2 = H(FLAG[user_id + 3 : user_id + 6])`
          * `enc3 = H(FLAG[user_id + 6 : user_id + 9])`
      * Memberi kita hasil *perkalian* ketiganya: `enc1 * enc2 * enc3`.

### Rencana Serangan

1.  **Langkah 1: Dapatkan Token Asli**

      * Kita akan mendaftar (pilihan 1) dengan nama "admin" untuk mendapatkan token dasar yang valid (`original_data` dan `original_hmac`).
      * `original_data` = `b"user_id=0:::name=admin:::authorized=false"`
      * `original_hmac` = (didapat dari server)

2.  **Langkah 2: Lakukan Serangan Hash Length Extension**

      * Kita perlu mem-bypass cek otorisasi *dan* mengontrol `user_id`.
      * Kita akan menggunakan *length extension attack* untuk menambahkan data ke `original_data`. Data yang ingin kita tambahkan adalah: `b":::authorized=true:::user_id=BINARY_STRING"`
      * Saat `parse_token` memproses token baru kita (yang berisi *padding* SHA256), ia akan mem-parsing `key=value` satu per satu. Nilai `authorized=true` dan `user_id=BINARY_STRING` yang kita tambahkan akan *menimpa* nilai `authorized=false` dan `user_id=0` yang asli.

3.  **Langkah 3: Manfaatkan Bocoran (Leak Oracle)**

      * Kita tahu `len(FLAG) == 78`. Flag ini terdiri dari 26 potong 3-byte.
      * Kita perlu membocorkan flag 3 byte demi 3 byte.
      * Kita tahu bahwa setiap *slice* dari *flag* yang berada di luar batas (misal, `FLAG[78:81]`) akan menghasilkan string kosong `b""`.
      * Hash dari string kosong, `H(b"")`, adalah nilai konstan yang bisa kita hitung. Mari sebut `H_EMPTY`.
      * **Serangan Inti:** Kita akan bekerja *mundur* dari akhir *flag*.
      * **Iterasi 1 (user\_id = 75):**
          * Kita buat token dengan `user_id = bin(75)[2:]` (yaitu `"1001011"`).
          * Server akan menghitung: `leak = H(FLAG[75:78]) * H(FLAG[78:81]) * H(FLAG[81:84])`
          * Ini disederhanakan menjadi: `leak = H(FLAG[75:78]) * H_EMPTY * H_EMPTY`
          * Kita bisa menyelesaikan `H(FLAG[75:78]) = leak // (H_EMPTY * H_EMPTY)`.
      * **Iterasi 2 (user\_id = 72):**
          * Kita buat token dengan `user_id = bin(72)[2:]` (yaitu `"1001000"`).
          * Server menghitung: `leak = H(FLAG[72:75]) * H(FLAG[75:78]) * H(FLAG[78:81])`
          * Ini disederhanakan menjadi: `leak = H(FLAG[72:75]) * H(FLAG[75:78]) * H_EMPTY`
          * Kita sudah tahu `H(FLAG[75:78])` dari langkah sebelumnya.
          * Kita bisa menyelesaikan `H(FLAG[72:75]) = leak // (H(FLAG[75:78]) * H_EMPTY)`.
      * **Iterasi 3 (user\_id = 69):**
          * Server menghitung: `leak = H(FLAG[69:72]) * H(FLAG[72:75]) * H(FLAG[75:78])`
          * Kita tahu `H(FLAG[72:75])` dan `H(FLAG[75:78])` dari dua langkah sebelumnya.
          * Kita bisa menyelesaikan `H(FLAG[69:72]) = leak // (H(FLAG[72:75]) * H(FLAG[75:78]))`.

4.  **Langkah 4: Bruteforce Hash**

      * Kita akan mengulangi proses ini untuk `user_id = 75, 72, 69, ... 3, 0`.
      * Di setiap langkah, kita mendapatkan `target_hash` untuk 3 byte *flag*.
      * Karena ini hanya 3 byte, kita bisa melakukan *bruteforce* pada hash `sha256` tersebut untuk menemukan 3 karakter aslinya.
      * Kita gabungkan semua 26 potongan 3-byte untuk mendapatkan *flag* lengkap.

### Skrip Exploit

Anda memerlukan library `pwntools` dan `hashpumpy` untuk menjalankan skrip ini.

```bash
pip install pwntools hashpumpy
```

Berikut adalah skrip Python lengkap untuk menyelesaikan tantangan:

```python
#!/usr/bin/env python3

from pwn import *
import base64
import hashpumpy
from hashlib import sha256
from libnum import s2n, n2s
import itertools
import string
import time

# --- Konfigurasi ---
HOST = "163.47.10.146"
PORT = 8570

# --- Konstanta ---
KEY_LEN = 32
FLAG_LEN = 78
H_EMPTY = s2n(sha256(b"").digest())

# Cache untuk bruteforce (opsional tapi mempercepat jika ada karakter berulang)
bruteforce_cache = {}

def crack_3_bytes(target_hash):
    """
    Bruteforce hash SHA256 dari string 3-byte.
    """
    if target_hash in bruteforce_cache:
        return bruteforce_cache[target_hash]

    # Asumsi flag berisi karakter yang bisa dicetak (printable)
    # Jika gagal, Anda bisa menggantinya dengan range(256) untuk semua byte
    # Namun, string.printable (100 char) jauh lebih cepat daripada 256^3
    possible_chars = string.printable.encode('latin-1')

    # Coba karakter umum terlebih dahulu
    common_chars = (string.ascii_letters + string.digits + "_{}?!@#$").encode('latin-1')
    for a, b, c in itertools.product(common_chars, repeat=3):
        chunk = bytes([a, b, c])
        h_num = s2n(sha256(chunk).digest())
        if h_num == target_hash:
            log.success(f"Ditemukan chunk (common): {chunk.decode('latin-1')}")
            bruteforce_cache[target_hash] = chunk
            return chunk

    # Jika tidak ditemukan, coba semua yang printable
    log.warning("Mencoba semua karakter printable...")
    for a, b, c in itertools.product(possible_chars, repeat=3):
        chunk = bytes([a, b, c])
        h_num = s2n(sha256(chunk).digest())
        if h_num == target_hash:
            log.success(f"Ditemukan chunk (printable): {chunk.decode('latin-1')}")
            bruteforce_cache[target_hash] = chunk
            return chunk

    log.error(f"Bruteforce gagal untuk hash: {target_hash}")
    return b"???"

def get_leak(r, original_hmac, original_data, user_id_str):
    """
    Melakukan hash length extension dan mengambil bocoran dari server.
    """
    data_to_add = f":::authorized=true:::user_id={user_id_str}".encode('latin-1')
    
    # Lakukan length extension
    new_hmac, new_data = hashpumpy.hashpump(original_hmac, original_data, data_to_add, KEY_LEN)
    
    # Buat token baru
    token_data = new_data + b":::hmac=" + new_hmac.encode('latin-1')
    final_token = base64.b64encode(token_data)
    
    # Kirim ke server
    r.sendlineafter(b"Enter your choice: ", b"3")
    r.sendlineafter(b"Enter access token: ", final_token)
    
    r.recvuntil(b"away...\n")
    leak_str = r.recvline().strip().decode()
    
    return int(leak_str)

def main():
    r = remote(HOST, PORT)
    
    # 1. Registrasi untuk mendapatkan token awal
    r.sendlineafter(b"Enter your choice: ", b"1")
    r.sendlineafter(b"Who are you?\n>>> ", b"admin")
    r.recvuntil(b"Your access token: ")
    b64_token = r.recvline().strip().decode()
    
    # Decode token
    token_bytes = base64.b64decode(b64_token)
    original_data, original_hmac = token_bytes.split(b":::hmac=")
    original_hmac = original_hmac.decode('latin-1')
    
    log.info("Berhasil mendapatkan token awal.")
    
    known_hashes = {}
    flag_parts = {}
    
    # 2. Loop mundur dari akhir flag
    for i in range(FLAG_LEN - 3, -1, -3):
        log.info(f"Mencoba membocorkan FLAG[{i}:{i+3}]...")
        user_id_str = bin(i)[2:]
        
        # Ambil bocoran dari server
        leak = get_leak(r, original_hmac, original_data, user_id_str)
        
        # Dapatkan hash yang sudah diketahui dari langkah sebelumnya
        h2 = known_hashes.get(i + 3, H_EMPTY)
        h3 = known_hashes.get(i + 6, H_EMPTY)
        
        # Hitung target hash
        if (leak % (h2 * h3)) != 0:
            log.error("Terjadi kesalahan! Hash tidak dapat dibagi habis.")
            break
            
        target_hash = leak // (h2 * h3)
        known_hashes[i] = target_hash
        
        # 3. Bruteforce hash
        chunk = crack_3_bytes(target_hash)
        flag_parts[i] = chunk.decode('latin-1')
        
        # Tampilkan progres
        current_flag = ""
        for j in range(0, FLAG_LEN, 3):
            current_flag += flag_parts.get(j, "...")
        log.info(f"Flag sementara: {current_flag}")

    r.close()
    
    # 4. Gabungkan flag
    log.success("Selesai! Menggabungkan flag...")
    full_flag = ""
    for i in range(0, FLAG_LEN, 3):
        full_flag += flag_parts.get(i, "???")
        
    print(f"\n[+] FLAG: {full_flag}\n")

if __name__ == "__main__":
    main()
```
