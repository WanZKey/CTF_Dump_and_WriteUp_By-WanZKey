# WriteUp: Flip

## Overview

* **Judul:** Flip
* **Kategori:** Cryptography
* **Poin:** 25
* **Deskripsi:** Masuk sebagai administrator, admin, system, atau root.
* **URL:** `http://localhost:1337`

## Reconnaissance & Reverse Engineering

Tantangan ini menyediakan file binary `app` yang merupakan web server berbasis Go (Golang). Analisis dilakukan dengan metode Blackbox (observasi traffic) dan Whitebox (Reverse Engineering binary).

**1. Blackbox Analysis:**

* Aplikasi memiliki fitur Register dan Login.
* Setelah login, server memberikan cookie bernama `auth` berisi string Hexadecimal panjang (misal: `c81284...`).
* Cookie ini digunakan untuk otentikasi saat mengakses endpoint `/dashboard`.

**2. Whitebox Analysis (Disassembly):**
Berdasarkan hasil disassembly menggunakan GDB dan analisis simbol binary:

* **Enkripsi:** Fungsi `main.encrypt` menggunakan algoritma **AES-CBC**. Ciphertext yang dihasilkan terdiri dari **IV (16 byte)** diikuti oleh blok data terenkripsi.
* **Format Plaintext:** Pada fungsi `main.loginHandler`, sebelum data dienkripsi, username diformat menggunakan `fmt.Sprintf`. Analisis assembly menunjukkan panjang format string adalah 11 karakter, dan pengecekan prefix pada `dashboardHandler` memvalidasi 9 byte pertama. Ini mengindikasikan format plaintext:
```text
username=[INPUT_USER]

```


String `username=` memiliki panjang 9 karakter (index 0-8), sehingga input user dimulai pada **index ke-9**.
* **Validasi:** Fungsi `main.dashboardHandler` mendekripsi cookie dan membandingkan hasilnya dengan string `"admin"`, `"root"`, atau `"system"`.

## Vulnerability Analysis

Aplikasi memiliki kerentanan **CBC Bit Flipping Attack**.

Dalam mode operasi AES-CBC (Cipher Block Chaining), dekripsi blok pertama dilakukan dengan rumus matematika berikut:


Dimana:

*  = Plaintext blok pertama.
*  = Hasil dekripsi ciphertext blok pertama (yang tidak bisa kita ubah karena tidak tahu kuncinya).
*  = Initialization Vector (yang terdapat di awal cookie dan bisa kita manipulasi).

Karena sifat operasi XOR (), jika kita mengubah 1 byte pada **IV**, maka 1 byte pada **Plaintext** di posisi yang sama akan berubah sesuai dengan nilai manipulasi kita. Penyerang dapat mengubah isi plaintext (misalnya mengubah identitas user) tanpa perlu mengetahui kunci enkripsi.

## Exploitation

Tujuannya adalah login sebagai `admin`. Karena kita tidak bisa mendaftar dengan nama "admin" (biasanya diblokir atau sudah ada), kita akan menggunakan teknik Bit Flipping.

**Skenario Serangan:**

1. **Register & Login** dengan username **`bdmin`**.
* Alasan: Panjang string sama dengan `admin`. Karakter 'b' dan 'a' hanya berbeda sedikit secara bit.
* Plaintext Server: `username=bdmin`


2. **Identifikasi Target Byte:**
* Huruf yang ingin diubah adalah `b` (dari `bdmin`) menjadi `a`.
* Posisi huruf `b` berada di **Index 9** (setelah prefix `username=` yang panjangnya 9 byte).


3. **Kalkulasi XOR:**
* ASCII `b` = `0x62` (`0110 0010`)
* ASCII `a` = `0x61` (`0110 0001`)
* XOR Difference = `0x62 ^ 0x61 = 0x03`.


4. **Manipulasi Cookie:**
* Ambil 16 byte pertama dari cookie (IV).
* Ambil byte ke-9 dari IV.
* Lakukan operasi: `IV_Baru[9] = IV_Lama[9] ^ 0x03`.


5. **Kirim Cookie Palsu:** Server akan mendekripsi cookie tersebut menjadi `username=admin`.

**Script Solver (`exploit.py`):**

```python
import requests
import sys

# Konfigurasi
TARGET_URL = "http://localhost:1337"
REGISTER_URL = f"{TARGET_URL}/register"
LOGIN_URL = f"{TARGET_URL}/login"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

# Skenario: 'bdmin' -> 'admin'
# Plaintext Server: "username=bdmin..."
# 'username=' panjangnya 9 byte (index 0-8).
# Jadi huruf 'b' ada di INDEX 9.
FAKE_USER = "bdmin"
TARGET_USER = "admin"
PASSWORD = "password123"

def exploit():
    # 1. Register & Login (Gunakan Session)
    s = requests.Session()
    print(f"[*] Registering & Logging in as {FAKE_USER}...")
    s.post(REGISTER_URL, data={"username": FAKE_USER, "password": PASSWORD})
    s.post(LOGIN_URL, data={"username": FAKE_USER, "password": PASSWORD})
    
    if not s.cookies:
        print("[-] Login gagal.")
        return

    # Ambil cookie hex
    cookie_name = list(s.cookies.keys())[0]
    original_hex = s.cookies[cookie_name]
    print(f"[+] Got Cookie: {original_hex[:32]}...")

    # 2. Modifikasi Cookie (Bit Flipping)
    # Target: Ubah 'b' (dari bdmin) menjadi 'a' (admin)
    print(f"[*] Flipping bit at Index 9 (Target: 'b' -> 'a')...")
    
    cookie_bytes = bytearray.fromhex(original_hex)
    
    # Hitung XOR Difference
    # 'b' XOR 'a' = 3
    xor_diff = ord(FAKE_USER[0]) ^ ord(TARGET_USER[0])
    
    # Manipulasi IV pada Index 9 (karena ada prefix 'username=')
    cookie_bytes[9] ^= xor_diff
    
    forged_cookie_hex = cookie_bytes.hex()
    print(f"[+] Forged Cookie: {forged_cookie_hex[:32]}...")

    # 3. Kirim Request ke Dashboard
    # PENTING: Gunakan requests.get() baru (stateless) 
    # agar library tidak mengirim cookie lama dari session.
    print("[*] Sending Forged Cookie to Dashboard...")
    
    final_cookies = {cookie_name: forged_cookie_hex}
    r = requests.get(DASHBOARD_URL, cookies=final_cookies)
    
    # 4. Cek Flag
    if "pwn{" in r.text:
        print("\n" + "="*40)
        print("[+] PWNED! Flag Found:")
        for line in r.text.splitlines():
            if "pwn{" in line:
                print(f"    {line.strip()}")
        print("="*40 + "\n")
    else:
        print("[-] Gagal.")

if __name__ == "__main__":
    exploit()

```

## Execution Output

```bash
$ ./exploit.py
[*] Registering & Logging in as bdmin...
[+] Got Cookie: c81284383bde85d7460a08de1e01d0b6...
[*] Flipping bit at Index 9 (Target: 'b' -> 'a')...
[+] Forged Cookie: c81284383bde85d7460908de1e01d0b6...
[*] Sending Forged Cookie to Dashboard...

========================================
[+] PWNED! Flag Found:
    <strong>FLAG:</strong> pwn{ee64d81e4491db3eb171a0888b0cfe6f}
========================================

```

## Flag

```
pwn{ee64d81e4491db3eb171a0888b0cfe6f}

```
