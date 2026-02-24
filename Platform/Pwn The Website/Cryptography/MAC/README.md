# WriteUp: MAC

## Overview

* **Judul:** MAC
* **Kategori:** Cryptography (Crypto)
* **Poin:** 50
* **Tingkat Kesulitan:** Hard
* **Deskripsi:** Masuk ke akun admin.
* **URL:** `http://localhost:1337`

## Reconnaissance (Pengumpulan Informasi)

Langkah pertama adalah memahami bagaimana aplikasi bekerja dan mengidentifikasi target serangan.

### 1. Blackbox Analysis & Information Leak

Saat mengakses halaman login (`/login`), terdapat informasi krusial yang bocor. Di bawah tombol login, terdapat daftar **"System Administrators"**.

* **Temuan:** Username admin digenerate secara acak setiap server restart.
* **Target User:** `administrator_6ad8be73` (Contoh dari sesi ini).
* **Cookie Format:** Setelah register/login user biasa, format cookie terlihat: `HEX_USERNAME|HEX_MAC`.

### 2. Whitebox Analysis (Reverse Engineering)

Menggunakan GDB dan `nm` untuk menganalisis binary `app` (Go Binary).

* **Algoritma MAC (`main.calculateMAC`):**
Fungsi ini tidak menggunakan HMAC standar (seperti HMAC-SHA256). Disassembly menunjukkan pemanggilan `crypto/cipher.NewCBCEncrypter`. Ini mengindikasikan penggunaan **CBC-MAC** (Cipher Block Chaining Message Authentication Code), yang pada dasarnya adalah blok terakhir dari enkripsi AES-CBC.
* **Mekanisme Padding (`main.ZeroPadding`):**
Analisis assembly pada fungsi ini menunjukkan logika pembagian (`idiv`).
* Jika panjang data adalah kelipatan 16 (Block Size AES), **tidak ada padding** yang ditambahkan.
* Jika tidak, data ditambah byte `\x00` (Null Byte) hingga mencapai kelipatan 16.


* **Secret Key (`main.init.0`):**
Kunci rahasia digenerate menggunakan `crypto/rand.ReadAtLeast`. Artinya, kunci bersifat acak dan **tidak bisa diambil** melalui *static analysis* (tidak hardcoded). Kita harus menyerang logikanya, bukan kuncinya.

## Vulnerability Analysis (Analisis Kerentanan)

Kerentanan utama terletak pada implementasi **CBC-MAC** yang dikombinasikan dengan **Zero Padding**.

### Konsep Serangan:

Dalam skema ini, server tidak membedakan antara:

1. **Padding Implisit:** Null byte yang ditambahkan otomatis oleh sistem saat memproses username asli.
2. **Padding Eksplisit:** Null byte yang memang menjadi bagian dari input username (jika kita mendaftar dengan nama tersebut).

### Logika Matematika:

Misalkan target kita adalah  (`administrator_6ad8be73`, panjang 22 byte).
AES Block Size = 16 byte.

1. **Sisi Server (Admin Asli):**
Saat memverifikasi , server melihat panjangnya 22 byte (bukan kelipatan 16).
Server menambahkan 10 byte `\x00` agar menjadi 32 byte (2 blok).



2. **Sisi Penyerang (User Palsu):**
Kita mendaftar dengan username  yang isinya adalah string  ditambah 10 byte `\x00` secara manual.
Panjang  = 32 byte (Pas kelipatan 16).
Karena sudah pas, fungsi `ZeroPadding` **tidak menambahkan apa-apa**.




**Kesimpulan:**
Karena input byte array ke fungsi enkripsi **identik**, maka MAC yang dihasilkan pun **identik**.


Kita bisa mendapatkan MAC yang valid untuk admin hanya dengan login menggunakan user palsu yang sudah dipadding.

## Exploitation (Langkah Penyelesaian)

### 1. Kalkulasi Padding

* **Target:** `administrator_6ad8be73`
* **Panjang String:** 22 karakter.
* **Target Panjang (Kelipatan 16):** 32 karakter.
* **Padding yang dibutuhkan:**  byte (`\x00`).

### 2. Register & Login User Palsu

Kita melakukan register dengan username:
`b'administrator_6ad8be73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'`

Server akan menerima ini, menghitung MAC-nya, dan memberikan cookie yang valid.

### 3. Cookie Forgery

Kita mengambil MAC dari cookie user palsu tersebut. Lalu, kita buat cookie baru:

* **Username:** `administrator_6ad8be73` (Hex encoded, tanpa null byte).
* **MAC:** MAC yang kita dapatkan dari langkah ke-2.

Saat dikirim ke server, server akan membaca username `administrator_6ad8be73`, menambahkan padding otomatis (karena kurang dari 32 byte), dan hasil verifikasi MAC akan **COCOK**.

### Solver Script

```python
import requests
import sys

# Username didapat dari halaman login (Information Leak)
TARGET_ADMIN = "administrator_6ad8be73" 

TARGET_URL = "http://localhost:1337"
REGISTER_URL = f"{TARGET_URL}/register"
LOGIN_URL = f"{TARGET_URL}/login"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

def exploit():
    s = requests.Session()
    
    # 1. Hitung Padding (Zero Padding Logic)
    target_len = len(TARGET_ADMIN)
    remainder = target_len % 16
    padding_len = 16 - remainder if remainder != 0 else 0

    # Bikin username palsu dengan Null Byte manual
    fake_user_bytes = TARGET_ADMIN.encode() + (b"\x00" * padding_len)
    fake_user_str = fake_user_bytes.decode('latin-1') 
    password = "password123"

    print(f"[*] Target Real : {TARGET_ADMIN} (Len: {target_len})")
    print(f"[*] Fake User   : {fake_user_bytes} (Len: {len(fake_user_bytes)})")

    # 2. Register & Login User Palsu
    # Server menghitung MAC("admin + padding manual"). 
    # Karena panjangnya pas blok, server tidak nambah padding lagi.
    print("[*] Registering & Logging in fake user...")
    s.post(REGISTER_URL, data={"username": fake_user_str, "password": password})
    s.post(LOGIN_URL, data={"username": fake_user_str, "password": password})
    
    if not s.cookies:
        print("[-] Login failed.")
        return

    full_cookie = list(s.cookies.values())[0]
    print(f"[+] Got Cookie   : {full_cookie}")
    
    # Extract MAC
    try:
        if '%7C' in full_cookie:
            _, mac_hex = full_cookie.split('%7C')
        else:
            _, mac_hex = full_cookie.split('|')
    except:
        print("[-] Error parsing cookie")
        return

    # 3. FORGE COOKIE
    # Gunakan Username ASLI (tanpa null) + MAC curian.
    # Server logic: Input "admin" -> Auto Padding "admin\0\0" -> Hitung MAC -> VALID!
    real_user_hex = TARGET_ADMIN.encode().hex()
    forged_cookie = f"{real_user_hex}|{mac_hex}"
    
    print(f"[*] Forged Cookie: {forged_cookie}")
    
    # 4. Access Dashboard
    # Gunakan request baru (stateless) untuk mengirim cookie palsu
    cookie_name = list(s.cookies.keys())[0]
    r = requests.get(DASHBOARD_URL, cookies={cookie_name: forged_cookie})
    
    if "pwn{" in r.text:
        print("\n" + "="*40)
        print("[+] PWNED! Flag Found:")
        for line in r.text.splitlines():
            if "pwn{" in line:
                print(line.strip())
        print("="*40 + "\n")
    else:
        print("[-] Failed.")

if __name__ == "__main__":
    exploit()

```

## Hasil Eksekusi

```text
[*] Target Real : administrator_6ad8be73 (Len: 22)
[*] Fake User   : b'administrator_6ad8be73\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
[+] Got Cookie   : 61646...00|addc810604804d7b13375776a5196332
[*] Forged Cookie: 61646...33|addc810604804d7b13375776a5196332
[+] PWNED! Flag Found:
<div class="flag-box">pwn{8494c57ab01f58edb2a8bc87fc088641}</div>

```

## Flag

```
pwn{8494c57ab01f58edb2a8bc87fc088641}

```
