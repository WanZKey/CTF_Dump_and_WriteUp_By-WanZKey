# WriteUp: Flip 2

## Overview

* **Judul:** Flip 2
* **Kategori:** Cryptography (Crypto)
* **Poin:** 25
* **Tingkat Kesulitan:** Medium/Hard
* **Deskripsi:** Masuk sebagai administrator.
* **URL:** `http://localhost:1337`

## Reconnaissance (Intel Gathering)

Tahap awal adalah memahami lingkungan dan bagaimana aplikasi menangani otentikasi.

### 1. Information Leak (Target User)

Saat membuka halaman login (`/login`), aplikasi secara tidak sengaja (atau sengaja) menampilkan daftar "System Administrators".

* **Target:** `administrator_5fe7716d` (Username ini berubah setiap restart container).
* **Masalah:** Kita tidak tahu password-nya, dan registrasi dengan nama ini diblokir.

### 2. Cookie Analysis

Setelah melakukan registrasi dan login dengan user biasa, kita menemukan dua cookie penting:

1. **`auth`:** String Base64 yang panjang.
* Setelah di-decode, strukturnya adalah: `[DATA USER] + [MAC (16 Byte)]`.
* Contoh: Jika user panjangnya 32 byte, total decoded bytes adalah 48 byte.


2. **`iv`:** String Base64 pendek (16 byte setelah decode). Ini adalah **Initialization Vector** untuk enkripsi AES-CBC.

### 3. Whitebox Analysis (Reverse Engineering)

Melalui analisis binary `app` menggunakan GDB:

* **Padding:** Fungsi `main.ZeroPadding` menunjukkan bahwa aplikasi menggunakan **Zero Padding** (`\x00`). Jika panjang data bukan kelipatan 16 (Block Size AES), server menambahkan Null Bytes sampai pas. Jika sudah pas, *tidak ada padding tambahan*.
* **Algorithm:** `main.calculateMAC` menggunakan `NewCBCEncrypter`. Ini mengonfirmasi skema **CBC-MAC**.

## Vulnerability Analysis (The Logic Flaw)

Celah keamanan terletak pada **CBC-MAC Forgery** yang memanfaatkan sifat **Zero Padding**.

### Konsep Collision

Dalam skema Zero Padding, server tidak bisa membedakan antara:

1. Null byte yang ditambahkan otomatis oleh sistem (Padding).
2. Null byte yang memang bagian dari input user (Payload kita).

Secara matematis:


Jika kita memiliki Target User  (`administrator_...`) dengan panjang 22 byte.
Untuk mencapai kelipatan 16 (Block Size), server butuh 32 byte.
Maka server secara internal melakukan:


Jika kita mendaftar dengan username  yang isinya adalah string  ditambah 10 Null Byte secara manual:


Karena , maka **MAC (Signature)** yang dihasilkan pun **IDENTIK**.

## Exploitation Strategy

Kita tidak perlu melakukan Bit Flipping yang rumit. Kita hanya perlu melakukan **Forgery** (pemalsuan) struktur data.

### Step 1: Target Calculation

* **Target:** `administrator_5fe7716d` (22 chars).
* **Block Alignment:** Kelipatan 16 terdekat adalah 32.
* **Padding Needed:**  bytes (`\x00`).

### Step 2: The "Trojan Horse" Registration

Kita mendaftar user baru dengan nama:
`administrator_5fe7716d` + `\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`

Server menerima ini sebagai user valid (32 byte). Server menghitung MAC dan memberikan kita cookie `auth` dan `iv`.

* **Cookie `auth`:** Berisi `[User Padded] + [Valid MAC]`.
* **Cookie `iv`:** Kunci pembuka enkripsi untuk sesi ini.

### Step 3: Cookie Forgery & Attack

Kita memanipulasi cookie `auth` secara lokal:

1. Ambil **Valid MAC** dari cookie user palsu.
2. Buat payload baru: `[User Asli (Tanpa Null Byte)] + [Valid MAC]`.
3. Encode kembali ke Base64.

Saat kita kirim cookie palsu ini **BERSAMAAN** dengan cookie `iv` yang asli ke server:

1. Server membaca `User Asli` (22 byte).
2. Server melihat panjangnya kurang, lalu melakukan **Auto-Padding** (tambah 10 Null Byte).
3. Hasil padding server sama persis dengan user palsu kita tadi.
4. MAC hasil hitungan server **COCOK** dengan MAC yang kita kirim.
5. **Login Sukses!**

### Solver Script (`exploit.py`)

```python
import requests
import sys
import base64

# GANTI DENGAN USERNAME DARI HALAMAN LOGIN
TARGET_ADMIN = "administrator_5fe7716d" 

TARGET_URL = "http://localhost:1337"
REGISTER_URL = f"{TARGET_URL}/register"
LOGIN_URL = f"{TARGET_URL}/login"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

def exploit():
    s = requests.Session()
    
    # 1. Hitung Padding
    target_len = len(TARGET_ADMIN)
    remainder = target_len % 16
    padding_len = 16 - remainder if remainder != 0 else 0

    # 2. Register User Palsu (Target + Null Bytes)
    fake_user_bytes = TARGET_ADMIN.encode() + (b"\x00" * padding_len)
    fake_user_str = fake_user_bytes.decode('latin-1') 
    password = "password123"

    print(f"[*] Target: {TARGET_ADMIN}")
    print(f"[*] Registering Padded User...")
    s.post(REGISTER_URL, data={"username": fake_user_str, "password": password})
    s.post(LOGIN_URL, data={"username": fake_user_str, "password": password})
    
    if not s.cookies:
        print("[-] Login failed.")
        return

    # 3. Identifikasi & Bedah Cookie
    # Kita butuh 'auth' (untuk dimodif) dan 'iv' (untuk pass-through)
    auth_cookie_name = "auth" # Default name
    if auth_cookie_name not in s.cookies:
        # Fallback logic cari cookie terpanjang
        auth_cookie_name = max(s.cookies, key=lambda k: len(s.cookies[k]))

    cookie_b64 = s.cookies[auth_cookie_name]
    
    try:
        cookie_raw = base64.b64decode(cookie_b64)
        mac_raw = cookie_raw[-16:]   # Ambil 16 byte terakhir (MAC)
        # Sisanya adalah username (yang ada paddingnya)
    except:
        print("[-] Error decoding.")
        return

    # 4. FORGE COOKIE
    # Gabung: Username Asli (22 byte) + MAC Valid (16 byte)
    # Total: 38 byte. Server akan nambah padding sendiri jadi 48 byte.
    real_user_bytes = TARGET_ADMIN.encode()
    forged_raw = real_user_bytes + mac_raw
    forged_b64 = base64.b64encode(forged_raw).decode()
    
    print(f"[*] Forged Cookie: {forged_b64}")
    
    # 5. Attack (PENTING: Bawa semua cookie termasuk IV)
    final_cookies = s.cookies.get_dict()
    final_cookies[auth_cookie_name] = forged_b64
    
    print("[*] Sending Forged Auth + Original IV...")
    r = requests.get(DASHBOARD_URL, cookies=final_cookies)
    
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

```bash
$ ./exploit.py
[*] Target: administrator_5fe7716d
[*] Registering Padded User...
[*] Forged Cookie: YWRtaW5pc3RyYXRvcl81ZmU3NzE2ZBiCw3MYZRXt12gu7hp5TgI=
[*] Sending Forged Auth + Original IV...

========================================
[+] PWNED! Flag Found:
<div class="flag-box">pwn{cd652d9b8cf2b0994bddf6f7e33a9a7e}</div>
========================================

```

## Flag

```
pwn{cd652d9b8cf2b0994bddf6f7e33a9a7e}

```
