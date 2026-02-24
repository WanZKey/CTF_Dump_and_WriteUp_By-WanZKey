#!/usr/bin/env python3
import requests
import jwt # pip install pyjwt

TARGET_URL = "http://localhost:1337"
LOGIN_URL = f"{TARGET_URL}/login"

CREDS = {"username": "WanZKey", "password": "anyaunyu"}

def recon():
    s = requests.Session()
    print("[*] Logging in...")
    r = s.post(LOGIN_URL, data=CREDS)
    
    if not s.cookies:
        print("[-] Login gagal.")
        return

    print("\n[+] Cookies Found:")
    token = None
    for name, value in s.cookies.items():
        print(f"    {name}: {value}")
        if "token" in name or len(value) > 100: # Asumsi nama cookie 'token' atau panjang
            token = value

    if token:
        print("\n[+] Decoding JWT...")
        try:
            # Decode tanpa verify signature dulu buat liat isi
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            print(f"Header : {header}")
            print(f"Payload: {payload}")
        except Exception as e:
            print(f"[-] Error decode JWT: {e}")

if __name__ == "__main__":
    recon()
