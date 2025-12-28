#!/usr/bin/env python3
import requests
import json
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Target URL
URL = "http://practice-digitalsecuritylab.di.unipi.it:11005/api/dh_exchange/"

# Constants from the server
G = 2
P = 123332382638231725701467272052746646677437210451686403929360967929971726170175522473010422422481335637035691756799160249433550988140577298403502161171408121294152540751727605530438344170959752812965964116010935488849567570589898718274440695293648653888226126185052620716306229882426016512073971282234225856687
C = 64612411667157069503976070918939607708875022270375896159569914279068171237996023267687125585927418267362932620044815107093025867940055155893108177681746956136085002346241007308415060540468449145442966833111022272981874509644086110124172781007706360095880503723087775599509214116527258964018584247604461917771

def xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (mimics server's xor using zip)"""
    return bytes(x ^ y for x, y in zip(a, b))

def exploit():
    print("[*] Starting Diffie-Hellman Attack...")
    print("[*] Vulnerability: Server reuses private key 'b' for both exchanges")
    print()
    # Request: Setting g = C to get B_a = C^b mod P = k_c
    print("[*] Request: Setting g = C to recover full k_c as B_a")
    payload = {
        "g": C,
        "p": P,
        "A": G  # A can be anything, using G=2
    }
    response = requests.post(URL, json=payload, headers={"Content-Type": "application/json"})
    data = response.json()
    if "error" in data:
        print(f"[-] Error: {data['error']}")
        return
    msg_c_hex = data["msg_c"]
    msg_c = bytes.fromhex(msg_c_hex)
    k_c = int(data["B_a"])
    print(f"[+] Recovered k_c: {k_c}")
    print()
    # Compute key bytes
    key = long_to_bytes(k_c)
    print(f"[*] Key bytes (hex): {key.hex()}")
    print(f"[*] Key length: {len(key)} bytes")
    print()
    # Decrypt flag
    flag = xor(msg_c, key[:len(msg_c)])
    print("="*60)
    print("[+] FLAG FOUND:")
    print(f"[+] {flag.decode('utf-8', errors='ignore')}")
    print("="*60)

if __name__ == "__main__":
    try:
        exploit()
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
