import requests
import json

# Konfigurasi Target
URL_BASE = "http://practice-digitalsecuritylab.di.unipi.it:11003/api/"

def solve():
    print("[*] Memulai serangan ECB Cut-and-Paste...")

    # LANGKAH 1: Dapatkan Blok Header ("ad")
    # Input 'ad' akan menghasilkan blok pertama: {"username": "ad
    print("[1] Requesting Header Block (input='ad')...")
    res1 = requests.post(URL_BASE + "get_encrypted_message/", json={"username": "ad"})
    token1 = res1.json()['token']
    
    # Ambil 16 byte pertama (32 karakter hex)
    header_block = token1[:32]
    print(f"    Header Block: {header_block}")

    # LANGKAH 2: Dapatkan Blok Tail ("min...")
    # Input 'aamin'. 'aa' mengisi sisa blok 1. 'min' masuk ke awal blok 2.
    # Struktur: {"username": "aa | min", "access_t | ...
    print("[2] Requesting Tail Blocks (input='aamin')...")
    res2 = requests.post(URL_BASE + "get_encrypted_message/", json={"username": "aamin"})
    token2 = res2.json()['token']
    
    # Buang 16 byte pertama (32 char), ambil sisanya
    tail_blocks = token2[32:]
    print(f"    Tail Blocks: {tail_blocks[:32]}...")

    # LANGKAH 3: Gabungkan (Cut and Paste)
    forged_token = header_block + tail_blocks
    print(f"[3] Forged Token: {forged_token[:64]}...")

    # LANGKAH 4: Kirim Token Palsu
    print("[4] Sending forged token...")
    res_final = requests.post(URL_BASE + "decrypt_message/", json={"token": forged_token})
    
    response = res_final.json()
    print("\n[+] Respon Server:")
    print(json.dumps(response, indent=2))

if __name__ == "__main__":
    solve()
