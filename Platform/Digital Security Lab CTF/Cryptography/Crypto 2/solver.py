import requests
import json
from pwn import xor

# Konfigurasi Target
BASE_URL = "http://practice-digitalsecuritylab.di.unipi.it:11002/api/"

def solve():
    print("[*] Memulai serangan CBC Bit Flipping...")

    # 1. Dapatkan Ciphertext & IV untuk username "bdmin"
    # Kita pakai "bdmin" karena hanya beda 1 bit/huruf dengan "admin"
    # Struktur JSON: {"user": "bdmin", ...
    # Indeks huruf 'b' ada di posisi ke-10 (dihitung dari 0)
    # { " u s e r " :   " b
    # 0 1 2 3 4 5 6 7 8 9 10
    username_fake = "bdmin"
    
    resp = requests.post(BASE_URL + "get_encrypted_message/", json={"user": username_fake})
    data = resp.json()
    
    token = data['token']
    iv_hex = data['iv']
    iv_bytes = bytes.fromhex(iv_hex)

    print(f"[+] Token didapat: {token[:10]}...")
    print(f"[+] IV Asli: {iv_hex}")

    # 2. Siapkan Payload Bit Flipping
    # Kita ingin mengubah 'b' (dari bdmin) menjadi 'a' (admin)
    # 'b' = 0x62, 'a' = 0x61
    # XOR Difference = 0x62 ^ 0x61 = 0x03
    
    iv_mutable = bytearray(iv_bytes)
    
    # Target index 10 (sesuai posisi "bdmin" dalam string JSON)
    # Operasi: IV_BARU = IV_LAMA XOR 'b' XOR 'a'
    target_index = 10
    xor_value = ord('b') ^ ord('a')
    
    iv_mutable[target_index] = iv_mutable[target_index] ^ xor_value
    
    iv_modified = iv_mutable.hex()
    print(f"[+] IV Modifikasi: {iv_modified}")

    # 3. Kirim IV palsu + Token asli ke endpoint decryption
    payload = {
        "token": token,
        "iv": iv_modified
    }
    
    resp_decrypt = requests.post(BASE_URL + "decrypt_message/", json=payload)
    result = resp_decrypt.json()

    print("\n[+] Respon Server:")
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    solve()
