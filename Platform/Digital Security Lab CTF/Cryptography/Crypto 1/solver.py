import requests
import json
from pwn import xor

# Konfigurasi Target
URL = "http://practice-digitalsecuritylab.di.unipi.it:11001/api/get_encrypted_message/"

def get_encrypted_token(username):
    """Mengirim request ke server dan mengambil token terenkripsi (hex)"""
    headers = {'Content-Type': 'application/json'}
    data = {"user": username}
    response = requests.post(URL, json=data)
    return bytes.fromhex(response.json()['token'])

def solve():
    # 1. Kirim payload panjang untuk mendapatkan keystream
    # Kita butuh panjang yang cukup untuk mengcover panjang flag nanti
    long_username = "A" * 150
    ciphertext_long = get_encrypted_token(long_username)

    # 2. Rekonstruksi Plaintext yang diketahui (Known Plaintext)
    # Format default json.dumps menggunakan separator (', ', ': ')
    # Struktur: {"user": "AAAA...", "flag": ...
    known_plaintext = json.dumps({"user": long_username, "flag": ""})
    
    # Kita hanya butuh bagian awal sampai sebelum flag asli muncul
    # json.dumps akan menghasilkan: {"user": "AAAA...", "flag": "
    # Kita potong string known_plaintext agar sesuai logika json
    prefix_str = f'{{"user": "{long_username}", "flag": "'
    known_bytes = prefix_str.encode()

    # 3. Recover Keystream
    # Keystream = Ciphertext XOR Plaintext
    # Kita ambil keystream sepanjang known_bytes
    keystream = xor(ciphertext_long[:len(known_bytes)], known_bytes)
    
    print(f"[+] Keystream recovered ({len(keystream)} bytes)")

    # 4. Kirim payload pendek untuk mendekripsi flag
    short_username = "a"
    ciphertext_short = get_encrypted_token(short_username)

    # 5. Dekripsi
    # Plaintext = Ciphertext XOR Keystream
    # Kita gunakan keystream yang sudah didapat
    decrypted = xor(ciphertext_short, keystream[:len(ciphertext_short)])

    print("\n[+] Hasil Dekripsi:")
    try:
        print(decrypted.decode())
    except:
        print(decrypted)

if __name__ == "__main__":
    solve()
