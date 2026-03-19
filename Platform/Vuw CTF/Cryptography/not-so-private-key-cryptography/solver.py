#!/usr/bin/env python3
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def solve():
    # 1. Mendapatkan kunci asli dari string base64 yang ada di source code
    key = b64decode('c3VwZXJzZWNyZXRwYXNzd29yZDEyMyEh')
    
    try:
        # 2. Membaca file output.txt menggunakan mode 'rb' sesuai permintaan
        with open('output.txt', 'rb') as f:
            hex_data = f.read().strip()
            
        # 3. Mengubah data hex (dalam bentuk bytes) menjadi raw bytes ciphertext
        ciphertext = bytes.fromhex(hex_data.decode('utf-8'))
        
        # 4. Inisialisasi cipher AES ECB dengan kunci yang didapat
        cipher = AES.new(key, AES.MODE_ECB)
        
        # 5. Proses dekripsi dan hilangkan padding-nya
        decrypted_data = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_data, 16).decode('utf-8')
        
        print("[*] Berhasil melakukan dekripsi!")
        print(f"[*] Flag : {plaintext}")
        
    except FileNotFoundError:
        print("[!] File output.txt tidak ditemukan. Pastikan file berada di direktori yang sama.")
    except Exception as e:
        print(f"[!] Terjadi kesalahan saat dekripsi: {e}")

if __name__ == '__main__':
    solve()
