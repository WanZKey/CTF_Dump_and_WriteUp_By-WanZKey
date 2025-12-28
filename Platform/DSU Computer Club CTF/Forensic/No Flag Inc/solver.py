import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def solve():
    # Konfigurasi dari Macro VBA
    input_file = "word/media/flagenc.png"  # Sesuaikan path jika perlu
    output_file = "flag_solved.png"
    
    hex_key = "a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6"
    hex_iv = "f1f2f3f4f5f6f7f8f9f0e1e2e3e4e5e6"

    # Convert Hex string ke Bytes
    key = binascii.unhexlify(hex_key)
    iv = binascii.unhexlify(hex_iv)

    print(f"[*] Key: {hex_key}")
    print(f"[*] IV : {hex_iv}")

    # Cek keberadaan file
    if not os.path.exists(input_file):
        print(f"[-] File {input_file} tidak ditemukan. Pastikan sudah unzip docm-nya.")
        # Coba cek di folder saat ini
        if os.path.exists("flagenc.png"):
            input_file = "flagenc.png"
        else:
            return

    # Baca file terenkripsi
    print(f"[*] Membaca {input_file}...")
    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    # Proses Dekripsi AES-128-CBC
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        # Update + Finalize
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Simpan hasil
        with open(output_file, "wb") as f:
            f.write(decrypted_data)
        
        print(f"[+] Sukses! Flag disimpan ke: {output_file}")
        
        # Cek Header PNG
        if decrypted_data.startswith(b'\x89PNG'):
            print("[+] Valid PNG Header detected.")
        else:
            print("[!] Warning: Header PNG tidak valid, tapi file tetap disimpan.")

    except Exception as e:
        print(f"[-] Error saat dekripsi: {e}")

if __name__ == "__main__":
    # Pastikan install library cryptography: pip install cryptography
    solve()
