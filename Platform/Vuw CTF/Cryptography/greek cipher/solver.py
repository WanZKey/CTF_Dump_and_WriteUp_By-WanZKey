#!/usr/bin/env python3
import math

def decrypt_scytale(ciphertext, key):
    # Menghitung jumlah baris (putaran) pada tongkat
    num_rows = math.ceil(len(ciphertext) / key)
    
    plaintext_rows = [""] * num_rows
    
    # Memisahkan kembali karakter ke baris aslinya
    for i, char in enumerate(ciphertext):
        row = i % num_rows
        plaintext_rows[row] += char
        
    # Menggabungkan baris menjadi satu plaintext utuh
    return "".join(plaintext_rows)

def solve():
    try:
        with open("ciphertext.txt", "r", encoding="utf-8") as f:
            ciphertext = f.read().strip()
            
        # Menghilangkan invisible characters dari terminal output jika ada
        ciphertext = ciphertext.replace('¶', '').strip()
            
        print("[*] Ciphertext length :", len(ciphertext))
        
        # Key 46 didapat dari (146 BC % 100)
        key = 46 
        print(f"[*] Menggunakan Scytale Key : {key}")
        
        decrypted_text = decrypt_scytale(ciphertext, key)
        
        # Mengganti middle dot dengan spasi agar mudah dibaca
        readable_text = decrypted_text.replace('·', ' ')
        
        print(f"\n[*] Decrypted Text:\n{readable_text}")
        
    except FileNotFoundError:
        print("[!] File ciphertext.txt tidak ditemukan.")
    except Exception as e:
        print(f"[!] Terjadi kesalahan: {e}")

if __name__ == '__main__':
    solve()
