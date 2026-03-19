#!/usr/bin/env python3
import hashlib

def solve():
    target_hash = "21232f297a57a5a743894a0e4a801fc3"
    print(f"[*] Target MD5 Hash : {target_hash}")
    
    # Daftar kata sandi umum sebagai dictionary sederhana
    common_passwords = ["password", "123456", "admin", "12345678", "qwerty"]
    
    print("[*] Memulai proses cracking...")
    
    for word in common_passwords:
        # Melakukan hashing MD5 pada setiap kata di wordlist
        hashed_word = hashlib.md5(word.encode('utf-8')).hexdigest()
        
        if hashed_word == target_hash:
            print("[*] CRACKED!")
            print(f"[*] Plaintext Password : {word}")
            print(f"[*] Flag : VuwCTF{{{word}}}")
            return
            
    print("[!] Password tidak ditemukan di wordlist.")

if __name__ == '__main__':
    solve()
