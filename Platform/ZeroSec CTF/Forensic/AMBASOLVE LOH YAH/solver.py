#!/usr/bin/env python3
def solve():
    print("[*] Reversing file bytes...")
    try:
        with open("ambasolve.png", "rb") as f:
            data = f.read()
        
        # Reverse seluruh raw bytes
        reversed_data = data[::-1]
        
        with open("fixed_ambasolve.png", "wb") as f:
            f.write(reversed_data)
            
        print("[+] File successfully reversed and saved as 'fixed_ambasolve.png'!")
        print("[*] Buka file 'fixed_ambasolve.png' untuk melihat isinya.")
        
    except FileNotFoundError:
        print("[-] File ambasolve.png tidak ditemukan. Pastikan file ada di direktori yang sama.")

if __name__ == "__main__":
    solve()
