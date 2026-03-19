#!/usr/bin/env python3
from pwn import *
import string

def solve():
    # Setup koneksi ke server target
    host = 'chals.vuwctf.com'
    port = 9997
    
    # Membuka koneksi remote
    io = remote(host, port)
    
    # Mengabaikan pesan sambutan
    io.recvuntil(b'Recover my secret :)\n')
    
    flag = ""
    block_size = 16
    
    print("[*] Memulai eksploitasi ECB Byte-at-a-time...")
    
    # Asumsi panjang flag tidak lebih dari 64 karakter (4 blok)
    for i in range(64):
        # 1. Hitung jumlah padding yang dibutuhkan untuk mendorong 1 byte target ke ujung blok
        pad_len = (block_size - 1) - (len(flag) % block_size)
        padding = b"A" * pad_len
        
        # 2. Dapatkan ciphertext block target dari server
        io.recvuntil(b'Enter message to encrypt: ')
        io.sendline(padding)
        
        response = io.recvline().strip().decode()
        ciphertext = bytes.fromhex(response)
        
        # Tentukan indeks blok yang sedang diserang
        block_idx = len(flag) // block_size
        start_idx = block_idx * block_size
        end_idx = start_idx + block_size
        
        target_block = ciphertext[start_idx:end_idx]
        
        found = False
        
        # 3. Brute-force byte terakhir menggunakan karakter ASCII yang dapat dicetak
        for c in string.printable:
            # Bentuk payload tebakan: padding + known_flag + tebakan_karakter
            guess_payload = padding + flag.encode() + c.encode()
            
            io.recvuntil(b'Enter message to encrypt: ')
            io.sendline(guess_payload)
            
            guess_response = io.recvline().strip().decode()
            guess_ciphertext = bytes.fromhex(guess_response)
            guess_block = guess_ciphertext[start_idx:end_idx]
            
            # Jika blok cocok, karakter tebakan benar
            if guess_block == target_block:
                flag += c
                print(f"[*] Flag sementara : {flag}")
                found = True
                break
        
        if not found:
            print("[!] Gagal menemukan karakter selanjutnya. Proses dihentikan.")
            break
            
        # Jika karakter penutup flag sudah ditemukan, hentikan serangan
        if flag.endswith('}'):
            print(f"\n[*] CRACKED! Flag sepenuhnya ditemukan.")
            print(f"[*] Flag Final : {flag}")
            break
            
    io.close()

if __name__ == '__main__':
    # Mematikan log pwntools agar output terminal lebih bersih
    context.log_level = 'error'
    solve()
