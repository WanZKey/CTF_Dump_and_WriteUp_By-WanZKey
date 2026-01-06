#!/usr/bin/env python3

from pwn import *
import base64
import hashpumpy
from hashlib import sha256
from libnum import s2n, n2s
import itertools
import string
import time

# --- Konfigurasi ---
HOST = "163.47.10.146"
PORT = 8570

# --- Konstanta ---
KEY_LEN = 32
FLAG_LEN = 78
H_EMPTY = s2n(sha256(b"").digest())

# Cache untuk bruteforce (opsional tapi mempercepat jika ada karakter berulang)
bruteforce_cache = {}

def crack_3_bytes(target_hash):
    """
    Bruteforce hash SHA256 dari string 3-byte.
    """
    if target_hash in bruteforce_cache:
        return bruteforce_cache[target_hash]

    # Asumsi flag berisi karakter yang bisa dicetak (printable)
    # Jika gagal, Anda bisa menggantinya dengan range(256) untuk semua byte
    # Namun, string.printable (100 char) jauh lebih cepat daripada 256^3
    possible_chars = string.printable.encode('latin-1')

    # Coba karakter umum terlebih dahulu
    common_chars = (string.ascii_letters + string.digits + "_{}?!@#$").encode('latin-1')
    for a, b, c in itertools.product(common_chars, repeat=3):
        chunk = bytes([a, b, c])
        h_num = s2n(sha256(chunk).digest())
        if h_num == target_hash:
            log.success(f"Ditemukan chunk (common): {chunk.decode('latin-1')}")
            bruteforce_cache[target_hash] = chunk
            return chunk

    # Jika tidak ditemukan, coba semua yang printable
    log.warning("Mencoba semua karakter printable...")
    for a, b, c in itertools.product(possible_chars, repeat=3):
        chunk = bytes([a, b, c])
        h_num = s2n(sha256(chunk).digest())
        if h_num == target_hash:
            log.success(f"Ditemukan chunk (printable): {chunk.decode('latin-1')}")
            bruteforce_cache[target_hash] = chunk
            return chunk

    log.error(f"Bruteforce gagal untuk hash: {target_hash}")
    return b"???"

def get_leak(r, original_hmac, original_data, user_id_str):
    """
    Melakukan hash length extension dan mengambil bocoran dari server.
    """
    data_to_add = f":::authorized=true:::user_id={user_id_str}".encode('latin-1')
    
    # Lakukan length extension
    new_hmac, new_data = hashpumpy.hashpump(original_hmac, original_data, data_to_add, KEY_LEN)
    
    # Buat token baru
    token_data = new_data + b":::hmac=" + new_hmac.encode('latin-1')
    final_token = base64.b64encode(token_data)
    
    # Kirim ke server
    r.sendlineafter(b"Enter your choice: ", b"3")
    r.sendlineafter(b"Enter access token: ", final_token)
    
    r.recvuntil(b"away...\n")
    leak_str = r.recvline().strip().decode()
    
    return int(leak_str)

def main():
    r = remote(HOST, PORT)
    
    # 1. Registrasi untuk mendapatkan token awal
    r.sendlineafter(b"Enter your choice: ", b"1")
    r.sendlineafter(b"Who are you?\n>>> ", b"admin")
    r.recvuntil(b"Your access token: ")
    b64_token = r.recvline().strip().decode()
    
    # Decode token
    token_bytes = base64.b64decode(b64_token)
    original_data, original_hmac = token_bytes.split(b":::hmac=")
    original_hmac = original_hmac.decode('latin-1')
    
    log.info("Berhasil mendapatkan token awal.")
    
    known_hashes = {}
    flag_parts = {}
    
    # 2. Loop mundur dari akhir flag
    for i in range(FLAG_LEN - 3, -1, -3):
        log.info(f"Mencoba membocorkan FLAG[{i}:{i+3}]...")
        user_id_str = bin(i)[2:]
        
        # Ambil bocoran dari server
        leak = get_leak(r, original_hmac, original_data, user_id_str)
        
        # Dapatkan hash yang sudah diketahui dari langkah sebelumnya
        h2 = known_hashes.get(i + 3, H_EMPTY)
        h3 = known_hashes.get(i + 6, H_EMPTY)
        
        # Hitung target hash
        if (leak % (h2 * h3)) != 0:
            log.error("Terjadi kesalahan! Hash tidak dapat dibagi habis.")
            break
            
        target_hash = leak // (h2 * h3)
        known_hashes[i] = target_hash
        
        # 3. Bruteforce hash
        chunk = crack_3_bytes(target_hash)
        flag_parts[i] = chunk.decode('latin-1')
        
        # Tampilkan progres
        current_flag = ""
        for j in range(0, FLAG_LEN, 3):
            current_flag += flag_parts.get(j, "...")
        log.info(f"Flag sementara: {current_flag}")

    r.close()
    
    # 4. Gabungkan flag
    log.success("Selesai! Menggabungkan flag...")
    full_flag = ""
    for i in range(0, FLAG_LEN, 3):
        full_flag += flag_parts.get(i, "???")
        
    print(f"\n[+] FLAG: {full_flag}\n")

if __name__ == "__main__":
    main()
