#!/usr/bin/env python3
from pwn import *
import warnings
import sys

# Mengabaikan warning tipe data dari pwntools agar terminal bersih
warnings.filterwarnings("ignore", category=BytesWarning)

def solve():
    host = 'chals.vuwctf.com'
    port = 9994
    
    io = remote(host, port)
    
    # Menangkap ciphertext FLAG dari banner awal
    io.recvuntil(b'Decrypt me!\n')
    encrypted_flag = io.recvline().strip().decode()
    iv_hex, ct_hex = encrypted_flag.split(', ')
    
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    
    # Menggabungkan IV dan Ciphertext menjadi satu kesatuan array blok
    full_data = iv + ct
    blocks = [full_data[i:i+16] for i in range(0, len(full_data), 16)]
    
    decrypted_flag = b''
    known_prefix = b"VuwCTF{"
    
    print(f"[*] Terhubung ke server. Mengeksekusi Padding Oracle Attack...")
    print(f"[*] Jumlah blok yang akan diproses: {len(blocks) - 1}\n")
    
    # Iterasi eksploitasi per blok
    for block_idx in range(1, len(blocks)):
        target_block = blocks[block_idx]
        prev_block = blocks[block_idx - 1]
        
        intermediate_state = bytearray(16)
        plaintext_block = bytearray(16)
        
        print(f"[*] Memproses Blok {block_idx}...")
        
        # Brute-force per byte dari belakang ke depan (index 15 ke 0)
        for byte_idx in range(15, -1, -1):
            padding_value = 16 - byte_idx
            
            # OPTIMASI: Gunakan known prefix jika berada di Blok 1
            if block_idx == 1 and byte_idx < len(known_prefix):
                known_char = known_prefix[byte_idx]
                plaintext_block[byte_idx] = known_char
                intermediate_state[byte_idx] = known_char ^ prev_block[byte_idx]
                
                sys.stdout.write(f"\r[+] Byte {byte_idx} (Known) : {chr(known_char)} -> Isi Blok: {plaintext_block[byte_idx:].decode('latin-1', 'ignore')}")
                sys.stdout.flush()
                continue
            
            # Mempersiapkan blok manipulasi
            manipulated_prev_block = bytearray(16)
            for i in range(byte_idx + 1, 16):
                manipulated_prev_block[i] = intermediate_state[i] ^ padding_value
                
            found = False
            for guess in range(256):
                manipulated_prev_block[byte_idx] = guess
                
                payload = f"{manipulated_prev_block.hex()}, {target_block.hex()}"
                
                io.recvuntil(b'Select an action: ')
                io.sendline(b'2')
                io.recvuntil(b'Enter your token: ')
                io.sendline(payload.encode())
                
                response = io.recvline().decode()
                
                # Jika response BUKAN 'Padding error!', berarti kita menemukan padding yang valid
                if "Padding error!" not in response:
                    # Edge-case untuk byte terakhir untuk menghindari original padding
                    if byte_idx == 15 and guess == prev_block[15]:
                        continue
                        
                    intermediate_state[byte_idx] = guess ^ padding_value
                    plaintext_block[byte_idx] = intermediate_state[byte_idx] ^ prev_block[byte_idx]
                    found = True
                    
                    sys.stdout.write(f"\r[+] Byte {byte_idx} Cracked : {chr(plaintext_block[byte_idx])} -> Isi Blok: {plaintext_block[byte_idx:].decode('latin-1', 'ignore')}")
                    sys.stdout.flush()
                    break
                    
            if not found:
                print(f"\n[!] Gagal menebak byte ke-{byte_idx} pada blok {block_idx}. Server mungkin terputus.")
                io.close()
                return
                
        decrypted_flag += plaintext_block
        print(f"\n[*] Hasil Blok {block_idx} : {plaintext_block}\n")
        
    io.close()
    
    # Menghapus padding PKCS#7 dari flag akhir
    pad_len = decrypted_flag[-1]
    final_flag = decrypted_flag[:-pad_len].decode('utf-8')
    
    print(f"[*] CRACKED! Flag sepenuhnya ditemukan.")
    print(f"[*] Flag Final : {final_flag}")

if __name__ == '__main__':
    context.log_level = 'error'
    solve()
