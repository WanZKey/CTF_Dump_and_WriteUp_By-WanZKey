from pwn import *
from Crypto.Util.Padding import pad
import binascii

# Konfigurasi Koneksi
host = 'gzcli.1pc.tf'
port = 52664

# Target Plaintext yang harus di-inject
target_plaintext = b"nottheflagbutstillcrucialvalidation"
BLOCK_SIZE = 16

# Setup Context
context.log_level = 'error' # Supaya output bersih

def get_oracle_response(payload_hex):
    """
    Mengirim payload ke server dan mengecek respon.
    Return True jika padding benar ([!] INTRUDER ALERT), False jika salah.
    """
    r = remote(host, port)
    try:
        r.recvuntil(b'> ')
        r.sendline(b'1')
        r.recvuntil(b'[?] ')
        r.sendline(payload_hex.encode())
        
        response = r.recvline()
        r.close()
        
        if b"INTRUDER ALERT" in response or b"Logged In" in response:
            return True
        return False
    except Exception as e:
        r.close()
        return False

def solve():
    print(f"[*] Target Plaintext: {target_plaintext}")
    
    # 1. Padding Target secara manual sesuai logika chall.py (PKCS#7)
    # Target length 35. 35 % 16 = 3. 16-3 = 13 padding bytes.
    padded_target = pad(target_plaintext, BLOCK_SIZE)
    print(f"[*] Padded Target ({len(padded_target)} bytes): {padded_target}")
    
    # Bagi menjadi blok-blok 16 byte
    pt_blocks = [padded_target[i:i+BLOCK_SIZE] for i in range(0, len(padded_target), BLOCK_SIZE)]
    
    # Kita mulai dengan blok ciphertext terakhir (C_N) sebagai random/null bytes
    # Karena kita ingin memalsukan seluruh pesan, blok terakhir bisa apa saja.
    next_cipher_block = b'\x00' * 16
    full_ciphertext = next_cipher_block
    
    # Iterasi mundur dari blok plaintext terakhir ke pertama
    for pt_block in reversed(pt_blocks):
        print(f"\n[*] Processing Block: {pt_block}")
        
        # Intermediate Value untuk blok saat ini
        intermediate = bytearray(16)
        
        # Brute force setiap byte dalam blok (dari byte 15 ke 0)
        for byte_index in range(15, -1, -1):
            padding_val = 16 - byte_index
            
            # Setup suffix untuk padding yang valid
            # Kita set byte yang sudah ditemukan sebelumnya agar sesuai dengan padding_val
            iv_prefix = bytearray(16)
            for x in range(byte_index + 1, 16):
                iv_prefix[x] = intermediate[x] ^ padding_val
            
            # Brute force byte saat ini (0-255)
            found = False
            for guess in range(256):
                iv_prefix[byte_index] = guess
                
                # Payload = IV_Attempt + Next_Cipher_Block
                payload = iv_prefix + next_cipher_block
                
                if get_oracle_response(payload.hex()):
                    # Ketemu! Hitung byte intermediate asli
                    # Intermediate[byte_index] ^ guess = padding_val
                    # Intermediate[byte_index] = guess ^ padding_val
                    intermediate[byte_index] = guess ^ padding_val
                    print(f"    Byte {byte_index} found. Intermediate: {hex(intermediate[byte_index])}", end='\r')
                    found = True
                    break
            
            if not found:
                print(f"\n[!] Gagal menemukan byte {byte_index}. Cek koneksi atau timing.")
                exit()
        
        print(f"\n    Intermediate Block Found: {intermediate.hex()}")
        
        # Hitung Ciphertext block sebelumnya (C_{i-1})
        # C_{i-1} = Intermediate ^ PT_Block
        prev_cipher_block = bytes([b1 ^ b2 for b1, b2 in zip(intermediate, pt_block)])
        print(f"    Calculated Previous Ciphertext: {prev_cipher_block.hex()}")
        
        # Gabungkan hasil (Prepending)
        full_ciphertext = prev_cipher_block + full_ciphertext
        
        # Update next_cipher_block untuk iterasi berikutnya
        next_cipher_block = prev_cipher_block

    print("\n[+] Forged Ciphertext Constructed!")
    print(f"Payload: {full_ciphertext.hex()}")
    
    # Kirim Payload Final untuk dapat Flag
    r = remote(host, port)
    r.recvuntil(b'> ')
    r.sendline(b'1')
    r.recvuntil(b'[?] ')
    r.sendline(full_ciphertext.hex().encode())
    final_res = r.recvall().decode()
    print("\n" + "="*30)
    print(final_res)
    print("="*30)

if __name__ == "__main__":
    solve()
