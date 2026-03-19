#!/usr/bin/env python3
from pwn import *
import warnings

warnings.filterwarnings("ignore", category=BytesWarning)

def solve():
    host = 'chals.vuwctf.com'
    port = 9994
    
    context.log_level = 'info'
    io = remote(host, port)
    
    io.recvuntil(b'Decrypt me!\n')
    encrypted_flag = io.recvline().strip().decode()
    iv_hex, ct_hex = encrypted_flag.split(', ')
    
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    
    full_data = iv + ct
    blocks = [full_data[i:i+16] for i in range(0, len(full_data), 16)]
    
    # Pre-fill dengan plaintext Blok 1 yang sudah didapatkan
    decrypted_flag = b'VuwCTF{padding_s'
    
    log.info(f"Jumlah blok keseluruhan: {len(blocks) - 1}")
    log.success(f"Blok 1 (Known) dilewati : {decrypted_flag.decode()}")
    
    # Loop langsung dimulai dari block_idx 2
    for block_idx in range(2, len(blocks)):
        target_block = blocks[block_idx]
        prev_block = blocks[block_idx - 1]
        
        intermediate_state = bytearray(16)
        plaintext_block = bytearray(16)
        
        p = log.progress(f'Memproses Blok {block_idx}')
        
        for byte_idx in range(15, -1, -1):
            padding_value = 16 - byte_idx
            
            manipulated_prev_block = bytearray(16)
            for i in range(byte_idx + 1, 16):
                manipulated_prev_block[i] = intermediate_state[i] ^ padding_value
                
            found = False
            for guess in range(256):
                p.status(f'Mencari Byte {byte_idx} | Mencoba: 0x{guess:02x} | Hasil: {plaintext_block[byte_idx+1:].decode("latin-1", "ignore")}')
                manipulated_prev_block[byte_idx] = guess
                
                payload = f"{manipulated_prev_block.hex()}, {target_block.hex()}"
                
                io.recvuntil(b'Select an action: ')
                io.sendline(b'2')
                io.recvuntil(b'Enter your token: ')
                io.sendline(payload.encode())
                
                response = io.recvline().decode()
                
                if "Padding error!" not in response:
                    # Menangani edge-case untuk original padding
                    if byte_idx == 15 and guess == prev_block[15]:
                        continue
                        
                    intermediate_state[byte_idx] = guess ^ padding_value
                    plaintext_block[byte_idx] = intermediate_state[byte_idx] ^ prev_block[byte_idx]
                    found = True
                    break
                    
            if not found:
                p.failure(f"Gagal menebak byte ke-{byte_idx}. Server mungkin terputus.")
                io.close()
                return
                
        p.success(f"{plaintext_block}")
        decrypted_flag += plaintext_block
        
    io.close()
    
    pad_len = decrypted_flag[-1]
    final_flag = decrypted_flag[:-pad_len].decode('utf-8')
    
    log.success(f"CRACKED! Flag Final : {final_flag}")

if __name__ == '__main__':
    solve()
