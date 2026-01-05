# Solver untuk bad_prng challenge
from pwn import *

def solve_prng():
    # Connect ke server
    r = remote('bad-prng.nc.broncoctf.xyz', 8000)
    
    # Ambil output hex dari server
    enc_hex = r.recvline().strip().decode()
    print(f"Received hex: {enc_hex}")
    
    # Convert hex ke bytes
    enc_bytes = bytes.fromhex(enc_hex)
    
    # Kita tahu bahwa flag dimulai dengan 'bronco{'
    known = b'bronco{'
    
    # Dapatkan 7 byte pertama dari key dengan XOR
    key_start = bytes([a ^ b for a, b in zip(enc_bytes[:7], known)])
    print(f"First 7 bytes of key: {key_start.hex()}")
    
    # Coba prediksi pattern PRNG berdasarkan 7 byte pertama
    key = bytearray(key_start)
    
    # Loop untuk setiap byte yang tersisa
    for i in range(7, len(enc_bytes)):
        # Coba berbagai kemungkinan untuk byte berikutnya
        for possible_byte in range(256):
            key.append(possible_byte)
            # XOR dengan encrypted byte
            test_char = enc_bytes[i] ^ possible_byte
            # Cek apakah karakter valid (printable ASCII atau '}')
            if (32 <= test_char <= 126) or test_char == ord('}'):
                # Kemungkinan byte yang valid ditemukan
                break
            key.pop()
    
    # Decrypt flag menggunakan key yang diprediksi
    flag = ''
    for i in range(len(enc_bytes)):
        flag += chr(enc_bytes[i] ^ key[i])
    
    print(f"Possible flag: {flag}")
    r.close()

if __name__ == "__main__":
    solve_prng()
