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
    
    # Analisis pola dari key yang kita dapat
    diffs = []
    for i in range(len(key_start)-1):
        diffs.append(key_start[i+1] - key_start[i])
    print(f"Key differences: {diffs}")
    
    # Prediksi pattern PRNG berdasarkan 7 byte pertama
    key = bytearray(key_start)
    last_byte = key_start[-1]
    
    # Loop untuk setiap byte yang tersisa
    for i in range(7, len(enc_bytes)):
        # Gunakan pola differences untuk memprediksi byte berikutnya
        next_diff = diffs[i % len(diffs)]  # Gunakan pola berulang
        next_byte = (last_byte + next_diff) & 0xFF
        key.append(next_byte)
        last_byte = next_byte
        
        # XOR dengan encrypted byte untuk verifikasi
        test_char = enc_bytes[i] ^ next_byte
        if not (32 <= test_char <= 126 or test_char == ord('}')):
            # Jika karakter tidak valid, coba perbaiki byte
            for adj in range(-5, 6):
                test_byte = (next_byte + adj) & 0xFF
                test_char = enc_bytes[i] ^ test_byte
                if 32 <= test_char <= 126 or test_char == ord('}'):
                    key[i] = test_byte
                    last_byte = test_byte
                    break
    
    # Decrypt flag menggunakan key yang diprediksi
    flag = ''
    for i in range(len(enc_bytes)):
        flag += chr(enc_bytes[i] ^ key[i])
    
    print(f"Possible flag: {flag}")
    r.close()

if __name__ == "__main__":
    solve_prng()
