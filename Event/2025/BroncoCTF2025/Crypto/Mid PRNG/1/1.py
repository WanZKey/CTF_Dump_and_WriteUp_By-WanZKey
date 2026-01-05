from pwn import *

def solve_prng():
    r = remote('bad-prng.nc.broncoctf.xyz', 8000)
    enc_hex = r.recvline().strip().decode()
    enc_bytes = bytes.fromhex(enc_hex)

    known = b'bronco{'
    key_start = bytes([a ^ b for a, b in zip(enc_bytes[:7], known)])

    print(f"First 7 bytes of key: {key_start.hex()}")

    key = bytearray(key_start)

    # Prediksi sisa key
    for i in range(7, len(enc_bytes)):
        next_byte = enc_bytes[i] ^ ord('A')  # Misalnya tebakan awal
        key.append(next_byte)

    # Hitung selisih antar setiap byte
    diffs = [key[i + 1] - key[i] for i in range(len(key) - 1)]
    print(f"Key differences: {diffs}")

    # Coba decrypt flag
    flag = ''.join(chr(enc_bytes[i] ^ key[i]) for i in range(len(enc_bytes)))
    print(f"Possible flag: {flag}")

if __name__ == "__main__":
    solve_prng()
