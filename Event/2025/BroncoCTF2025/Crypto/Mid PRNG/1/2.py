from mt19937predictor import MT19937Predictor
from pwn import *

def solve_mt19937():
    r = remote('bad-prng.nc.broncoctf.xyz', 8000)

    # Ambil output hex dari server
    enc_hex = r.recvline().strip().decode()
    enc_bytes = bytes.fromhex(enc_hex)

    # Kita tahu bahwa flag dimulai dengan 'bronco{'
    known_plaintext = b'bronco{'

    # XOR untuk dapatkan 7 byte pertama dari key stream
    keystream_start = bytes([enc_bytes[i] ^ known_plaintext[i] for i in range(7)])

    print(f"7 bytes awal keystream: {keystream_start.hex()}")

    # Karena MT19937 mengeluarkan 4 byte sekaligus (uint32), kita pecah jadi 32-bit chunks
    predictor = MT19937Predictor()

    # Input 7 byte awal ke predictor
    keystream_ints = []
    for i in range(0, len(keystream_start), 4):
        chunk = keystream_start[i:i+4]
        if len(chunk) < 4:
            chunk = chunk.ljust(4, b'\x00')  # Pad dengan 0 jika kurang dari 4 byte
        keystream_ints.append(int.from_bytes(chunk, 'big'))

    # Masukkan ke predictor
    for ki in keystream_ints:
        predictor.setrandbits(ki, 32)

    # Generate keystream selanjutnya
    keystream = bytearray(keystream_start)

    while len(keystream) < len(enc_bytes):
        predicted_int = predictor.getrandbits(32)
        keystream.extend(predicted_int.to_bytes(4, 'big'))

    # Decrypt flag
    flag = bytes([enc_bytes[i] ^ keystream[i] for i in range(len(enc_bytes))])

    print(f"Possible Flag: {flag.decode(errors='ignore')}")

    r.close()

if __name__ == '__main__':
    solve_mt19937()
