from ctypes import CDLL
import time

libc = CDLL("libc.so.6")

enc_bytes = bytes.fromhex("50e4ad28b1191916190933726169ccd6c64925b461c296db")
known = b"bronco{"

for seed in range(int(time.time()) - 100000, int(time.time()) + 100000):
    libc.srand(seed)
    key_guess = bytes([libc.rand() % 256 for _ in range(len(enc_bytes))])
    decrypted = bytes([enc_bytes[i] ^ key_guess[i] for i in range(len(enc_bytes))])
    if decrypted.startswith(known):
        print(f"Found Seed: {seed}")
        print(f"Decrypted: {decrypted.decode()}")
        break
