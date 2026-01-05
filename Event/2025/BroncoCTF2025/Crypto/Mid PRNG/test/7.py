import socket
from itertools import cycle

# Fungsi untuk ambil output dari server nc
def get_output():
    with socket.create_connection(("bad-prng.nc.broncoctf.xyz", 8000)) as s:
        return bytes.fromhex(s.recv(1024).decode().strip())

# Fungsi Middle Square PRNG dengan cycle
def cycle_middle_square(seed):
    seen = []
    while seed not in seen:
        seen.append(seed)
        seed = int(str(seed * seed).zfill(8)[2:6])
        yield seed & 0xFF
    # Kalau masuk cycle, ulang terus cycle-nya
    yield from cycle(seen)

# Fungsi Park-Miller LCG (LCG klasik, banyak dipakai di CTF)
def park_miller(seed):
    while True:
        seed = (seed * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        yield (seed >> 16) & 0xFF

# Ambil output dari server
output = get_output()

# BRUTEFORCE Middle Square (4 digit)
for seed in range(10000):
    gen = cycle_middle_square(seed)
    decrypted = bytes((o ^ next(gen)) & 0xFF for o in output)
    if b"bronco{" in decrypted:
        print(f"[+] FOUND (Middle Square) - Seed: {seed}")
        print(f"[+] FLAG: {decrypted.decode()}")
        exit()

# BRUTEFORCE Park-Miller LCG (32-bit seed)
for seed in range(0, 0x10000):  # 16-bit dulu biar cepat
    gen = park_miller(seed)
    decrypted = bytes((o ^ next(gen)) & 0xFF for o in output)
    if b"bronco{" in decrypted:
        print(f"[+] FOUND (Park-Miller LCG) - Seed: {seed}")
        print(f"[+] FLAG: {decrypted.decode()}")
        exit()

print("[-] Seed tidak ditemukan, mungkin pakai PRNG lain atau seed lebih besar.")
