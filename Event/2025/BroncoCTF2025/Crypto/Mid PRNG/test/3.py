import socket

# Fungsi untuk menghubungkan ke server dan mendapatkan output terenkripsi
def get_encrypted_output():
    with socket.create_connection(("bad-prng.nc.broncoctf.xyz", 8000)) as s:
        data = s.recv(1024).decode().strip()
        return bytes.fromhex(data)

# Fungsi LCG
def lcg(a, c, m, seed):
    while True:
        seed = (a * seed + c) % m
        yield seed & 0xFF  # Menghasilkan 1 byte

# Mendapatkan output terenkripsi
encrypted_output = get_encrypted_output()

# Rentang nilai untuk parameter LCG
a_values = range(1, 100)
c_values = range(0, 100)
m_values = range(2, 256)
seed_values = range(0, 256)

# Brute-force untuk menemukan parameter yang tepat
for a in a_values:
    for c in c_values:
        for m in m_values:
            for seed in seed_values:
                gen = lcg(a, c, m, seed)
                decrypted = bytes([byte ^ next(gen) for byte in encrypted_output])
                if b"bronco{" in decrypted:
                    print(f"Found potential flag: {decrypted.decode()}")
                    print(f"Parameters - a: {a}, c: {c}, m: {m}, seed: {seed}")
                    break
