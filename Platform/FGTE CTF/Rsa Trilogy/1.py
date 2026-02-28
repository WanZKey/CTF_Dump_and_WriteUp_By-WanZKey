from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long
import base64
import gmpy2

# 1. Load Public Key untuk mendapatkan N dan e
with open("part1_pubkey.pem", "r") as f:
    key = RSA.importKey(f.read())

n = key.n
e = key.e

# 2. Load Ciphertext dan decode Base64
with open("part1_ciphertext.enc", "r") as f:
    b64_cipher = f.read().strip()
    c_bytes = base64.b64decode(b64_cipher)
    c = bytes_to_long(c_bytes)

print(f"[Part 1] e = {e}")

# 3. Serangan: Karena e = 3, kita coba akar pangkat 3 langsung
# Jika m^3 < n, maka c = m^3, sehingga m = c^(1/3)
m, exact = gmpy2.iroot(c, e)

if exact:
    print(f"[Part 1] Decrypted: {long_to_bytes(m).decode()}")
else:
    # Jika tidak exact, mungkin m^3 > n (tapi masih kecil), 
    # bisa dicoba brute force k*n (c + k*n)^(1/3), tapi biasanya untuk part 1 ini cukup simple root.
    print("[Part 1] Gagal melakukan direct cube root.")
