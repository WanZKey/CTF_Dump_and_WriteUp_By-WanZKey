def xor_with_key(data: bytes, key: bytes) -> bytes:
    key_repeated = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes([b ^ k for b, k in zip(data, key_repeated)])

# Nama file dan key
filename = "Key is the Key.txt"
key = b"crypto"

# Baca isi file
with open(filename, "rb") as f:
    content = f.read()

# XOR
decrypted = xor_with_key(content, key)

# Tampilkan hasil
try:
    print("Hasil XOR (teks):")
    print(decrypted.decode())  # coba decode sebagai teks
except UnicodeDecodeError:
    print("Hasil XOR (hex):")
    print(decrypted.hex())
