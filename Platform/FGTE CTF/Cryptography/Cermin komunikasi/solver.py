# Cermin Komunikasi Solver - by ChatGPT
# Challenge by aria (FGTE CTF)

def xor_mirror_decrypt(hex_data, key="mirror"):
    # Ubah string hex jadi list byte
    data = bytes.fromhex(hex_data.replace(" ", ""))
    # Balik urutan bytes (mirror)
    mirrored = data[::-1]
    # XOR dengan key berulang
    key_bytes = key.encode()
    decrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(mirrored)])
    return decrypted.decode(errors="ignore")

if __name__ == "__main__":
    hex_input = "0f 1e 08 03 15 06 01 2d 0d 08 06 0c 17 1e 0f 08 00 14 37 26 2e 2b"
    flag = xor_mirror_decrypt(hex_input)
    print("Flag:", flag)
