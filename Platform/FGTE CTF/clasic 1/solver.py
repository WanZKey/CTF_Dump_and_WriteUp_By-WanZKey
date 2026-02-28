import base64

def main():
    # Baca file clasic1.txt
    with open("clasic1.txt", "r") as f:
        data = f.read().strip()

    # Step 1: Decode dari base64
    decoded_b64 = base64.b64decode(data)

    # Step 2: Decode dari base32
    decoded_b32 = base64.b32decode(decoded_b64)

    # Step 3: Ubah bytes jadi string (berisi "70|71|73|...")
    numbers = decoded_b32.decode()

    # Step 4: Mapping ke binary
    mapping = {"70": "0", "71": "1"}
    bits = []
    for token in numbers.split("|"):
        if token in mapping:
            bits.append(mapping[token])
    binary_str = "".join(bits)

    # Step 5: Decode binary ke ASCII
    chars = []
    for i in range(0, len(binary_str), 8):
        byte = binary_str[i:i+8]
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    flag = "".join(chars)

    print("[+] Flag ditemukan:")
    print(flag)

if __name__ == "__main__":
    main()
