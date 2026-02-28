# solver2.py
def main():
    # 1️⃣ Baca file
    with open("hasil_decode.txt", "r") as f:
        data = f.read().strip()

    # 2️⃣ Hilangkan separator '11'
    tokens = data.replace("11", "|")  # ganti jadi delimiter biar mudah split
    tokens = [t for t in tokens.split("|") if t]  # buang kosong

    # 3️⃣ Mapping angka ke bit
    mapping = {
        "88": "0",
        "99": "1",
        # "33" dan "44" abaikan (decoy)
    }

    bits = []
    for t in tokens:
        if t in mapping:
            bits.append(mapping[t])

    binary_str = "".join(bits)

    # 4️⃣ Ubah ke ASCII per 8 bit
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
