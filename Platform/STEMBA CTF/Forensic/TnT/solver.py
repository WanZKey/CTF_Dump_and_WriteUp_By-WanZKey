def main():
    with open("chall.txt", "rb") as f:
        data = f.read()

    bits = []

    # Setiap byte dianggap 1 bit: 0x00 → 0, 0x01 → 1
    for i, byte in enumerate(data):
        if byte == 0x00:
            bits.append('0')
        elif byte == 0x01:
            bits.append('1')
        else:
            # Kalau ada byte aneh selain 0x00 / 0x01, kasih warning
            print(f"[!] Warning: byte tidak dikenali di offset {i}: {byte:02x}")

    # Gabungkan tiap 8 bit jadi karakter ASCII
    text = ''
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break  # skip sisa tak genap
        byte_str = ''.join(byte_bits)
        ascii_char = chr(int(byte_str, 2))
        text += ascii_char

    print("[+] Pesan tersembunyi:", text)
    print("[+] Flag: STEMBACTF{" + text + "}")

if __name__ == "__main__":
    main()
