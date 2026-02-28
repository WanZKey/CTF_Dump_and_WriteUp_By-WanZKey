# solver.py

def decode_message(cipher_text: str) -> str:
    """
    Mendekripsi pesan dengan membalik urutan bit
    untuk setiap karakter.
    """
    decoded_chars = []
    for char in cipher_text:
        # Langkah 1: Ubah karakter menjadi representasi biner 8-bit
        # Contoh: 'b' (98) -> '01100010'
        bits = f"{ord(char):08b}"

        # Langkah 2: Balik urutan string biner tersebut
        # Contoh: '01100010' -> '01000110'
        reversed_bits = bits[::-1]

        # Langkah 3: Ubah biner yang sudah dibalik kembali menjadi karakter
        # Contoh: '01000110' (70) -> 'F'
        original_char = chr(int(reversed_bits, 2))
        decoded_chars.append(original_char)

    # Gabungkan semua karakter yang telah didekripsi
    return "".join(decoded_chars)


if __name__ == "__main__":
    try:
        # Buka file cipher.txt dengan encoding 'latin-1',
        # sama seperti saat file itu dibuat oleh chall.py
        with open("cipher.txt", "r", encoding="latin-1") as f:
            ciphertext = f.read()

        print(f"[*] Ciphertext berhasil dibaca:\n{ciphertext}\n")

        # Panggil fungsi dekripsi
        flag = decode_message(ciphertext)

        print("="*30)
        print(f"✅ Flag berhasil ditemukan!")
        print(f"   Flag: {flag}")
        print("="*30)

    except FileNotFoundError:
        print("[!] Error: File 'cipher.txt' tidak ditemukan.")
        print("    Pastikan 'solver.py' dan 'cipher.txt' berada di folder yang sama.")
