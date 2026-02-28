import base64

def solve_double_challenge(encoded_string):
    """
    Memecahkan tantangan "double" CTF.
    Melakukan dekripsi hex kustom, konversi hex ke ASCII, dan dekode Base64.
    """

    print(f"Original encoded string: {encoded_string}\n")

    # --- Langkah 1: Dekode Hex Kustom (Pergeseran -7 untuk non-hex chars) ---
    # Petunjuk: 'i' = 'b' + 7, 'j' = 'c' + 7, dst.
    # Kita perlu melakukan pergeseran balik (-7)
    hex_custom_map = {
        'h': 'a', 'i': 'b', 'j': 'c', 'k': 'd', 'l': 'e', 'm': 'f'
    }

    decoded_hex_string = ""
    for char in encoded_string:
        decoded_hex_string += hex_custom_map.get(char, char)

    print(f"Step 1: Decoded custom hex string: {decoded_hex_string}\n")

    # --- Langkah 2: Konversi Hex ke ASCII ---
    # String sudah berupa heksadesimal yang valid, konversi ke byte kemudian ke string.
    try:
        # Konversi hex string ke bytes
        ascii_bytes = bytes.fromhex(decoded_hex_string)
        # Dekode bytes ke string menggunakan UTF-8 (umumnya aman untuk CTF)
        decoded_ascii_string = ascii_bytes.decode('utf-8')
        print(f"Step 2: Decoded hex to ASCII string: {decoded_ascii_string}\n")
    except ValueError as e:
        print(f"Error converting hex to ASCII: {e}")
        return "Failed at Step 2"

    # --- Langkah 3: Dekode Base64 ---
    # Hasil dari langkah 2 adalah string Base64
    try:
        # Encode string kembali ke bytes sebelum dekode Base64
        base64_bytes = decoded_ascii_string.encode('ascii')
        decoded_base64_bytes = base64.b64decode(base64_bytes)
        final_message = decoded_base64_bytes.decode('utf-8')
        print(f"Step 3: Decoded Base64 message: {final_message}\n")
    except base64.binascii.Error as e:
        print(f"Error decoding Base64: {e}")
        return "Failed at Step 3"
    except UnicodeDecodeError as e:
        print(f"Error decoding Base64 result to UTF-8: {e}")
        return "Failed at Step 3 (Unicode)"

    return final_message

def caesar_decrypt(text, shift):
    """
    Mendekripsi teks menggunakan Caesar Cipher.
    Positive shift berarti digeser ke kiri (A->Z jika shift=1)
    Negative shift berarti digeser ke kanan (A->B jika shift=-1 atau shift=25)
    """
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
        elif 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a'))
        else:
            result += char
    return result

# --- Data Challenge ---
challenge_string = "526i645552587444556j6j515645396653564l66526j564m58304h565646394451553566516i566656464h4h5130745h587h49774k6h55774f54493166513k3k0h" # Saya mengubah 'm' menjadi 'f' di akhir berdasarkan hasil awal, untuk memastikan output hex yang valid.
                                                                                                                                                             # Jika Anda menggunakan string asli dari problem, pastikan 'm'->'f' dan 'k'->'d'.
# Cek string asli dari prompt:
# 526i645552587444556j6j515645396653564l66526j564m58304h565646394451553566516i566656464h4h5130745h587h49774k6h55774m54493166513k3k0h
# Oh, ternyata di akhir ada 'm' dan 'k'. String di atas sudah benar.

# Jalankan solver
final_decoded_message = solve_double_challenge(challenge_string)

print("\n-------------------------------------------------")
print("SUMMARY:")
print(f"The message after all layers (Hex Kustom -> ASCII -> Base64) is:\n{final_decoded_message}")

# --- Optional: Percobaan Caesar Cipher pada flag yang ditemukan ---
# Jika Anda menganggap bagian "pergeseran +7" dari petunjuk berlaku untuk flag akhir,
# maka kita perlu menggeser mundur 7 karakter.
# Namun, seperti yang kita duga sebelumnya, flag CTF biasanya tidak perlu
# mendekripsi ulang setelah pesan "The flag is..." sudah jelas.
# Jadi, bagian ini lebih ke eksplorasi atau jika Anda ingin mencoba.

if final_decoded_message and "CTRI{" in final_decoded_message:
    print("\n-------------------------------------------------")
    print("OPTIONAL: Caesar Decryption for the flag part (shift -7):")
    flag_start_index = final_decoded_message.find("CTRI{")
    if flag_start_index != -1:
        flag_part = final_decoded_message[flag_start_index:]
        # Shift -7 (atau +19) untuk mendekripsi
        decrypted_flag_caesar = caesar_decrypt(flag_part, 7)
        print(f"Original potential flag: {flag_part}")
        print(f"Decrypted flag with Caesar Shift -7: {decrypted_flag_caesar}")
    else:
        print("Could not find 'CTRI{' in the final message to apply Caesar decryption.")
