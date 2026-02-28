def atbash(text):
    """Menerapkan Atbash Cipher pada teks."""
    decoded_text = ""
    for char in text:
        if 'A' <= char <= 'Z':
            # Rumus Atbash: A->Z, B->Y, dst.
            decoded_char = chr(ord('A') + (ord('Z') - ord(char)))
            decoded_text += decoded_char
        else:
            # Biarkan angka dan simbol tidak berubah
            decoded_text += char
    return decoded_text

def rot13(text):
    """Menerapkan ROT13 (shift +13) pada teks."""
    decoded_text = ""
    for char in text:
        if 'A' <= char <= 'Z':
            # Geser huruf sebanyak 13 posisi
            new_ord = ord(char) + 13
            if new_ord > ord('Z'):
                new_ord -= 26
            decoded_text += chr(new_ord)
        else:
            # Biarkan angka dan simbol tidak berubah
            decoded_text += char
    return decoded_text

# --- Program Utama ---

# Ciphertext dari challenge
ciphertext = "HGTI{IZK0J1ZG_TV4ZUH0VAMU1_KVOXT0}"

# Langkah 1: Dekripsi lapisan "Mirror" (Atbash)
intermediate_text = atbash(ciphertext)

# Langkah 2: Dekripsi lapisan "Shift" (ROT13)
flag = rot13(intermediate_text)

# Cetak hasilnya
print(f"[*] Ciphertext Original : {ciphertext}")
print(f"[*] Setelah Atbash (Mirror) : {intermediate_text}")
print("-" * 30)
print(f"✅ Flag Ditemukan : {flag}")
print("-" * 30)
