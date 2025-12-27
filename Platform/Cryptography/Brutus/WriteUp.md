
# WriteUp: Brutus

## Informasi Dasar

* **Kategori:** Cryptography
* **Poin:** 50
* **Deskripsi:**
> I lived in Rome for a bit, and was struck when one of my best friends betrayed me. This is what I had to say.
> `KZB{04_4b_iyba0}`



## Analisis

1. **Identifikasi Cipher:**
Judul "Brutus", referensi "Rome", dan "betrayed" adalah petunjuk klasik untuk **Caesar Cipher** (Julius Caesar dikhianati oleh Brutus).
2. **Percobaan Awal (Standard Decoder):**
Menggunakan decoder standar (hanya huruf A-Z) dengan Shift 7 (K  D):
* Ciphertext: `KZB{04_4b_iyba0}`
* Plaintext Awal: `DSU{04_4u_brut0}`


Namun, flag ini ditolak.
3. **Analisis Lanjutan (The Twist):**
Petunjuk soal menyatakan bahwa angka **0-9 juga harus digeser**, tidak seperti Caesar Cipher standar yang membiarkan angka tetap sama.
Kita perlu menerapkan pergeseran -7 (mundur 7 langkah) pada angka dengan modulus 10.
* Angka **0**: 
* Angka **4**: 



## Penyelesaian

Menggabungkan hasil dekripsi huruf dan angka:

* Huruf: `DSU{.._4u_brut.}`
* Angka: `0`  `3`, `4`  `7`

Hasil Akhir: `DSU{37_7u_brut3}` (Membaca: "Et tu, Brute")

## Solver Script

Berikut adalah script Python untuk mengotomatisasi dekripsi dengan custom logic (huruf mod 26, angka mod 10):

```python
import string

def custom_caesar_decrypt(ciphertext, shift):
    plaintext = ""
    
    for char in ciphertext:
        # 1. Handle Huruf (A-Z dan a-z) - Modulus 26
        if char.isalpha():
            ascii_base = ord('A') if char.isupper() else ord('a')
            decoded = chr((ord(char) - ascii_base - shift) % 26 + ascii_base)
            plaintext += decoded
            
        # 2. Handle Angka (0-9) - Modulus 10
        elif char.isdigit():
            digit = int(char)
            # (Digit - Shift) % 10
            decoded = str((digit - shift) % 10)
            plaintext += decoded
            
        # 3. Simbol tetap
        else:
            plaintext += char
            
    return plaintext

# Parameter
ciphertext = "KZB{04_4b_iyba0}"
shift_key = 7 

flag = custom_caesar_decrypt(ciphertext, shift_key)
print(f"[+] FLAG: {flag}")

```

## Flag

`DSU{37_7u_brut3}`
