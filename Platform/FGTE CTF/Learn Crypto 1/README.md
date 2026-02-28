# WriteUp - Learn Crypto 1

## Overview

* **Judul:** Learn Crypto 1
* **Kategori:** Crypto
* **Poin:** 60
* **Author:** aria
* **Deskripsi:**
Selamat datang di dunia kriptografi! Pada challenge ini, kamu akan diajak memahami dasar-dasar teknik encoding dan encryption yang sering digunakan dalam dunia CTF. Sebuah pesan rahasia telah dikunci menggunakan beberapa lapisan kriptografi. Tugasmu adalah membongkar setiap lapisan tersebut secara berurutan hingga menemukan flag tersembunyi di dalamnya.
TIPS: “Sebelum pakai decode X, lakukan Base64 dulu”

## Informasi Attachment

File yang diberikan adalah `ct.txt` yang berisi ciphertext dengan encoding bertingkat.

**Struktur Direktori:**

```text
.
├── ct.txt
└── solve.py

```

**Isi ct.txt:**

```text
S1lZR0lTSzJHQkRFS1QySU1SRldLU0NDSkZMRUlSSlVLRkxFNFIyVUlWU0ZBWkNWUEJIRkVWU09KVk5FSzQzWUtSRFdJU0NTSkJERk1VM09OUTJHRzIzTUlWU0VJTUNPSU5WV0k2SzJLNDJUSVpDWUxKV0VZUTJDR0JRVU9SVFZNVkRUSzJDSklWMkVHVVNUSUo0R0czS0dHQlJHMlJMSE1WRFdRMkRESkJNV09TTE9JSldHRVIyT05aTVc0V1ROTU1aR1EyQ0pORTJEMkNTQ01GVFhLNFpPRUJKV0syM0JPSlFXNFpaQU01Mlc0WUxMTUZYQ0FVU1BLUVlUR0xRPQpJbmkgYmVsdW0gZmxhZy4gRGVjb2RlIGxhZ2kgbWVuZ2d1bmFrYW4gQmFzZTMyLg==

```

## Proses Penyelesaian

1. **Analisa Layer 1 (Base64):**
Isi file `ct.txt` merupakan string Base64. Setelah di-decode, outputnya menginstruksikan untuk menggunakan Base32.
2. **Decoding Layer 2 (Base32):**
Hasil decode dari Layer 1 berupa string Base32. Setelah di-decode, kita mendapatkan string Base64 baru:
`V0dIZ0FEOHdKeHBIVDE4QVNGTEdPdUxNRVNMZEsxTGdHRHFVSnl4cklEdD0NCkdyZW54dXZlLCB0aGFueG5hIEtCRSBxcmF0bmEgeGhhcHYgInBlbGNnYnZmc2hhIi4=`
3. **Decoding Layer 3 (Base64 Wrapper):**
String dari Layer 2 di-decode kembali menggunakan Base64, menghasilkan dua baris teks terpisah:
* **Baris 1 (Ciphertext):** `WGHgAD8wJxpHT18ASFLGOuLMESLdK1LgGDqUJyxrIDt=`
* **Baris 2 (Hint):** `Grenxuve, thanxna KBE qratna xhapv "pelcgbvfsha".`


4. **Analisa Hint & Key Extraction:**
Hint pada baris kedua menggunakan enkripsi ROT13.
* Cipher: `Grenxuve...`
* Plain: `Terakhir, gunakan XOR dengan kunci "cryptoisfun".`
Key untuk tahap akhir adalah `cryptoisfun`.


5. **Final Decryption (ROT13 + Base64 + XOR):**
Karena hint menggunakan ROT13, Ciphertext pada baris pertama (`WGHg...`) juga terenkripsi ROT13 sebelum di-encoding Base64.
* **Langkah 1:** ROT13 pada Ciphertext `WGHg...` menjadi `JTUt...`.
* **Langkah 2:** Base64 Decode pada `JTUt...` menjadi raw bytes.
* **Langkah 3:** XOR raw bytes dengan key `cryptoisfun`.



## Script Solver

Berikut adalah script Python (`solve.py`) untuk menyelesaikan challenge secara otomatis:

```python
import base64
import codecs
import re

def xor_decrypt(data, key):
    key_bytes = key.encode()
    result = bytearray()
    for i in range(len(data)):
        result.append(data[i] ^ key_bytes[i % len(key_bytes)])
    return result

def solve():
    print("[*] Starting Final Solver...")
    
    try:
        # 1. Baca CT
        with open("ct.txt", "r") as f:
            content = f.read().strip()
            
        # 2. Decode Layer 1 (Base64) & Layer 2 (Base32)
        print("[*] Decoding Layer 1 (B64) -> Layer 2 (B32)...")
        l1 = base64.b64decode(content).decode('utf-8', errors='ignore')
        
        # Ambil string Base32 (biasanya baris pertama jika ada sampah lain)
        b32_str = l1.split()[0] 
        l2 = base64.b32decode(b32_str).decode('utf-8')
        
        # l2 sekarang adalah "V0dIZ..."
        print(f"    [>] Layer 2 Output: {l2[:20]}...")

        # 3. Decode Layer 3 (Base64 wrapper)
        print("[*] Decoding Layer 3 (Base64 Wrapper)...")
        l3_decoded = base64.b64decode(l2).decode('utf-8')
        
        lines = l3_decoded.strip().split('\n')
        target_cipher_rot = lines[0].strip() # "WGHg..."
        hint_rot13 = lines[1].strip()        # "Grenxuve..."
        
        print(f"    [>] Target Cipher : {target_cipher_rot}")
        print(f"    [>] Hint          : {hint_rot13}")

        # 4. Parse Hint
        hint_plain = codecs.decode(hint_rot13, 'rot_13')
        key_match = re.search(r'"(.*?)"', hint_plain)
        key = key_match.group(1) if key_match else "cryptoisfun"
        print(f"    [+] Key           : {key}")

        # 5. Apply ROT13 to Target Cipher
        # Hint bilang "ROT13", dan ini berlaku untuk Cipher-nya juga sebelum di-decode
        print("[*] Applying ROT13 to Target Cipher...")
        cipher_rot13 = codecs.decode(target_cipher_rot, 'rot_13')
        print(f"    [>] Cipher (ROT13): {cipher_rot13}")

        # 6. Decode Base64 Final & XOR
        print(f"[*] Decoding Base64 & XOR with '{key}'...")
        cipher_bytes = base64.b64decode(cipher_rot13)
        decrypted = xor_decrypt(cipher_bytes, key)
        flag = decrypted.decode('utf-8')

        print("\n" + "="*50)
        print(f"SOLVED FLAG: {flag}")
        print("="*50 + "\n")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()

```

## Output Terminal

```bash
 󰋑  ▶  ./solver.py
[*] Starting Final Solver...
[*] Decoding Layer 1 (B64) -> Layer 2 (B32)...
    [>] Layer 2 Output: V0dIZ0FEOHdKeHBIVDE4...
[*] Decoding Layer 3 (Base64 Wrapper)...
    [>] Target Cipher : WGHgAD8wJxpHT18ASFLGOuLMESLdK1LgGDqUJyxrIDt=
    [>] Hint          : Grenxuve, thanxna KBE qratna xhapv "pelcgbvfsha".
    [+] Key           : cryptoisfun
[*] Applying ROT13 to Target Cipher...
    [>] Cipher (ROT13): JTUtNQ8jWkcUG18NFSYTBhYZRFYqX1YtTQdHWlkeVQg=
[*] Decoding Base64 & XOR with 'cryptoisfun'...

==================================================
SOLVED FLAG: FGTE{L34rn1ng_cryp70_15_4w350m3}
==================================================

```

## Flag

```
FGTE{L34rn1ng_cryp70_15_4w350m3}

```
