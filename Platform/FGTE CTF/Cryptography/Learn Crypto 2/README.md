# WriteUp - Learn Crypto 2

## Overview

* **Judul:** Learn Crypto 2
* **Kategori:** Crypto
* **Poin:** 90
* **Author:** aria
* **Deskripsi:**
Selamat datang di dunia kriptografi! Pada challenge ini, kamu akan diajak memahami dasar-dasar teknik encoding dan encryption yang sering digunakan dalam dunia CTF. Sebuah pesan rahasia telah dikunci menggunakan beberapa lapisan kriptografi. Tugasmu adalah membongkar setiap lapisan tersebut secara berurutan hingga menemukan flag tersembunyi di dalamnya.
TIPS: “Sebelum pakai decode X, lakukan Base64 dulu”

## Informasi Attachment

File yang diberikan adalah `ct.txt` yang berisi ciphertext dengan multiple layer encoding.

**Struktur Direktori:**

```text
.
├── ct.txt
└── solve.py

```

**Isi ct.txt (Partial):**

```text
TzIxZE1uSTJZbEZjVUZjcFAxNVZaanNzSlNwWGJqWkpLVmxSUVZscExqRTZTVEJxUG1SaVltNVZhVTAvTFZoQ01uMUdiM0pDWVVzMFJtMG5XR050TzBGS01FMWhTekJlWXp4b2VsTTZhaTh6WDJsSkx6Z3hNQzlGVkdrcldpdHFURHBwWldzM05WVjVaVlpBUHlSUU56TWhNUzVaTHk5b05TOXdXVU01UHp3OEtpVkZhWEpqUmtSeFdTWnRKVkpsVFNRNlpGQnJOVmhjS25CVVZDWktNVHdzUERGZFVEUkNQMXRyYVZZcFIyUkhSR2xOV2wweFlUVXhSaWhaWjA5VlJUNWRNak5KVzJSYlNWdDBjRHhCYmtCalh6eFZQaXBlYURGdmNWbFhUM2hCYlRGaktWRmNPa0J0VlU4L1p6d2xORVk5TVhKSlhTMDZMRU01UG5FOFhUMVdSMEJ6V21WQUwzWlpjR3hZWFhoSFpWNXNOakF4WDNrdVVpUThYandwUGxSZFoxMWJMa0pXTkZCaVZtbFNUemRNV21RbFFXSTBRRjVDU2lsQU1UaEVPanhxWkRwVVkwdDZjRnRCZVNZa0xVTTdmVDVJSzE4PQ0KSW5pIGJlbHVtIGZsYWcuIERlY29kZSBsYWdpIG1lbmdndW5ha2FuIEJhc2U5Mg==

```

## Proses Penyelesaian

Challenge ini memiliki 6 lapisan encoding/enkripsi yang harus diselesaikan secara berurutan:

1. **Layer 1 (Base64):**
Decode konten `ct.txt`. Outputnya memberikan petunjuk: "Decode lagi menggunakan Base92".
2. **Layer 2 (Base64 Wrapper):**
Sebelum masuk ke Base92, payload dari Layer 1 harus di-decode Base64 sekali lagi untuk mendapatkan string Base92 yang valid (string yang terlihat seperti *garbage text*).
3. **Layer 3 (Base92):**
Menggunakan library `base92`, string dari Layer 2 di-decode. Hasilnya adalah string Base64 yang membungkus layer berikutnya beserta hint: "Gunakan ROT47".
4. **Layer 4 (ROT47):**
Payload di-decode Base64, lalu diaplikasikan decryption **ROT47**. Hasilnya memberikan hint baru: "Lalu gunakan Caesar Cipher dengan shift 10".
5. **Layer 5 (Caesar Cipher):**
Payload berikutnya di-decode Base64, lalu di-decrypt menggunakan **Caesar Cipher** dengan pergeseran (shift) 10.
Hint yang didapat: "Terakhir gunakan Vigenere Cipher dengan kunci 'cryptoisfun'".
6. **Layer 6 (Vigenere Cipher):**
Payload terakhir di-decode Base64, menghasilkan ciphertext: `HXRT{Dsmh_Q34la1px_Agrd70_O31cx!}`.
Ciphertext ini di-decrypt menggunakan **Vigenere Cipher** dengan key `cryptoisfun`.

## Script Solver

Berikut adalah script Python (`solve.py`) yang mengotomatiskan seluruh proses *decoding* dari awal hingga mendapatkan flag:

```python
import base64
import base92
import re

def rot47(data):
    decoded = []
    for char in data:
        n = ord(char)
        if 33 <= n <= 126:
            decoded.append(chr(33 + ((n + 14) % 94)))
        else:
            decoded.append(char)
    return "".join(decoded)

def caesar_decrypt(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            decoded_char = chr(start + (ord(char) - start - shift) % 26)
            result.append(decoded_char)
        else:
            result.append(char)
    return "".join(result)

def vigenere_decrypt(ciphertext, key):
    key_length = len(key)
    plaintext = ''
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            key_char = key[key_index % key_length]
            key_offset = 65 if key_char.isupper() else 97
            
            val = (ord(char) - offset) - (ord(key_char) - key_offset)
            val = (val % 26) + offset
            plaintext += chr(val)
            key_index += 1
        else:
            plaintext += char
    return plaintext

def solve():
    print("[*] Starting Full Auto Solver...")
    print("-" * 40)

    try:
        # STEP 1: Load File
        with open("ct.txt", "r") as f:
            content = f.read().strip()
        
        # STEP 2: Layer 1 (Base64)
        print("[1] Decoding Layer 1 (Base64)...")
        l1_out = base64.b64decode(content).decode('utf-8', errors='ignore')
        l1_payload = l1_out.split('\n')[0].strip()

        # STEP 3: Layer 2 (Base64 wrapper for Base92)
        print("[2] Decoding Layer 2 (Base64 wrapper)...")
        l2_bytes = base64.b64decode(l1_payload)

        # STEP 4: Layer 3 (Base92)
        print("[3] Decoding Layer 3 (Base92)...")
        l3_out = base92.decode(l2_bytes)
        if isinstance(l3_out, bytes):
            l3_out = l3_out.decode('utf-8')
        l3_payload_b64 = l3_out.strip()

        # STEP 5: Layer 4 (Base64 -> ROT47)
        print("[4] Decoding Layer 4 (ROT47)...")
        l4_rot_encoded = base64.b64decode(l3_payload_b64).decode('utf-8')
        l4_plain = rot47(l4_rot_encoded)
        
        lines = l4_plain.strip().split('\n')
        l5_input_b64 = lines[0].strip()
        print(f"    [>] Hint Found: {lines[1]}")

        # STEP 6: Layer 5 (Base64 -> Caesar Shift 10)
        print("[5] Decoding Layer 5 (Caesar Shift 10)...")
        l5_cipher = base64.b64decode(l5_input_b64).decode('utf-8')
        l5_plain = caesar_decrypt(l5_cipher, 10)
        
        lines = l5_plain.strip().split('\n')
        l6_input_b64 = lines[0].strip()
        hint_vigenere = lines[1].strip()
        
        # Extract Key
        key_match = re.search(r'"(.*?)"', hint_vigenere)
        key = key_match.group(1) if key_match else "cryptoisfun"
        print(f"    [>] Key Found : {key}")

        # STEP 7: Layer 6 (Base64 -> Vigenere)
        print("[6] Decoding Layer 6 (Vigenere)...")
        l6_cipher = base64.b64decode(l6_input_b64).decode('utf-8')
        flag = vigenere_decrypt(l6_cipher, key)

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
[*] Starting Full Auto Solver...
----------------------------------------
[1] Decoding Layer 1 (Base64)...
[2] Decoding Layer 2 (Base64 wrapper)...
[3] Decoding Layer 3 (Base92)...
[4] Decoding Layer 4 (ROT47)...
    [>] Hint Found: Lalu gunakan Caesar Cipher dengan shift 10.
[5] Decoding Layer 5 (Caesar Shift 10)...
    [>] Key Found : cryptoisfun
[6] Decoding Layer 6 (Vigenere)...

==================================================
SOLVED FLAG: FGTE{Keep_L34rn1ng_Cryp70_G31ks!}
==================================================

```

## Flag

```
FGTE{Keep_L34rn1ng_Cryp70_G31ks!}

```
