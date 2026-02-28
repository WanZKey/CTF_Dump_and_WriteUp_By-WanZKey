# WriteUp - 10 Kunci Jawaban

## Overview

* **Judul:** 10 Kunci Jawaban
* **Kategori:** Crypto
* **Poin:** 100
* **Author:** aria
* **Deskripsi:**
10 soal yang memerlukan kunci "jawaban".
Format: FGTE{jawaban}

## Informasi Attachment

Ciphertext yang diberikan: `F4mc_B1d4_M3ab3rR4k4y_S04y_E4w4j4n_J4nt_O3p4b`

## Proses Penyelesaian

1. **Analisa Kriptografi:**
* **Cipher:** Vigenere Cipher (terindikasi dari hint dan pola karakter).
* **Key:** `jawaban` (dari deskripsi).
* **Logic:** Judul "10 Kunci Jawaban" mengindikasikan proses repetisi.


2. **Decoding Bertingkat (Recursive Decryption):**
Percobaan dekripsi standar (1x putaran) menghasilkan teks yang belum terbaca sempurna (`W4mg...`).
Berdasarkan judul, proses dekripsi dilakukan secara berulang (iteratif). Setelah dilakukan analisis brute-force pada jumlah putaran, ditemukan bahwa ciphertext akan menjadi plaintext yang valid pada **putaran ke-11**.
* **Iterasi 1:** `W4mg_B1c4...`
* ...
* **Iterasi 11:** `K4mu_B1s4_M3ng3rJ4k4n_S04l_J4w4b4n_Y4ng_T3p4t`


Kalimat yang terbentuk: *"Kamu bisa mengerjakan soal jawaban yang tepat"*.

## Script Solver

```python
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
    print("[*] Solver 10 Kunci Jawaban")
    
    cipher = "F4mc_B1d4_M3ab3rR4k4y_S04y_E4w4j4n_J4nt_O3p4b"
    key = "jawaban"
    
    # Melakukan dekripsi berulang sebanyak 11 kali
    current_text = cipher
    for i in range(11):
        current_text = vigenere_decrypt(current_text, key)
        
    print(f"Result (Round 11): {current_text}")
    print(f"Flag             : FGTE{{{current_text}}}")

if __name__ == "__main__":
    solve()

```

## Output Terminal

```bash
 󰋑  ▶  ./solver.py
[*] Solver 10 Kunci Jawaban (Final Logic)
Result (Round 11): K4mu_B1s4_M3ng3rJ4k4n_S04l_J4w4b4n_Y4ng_T3p4t
Flag             : FGTE{K4mu_B1s4_M3ng3rJ4k4n_S04l_J4w4b4n_Y4ng_T3p4t}

```

## Flag

```
FGTE{K4mu_B1s4_M3ng3rJ4k4n_S04l_J4w4b4n_Y4ng_T3p4t}

```
