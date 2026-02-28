https://g.co/gemini/share/4cb51ad8fe36
-----

# Write-Up CTF: Mirror & Shift

## Informasi Challenge

| Kategori      | Nama Challenge   | Poin |
|---------------|------------------|------|
| Cryptography  | Mirror & Shift   | 100  |

-----

## Deskripsi

> Pesan ini disembunyikan dalam dua lapisan transformasi huruf. Buka lapisan demi lapisan untuk menemukan flag.

**Ciphertext:** `HGTI{IZK0J1ZG_TV4ZUH0VAMU1_KVOXT0}`

-----

## Analisis

Dari nama challenge, "Mirror & Shift", dan deskripsi yang menyebutkan "dua lapisan", kita dapat langsung mencurigai adanya dua jenis cipher klasik:

1.  **Mirror (Cermin)**: Mengarah pada **Atbash Cipher**, sebuah cipher substitusi di mana alfabet dibalik (A menjadi Z, B menjadi Y, dst.).
2.  **Shift (Pergeseran)**: Mengarah pada **Caesar Cipher**, di mana setiap huruf digeser sejumlah posisi tertentu dalam alfabet.

Strategi kita adalah mendekripsi ciphertext lapis demi lapis, dimulai dari lapisan terluar.

-----

## Langkah 1: Dekripsi Lapisan 'Mirror' (Atbash Cipher)

Pertama, kita terapkan Atbash Cipher pada ciphertext. Angka dan simbol selain huruf kapital akan kita biarkan.

  - **Ciphertext**: `HGTI{IZK0J1ZG_TV4ZUH0VAMU1_KVOXT0}`
  - **Proses**: `H` menjadi `S`, `G` menjadi `T`, `T` menjadi `G`, `I` menjadi `R`, dan seterusnya.
  - **Hasil Sementara**: `STGR{RAP0Q1AT_GE4AFS0EZNF1_PELCG0}`

Hasilnya masih berupa teks acak, yang menandakan adanya lapisan enkripsi kedua.

## Langkah 2: Dekripsi Lapisan 'Shift' (Caesar Cipher / ROT13)

Sekarang kita memiliki teks `STGR{...}`. Format flag standar biasanya `FGTE{...}`. Dengan membandingkan awalan ini, kita bisa menemukan kunci pergeseran:

  - `S` → `F` = pergeseran +13
  - `T` → `G` = pergeseran +13
  - `G` → `T` = pergeseran +13
  - `R` → `E` = pergeseran +13

Pergeserannya konsisten, yaitu **+13**, yang merupakan cipher **ROT13**. Kita terapkan ROT13 pada hasil dari langkah pertama.

  - **Teks Sementara**: `STGR{RAP0Q1AT_GE4AFS0EZNF1_PELCG0}`
  - **Proses**: `S` menjadi `F`, `T` menjadi `G`, `R` menjadi `E`, `A` menjadi `N`, dst.
  - **Hasil Akhir**: `FGTE{ENC0D1NG_TR4NSF0RMAS1_CRYPT0}`

-----

## Skrip Solusi

Untuk memvalidasi dan mengotomatiskan proses, kita bisa menggunakan skrip Python berikut.

**`solver.py`**

```python
def atbash(text):
    """Menerapkan Atbash Cipher pada teks."""
    decoded_text = ""
    for char in text:
        if 'A' <= char <= 'Z':
            decoded_char = chr(ord('A') + (ord('Z') - ord(char)))
            decoded_text += decoded_char
        else:
            decoded_text += char
    return decoded_text

def rot13(text):
    """Menerapkan ROT13 (shift +13) pada teks."""
    decoded_text = ""
    for char in text:
        if 'A' <= char <= 'Z':
            new_ord = ord(char) + 13
            if new_ord > ord('Z'):
                new_ord -= 26
            decoded_text += chr(new_ord)
        else:
            decoded_text += char
    return decoded_text

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
```

-----

## Eksekusi dan Flag

Menjalankan skrip di atas memberikan output sebagai berikut, yang mengonfirmasi flag yang benar.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Crypto/Mirror & Shift]
└─$ python3 solver.py
[*] Ciphertext Original : HGTI{IZK0J1ZG_TV4ZUH0VAMU1_KVOXT0}
[*] Setelah Atbash (Mirror) : STGR{RAP0Q1AT_GE4AFS0EZNF1_PELCG0}
------------------------------
✅ Flag Ditemukan : FGTE{ENC0D1NG_TR4NSF0RMAS1_CRYPT0}
------------------------------
```

Flag yang ditemukan adalah:
**`FGTE{ENC0D1NG_TR4NSF0RMAS1_CRYPT0}`**
