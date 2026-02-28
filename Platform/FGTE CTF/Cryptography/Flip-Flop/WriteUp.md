https://g.co/gemini/share/669fe6ef27d7
-----

# Write-Up CTF: Flip-Flop

## Informasi Challenge

| Kategori      | Nama Challenge | Poin |
|---------------|----------------|------|
| Cryptography  | Flip-Flop      | 100  |

-----

## Deskripsi

> Sebuah pesan disembunyikan dengan cara membalik urutan bit pada setiap karakter. Kelihatannya aneh, tapi kalau kamu tahu triknya, kamu bisa membalik balikannya lagi.

Diberikan dua file: `chall.py` dan `cipher.txt`.

-----

## Analisis

Langkah pertama adalah menganalisis skrip `chall.py` untuk memahami bagaimana proses enkripsi bekerja.

**`chall.py`**

```python
# flip_flop.py
def encode(text: str) -> str:
    out = []
    for c in text:
        bits = f"{ord(c):08b}"      # jadi biner 8-bit
        rev = bits[::-1]           # dibalik
        out.append(chr(int(rev, 2))) # balik ke char
    return "".join(out)

if __name__ == "__main__":
    plain = "FGTE{FLAG_EXAMPLE}"
    cipher = encode(plain)

    # simpan ke file
    with open("cipher.txt", "wb") as f:
        f.write(cipher.encode("latin-1"))

    print("Ciphertext disimpan ke cipher.txt")
```

Dari skrip di atas, kita dapat menyimpulkan proses enkripsi untuk setiap karakter adalah sebagai berikut:

1.  Karakter diubah menjadi nilai ordinal (ASCII).
2.  Nilai ordinal diubah menjadi string biner 8-bit.
3.  String biner tersebut **dibalik** urutannya.
4.  String biner yang telah dibalik diubah kembali menjadi integer, lalu diubah menjadi karakter baru.

Kunci utama dari challenge ini adalah **operasi pembalikan (reverse) merupakan operasinya sendiri (involusi)**. Artinya, jika kita membalik sesuatu dua kali, kita akan kembali ke keadaan semula.

`Original -> Reverse -> Reversed`
`Reversed -> Reverse -> Original`

Ini berarti, fungsi `encode` yang sama dapat digunakan untuk proses `decode`.

-----

## Solusi

Untuk mendapatkan flag, kita hanya perlu membuat skrip yang membaca `cipher.txt` dan menerapkan logika yang sama persis seperti pada fungsi `encode` ke setiap karakter dari ciphertext.

Berikut adalah skrip solver yang digunakan:

**`solver.py`**

```python
# solver.py

def decode_message(cipher_text: str) -> str:
    """
    Mendekripsi pesan dengan membalik urutan bit
    untuk setiap karakter.
    """
    decoded_chars = []
    for char in cipher_text:
        # 1. Ubah karakter menjadi representasi biner 8-bit
        bits = f"{ord(char):08b}"

        # 2. Balik urutan string biner tersebut
        reversed_bits = bits[::-1]

        # 3. Ubah biner yang sudah dibalik kembali menjadi karakter
        original_char = chr(int(reversed_bits, 2))
        decoded_chars.append(original_char)

    # Gabungkan semua karakter yang telah didekripsi
    return "".join(decoded_chars)


if __name__ == "__main__":
    try:
        # Buka file cipher.txt dengan encoding 'latin-1'
        with open("cipher.txt", "r", encoding="latin-1") as f:
            ciphertext = f.read()

        # Panggil fungsi dekripsi
        flag = decode_message(ciphertext)

        print("="*30)
        print(f"✅ Flag berhasil ditemukan!")
        print(f"   Flag: {flag}")
        print("="*30)

    except FileNotFoundError:
        print("[!] Error: File 'cipher.txt' tidak ditemukan.")
```

-----

## Eksekusi & Flag

Menjalankan skrip `solver.py` akan membaca `cipher.txt` dan langsung mencetak flag yang benar.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Crypto/Flip-Flop]
└─$ python3 solver.py
==============================
✅ Flag berhasil ditemukan!
   Flag: FGTE{B1T_FL1PP1NG_FUN}
==============================
```

Flag-nya adalah:

`FGTE{B1T_FL1PP1NG_FUN}`
