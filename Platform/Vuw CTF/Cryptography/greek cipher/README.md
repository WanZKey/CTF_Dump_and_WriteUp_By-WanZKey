# WriteUp - greek cipher

## Overview
- **Judul Challenge:** greek cipher
- **Kategori:** Cryptography
- **Poin:** 75
- **Author:** Aterlone
- **Release:** Site Release
- **Solves:** 33
- **First Blood:** BAkingBRead
- **Deskripsi:** I discovered this message that was apparently encrypted using an ancient Greek method involving a rod or staff. The year of Greece's fall seems to be relevant, % 100.

## Informasi Attachment & Struktur Direktori
Terdapat satu file attachment berupa `ciphertext.txt`. Berikut adalah informasi direktori beserta inspeksi awal file menggunakan terminal:

```bash
 WanZKey  ～  ~../Cryptography/greek cipher 󱎫 0s 󱑎 23.43
 󰋑  ▶  file ciphertext.txt
ciphertext.txt: Unicode text, UTF-8 text, with no line terminators

 WanZKey  ～  ~../Cryptography/greek cipher 󱎫 0s 󱑎 23.43
 󰋑  ▶  cat ciphertext.txt
T·haen·df·ltahgi·si·sc·iVpuhweCrT·Fw{aasn·cuiseendt·_ignr·eaenkc_icernytp·tGorgereacpeh.y·}·¶
```

## Proses Penyelesaian
1. Melakukan inspeksi awal terhadap file `ciphertext.txt` yang berisi deretan teks acak dengan sisipan karakter *middle dot* (`·`).
2. Menganalisis petunjuk pertama dari deskripsi: "ancient Greek method involving a rod or staff". Hal ini secara langsung merujuk pada teknik kriptografi kuno **Scytale Cipher**, yang bekerja dengan cara mentransposisi teks menggunakan silinder dengan ukuran tertentu.
3. Menganalisis petunjuk kedua: "The year of Greece's fall seems to be relevant, % 100". Berdasarkan catatan sejarah, Yunani jatuh ke tangan Romawi pada Pertempuran Korintus di tahun 146 SM. Dengan melakukan operasi modulus `146 % 100`, didapatkan nilai **46**. Nilai ini berfungsi sebagai kunci utama (panjang silinder) untuk dekripsi Scytale.
4. Karena panjang *ciphertext* adalah 92 karakter, penggunaan kunci 46 berarti teks tersebut digulung ke dalam 2 baris (putaran) pada silinder Scytale.
5. Menyusun *script solver* menggunakan Python untuk mengotomatisasi proses transposisi dekripsi Scytale dengan kunci 46 dan membersihkan *output* dari karakter *middle dot* agar menjadi kalimat yang utuh dan terbaca.
6. Mengeksekusi *script solver* melalui terminal, yang secara langsung mengungkapkan *plaintext* beserta *flag* yang valid.

## Script Solver
**solver.py**
```python
import math

def decrypt_scytale(ciphertext, key):
    num_rows = math.ceil(len(ciphertext) / key)
    plaintext_rows = [""] * num_rows
    
    for i, char in enumerate(ciphertext):
        row = i % num_rows
        plaintext_rows[row] += char
        
    return "".join(plaintext_rows)

def solve():
    try:
        with open("ciphertext.txt", "r", encoding="utf-8") as f:
            ciphertext = f.read().strip()
            
        ciphertext = ciphertext.replace('¶', '').strip()
        print("[*] Ciphertext length :", len(ciphertext))
        
        key = 46 
        print(f"[*] Menggunakan Scytale Key : {key}")
        
        decrypted_text = decrypt_scytale(ciphertext, key)
        readable_text = decrypted_text.replace('·', ' ')
        
        print(f"\n[*] Decrypted Text:\n{readable_text}")
        
    except FileNotFoundError:
        print("[!] File ciphertext.txt tidak ditemukan.")
    except Exception as e:
        print(f"[!] Terjadi kesalahan: {e}")

if __name__ == '__main__':
    solve()
```

**Output Terminal**
```bash
 󰋑  ▶  ./solver.py
[*] Ciphertext length : 92
[*] Menggunakan Scytale Key : 46

[*] Decrypted Text:
The flag is VuwCTF{ancient_greek_cryptography} and this cipher was used in ancient Greece.
```

## Flag

```
VuwCTF{ancient_greek_cryptography}
```
