
# Writeup: Between the Margins (Crypto)

## Informasi Challenge

* **Kategori:** Cryptography
* **Poin:** 280
* **Hint:** "Sinyal yang kamu temukan hanyalah sebuah rujukan. Sisanya tersembunyi di antara batas-batasnya."
* **File:** `referensi.txt`
* **Deret Angka:** `234, 235, 1, 237, 238`

## Analisis

Challenge ini merupakan variasi dari **Book Cipher**, di mana deret angka yang diberikan merujuk pada urutan kata (indeks) di dalam file teks `referensi.txt`.

1. **Ekstraksi Kata:** Kita perlu mengambil kata-kata berdasarkan urutan kemunculannya di teks. Simbol dan tanda baca harus diabaikan.
2. **Analisis Indeks:**
* **234:** truth
* **235:** lives
* **1:** Between (Kata pertama pada judul file)
* **237:** the
* **238:** margins


3. **Susunan Kalimat:** Kata-kata tersebut membentuk kalimat "truth lives Between the margins".
4. **Format Flag:** Berdasarkan percobaan, flag yang valid mengharuskan seluruh huruf dikonversi menjadi huruf kapital (**Uppercase**).

## Solusi (Script Solver)

Berikut adalah script Python yang telah dimodifikasi. Perubahan utama ada pada penambahan fungsi `.upper()` saat menyusun string akhir agar output otomatis menjadi kapital.

```python
import re

def solve():
    filename = "referensi.txt"
    
    try:
        with open(filename, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] File {filename} tidak ditemukan.")
        return

    # Menggunakan Regex untuk mengambil hanya kata-kata (alfanumerik)
    # Ini otomatis membuang '#', tanda baca, dan spasi
    words = re.findall(r"[a-zA-Z0-9]+", content)
    
    # Target indeks dari soal
    indices = [234, 235, 1, 237, 238]
    
    flag_parts = []
    
    print(f"[+] Total kata bersih ditemukan: {len(words)}")
    
    for idx in indices:
        # Konversi ke index 0 (Python list dimulai dari 0)
        py_idx = idx - 1
        
        if 0 <= py_idx < len(words):
            found_word = words[py_idx]
            flag_parts.append(found_word)
            print(f"Index {idx}: {found_word}")
        else:
            print(f"Index {idx} OUT OF RANGE!")

    # Susun kata-kata dengan pemisah underscore
    # Gunakan .upper() untuk mengubah menjadi Huruf Besar Semua
    flag_content = "_".join(flag_parts).upper()
    
    print(f"\n[+] Flag Result: FGTE{{{flag_content}}}")

if __name__ == "__main__":
    solve()

```

## Hasil Output

Saat script dijalankan:

```text
[+] Total kata bersih ditemukan: 238
Index 234: truth
Index 235: lives
Index 1: Between
Index 237: the
Index 238: margins

[+] Flag Result: FGTE{TRUTH_LIVES_BETWEEN_THE_MARGINS}

```

## Flag

```text
FGTE{TRUTH_LIVES_BETWEEN_THE_MARGINS}

```
