# WriteUp - Bendera Negara

## Overview

* **Judul:** Bendera Negara
* **Kategori:** Crypto
* **Poin:** 100
* **Author:** aria
* **Deskripsi:**
sebuah bendera yang berderet di suatu pertemuan laut, terlihat seperti kode rahasia. Bisakah kamu mengungkap pesannya?
Format: FGTE{W0rd_W0rd_W0rd}

## Informasi Attachment

Challenge ini memberikan sebuah gambar (`Bendera_Negara.png`) yang berisi deretan bendera sinyal maritim (International Maritime Signal Flags).

Data hasil pembacaan bendera (ekstraksi) adalah:

```text
char(77)karakter(52)char(82)char(49)char(49)char(84)char(49)char(77)char(51)char(53)char(49)char(71)char(78)char(52)char(76)char(53)char(67)char(48)char(68)char(51)char(52)char(78)char(68)char(78)char(52)char(55)char(79)char(52)char(76)char(80)char(72)char(52)char(66)char(51)char(55)

```

## Proses Penyelesaian

1. **Identifikasi Cipher:**
Gambar menampilkan bendera yang digunakan dalam komunikasi internasional laut (International Code of Signals). Setiap bendera merepresentasikan satu karakter alphanumerik.
2. **Decoding:**
Berdasarkan data ekstraksi di atas, setiap kode `char(ASCII)` atau `karakter(ASCII)` diterjemahkan kembali menjadi karakter teks biasa.
* `char(77)` -> `M`
* `karakter(52)` -> `4`
* `char(82)` -> `R`
* ... dan seterusnya.


Hasil penggabungan karakter menghasilkan string:
`M4R11T1M351GN4L5C0D34NDN47O4LPH4B37`
3. **Formatting:**
String tersebut merupakan kalimat dalam format *Leetspeak*. Untuk mendapatkan flag, string dipisahkan berdasarkan kata-kata bahasa Inggris yang terbentuk:
* `M4R11T1M3` (Maritime)
* `51GN4L5` (Signals)
* `C0D3` (Code)
* `4ND` (And)
* `N47O` (NATO)
* `4LPH4B37` (Alphabet)


Format akhir: `FGTE{M4R11T1M3_51GN4L5_C0D3_4ND_N47O_4LPH4B37}`

## Script Solver

Berikut adalah script Python untuk menerjemahkan kode ASCII desimal menjadi string dan memformat flagnya:

```python
import re

def solve():
    print("[*] Solver Bendera Negara")
    
    # Data mentah dari soal (hasil baca bendera)
    raw_data = "char(77)karakter(52)char(82)char(49)char(49)char(84)char(49)char(77)char(51)char(53)char(49)char(71)char(78)char(52)char(76)char(53)char(67)char(48)char(68)char(51)char(52)char(78)char(68)char(78)char(52)char(55)char(79)char(52)char(76)char(80)char(72)char(52)char(66)char(51)char(55)"
    
    # Normalisasi string agar seragam (ubah 'karakter' jadi 'char')
    normalized_data = raw_data.replace("karakter", "char")
    
    # Ekstrak angka ASCII dalam kurung menggunakan Regex
    ascii_codes = re.findall(r'char\((\d+)\)', normalized_data)
    
    # Convert kode ASCII ke Karakter
    decoded_chars = [chr(int(code)) for code in ascii_codes]
    decoded_string = "".join(decoded_chars)
    
    print(f"Decoded String: {decoded_string}")
    
    # Formatting manual berdasarkan analisis kata (Leetspeak)
    # Words: M4R11T1M3, 51GN4L5, C0D3, 4ND, N47O, 4LPH4B37
    flag = f"FGTE{{{decoded_string[:9]}_{decoded_string[9:16]}_{decoded_string[16:20]}_{decoded_string[20:23]}_{decoded_string[23:27]}_{decoded_string[27:]}}}"
    
    print(f"Flag Format   : {flag}")

if __name__ == "__main__":
    solve()

```

## Output Terminal

```bash
 󰋑  ▶  ./solver.py
Decoded String: M4R11T1M351GN4L5C0D34NDN47O4LPH4B37
Flag Format   : FGTE{M4R11T1M3_51GN4L5_C0D3_4ND_N47O_4LPH4B37}

```

## Flag

```
FGTE{M4R11T1M3_51GN4L5_C0D3_4ND_N47O_4LPH4B37}

```
