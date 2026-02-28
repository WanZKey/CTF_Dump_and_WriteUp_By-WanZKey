https://chatgpt.com/canvas/shared/68ea6ff5b64081918946e5fd142d497e
# 🧩 Writeup CTF Crypto - clasic 2 (ARIAF CTF 2025)

**Category:** Cryptography
**Difficulty:** Medium
**Author:** aria
**Solves:** 5

---

## 🧠 Challenge Description

> Kriptografi kadang cuma soal konversi sederhana.

File yang diberikan: `clasic2.txt`

---

## 🔍 Step 1 - Analisis Awal

Isi file `clasic2.txt` merupakan hasil encoding berlapis:

1. **Base62 → Base58**
2. Setelah didecode, hasilnya berupa deretan angka seperti berikut:

   ```
   8811991188118811881199119911881188...
   ```

---

## 🔬 Step 2 - Pola Angka

Dari percakapan dengan problem setter, diberikan petunjuk:

> "Ini mirip classical 1. Kalau clasic 1: 70 -> 0, 71 -> 1, sisanya decoy. Kalau clasic 2: 88, 99, 11, 33, 44. 11 itu pemisah."

Artinya:

* `11` → separator antar token.
* Sisa angka penting: `88`, `99`, `33`, `44`.

Kita asumsikan:

```
88 → 0
99 → 1
33, 44 → decoy (abaikan)
```

---

## ⚙️ Step 3 - Solusi Programatis

Script Python sederhana dibuat untuk:

1. Membaca isi file `clasic2.txt`
2. Menghapus semua `11` (sebagai separator)
3. Memetakan angka:

   ```
   88 → 0
   99 → 1
   ```
4. Menggabungkan bit menjadi string biner.
5. Mengonversi setiap 8-bit ke ASCII.

```python
# solver.py

def main():
    with open("clasic2.txt", "r") as f:
        data = f.read().strip()

    tokens = data.replace("11", "|")
    tokens = [t for t in tokens.split("|") if t]

    mapping = {"88": "0", "99": "1"}

    bits = [mapping[t] for t in tokens if t in mapping]
    binary_str = "".join(bits)

    chars = [chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8) if len(binary_str[i:i+8]) == 8]

    flag = "".join(chars)
    print("[+] Flag ditemukan:")
    print(flag)

if __name__ == "__main__":
    main()
```

---

## 🧾 Step 4 - Output

Setelah dijalankan:

```bash
$ python3 solver.py
[+] Flag ditemukan:
FGTE{L4njut4n_Cl4sic_2_b4s3_58_d4n_b4s3_62}
```

🎯 **Flag:** `FGTE{L4njut4n_Cl4sic_2_b4s3_58_d4n_b4s3_62}`

---

## 🧩 Insight

* Challenge ini merupakan *continuation* dari **clasic 1**, namun kali ini menggunakan encoding **base62 → base58** dan representasi angka berbeda.
* Pola tetap sama: dua angka penting mewakili bit `0` dan `1`, sementara angka lain berfungsi sebagai pemisah atau decoy.

---

## ✅ Takeaway

> Kadang kriptografi klasik hanyalah soal **pattern recognition dan konversi sederhana.**

Dengan sedikit analisis dan pemetaan ulang simbol, flag pun terbuka dengan mudah!

---

**Author Writeup:** WanzKey
**CTF:** ARIAF CTF 2025
