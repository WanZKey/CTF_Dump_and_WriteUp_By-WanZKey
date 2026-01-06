https://chatgpt.com/share/687f336a-77dc-8002-a371-8397a9d638a0
# STEMBACTF - Forensic: TnT (400 pts)

## 🧩 Challenge Info

**Nama Soal:** TnT
**Poin:** 400
**Kategori:** Forensik
**Author:** kyruu
**Clue:** "Gajah terbang nampak?"
**Wrap Flag:** `STEMBACTF{...}`

---

## 📁 File yang Diberikan

```
chall.txt
```

Saat dicek dengan perintah `file`, hasilnya:

```
chall.txt: data
```

Bukan file teks biasa. Maka perlu dianalisis struktur bytenya.

---

## 🔍 Analisis Awal

Cek isi file dengan `xxd`:

```
00000000: 0001 0000 0000 0100 0001 0100 0100 0001
...
```

Terlihat bahwa nilai-nilai hex didominasi oleh `00` dan `01`.

> **Dugaan awal:** setiap byte mewakili 1 digit biner, yaitu:
>
> * `0x00` = bit 0
> * `0x01` = bit 1

Berarti isi file merupakan **stream of bits** yang membentuk pesan tersembunyi.

---

## 🛠️ Solusi (Script)

Script berikut membaca file byte-per-byte dan menginterpretasi 0x00 sebagai bit 0 dan 0x01 sebagai bit 1. Setiap 8 bit kemudian digabung menjadi 1 karakter ASCII.

```python
# solver.py
def main():
    with open("chall.txt", "rb") as f:
        data = f.read()

    bits = []

    # Konversi byte menjadi bit
    for i, byte in enumerate(data):
        if byte == 0x00:
            bits.append('0')
        elif byte == 0x01:
            bits.append('1')
        else:
            print(f"[!] Warning: byte tidak dikenali di offset {i}: {byte:02x}")

    # Gabungkan setiap 8 bit jadi karakter ASCII
    text = ''
    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i+8]
        if len(byte_bits) < 8:
            break
        byte_str = ''.join(byte_bits)
        ascii_char = chr(int(byte_str, 2))
        text += ascii_char

    print("[+] Pesan tersembunyi:", text)
    print("[+] Flag: STEMBACTF{" + text + "}")

if __name__ == "__main__":
    main()
```

---

## 🖥️ Output dari Terminal

```
┌──(wanzkey㉿Hengker-Bwang)-[~/STEMBA-CTF/Forensic/TnT]
└─$ python3 solver.py
[+] Pesan tersembunyi: BinnAries_File
[+] Flag: STEMBACTF{BinnAries_File}
```

---

## 🏁 Final Flag

```
STEMBACTF{BinnAries_File}
```

---

## 📌 Catatan

* Nama "BinnAries\_File" adalah permainan kata dari **Binary + Aries**.
* Teknik ini umum digunakan di forensik CTF, menyembunyikan data di antara nilai low-level seperti bit.

---

## ✅ Status

**Solved!** 🎉
