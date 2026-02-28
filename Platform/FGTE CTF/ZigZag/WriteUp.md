https://chatgpt.com/share/68d9558d-b70c-8002-8b51-36c1862eaa52

# 🧩 Write-Up: ZigZag (Crypto - Easy)

**CTF:** ARIAF-CTF 2025
**Challenge:** ZigZag
**Category:** Cryptography
**Author:** aria
**Points:** 100

---

## 📜 Deskripsi Challenge

> Pesan tersembunyi, jalurnya tidak jelas. Bisakah kamu temukan flag?
>
> ```
> FZAMBRYGEIZGIPEUTIKTGSLTC
> ```
>
> **Format flag:** `FGTE{WORD_WORD_WORD_WORD}`

Dari judul *ZigZag* dan deskripsi yang menyebutkan *"jalurnya tidak jelas"*, kita bisa menduga bahwa cipher yang digunakan adalah **Rail Fence Cipher**, juga dikenal sebagai **ZigZag Cipher**.

---

## 🔍 Analisis

Ciphertext yang diberikan:

```
FZAMBRYGEIZGIPEUTIKTGSLTC
```

Kita akan mencoba mendekripsinya menggunakan metode **Rail Fence** dengan berbagai jumlah *rail* (biasanya antara 2–5).

---

## 🧮 Proses Dekripsi

Buat file `solver.py` untuk mencoba dekripsi dengan Rail Fence Cipher.

### 📄 `solver.py`

```python
ct = "FZAMBRYGEIZGIPEUTIKTGSLTC"

def rail_fence_decrypt(ct, rails):
    n = len(ct)
    rail_indices = [[] for _ in range(rails)]
    idx = 0
    direction = 1
    for i in range(n):
        rail_indices[idx].append(i)
        if rails > 1:
            idx += direction
            if idx == 0 or idx == rails - 1:
                direction *= -1
    res = [''] * n
    pos = 0
    for r in range(rails):
        for _ in rail_indices[r]:
            res[_] = ct[pos]
            pos += 1
    return ''.join(res)

# coba dengan 3 rail
print(rail_fence_decrypt(ct, 3))
```

---

## 💻 Eksekusi Script

```
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Crypto/ZigZag]
└─$ python3 solver.py
FGTEZIGZAGSIMPLEBUTTRICKY
```

---

## ✅ Hasil Dekripsi

Plaintext hasil dekripsi adalah:

```
FGTEZIGZAGSIMPLEBUTTRICKY
```

Setelah diformat sesuai dengan ketentuan flag:

```
FGTE{ZIGZAG_SIMPLE_BUT_TRICKY}
```

---

## 🏁 Final Flag

🎯 **Flag:**

```
FGTE{ZIGZAG_SIMPLE_BUT_TRICKY}
```

---

## 📘 Penjelasan Singkat

**Rail Fence Cipher** bekerja dengan cara menulis plaintext dalam pola zigzag di beberapa *rail* (baris), kemudian membaca baris demi baris untuk menghasilkan ciphertext. Dekripsi dilakukan dengan membalik proses tersebut — menyusun indeks posisi huruf sesuai pola zigzag, lalu mengembalikan urutannya ke bentuk asli.

Dalam challenge ini, jumlah *rail* yang digunakan adalah **3**, dan setelah dekripsi, didapatkan flag yang bermakna dan sesuai format.

---

## 🧠 Kesimpulan

Challenge ini menguji kemampuan mengenali pola enkripsi klasik (ZigZag/Rail Fence). Dengan sedikit intuisi terhadap clue dari judul dan deskripsi, serta pengujian terhadap jumlah *rail*, kita berhasil menemukan flag dengan cepat.

**Flag Akhir:** ✅ `FGTE{ZIGZAG_SIMPLE_BUT_TRICKY}`

