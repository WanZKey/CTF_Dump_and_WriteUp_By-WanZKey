https://chatgpt.com/canvas/shared/68f371096aa481919b7469ce4c0110e2
# 🧩 Writeup CTF Cryptography — *Jane Doe*

**Author:** k4tou
**Category:** Cryptography
**Solver:** wanzkey
**Platform:** ITB CTF Community
**Flag:** `CTFITB2025{__https://youtu.be/qYcU41ew_BM?si=a7tqWT7SmrGX2GH8__myreze:'}`

---

## 🧠 Deskripsi Challenge

> "Jane Doe is a common placeholder name for an unidentified person. Here are her last words before she disappeared:
> 'Truth is... I've never gone to school either'"

File yang diberikan:

```
message.py
output.txt
```

Dari deskripsi tersebut, challenge ini mengindikasikan bahwa enkripsi dilakukan menggunakan *pseudorandom number generator* (PRNG) bawaan Python — yaitu **Mersenne Twister (MT19937)** — yang dikenal digunakan dalam library `random` Python. Kalimat *"never gone to school"* adalah clue bahwa generator-nya **bukan cryptographically secure**, karena Mersenne Twister mudah diprediksi.

---

## 🔍 Analisis File `message.py`

File `message.py` berisi proses enkripsi yang dilakukan sebagai berikut (ringkasan setelah analisis manual):

```python
# message.py (potongan logika inti)
import random

p = getPrime(513)
b = getrandbits(512)

s = [random.getrandbits(512) for _ in range(10)]
m = [random.getrandbits(512) for _ in range(9)]

for i in range(9):
    s[i+1] = (s[i] * m[i] + b) % p

enc = []
for i in range(9):
    block = plain[i] ^ (s[i] & ((1<<64)-1))
    enc.append(block)

hint = s[1:]
```

### ⚙️ Mekanisme Enkripsi

1. Sebuah bilangan prima `p` (513-bit) dan nilai acak `b` (512-bit) dihasilkan.
2. Generator `random` Python menghasilkan serangkaian nilai `m[i]` dan `s[i]`, masing-masing 512-bit.
3. Setiap `s[i+1]` dihitung dari rumus linear:

   ```
   s[i+1] = (s[i] * m[i] + b) % p
   ```

   yang mirip dengan LCG (*Linear Congruential Generator*) tapi dikalikan dengan output PRNG lain.
4. Proses enkripsi: setiap blok plaintext 64-bit di-XOR dengan bagian bawah 64-bit dari `s[i]`.
5. Output `output.txt` menyimpan `b`, `p`, `enc`, dan `hint` (yaitu sisa `s[1:]`).

### 🧨 Vulnerability

Masalah utamanya: **`m[i]` dihasilkan langsung dari `random.getrandbits(512)`** yang bersumber dari **MT19937**, PRNG yang *bisa diprediksi* jika cukup banyak output diketahui.

Karena kita memiliki `hint` yang memungkinkan menghitung 63 nilai `m[i]`, maka kita memiliki cukup banyak output (lebih dari 624 × 32 bit) untuk **merekonstruksi state internal MT19937** dan memprediksi semua nilai acak berikutnya maupun sebelumnya.

---

## 🧩 Langkah Solusi

### 1. Parse Data dari `output.txt`

Kita ekstrak nilai `b`, `p`, `enc`, dan `hint`.
Kemudian kita hitung `m_i` dengan rumus:

```python
m[i] = ((s[i+1] - b) * inverse_mod(s[i], p)) % p
```

### 2. Rekonstruksi State Mersenne Twister

Dengan 63 nilai `m_i` (masing-masing 512 bit), kita bisa memecah setiap nilai menjadi 16 kata 32-bit.
Mersenne Twister membutuhkan 624 kata 32-bit untuk state penuh.

Namun karena endianess dan urutan penyusunan bit tidak dijelaskan, kita perlu mencoba semua kombinasi:

* endian: big / little
* per-chunk reversal
* byte swap (endianness per word)
* rotasi chunk

Script eksplorasi otomatis (`2.py`) mencoba semua kombinasi ini sampai menemukan kandidat valid.

### 3. Hasil Pencarian Kombinasi Benar

```
[+] Found candidate! variant={'endian': 'big', 'rotation': 0, 'per_chunk_rev': True, 'byte_swap': False, 'stream_rev': False}, start=0, match_idx=39
```

Artinya: setiap blok 512-bit harus diperlakukan **big-endian**, **dibalik urutan word 32-bit di dalamnya**, dan digabungkan secara berurutan.

### 4. Rekonstruksi dan Backtrack State

Dengan `extend_mt19937_predictor`, kita bisa tidak hanya memprediksi keluaran berikutnya tetapi juga *backtrack* ke keluaran sebelumnya, untuk memperoleh `m_0` hingga `m_8` yang digunakan dalam enkripsi.

### 5. Dekripsi Pesan

Setelah `m_0..m_8` dan `s_0..s_8` diperoleh, plaintext bisa didapat dengan:

```python
plaintext = enc[i] ^ (s[i] & ((1<<64)-1))
```

---

## ⚙️ Output Eksekusi Solver

Hasil eksekusi final:

```
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ITB CTF Community/Cryprography/Jane Doe]
└─$ python3 solver.py
🧠 [Jane Doe Decryptor] Starting...
[*] Parsed output.txt → b(512 bits), p(513 bits), enc=9 blocks, hint=64
[*] Computed 63 multipliers m_i
[*] Using discovered variant: {'endian': 'big', 'rotation': 0, 'per_chunk_rev': True, 'byte_swap': False, 'stream_rev': False}
[*] Predictor seeded with 624 words.
[*] Backtracking 48 chunks to recover m0..m8...
[*] m0..m8 recovered.
[*] Computed s_0..s_8
[+] Decrypted bytes: b"CTFITB2025{__https://youtu.be/qYcU41ew_BM?si=a7tqWT7SmrGX2GH8__myreze:'}"
[+] UTF-8 decode: CTFITB2025{__https://youtu.be/qYcU41ew_BM?si=a7tqWT7SmrGX2GH8__myreze:'}
⚠️  No flag pattern detected.
[*] Maybe plaintext: CTFITB2025{__https://youtu.be/qYcU41ew_BM?si=a7tqWT7SmrGX2GH8__myreze:'}
⏱️  Done in 0.02s
```

---

## 🏁 Hasil Akhir

**Flag:**

```
CTFITB2025{__https://youtu.be/qYcU41ew_BM?si=a7tqWT7SmrGX2GH8__myreze:'}
```

---

## 🧩 Kesimpulan & Pembelajaran

1. **PRNG ≠ Cryptographically Secure RNG** — menggunakan Mersenne Twister (`random` Python) untuk menghasilkan nilai kunci sangat tidak aman karena dapat diprediksi.
2. **Mersenne Twister memiliki periode 2^19937−1** tetapi tidak memiliki keamanan kriptografi: dengan 624 output 32-bit, seluruh state internal dapat direkonstruksi sepenuhnya.
3. **`extend_mt19937_predictor`** memungkinkan tidak hanya memprediksi output, tetapi juga mundur ke masa lalu (backtrack), membuat enkripsi seperti ini sepenuhnya dapat dibalik.
4. **Selalu gunakan RNG yang aman seperti `secrets` atau `os.urandom()`** untuk operasi kriptografi.

---

## 🧾 Referensi

* [Mersenne Twister Predictor (GitHub)](https://github.com/kmyk/mersenne-twister-predictor)
* [Extend MT19937 Predictor (PyPI)](https://pypi.org/project/extend-mt19937-predictor/)
* [Python Random Implementation](https://docs.python.org/3/library/random.html)

---

**Author of writeup:** wanzkey (CTF Player) ✨


