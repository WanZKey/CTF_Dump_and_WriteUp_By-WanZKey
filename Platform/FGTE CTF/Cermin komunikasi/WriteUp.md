https://chatgpt.com/share/68f06fb0-e6b8-8000-9d84-463259348231
# CTF Writeup: Cermin Komunikasi

**Kategori:** Cryptography
**Tingkat Kesulitan:** Easy
**Author:** aria
**Flag:** `FGTE{reflected_signal}`

---

## Deskripsi Soal

> Sistem komunikasi ini dikabarkan menggunakan protokol bernama “mirror”. Setiap byte dari pesan akan “pantulkan” sebelum dikirimkan ke penerima. Namun, hasil akhirnya tampak seperti deretan kode heksadesimal, meskipun isinya sulit dibaca.
>
> ```
> ```

0f 1e 08 03 15 06 01 2d 0d 08 06 0c 17 1e 0f 08 00 14 37 26 2e 2b

````
>
> **Hint:** Refleksi seringkali menunjukkan kebenaran — dan kata itu juga kuncinya.

---

## Analisis Challenge

1. **Kata kunci “mirror”** mengindikasikan adanya proses *refleksi*, yang dapat diartikan sebagai **membalik urutan data**.
2. Data yang diberikan berupa **deretan nilai heksadesimal**, yang kemungkinan besar merepresentasikan hasil enkripsi.
3. Berdasarkan hint, kemungkinan terdapat dua langkah utama:
   - Membalik urutan bytes (refleksi).
   - Menggunakan kata kunci `mirror` sebagai kunci dekripsi, mungkin melalui operasi **XOR**.

Langkah ini umum pada challenge bertema *custom cipher* sederhana, di mana byte diacak dan di-*obfuscate* dengan XOR.

---

## Proses Penyelesaian

### 1️⃣ Ubah data hex menjadi bytes
Kita ubah deretan hex menjadi byte array agar dapat diproses per-byte.

### 2️⃣ Lakukan *mirror* (pembalikan urutan)
Karena disebut protokol “mirror”, maka kita balik urutan seluruh byte (`[::-1]`).

### 3️⃣ XOR setiap byte dengan key “mirror”
Key dikonversi ke byte (`b'mirror'`), lalu diulang sepanjang panjang data, dan setiap byte di-XOR-kan dengan byte dari key yang bersesuaian.

### 4️⃣ Decode hasil ke ASCII
Hasil XOR akan menghasilkan plaintext yang bisa dibaca.

---

## 💻 Script Solver

```python
# Cermin Komunikasi Solver - by ChatGPT
# Challenge by aria (FGTE CTF)

def xor_mirror_decrypt(hex_data, key="mirror"):
    # Ubah string hex jadi list byte
    data = bytes.fromhex(hex_data.replace(" ", ""))
    # Balik urutan bytes (mirror)
    mirrored = data[::-1]
    # XOR dengan key berulang
    key_bytes = key.encode()
    decrypted = bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(mirrored)])
    return decrypted.decode(errors="ignore")

if __name__ == "__main__":
    hex_input = "0f 1e 08 03 15 06 01 2d 0d 08 06 0c 17 1e 0f 08 00 14 37 26 2e 2b"
    flag = xor_mirror_decrypt(hex_input)
    print("Flag:", flag)
````

---

## Hasil Eksekusi di Terminal

```
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Crypto/Cermin komunikasi]
└─$ python3 solver.py
Flag: FGTE{reflected_signal}
```

---

## Kesimpulan

* Protokol *mirror* merepresentasikan proses pembalikan urutan data.
* Hint “refleksi” juga menjadi petunjuk kunci (`mirror`) yang digunakan dalam XOR.
* Kombinasi keduanya menghasilkan plaintext berupa flag.

> **Final Flag:** `FGTE{reflected_signal}`
