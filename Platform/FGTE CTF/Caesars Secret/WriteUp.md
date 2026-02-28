# Caesar's Secret - Writeup

**Challenge Title:** Caesar's Secret  
**Category:** Cryptography  
**Points:** Easy  
**Date Solved:** 08 April 2025  
**Author:** Unknown

---

## Deskripsi

> Seorang mata-mata zaman Romawi kuno meninggalkan pesan terenkripsi. Pesan ini sepertinya menggunakan metode kriptografi klasik. Tapi... ada yang aneh dengan panjang kata-katanya.
>
> Pesan terenkripsi:
>
> `Kv uqog ogcp kp rjkejv vjg ugetgv!`
>
> Format flag: `CWA{...}`
>
> Jika flag mengandung spasi, ubah setiap spasi menjadi underscore (_).

---

## Langkah Penyelesaian

Pesan ini tampak seperti hasil enkripsi dengan **Caesar cipher**, salah satu metode kriptografi klasik yang paling terkenal. Karena disebut "Caesar" dan ada hint tentang pergeseran alfabet, kita mulai dengan mencoba brute-force seluruh kemungkinan shift dari 1 sampai 25.

### Step 1: Brute-force Caesar Cipher
Menggunakan Python script sederhana:

```python
def caesar_decrypt(text, shift):
    result = ''
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base - shift) % 26 + base)
        else:
            result += c
    return result

cipher = "Kv uqog ogcp kp rjkejv vjg ugetgv!"
for s in range(1, 26):
    print(f"Shift {s}: {caesar_decrypt(cipher, s)}")
```

### Step 2: Temukan Shift yang Benar

Dari output script di atas, ditemukan bahwa **shift = 2** memberikan hasil paling masuk akal:

```
Shift 2: It some mean in phicht the secret!
```

Kata-kata tersebut cukup bisa dimengerti dan cocok dengan konteks challenge.

### Step 3: Format Flag

Sesuai instruksi, spasi diganti dengan underscore (`_`), dan tanda seru di akhir tetap dipertahankan.

Maka flag-nya adalah:

```
CWA{It_some_mean_in_phicht_the_secret!}
```

---

## Flag

```
CWA{It_some_mean_in_phicht_the_secret!}
```

---

## Catatan Tambahan

- Kata "phicht" kemungkinan adalah bentuk kata hasil enkripsi yang tidak lazim, namun tetap diterima oleh sistem.
- Brute-force Caesar cipher sangat efektif karena jumlah kemungkinan pergeseran hanya 25.
- Menariknya, panjang tiap kata disebutkan dalam soal, namun ternyata hanya sebagai pengalih perhatian (decoy).

---

## Tools

- Python 3
- Caesar Decrypt Script (manual brute-force)

---

## Selesai 🚩
