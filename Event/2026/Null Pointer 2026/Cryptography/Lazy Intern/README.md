# WriteUp - Lazy Intern

## Overview

* **Judul:** Lazy Intern
* **Kategori:** Cryptography
* **Poin:** 100
* **Author:** Unknown
* **Deskripsi:** A company intern sent a secret message but forgot that "obfuscation is not encryption." The Cont.: `w`txwJp$sb8HA2~_@`hJ{zpdza(=+&_l`

## Proses Penyelesaian

1. Menganalisa deskripsi soal dan ciphertext `w`txwJp$sb8HA2~_@`hJ{zpdza(=+&_l`. Petunjuk "obfuscation is not encryption" mengindikasikan adanya penggunaan metode encoding yang ditumpuk secara berlapis.
2. Mencoba melakukan decode menggunakan Base85 dan Ascii85 pada script solver pertama, namun gagal karena format tidak valid.
3. Melakukan pergeseran karakter menggunakan ROT47 pada ciphertext awal, yang berhasil menghasilkan output: `H1EIHyASD3gwpaO0o19yLKA5K2WlZU0=`.
4. Mencoba melakukan Base64 decode pada hasil ROT47 tersebut, namun kembali mengalami kegagalan (invalid byte error) karena teks masih terenkripsi.
5. Menganalisa hasil ROT47 lebih lanjut dan mengeksekusi pergeseran tambahan menggunakan ROT13. Proses ini berhasil membentuk string Base64 yang utuh dan valid: `U1RVUlNFQ3tjcnB0b19lYXN5X2JyMH0=`.
6. Melakukan tahap akhir dengan mengeksekusi Base64 decode pada hasil ROT13 untuk mendapatkan flag yang sebenarnya. We got this bro!

## Terminal Output (Proses Recon)

```text
  ▶  ./1.py
[*] Hustling Base85 (b85decode)...
Failed: 'utf-8' codec can't decode byte 0xb7 in position 0: invalid start byte

[*] Hustling Ascii85 (a85decode)...
Failed: Non-Ascii85 digit found: w

[*] Hustling ROT47...
Result: H1EIHyASD3gwpaO0o19yLKA5K2WlZU0=

  ▶  ./solver.spy
[*] Hustling Base64 decode on the ROT47 output...
Failed: 'utf-8' codec can't decode byte 0xa5 in position 9: invalid start byte

```

## Script Solver

```python
import base64
import codecs

def solve():
    enc = "w`txwJp$sb8HA2~_@`hJ{zpdza(=+&_l"
    
    print("[*] Hustling ROT47...")
    rot47_res = []
    for char in enc:
        if 33 <= ord(char) <= 126:
            rot47_res.append(chr(33 + ((ord(char) + 14) % 94)))
        else:
            rot47_res.append(char)
    step1 = ''.join(rot47_res)
    print(f"ROT47 Output: {step1}")

    print("\n[*] Hustling ROT13 on the ROT47 output...")
    step2 = codecs.encode(step1, 'rot_13')
    print(f"ROT13 Output: {step2}")

    print("\n[*] Hustling Base64 decode on the final output...")
    try:
        flag = base64.b64decode(step2).decode('utf-8')
        print(f"Result: {flag}")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    solve()

```

## Terminal Output (Final Script)

```text
  ▶  ./solver.py
[*] Hustling ROT47...
ROT47 Output: H1EIHyASD3gwpaO0o19yLKA5K2WlZU0=

[*] Hustling ROT13 on the ROT47 output...
ROT13 Output: U1RVUlNFQ3tjcnB0b19lYXN5X2JyMH0=

[*] Hustling Base64 decode on the final output...
Result: STURSEC{crpto_easy_br0}

```

## Flag

```text
STURSEC{crpto_easy_br0}

```


