# WriteUp - 23 stab wounds

## Overview
- **Judul Challenge:** 23 stab wounds
- **Kategori:** Cryptography
- **Poin:** 50
- **Author:** Aterlone
- **Release:** Site Release
- **Solves:** 54
- **First Blood:** Kakapo
- **Deskripsi:** I found this encrypted message. It looks like it might be using an ancient encryption technique. Can you help me decode it?

## Informasi Attachment & Struktur Direktori
Terdapat satu file attachment berupa `ciphertext.txt`. Berikut adalah informasi direktori beserta inspeksi awal file dari terminal:

```bash
 WanZKey  ～  ~../Cryptography/23 stab wounds 󱎫 0s 󱑎 23.38
 󰋑  ▶  file ciphertext.txt
ciphertext.txt: ASCII text, with no line terminators

 WanZKey  ～  ~../Cryptography/23 stab wounds 󱎫 0s 󱑎 23.38
 󰋑  ▶  cat ciphertext.txt
Gur synt vf IhjPGS{fuvsg_pvcure} naq guvf pvcure vf irel rnfl gb oernx.
```

## Proses Penyelesaian
1. Melakukan analisis awal dengan membaca isi dari `ciphertext.txt` melalui terminal. Output yang didapatkan adalah pesan terenkripsi: `Gur synt vf IhjPGS{fuvsg_pvcure} naq guvf pvcure vf irel rnfl gb oernx.`
2. Berdasarkan deskripsi soal yang menyinggung "ancient encryption technique" dan pola *ciphertext* yang terlihat memanipulasi susunan alfabet, enkripsi yang digunakan dapat diidentifikasi sebagai Caesar Cipher, lebih spesifiknya ROT13.
3. Dekripsi dilakukan dengan memanfaatkan tools dari website dCode: [https://www.dcode.fr/rot-13-cipher](https://www.dcode.fr/rot-13-cipher).
4. Setelah *ciphertext* dimasukkan ke dalam tools tersebut, didapatkan teks asli yang berbunyi: `The flag is VuwCTF{shift_cipher} and this cipher is very easy to break.`

## Script Solver
Sesuai prosedur standar, berikut adalah *script solver* berbasis Python (sebagai alternatif tools website) untuk mengotomatisasi proses dekripsi ROT13, lengkap dengan output terminalnya.

**solver.py**
```python
import codecs

def solve():
    try:
        with open("ciphertext.txt", "r") as f:
            ciphertext = f.read().strip()
            
        plaintext = codecs.decode(ciphertext, 'rot_13')
        
        print(f"[*] Ciphertext : {ciphertext}")
        print(f"[*] Decoded    : {plaintext}")
    except FileNotFoundError:
        print("[!] File ciphertext.txt tidak ditemukan.")

if __name__ == '__main__':
    solve()
```

**Output Terminal**
```bash
 WanZKey  ～  ~../Cryptography/23 stab wounds 
 󰋑  ▶  python3 solver.py
[*] Ciphertext : Gur synt vf IhjPGS{fuvsg_pvcure} naq guvf pvcure vf irel rnfl gb oernx.
[*] Decoded    : The flag is VuwCTF{shift_cipher} and this cipher is very easy to break.
```

## Flag

```
VuwCTF{shift_cipher}
```
