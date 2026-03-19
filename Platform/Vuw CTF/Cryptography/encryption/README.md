# WriteUp - encryption

## Overview
- **Judul Challenge:** encryption
- **Kategori:** Cryptography
- **Poin:** 50
- **Author:** Aterlone
- **Release:** Site Release
- **Solves:** 54
- **First Blood:** Kakapo
- **Deskripsi:** I'm not so sure about the challenge title...

## Informasi Attachment & Struktur Direktori
Terdapat satu file attachment berupa `challenge.txt`. Berikut adalah inspeksi awal direktori dan file melalui terminal WSL:

```bash
 WanZKey  ～  ~../Cryptography/encryption 󱎫 2s 󱑎 23.52
 󰋑  ▶  file challenge.txt
challenge.txt: ASCII text

 WanZKey  ～  ~../Cryptography/encryption 󱎫 0s 󱑎 23.52
 󰋑  ▶  cat challenge.txt
VGhlIGZsYWcgaXMgVnV3Q1RGe2Jhc2U2NF9pc19lbmNvZGluZ19ub3RfZW5jcnlwdGlvbn0gYW5kIHRoaXMgaXMganVzdCBlbmNvZGluZy4=
```

## Proses Penyelesaian
1. Mengunduh dan memeriksa tipe file `challenge.txt` menggunakan perintah `file`, lalu melihat isinya menggunakan `cat`.
2. Menganalisis isi file yang berupa string `VGhlIGZsYWcgaXMgVnV3Q1RGe2Jhc2U2NF9pc19lbmNvZGluZ19ub3RfZW5jcnlwdGlvbn0gYW5kIHRoaXMgaXMganVzdCBlbmNvZGluZy4=`. Adanya karakter padding `=` di akhir string dan deskripsi soal yang meragukan judul ("encryption") merupakan indikator kuat bahwa ini adalah skema **encoding Base64**, bukan enkripsi.
3. Melakukan decoding string tersebut menggunakan *tools* `dcode` (Decodify) langsung dari command line.
4. Teks berhasil di-decode dan menampilkan pesan *plaintext* yang berisi *flag*.

**Output Terminal (Decoding dengan dcode):**
```bash
 󰋑  ▶  dcode VGhlIGZsYWcgaXMgVnV3Q1RGe2Jhc2U2NF9pc19lbmNvZGluZ19ub3RfZW5jcnlwdGlvbn0gYW5kIHRoaXMgaXMganVzdCBlbmNvZGluZy4=

              __                         __
            |/  |                   | / /
            |   | ___  ___  ___  ___|  (
            |   )|___)|    |   )|   )| |___ \   )
            |__/ |__  |__  |__/ |__/ | |    \_/
                                     /
            https://github.com/s0md3v/Decodify
[+] Decoded from Base64: The flag is VuwCTF{base64_is_encoding_not_encryption} and this is just encoding.
```

## Script Solver
Sesuai prosedur *writeup* standar, berikut adalah *script solver* menggunakan Python sebagai metode alternatif untuk melakukan decoding Base64 secara otomatis.

**solver.py**
```python
import base64

def solve():
    try:
        with open("challenge.txt", "r") as f:
            encoded_text = f.read().strip()
            
        print(f"[*] Encoded Text : {encoded_text}")
        
        # Proses decoding base64
        decoded_bytes = base64.b64decode(encoded_text)
        decoded_text = decoded_bytes.decode('utf-8')
        
        print(f"[*] Decoded Text : {decoded_text}")
        
    except FileNotFoundError:
        print("[!] File challenge.txt tidak ditemukan.")
    except Exception as e:
        print(f"[!] Terjadi kesalahan: {e}")

if __name__ == '__main__':
    solve()
```

**Output Terminal (Python Solver):**
```bash
 WanZKey  ～  ~../Cryptography/encryption
 󰋑  ▶  python3 solver.py
[*] Encoded Text : VGhlIGZsYWcgaXMgVnV3Q1RGe2Jhc2U2NF9pc19lbmNvZGluZ19ub3RfZW5jcnlwdGlvbn0gYW5kIHRoaXMgaXMganVzdCBlbmNvZGluZy4=
[*] Decoded Text : The flag is VuwCTF{base64_is_encoding_not_encryption} and this is just encoding.
```

## Flag

```
VuwCTF{base64_is_encoding_not_encryption}
```
