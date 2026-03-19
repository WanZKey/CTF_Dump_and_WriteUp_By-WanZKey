# WriteUp - Disc dancer

## Overview

* **Judul:** Disc dancer
* **Kategori:** Cryptography
* **Poin:** 150
* **Author:** Unknown
* **Deskripsi:** 簾簼 簾簽 簾簾 簾簻 簾簼 簽簾 簽簼 籀籫 簿簽 簿簿 簿簿 簿籀 簿籬 簿籯 簼簹 簼簹 簼籂 簼籁 籀籭 Decode

## Proses Penyelesaian

1. Menganalisa ciphertext yang terdiri dari blok karakter CJK (Chinese/Bamboo ideographs). Karakteristik ini awalnya mengindikasikan metode encoding *Shift* seperti ROT8000.
2. Melakukan percobaan decode menggunakan script ROT8000 standar (offset `0x8000`), namun gagal menghasilkan output plaintext.
3. Melakukan recon lanjutan menggunakan *CyberChef* dan mendapati bahwa teks tersebut menyimpan struktur data Hex: `53 54 55 52 53 45 43 7b 64 66 66 67 6c 6f 30 30 39 38 7d`.
4. Menganalisa ulang algoritma pergeseran dan menemukan bahwa soal ini menggunakan *custom shift* (pengurangan *code point* Unicode) spesifik sebesar `0x7C09` untuk mengubah setiap karakter kembali menjadi karakter Hexadecimal.
5. Membangun script solver Python untuk melakukan iterasi *decoding* dengan mengurangi `0x7C09` dari setiap karakter CJK, mengumpulkan string Hex yang terbentuk, dan mengonversinya (unhexlify) ke dalam format ASCII.
6. Mengeksekusi script solver secara lokal untuk memvalidasi alur penyelesaian dan mengekstrak flag yang dituju. We got this bro!

## Terminal Output (Proses Recon)

```text
  ▶  ./solver.py
[*] Hustling ROT8000 decode...

[+] Result: 簾簼 簾簽 簾簾 簾簻 簾簼 簽簾 簽簼 籀籫 簿簽 簿簿 簿簿 簿籀 簿籬 簿籯 簼簹 簼簹 簼籂 簼籁 籀籭

```

## Script Solver

```python
import binascii

def solve():
    enc = "簾簼 簾簽 簾簾 簾簻 簾簼 簽簾 簽簼 籀籫 簿簽 簿簿 簿簿 簿籀 簿籬 簿籯 簼簹 簼簹 簼籂 簼籁 籀籭"
    
    print("[*] Hustling Custom Shift (0x7C09)...")
    hex_str = ""
    
    # Hilangin spasi dan balikin ke hex awal
    for char in enc.replace(" ", ""):
        # Kurangi code point dengan offset custom dari author
        hex_str += chr(ord(char) - 0x7C09)
        
    print(f"[*] Recovered Hex: {hex_str}")
    
    print("\n[*] Hustling Hex to ASCII decode...")
    try:
        flag = binascii.unhexlify(hex_str).decode('utf-8')
        print(f"[+] Decoded Flag: {flag}")
    except Exception as e:
        print(f"[-] Failed: {e}")

if __name__ == "__main__":
    solve()

```

## Terminal Output (Final Script)

```text
  ▶  ./solver.py
[*] Hustling Custom Shift (0x7C09)...
[*] Recovered Hex: 535455525345437b646666676c6f303039387d

[*] Hustling Hex to ASCII decode...
[+] Decoded Flag: STURSEC{dffglo0098}

```

## Flag

```text
STURSEC{dffglo0098}

```
