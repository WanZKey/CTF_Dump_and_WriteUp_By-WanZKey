# WriteUp - Seven Bits

## Overview

* **Judul:** Seven Bits
* **Kategori:** Crypto
* **Poin:** 100
* **Author:** aria
* **Deskripsi:**
Binary ini disusun dalam potongan dengan panjang yang sama. Setiap potongan merepresentasikan sesuatu yang lebih dari sekadar angka.
Format: FGTE{xxxxx_x_xx}
Hint: Seven-segment display

## Informasi Attachment

Challenge memberikan deretan angka biner 7-bit:

```text
1111100 0110000 0110111 1110111 0110001 1101110 0001000 0000111 0001000 0111111 0000110

```

## Proses Penyelesaian

1. **Analisa Format:**
Berdasarkan judul "Seven Bits" dan hint "Seven-segment display", deretan biner ini merepresentasikan status nyala/mati lampu pada layar 7-segmen. Setiap bit (dari index 6 ke 0 atau g-a) mengontrol satu segmen.
2. **Decoding (Mapping Visual):**
Setiap blok 7-bit diterjemahkan menjadi karakter visual yang terbentuk pada display:
* `1111100` -> **b** (Lowercase B)
* `0110000` -> **1** (Vertical line, dibaca 1)
* `0110111` -> **n** (Arch shape)
* `1110111` -> **A** (Uppercase A)
* `0110001` -> **r** (Top-left hook)
* `1101110` -> **y** (Lowercase Y)
* `0001000` -> **_** (Underscore / Bottom segment)
* `0000111` -> **7** (Digit 7)
* `0001000` -> **_** (Underscore)
* `0111111` -> **0** (Digit 0)
* `0000110` -> **1** (Vertical line right)


3. **Assembly:**
Menggabungkan karakter-karakter tersebut membentuk string: `b1nAry_7_01`.

## Script Solver

Berikut adalah script Python untuk menerjemahkan biner tersebut berdasarkan peta karakter 7-segment:

```python
def solve():
    print("[*] Solver Seven Bits")
    
    # Input Binary
    binary_data = "1111100 0110000 0110111 1110111 0110001 1101110 0001000 0000111 0001000 0111111 0000110"
    chunks = binary_data.split()
    
    # Mapping Manual (Biner -> Karakter 7-Segment)
    segment_map = {
        "1111100": "b",
        "0110000": "1",
        "0110111": "n",
        "1110111": "A",
        "0110001": "r",
        "1101110": "y",
        "0001000": "_",
        "0000111": "7",
        "0111111": "0",
        "0000110": "1"
    }
    
    decoded = ""
    for chunk in chunks:
        if chunk in segment_map:
            decoded += segment_map[chunk]
        else:
            decoded += "?"
            
    print(f"Decoded String: {decoded}")
    print(f"Flag Format   : FGTE{{{decoded}}}")

if __name__ == "__main__":
    solve()

```

## Output Terminal

```bash
 󰋑  ▶  ./solver.py
[*] Solver Seven Bits
Decoded String: b1nAry_7_01
Flag Format   : FGTE{b1nAry_7_01}

```

## Flag

```
FGTE{b1nAry_7_01}

```
