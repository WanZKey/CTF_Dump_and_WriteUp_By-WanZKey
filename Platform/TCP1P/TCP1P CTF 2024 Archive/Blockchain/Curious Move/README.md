# Curious Move **[Local Simulation]**

## Overview

* **Judul**: Curious Move
* **Kategori**: Blockchain / Reverse Engineering
* **Poin**: 836 pts
* **Author**: Kiinzu
* **Deskripsi**: Analisis bytecode smart contract berbasis bahasa Move.

## Informasi File

File yang diberikan adalah `curiousmove_curiousmove.mv`.

* **Magic Bytes**: `a1 1c eb 0b` (Move Bytecode).
* **Strings**: Terdapat string `xor_array` dan `print`, mengindikasikan adanya operasi XOR pada array byte sebelum dicetak.

## Analisis Bytecode & Logic

Berdasarkan hexdump (`xxd`), ditemukan pola instruksi yang berulang mulai offset `00000090`:

```text
00000090: .... .... 0031 6344 020d 0031
000000a0: 7444 020d 0031 6744 020d 0031 0644 020d

```

Pola instruksinya adalah `00 31 XX 44`, dimana:

* `31`: Opcode untuk `LdU8` (Load Unsigned 8-bit Integer) dalam Move VM.
* `XX`: Nilai byte data yang di-push ke stack.
* `44`: Instruksi separator/next op.

Data `XX` yang diekstrak adalah: `63`, `74`, `67`, `06`, `67`, `4c`, dst.

### Menentukan Key XOR

Kita tahu format flag dimulai dengan `TCP1P`.

* Cipher byte pertama: `0x63`
* Target byte pertama: `'T'` (`0x54`)
* Mencari Key: `0x63 ^ 0x54 = 0x37`

Verifikasi ke byte kedua:

* Cipher: `0x74`
* Target: `'C'` (`0x43`)
* Cek: `0x74 ^ 0x37 = 0x43` (Valid)

Kesimpulannya, seluruh byte array di-XOR dengan key `0x37`.

## Script Solver

Script Python untuk mengekstrak byte dari pola hex dan melakukan dekripsi XOR.

```python
def solve():
    # Data diekstrak dari pola "00 31 [XX] 44" pada hexdump
    encrypted_bytes = [
        0x63, 0x74, 0x67, 0x06, 0x67, 0x4c, 0x56, 0x68, 
        0x54, 0x42, 0x45, 0x5e, 0x58, 0x42, 0x44, 0x68, 
        0x40, 0x56, 0x59, 0x53, 0x52, 0x45, 0x52, 0x45, 
        0x68, 0x5e, 0x43, 0x68, 0x44, 0x52, 0x52, 0x5a, 
        0x44, 0x4a
    ]

    key = 0x37
    flag = ""
    
    for b in encrypted_bytes:
        flag += chr(b ^ key)
        
    print(f"FLAG: {flag}")

if __name__ == "__main__":
    solve()

```

## Output Terminal

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/TCP1P/TCP1P CTF 2024 Archive/Blockchain/Curious Move]
└─$ python3 solver.py
FLAG: TCP1P{a_curious_wanderer_it_seems}

```

## Flag

``TCP1P{a_curious_wanderer_it_seems}``
