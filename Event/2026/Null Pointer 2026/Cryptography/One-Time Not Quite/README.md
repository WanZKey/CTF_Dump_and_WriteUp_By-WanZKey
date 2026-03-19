# WriteUp - One-Time? Not Quite

## Overview

* **Judul:** One-Time? Not Quite
* **Kategori:** Cryptography
* **Poin:** 150
* **Author:** Unknown
* **Deskripsi:** An "unbreakable" One-Time Pad (OTP) was used to encrypt two different messages with the same key. Ciphertext 1 (hex): `73b38970473151c752982490b356d92a194d35286015d129d3b414de113ce6fbc30643` Ciphertext 2 (hex): `548fb90265017bdf56cc36bdae44c2791a4612636f19cf06c1e61ef7102b` Target for crib dragging (c1 ^ c2): `273c307222302a180454122d1d121b53030b274b0f0c1e2f12520a290117`

## Proses Penyelesaian

1. Menganalisa deskripsi soal. Terdapat kelemahan fatal di mana dua pesan berbeda dienkripsi menggunakan key One-Time Pad (OTP) yang sama, dikenal sebagai kerentanan *Two-Time Pad*.
2. Memanfaatkan sifat XOR pada OTP di mana $C1 \oplus C2 = M1 \oplus M2$. Karena key yang sama digunakan ganda, XOR kedua ciphertext akan mengeliminasi key tersebut.
3. Menerapkan teknik *crib dragging* pada hasil XOR kedua ciphertext tersebut menggunakan format flag yang diketahui, yaitu `STURSEC{`, sebagai tebakan awal untuk pesan pertama (M1).
4. Mengeksekusi solver script untuk meng-XOR tebakan `STURSEC{` dengan target gabungan. Hasilnya memunculkan potongan kata `the quic` untuk pesan kedua (M2).
5. Mengenali pola tersebut sebagai bagian dari pangram klasik "the quick brown fox jumps over". Menggunakan kalimat tersebut sebagai tebakan balik (crib) untuk mengekstrak pesan pertama (M1) lebih lanjut.
6. Hasil eksekusi mengembalikan teks `STURSEC{otp_reused_keys_are_de` untuk pesan pertama (M1).
7. Menganalisa panjang karakter dan konteks kalimat untuk menebak sisa 5 byte terakhir, sehingga melengkapi flag secara utuh menjadi `STURSEC{otp_reused_keys_are_deadly}`. We got this bro!

## Script Solver

```python
import binascii

def strxor(b1, b2):
    return bytes([a ^ b for a, b in zip(b1, b2)])

def solve():
    c1_hex = "73b38970473151c752982490b356d92a194d35286015d129d3b414de113ce6fbc30643"
    c2_hex = "548fb90265017bdf56cc36bdae44c2791a4612636f19cf06c1e61ef7102b"
    
    c1 = bytes.fromhex(c1_hex)
    c2 = bytes.fromhex(c2_hex)
    
    print("[*] Hustling Crib Dragging...")
    
    # Get the XOR of the two ciphertexts (up to the length of the shortest one)
    min_len = min(len(c1), len(c2))
    c1_c2_xor = strxor(c1[:min_len], c2[:min_len])
    
    # Step 1: Drag the known flag format
    crib_m1 = b"STURSEC{"
    partial_m2 = strxor(c1_c2_xor[:len(crib_m1)], crib_m1)
    print(f"[*] If M1 starts with '{crib_m1.decode()}', M2 starts with: '{partial_m2.decode(errors='ignore')}'")
    
    # Step 2: "the quic" is a dead giveaway for the classic pangram
    guess_m2 = b"the quick brown fox jumps over"
    print(f"[*] Guessing M2 is the classic phrase: '{guess_m2.decode()}'")
    
    # Step 3: XOR our M2 guess back against the combined string to get M1
    partial_m1 = strxor(c1_c2_xor, guess_m2)
    print(f"[*] Recovered partial M1: '{partial_m1.decode(errors='ignore')}'")
    
    # Step 4: The recovered M1 is 30 bytes, but C1 is 35 bytes.
    # We have "STURSEC{otp_reused_keys_are_de", so we can easily guess the last 5 bytes.
    guessed_flag = partial_m1.decode(errors='ignore') + "adly}"
    print(f"\n[+] We got the bag! Full Flag Guess: {guessed_flag}")

if __name__ == "__main__":
    solve()

```

## Terminal Output

```text
  ▶  ./solver.py
[*] Hustling Crib Dragging...
[*] If M1 starts with 'STURSEC{', M2 starts with: 'the quic'
[*] Guessing M2 is the classic phrase: 'the quick brown fox jumps over'
[*] Recovered partial M1: 'STURSEC{otp_reused_keys_are_de'

[+] We got the bag! Full Flag Guess: STURSEC{otp_reused_keys_are_deadly}

```

## Flag

```text
STURSEC{otp_reused_keys_are_deadly}

```
