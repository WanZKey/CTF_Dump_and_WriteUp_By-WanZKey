Berikut adalah file **WriteUp.md** berdasarkan solusi brute-force yang berhasil kamu jalankan.

---

# WriteUp: Enigmatic Curves

## Informasi Dasar

* **Kategori:** Cryptography
* **Poin:** 300
* **Flag:** `DSU{elliptic_enigma_mastery_2025}`

## Deskripsi Tantangan

Kita diberikan sebuah file binary `enigma_curves_generated.bin` dan parameter kriptografi `params_generated.json`. Tantangan ini melibatkan dua lapisan enkripsi:

1. **Elliptic Curve Cryptography (ECC):** Menyelesaikan Discrete Logarithm Problem (ECDLP) untuk mendapatkan secret .
2. **Stream Cipher:** Menggunakan secret  dan posisi awal rotor untuk mendekripsi ciphertext akhir.

## Langkah Penyelesaian

### 1. Menyelesaikan ECDLP (Mencari )

Dari `params_generated.json`, kita memiliki kurva:



Titik  dan .

Karena modulus  cukup kecil (sekitar ), kita tidak perlu menggunakan algoritma kompleks seperti Baby-step Giant-step. Kita bisa melakukan **Brute Force iterasi sederhana** untuk mencari  dimana .

Ditemukan nilai ****.

### 2. Bypass Decoding Payload (Metode Brute Force Rotor)

Tantangan memberikan hint bahwa posisi rotor di-masking menggunakan operasi `XOR` dengan `sha256(...)[0] & 0x1F`.

* Masking `0x1F` (binary `00011111`) mengindikasikan bahwa nilai posisi rotor berada dalam rentang **0 hingga 31** (5 bit).
* Payload Base85 yang diberikan rusak/sulit di-decode, namun kita tahu ada **3 rotor** (berdasarkan struktur soal umum atau JSON).

Daripada memperbaiki decoding payload, kita bisa melakukan **Brute Force** pada posisi rotor.

* Ruang pencarian:  kombinasi.
* Ini dapat diselesaikan dalam hitungan detik oleh komputer modern.

### 3. Logika Dekripsi

Algoritma pembuatan keystream:

1. Gabungkan  dan posisi rotor: `key_input = str(k) + str(pos0) + str(pos1) + str(pos2)`
2. Buat keystream: `keystream = sha256(key_input)`
3. Dekripsi: `Plaintext = Ciphertext ^ Keystream`

### 4. Solver Script

Script berikut mengimplementasikan brute-force pada posisi rotor untuk menemukan flag yang valid (dimulai dengan format `DSU{`).

```python
import hashlib
import sys

def main():
    # 1. Nilai k yang ditemukan dari ECDLP
    k = 98765
    print(f"[+] Using k = {k}")

    # 2. Membaca Ciphertext
    try:
        with open('enigma_curves_generated.bin', 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print("[-] File not found")
        return

    # Mencari lokasi ciphertext setelah penanda '! \x00 \x00 \x00'
    pattern = b'!\x00\x00\x00'
    pattern_pos = data.find(pattern)

    if pattern_pos != -1:
        ciphertext_start = pattern_pos + len(pattern)
    else:
        # Fallback jika pattern tidak ditemukan persis (offset manual)
        ciphertext_start = 148
    
    ciphertext = data[ciphertext_start:]
    print(f"[+] Ciphertext found at offset {ciphertext_start}, length: {len(ciphertext)}")

    # 3. Brute Force Posisi Rotor (0-31)
    print("[*] Brute forcing init_positions (0-31 for each of 3 rotors)...")

    found_flag = False
    for pos0 in range(32):
        for pos1 in range(32):
            for pos2 in range(32):
                test_positions = [pos0, pos1, pos2]

                # Derive Keystream
                # Format: str(k) + concat(posisi) -> "98765" + "17" + "3" + "12"
                concat_pos = "".join([str(x) for x in test_positions])
                key_input = (str(k) + concat_pos).encode()
                keystream = hashlib.sha256(key_input).digest()

                # Decrypt (XOR)
                plaintext = bytearray()
                for i in range(len(ciphertext)):
                    plaintext.append(ciphertext[i] ^ keystream[i % len(keystream)])

                # Cek apakah hasil dekripsi mengandung format Flag
                try:
                    result = plaintext.decode('utf-8')
                    if 'DSU{' in result:
                        print(f"\n[SUCCESS] Flag Found!")
                        print(f"Rotor Positions: {test_positions}")
                        print(f"Flag: {result}")
                        found_flag = True
                        break
                except:
                    continue
            if found_flag: break
        if found_flag: break

if __name__ == "__main__":
    main()

```

### Hasil Eksekusi

Script berhasil menemukan kombinasi rotor yang tepat:

* **Posisi Rotor:** `[17, 3, 12]`
* **Flag:** `DSU{elliptic_enigma_mastery_2025}`
