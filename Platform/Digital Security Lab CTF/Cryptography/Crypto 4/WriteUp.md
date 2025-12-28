https://gemini.google.com/share/f3818452508e
# WriteUp: Crypto 4 - Diffie-Hellman Key Exchange

## Informasi Tantangan

* **Nama Challenge:** Crypto 4
* **Kategori:** Cryptography
* **Platform:** Practice Digital Security Lab (Unipi)
* **Poin:** 500

## Deskripsi

Tantangan ini mengimplementasikan protokol pertukaran kunci **Diffie-Hellman**. Server meminta pengguna untuk mengirimkan parameter bilangan prima (), generator (), dan kunci publik klien ().

Setelah menerima parameter tersebut, server:

1. Menghasilkan kunci privat acak ().
2. Menghitung kunci publik server ().
3. Menghitung *shared secret* ().
4. Mengenkripsi flag menggunakan operasi XOR dengan .
5. Mengembalikan encrypted flag dan kunci publik server ().

## Analisis Kerentanan

Celah keamanan terletak pada **kurangnya validasi parameter**. Server mempercayai nilai , , dan  yang kita kirimkan sepenuhnya.

Secara matematis, *Shared Secret* () dihitung oleh server dengan rumus:


Sedangkan *Public Key* server () dihitung dengan rumus:


Jika kita memanipulasi input dengan mengirimkan ** yang sama dengan ** (yaitu ), maka perhitungan server menjadi:

1. **Shared Secret:** 
2. **Public Key:** 

Akibatnya:


Artinya, kunci rahasia yang digunakan untuk mengenkripsi flag adalah **sama persis** dengan Public Key  yang dikirimkan server secara terbuka kepada kita. Kita tidak perlu memecahkan Discrete Logarithm Problem; kita hanya perlu menggunakan nilai  sebagai kunci dekripsi.

## Strategi Penyelesaian

1. Gunakan bilangan prima  yang disarankan (agar valid).
2. Tentukan .
3. **Eksploitasi:** Kirimkan Public Key kita  (sehingga ).
4. Server akan merespons dengan `enc_flag` dan `B`.
5. Karena , lakukan dekripsi:



## Solver Script

Berikut adalah script Python yang digunakan untuk mengeksploitasi celah tersebut:

```python
import requests
import json
from Crypto.Util.number import long_to_bytes
from pwn import xor

# URL Target
URL = "http://practice-digitalsecuritylab.di.unipi.it:11004/api/dh_exchange/"

# Parameter Diffie-Hellman (Dari saran soal)
P_STR = "101264875096291756590724160710266238607742308517803523368410730143610813157544871108800681242310021754893641284891313106040348046843467119852986330168576405484604905473258559094972474777116950163245724407474846725895361246270063255973321572589185857691867743767640291346478044611088448612145846051361865736827"
P = int(P_STR)
G = 2

def solve():
    print("[*] Memulai serangan Diffie-Hellman Parameter Injection...")
    
    # Vulnerability: Mengirim A = G
    # Server menghitung Shared Key (k) = A^b mod p
    # Karena A=G, maka k = G^b mod p, yang mana sama dengan Public Key Server (B)
    payload = {
        "p": P,
        "g": G,
        "A": G 
    }

    print(f"[+] Mengirim A = {G}...")
    
    response = requests.post(URL, json=payload)
    data = response.json()

    # Ambil data respon
    enc_flag_hex = data['enc_flag']
    server_public_B = int(data['B'])
    
    print(f"[+] Terima Encrypted Flag (Hex): {enc_flag_hex}")
    print(f"[+] Terima Public Key Server (B): {server_public_B}")

    # Dekripsi: Flag = Enc_Flag XOR B
    key_bytes = long_to_bytes(server_public_B)
    enc_flag_bytes = bytes.fromhex(enc_flag_hex)
    
    # Lakukan XOR
    flag = xor(enc_flag_bytes, key_bytes[:len(enc_flag_bytes)])

    print("\n[+] Hasil Dekripsi:")
    print(flag.decode())

if __name__ == "__main__":
    solve()

```

## Eksekusi dan Hasil

Berikut adalah output terminal dari eksekusi script solver:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Cryptography/Crypto 4]
└─$ python3 solver.py
[*] Memulai serangan Diffie-Hellman Parameter Injection...
[+] Mengirim A = 2...
[+] Terima Encrypted Flag (Hex): 60242e4c0e1b39595a3e574f6f7f44fe7275d69478
[+] Terima Public Key Server (B): 36840632682371095459899515448405335066031127690687884443859980672601141032244679633414797137297084313292448429369656613300479579323434064864638906986208091953994394444328181346603571315829355543940683816704441209589567240006068937356575450989308530645187658196992305973402500179757123657735452065286439599363

[+] Hasil Dekripsi:
TRT{c4951dbbba618070}

```

## Langkah Manual (Tanpa Script)

1. **INTERACT:** Masukkan  (dari soal), , dan .
2. **COPY:** Ambil nilai `B` (Desimal) dan `enc_flag` (Hex).
3. **CONVERT:** Gunakan tool *Dec/Hex Converter* untuk mengubah `B` menjadi Hex.
4. **XOR:** Gunakan *XOR Tool* untuk melakukan: `enc_flag` XOR `B (Hex)`.
5. **DECODE:** Gunakan *Hex Encoder/Decoder* pada hasil XOR untuk mendapatkan flag ASCII.

## Kesimpulan

Validasi parameter pada pertukaran kunci Diffie-Hellman sangat krusial. Tanpa validasi, penyerang dapat memaksa *shared secret* menjadi nilai yang dapat diprediksi atau diketahui.

**Flag:** `TRT{c4951dbbba618070}`
