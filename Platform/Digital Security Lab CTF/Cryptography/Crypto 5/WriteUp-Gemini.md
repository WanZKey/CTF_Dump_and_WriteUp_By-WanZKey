https://gemini.google.com/share/f3818452508e
# WriteUp: Crypto 5 - Diffie-Hellman Parameter Injection

## Informasi Tantangan

* **Nama Challenge:** Crypto 5
* **Kategori:** Cryptography (Diffie-Hellman)
* **Platform:** Practice Digital Security Lab (Unipi)
* **Poin:** 500

## Deskripsi

Tantangan ini menyimulasikan pertukaran kunci Diffie-Hellman. Server melakukan dua jenis pertukaran:

1. **Pertukaran Statis (Charlie):** Server bertukar kunci dengan "Charlie" menggunakan parameter standar dan mengenkripsi flag menggunakan *shared key* ().
2. **Pertukaran Dinamis (Alice/User):** Server menerima parameter  dari pengguna dan mengembalikan *Public Key* server () serta pesan tes terenkripsi.

**Vulnerabilitas Utama:**
Server menggunakan **Private Key () yang sama** untuk kedua pertukaran tersebut dan tidak memvalidasi parameter  (Generator) yang dikirimkan oleh pengguna.

## Analisis Matematika

Tujuan utama kita adalah mendekripsi pesan untuk Charlie (`msg_c`). Untuk itu, kita membutuhkan *Shared Key* Charlie ().

Rumus *Shared Key* Charlie:


*  = Public Key Charlie (Diketahui).
*  = Modulus Global (Diketahui).
*  = Private Key Server (Rahasia).

Saat kita berinteraksi sebagai Alice, server menghitung *Public Key*-nya sendiri () untuk dikirimkan kepada kita dengan rumus:


*  = Generator (Input dari kita).
*  = Modulus (Input dari kita).

### Strategi Eksploitasi ()

Kita dapat memanipulasi parameter input untuk memaksa server menghitung nilai yang kita inginkan.

Jika kita mengirimkan parameter:

1. **** (Kita gunakan Modulus Global yang sama dengan Charlie).
2. **** (Kita ganti Generator dengan Public Key Charlie).

Maka perhitungan yang dilakukan server menjadi:


Perhatikan bahwa hasil perhitungan ini **identik** dengan rumus *Shared Key* Charlie ().


Akibatnya, variabel `B_a` yang dikembalikan server dalam respons JSON sebenarnya adalah **Kunci Rahasia Charlie** yang bocor sepenuhnya.

## Solver Script

Berikut adalah script Python untuk mengeksekusi serangan ini secara otomatis.

```python
#!/usr/bin/env python3
import requests
from Crypto.Util.number import long_to_bytes

# Konfigurasi Target
URL = "http://practice-digitalsecuritylab.di.unipi.it:11005/api/dh_exchange/"

# Konstanta dari Server (Source Code)
G = 2
P = 123332382638231725701467272052746646677437210451686403929360967929971726170175522473010422422481335637035691756799160249433550988140577298403502161171408121294152540751727605530438344170959752812965964116010935488849567570589898718274440695293648653888226126185052620716306229882426016512073971282234225856687
C = 64612411667157069503976070918939607708875022270375896159569914279068171237996023267687125585927418267362932620044815107093025867940055155893108177681746956136085002346241007308415060540468449145442966833111022272981874509644086110124172781007706360095880503723087775599509214116527258964018584247604461917771

def xor(a: bytes, b: bytes) -> bytes:
    """Melakukan operasi XOR antar dua byte string"""
    return bytes(x ^ y for x, y in zip(a, b))

def solve():
    print("[*] Memulai serangan Diffie-Hellman Parameter Injection...")
    print("[*] Strategi: Mengatur Generator (g) = Charlie's Public Key (C)")
    
    # Payload Attack
    # Kita menyuntikkan C sebagai g.
    # Server akan menghitung: B_a = C^b mod P
    # Yang mana nilainya sama dengan Shared Key Charlie (k_c)
    payload = {
        "g": C, 
        "p": P,
        "A": G  # Nilai A tidak relevan untuk eksploitasi ini
    }
    
    try:
        print("[*] Mengirim payload ke server...")
        response = requests.post(URL, json=payload).json()
        
        if "error" in response:
            print(f"[-] Error Server: {response['error']}")
            return

        # 1. Ambil Encrypted Flag (msg_c) dan Key yang Bocor (B_a)
        msg_c_hex = response["msg_c"]
        leaked_key_int = int(response["B_a"]) 
        
        print(f"[+] Berhasil memancing Shared Key Charlie!")
        print(f"[+] Leaked Key (Int): {str(leaked_key_int)[:30]}...")
        
        # 2. Konversi Key ke Bytes
        key_bytes = long_to_bytes(leaked_key_int)
        msg_c_bytes = bytes.fromhex(msg_c_hex)
        
        print(f"[+] Key Length: {len(key_bytes)} bytes")
        
        # 3. Dekripsi Flag (XOR)
        # Karena ini Stream Cipher sederhana (XOR), kita tinggal XOR ciphertext dengan key
        flag = xor(msg_c_bytes, key_bytes)
        
        print("\n" + "="*60)
        print("[+] FLAG FOUND:")
        print(f"[+] {flag.decode('utf-8', errors='ignore')}")
        print("="*60)

    except Exception as e:
        print(f"[-] Terjadi Kesalahan: {e}")

if __name__ == "__main__":
    solve()

```

## Eksekusi dan Output

Berikut adalah hasil eksekusi script di terminal:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Cryptography/Crypto 5]
└─$ python3 solver.py
[*] Memulai serangan Diffie-Hellman Parameter Injection...
[*] Strategi: Mengatur Generator (g) = Charlie's Public Key (C)
[*] Mengirim payload ke server...
[+] Berhasil memancing Shared Key Charlie!
[+] Leaked Key (Int): 205512964601796131453363877509...
[+] Key Length: 128 bytes

============================================================
[+] FLAG FOUND:
[+] TRT{938939e4a0dbafd8}
============================================================

```

## Kesimpulan

Dengan memanfaatkan celah pada validasi parameter Diffie-Hellman, kita berhasil memaksa server untuk menghitung *Shared Key* target dan mengirimkannya kembali kepada kita. Teknik ini jauh lebih cepat dan efisien dibandingkan serangan matematis seperti *Small Subgroup Attack* (CRT).

**Flag:** `TRT{938939e4a0dbafd8}`
