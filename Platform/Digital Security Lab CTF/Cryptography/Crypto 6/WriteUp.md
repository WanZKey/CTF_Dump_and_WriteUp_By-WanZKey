https://gemini.google.com/share/f3818452508e
# WriteUp: Crypto 6 - RSA Encryption

## Informasi Tantangan

* **Nama Challenge:** Crypto 6
* **Kategori:** Cryptography (RSA)
* **Platform:** Practice Digital Security Lab (Unipi)
* **Poin:** 500

## Deskripsi

Tantangan ini menyajikan layanan enkripsi RSA. Server memberikan Public Key () dan Flag yang terenkripsi ().
Server juga menyediakan fitur **Decryption Oracle** (`/api/rsa_decrypt/`), di mana server bersedia mendekripsi ciphertext apa pun yang kita kirim, dengan satu pengecualian: **Server menolak untuk mendekripsi ciphertext dari Flag itu sendiri.**

Tugas kita adalah mendapatkan Plaintext dari Flag dengan memanfaatkan kelemahan matematis RSA tanpa memfaktorkan modulus .

## Analisis Vulnerability: RSA Homomorphic Property

RSA memiliki sifat **Multiplicative Homomorphic**. Artinya, hasil perkalian dua ciphertext sama dengan hasil enkripsi dari perkalian dua plaintext-nya.

Rumus dasarnya:


Kelemahan ini memungkinkan serangan **Chosen Ciphertext Attack (CCA)**. Meskipun server memblokir , server tidak bisa mengetahui jika kita mengirimkan  yang sudah dimodifikasi (disamarkan/blinding).

## Strategi Eksploitasi

Kita akan melakukan serangan **Blinding Attack**:

1. **Persiapan:** Ambil , , dan  dari server.
2. **Blinding (Penyamaran):**
Kita pilih angka sembarang untuk mengalikan pesan, misalnya **2**.
Kita buat ciphertext baru () dengan cara mengalikan  dengan enkripsi dari angka 2 ().



Karena , server akan menganggap ini ciphertext biasa dan bersedia mendekripsinya.
3. **Dekripsi Oracle:**
Kirim  ke endpoint `rsa_decrypt`.
Server akan melakukan perhitungan:






4. **Recovery:**
Hasil yang kita terima () adalah Flag yang dikali 2. Untuk mendapatkan flag asli, kita tinggal membaginya dengan 2 (atau dikali inverse modulo dari 2).



## Solver Script

Berikut adalah script Python yang mengotomatisasi serangan tersebut:

```python
import requests
from Crypto.Util.number import long_to_bytes, inverse

# Konfigurasi Target
URL_BASE = "http://practice-digitalsecuritylab.di.unipi.it:11006/api/"

def solve():
    print("[*] Memulai RSA Chosen Ciphertext Attack...")

    # LANGKAH 1: Dapatkan Parameter (N, e, Encrypted Flag)
    try:
        resp = requests.get(URL_BASE + "get_params/")
        data = resp.json()
        
        n = int(data['n'])
        e = int(data['e'])
        c_flag = int(data['enc_flag'])
        
        print(f"[+] Parameter didapat:")
        print(f"    e = {e}")
        print(f"    n = {str(n)[:30]}...")
        print(f"    c = {str(c_flag)[:30]}...")

    except Exception as err:
        print(f"[-] Gagal mengambil parameter: {err}")
        return

    # LANGKAH 2: Buat Ciphertext Palsu (Blinding)
    # Kita kali ciphertext asli dengan enkripsi dari 2 (2^e)
    S = 2
    blinding_factor = pow(S, e, n)
    c_modified = (c_flag * blinding_factor) % n
    
    print(f"[*] Mengirim Ciphertext Modifikasi (C * 2^e)...")

    # LANGKAH 3: Minta Server Mendekripsi Ciphertext Palsu
    try:
        payload = {"ct": c_modified}
        resp_dec = requests.post(URL_BASE + "rsa_decrypt/", json=payload).json()
        
        if "error" in resp_dec:
            print(f"[-] Oracle Error: {resp_dec['error']}")
            return
            
        p_modified = int(resp_dec['pt'])
        print(f"[+] Terima Plaintext Modifikasi (Flag * 2): {str(p_modified)[:30]}...")

    except Exception as err:
        print(f"[-] Gagal dekripsi: {err}")
        return

    # LANGKAH 4: Pulihkan Flag Asli
    # Flag = Plaintext_Modifikasi / 2
    print("[*] Memulihkan Flag Asli...")
    
    flag_int = (p_modified * inverse(S, n)) % n
    flag_bytes = long_to_bytes(flag_int)
    
    print("\n" + "="*40)
    print(f"[+] FLAG: {flag_bytes.decode()}")
    print("="*40)

if __name__ == "__main__":
    solve()

```

## Output Terminal

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Cryptography/Crypto 6]
└─$ python3 solver.py
[*] Memulai RSA Chosen Ciphertext Attack...
[+] Parameter didapat:
    e = 65537
    n = 292145945200473620856865476312...
    c = 320561394701240434007077579603...
[*] Mengirim Ciphertext Modifikasi (C * 2^e)...
[+] Terima Plaintext Modifikasi (Flag * 2): 246472317582512287699000572070...
[*] Memulihkan Flag Asli...

========================================
[+] FLAG: TRT{ffc0f937a26b8652}
========================================

```

## Kesimpulan

Dengan memanfaatkan sifat Homomorfik RSA, kita dapat memodifikasi ciphertext flag menjadi bentuk lain yang "tidak dikenali" oleh filter server, namun tetap memiliki hubungan matematis dengan pesan aslinya. Server mendekripsi pesan tersebut, dan kita membalikkan operasi matematika (pembagian) untuk mendapatkan flag.

**Flag:** `TRT{ffc0f937a26b8652}`
