# WriteUp - hash brute force

## Overview
- **Judul Challenge:** hash brute force
- **Kategori:** Cryptography
- **Poin:** 100
- **Author:** Aterlone
- **Release:** Site Release
- **Solves:** 41
- **First Blood:** BAkingBRead
- **Deskripsi:** I found this MD5 hash from a compromised system. I know it's the hash of a common password. Can you crack it and submit the password wrapped in our flag format?

## Informasi Attachment & Struktur Direktori
Terdapat satu file attachment berupa `hash.txt` yang berisi string *hash*. Berikut adalah hasil inspeksi direktori dan file dari terminal:

```bash
…ey  ～  ~../Cryptography/hash brute force 󱎫 0s 󱑎 00.13
 󰋑  ▶  file hash.txt
hash.txt: ASCII text, with no line terminators

…ey  ～  ~../Cryptography/hash brute force 󱎫 0s 󱑎 00.13
 󰋑  ▶  cat hash.txt
21232f297a57a5a743894a0e4a801fc3¶   
```

## Proses Penyelesaian
1. Menganalisis *file* `hash.txt` yang berisi *string* heksadesimal dengan panjang 32 karakter: `21232f297a57a5a743894a0e4a801fc3`. Karakteristik ini, beserta deskripsi *challenge*, mengonfirmasi bahwa ini adalah sebuah nilai *hash* **MD5**.
2. Deskripsi *challenge* memberikan petunjuk penting bahwa *hash* tersebut berasal dari *common password* (kata sandi yang sangat umum).
3. Nilai *hash* `21232f297a57a5a743894a0e4a801fc3` adalah salah satu *hash* yang paling dikenal di dunia keamanan siber. Tanpa perlu melakukan *brute-force* yang memakan waktu lama, nilai ini dapat langsung diidentifikasi sebagai *hash* MD5 dari kata sandi **`admin`**.
4. Untuk membuktikannya secara terstruktur dan memenuhi standar penyelesaian CTF, *script solver* dibuat menggunakan bahasa Python. *Script* ini akan memvalidasi kata sandi umum dari *wordlist* internal sederhana (atau membaca dari `rockyou.txt`) dan mencocokkan nilai *hash*-nya.
5. Setelah kata sandi ditemukan, kata sandi tersebut dibungkus dengan format *flag* yang diminta: `VuwCTF{admin}`.

## Script Solver
Berikut adalah *script* Python menggunakan *library* bawaan `hashlib` untuk melakukan simulasi *dictionary attack* sederhana dan mengonfirmasi bahwa *plaintext* dari *hash* tersebut adalah `admin`.

**solver.py**
```python
import hashlib

def solve():
    target_hash = "21232f297a57a5a743894a0e4a801fc3"
    print(f"[*] Target MD5 Hash : {target_hash}")
    
    # Daftar kata sandi umum sebagai dictionary sederhana
    common_passwords = ["password", "123456", "admin", "12345678", "qwerty"]
    
    print("[*] Memulai proses cracking...")
    
    for word in common_passwords:
        # Melakukan hashing MD5 pada setiap kata di wordlist
        hashed_word = hashlib.md5(word.encode('utf-8')).hexdigest()
        
        if hashed_word == target_hash:
            print("[*] CRACKED!")
            print(f"[*] Plaintext Password : {word}")
            print(f"[*] Flag : VuwCTF{{{word}}}")
            return
            
    print("[!] Password tidak ditemukan di wordlist.")

if __name__ == '__main__':
    solve()
```

**Output Terminal**
```bash
 󰋑  ▶  python3 solver.py
[*] Target MD5 Hash : 21232f297a57a5a743894a0e4a801fc3
[*] Memulai proses cracking...
[*] CRACKED!
[*] Plaintext Password : admin
[*] Flag : VuwCTF{admin}
```

## Flag

```
VuwCTF{admin}
```


