# WriteUp - delicious_cooking

## Overview
- **Judul Challenge:** delicious_cooking
- **Kategori:** Cryptography
- **Poin:** 150
- **Author:** leastinformednerd
- **Release:** VuwCTF 2025
- **Deskripsi:** I forgot the password to my account on my cooking forum, please help me get back in! My username is meatballfan19274. Flag format is VuwCTF{password}

## Informasi Attachment & Struktur Direktori
Terdapat satu file attachment berupa `users.db`. Berikut adalah informasi inspeksi awal file menggunakan terminal:

```bash
 󰋑  ▶  file users.db
users.db: SQLite 3.x database, last written using SQLite version 3050004, file counter 2, database pages 55, cookie 0x1, schema 4, UTF-8, version-valid-for 2
```

## Proses Penyelesaian
1. Melakukan analisis pada file attachment `users.db` yang merupakan *database* SQLite. Ekstraksi pada tabel `users` untuk target *username* `meatballfan19274` menghasilkan nilai *password* berformat `hash$salt`: `09be2259e0224f41b96b633b73e7138b50b4be0a1ae20c0eb6a7434e8fc47303$334aa758c52bb2f862f1607ff098e954`.
2. Melakukan observasi menyeluruh terhadap data *security questions* (pertanyaan keamanan) dari pengguna lain di dalam *database*. Ditemukan bahwa tema keseluruhan mengarah pada film "Ratatouille", dan terdapat pola kata sandi yang digunakan oleh *user* lain, yaitu gabungan "fav movie + bank pin" (film favorit + PIN bank 4 digit).
3. Berdasarkan temuan tersebut, format *plaintext password* dapat dipastikan berbentuk `ratatouilleXXXX`, di mana `XXXX` merepresentasikan 4 digit angka dari `0000` hingga `9999`.
4. Algoritma *hashing* yang dikonfirmasi adalah `SHA256(password_bytes + salt_bytes)`, di mana *salt* harus di-*decode* dari representasi heksadesimal menjadi *raw bytes* sebelum digabungkan.
5. Menyusun *script solver* menggunakan Python untuk melakukan *brute-force* spesifik pada 10.000 kemungkinan kombinasi PIN bank (0000-9999) yang digabungkan dengan kata "ratatouille".
6. Mengeksekusi *script solver* melalui terminal WSL dan berhasil mencocokkan *hash* target dengan kombinasi `ratatouille6281`.

## Script Solver
**solver.py**
```python
import hashlib

def solve():
    target_hash = "09be2259e0224f41b96b633b73e7138b50b4be0a1ae20c0eb6a7434e8fc47303"
    salt_hex = "334aa758c52bb2f862f1607ff098e954"
    
    print(f"[*] Target Hash : {target_hash}")
    print(f"[*] Target Salt : {salt_hex}")
    print("[*] Melakukan proses brute-force dengan pola 'ratatouilleXXXX'...\n")
    
    # Konversi salt hex menjadi raw bytes
    salt_bytes = bytes.fromhex(salt_hex)
    
    # Brute-force 4 digit PIN (0000 - 9999)
    for i in range(10000):
        # Format angka menjadi 4 digit dengan zero-padding
        pwd = f"ratatouille{i:04d}"
        
        # Algoritma: SHA256(password_bytes + salt_bytes)
        h = hashlib.sha256(pwd.encode('utf-8') + salt_bytes).hexdigest()
        
        if h == target_hash:
            print("[*] CRACKED!")
            print(f"[*] Plaintext Password : {pwd}")
            print(f"[*] Flag : VuwCTF{{{pwd}}}")
            return
            
    print("[!] Password tidak ditemukan dalam jangkauan brute-force.")

if __name__ == '__main__':
    solve()
```

**Output Terminal**
```bash
 󰋑  ▶  python3 solver.py
[*] Target Hash : 09be2259e0224f41b96b633b73e7138b50b4be0a1ae20c0eb6a7434e8fc47303
[*] Target Salt : 334aa758c52bb2f862f1607ff098e954
[*] Melakukan proses brute-force dengan pola 'ratatouilleXXXX'...

[*] CRACKED!
[*] Plaintext Password : ratatouille6281
[*] Flag : VuwCTF{ratatouille6281}
```

## Flag

```
VuwCTF{ratatouille6281}
```
