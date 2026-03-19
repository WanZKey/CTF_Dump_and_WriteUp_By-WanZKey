# WriteUp - not-so-private-key-cryptography

## Overview
- **Judul Challenge:** not-so-private-key-cryptography
- **Kategori:** Cryptography
- **Poin:** 100
- **Author:** tev27
- **Release:** Cryptology Meetup
- **Solves:** 21
- **First Blood:** hnn2436
- **Deskripsi:** My friend told me to encrypt my secrets to keep them safe. This is encrypted right?

## Informasi Attachment & Struktur Direktori
Berdasarkan pengecekan awal, terdapat dua file dalam direktori *challenge* ini: *source code* enkripsi Python dan file output yang berisi *ciphertext*. Berikut adalah struktur dan isi filenya:

```bash
… ~../Cryptography/not-so-private-key-cryptography 󱎫 0s 󱑎 23.54
 󰋑  ▶  tree
.
├── not-so-private-key-cryptography.py
└── output.txt

1 directory, 2 files

… ~../Cryptography/not-so-private-key-cryptography 󱎫 0s 󱑎 23.54
 󰋑  ▶  file *
not-so-private-key-cryptography.py: Python script, ASCII text executable
output.txt:                         ASCII text

… ~../Cryptography/not-so-private-key-cryptography 󱎫 0s 󱑎 23.54
 󰋑  ▶  cat not-so-private-key-cryptography.py
import os
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

FLAG = os.environ.get('FLAG', 'VuwCTF{not_so_private_key_test_flag}')
FLAG = FLAG.encode()
key = b64decode('c3VwZXJzZWNyZXRwYXNzd29yZDEyMyEh')

cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(pad(FLAG, 16))

print(ciphertext.hex())

… ~../Cryptography/not-so-private-key-cryptography 󱎫 0s 󱑎 23.54
 󰋑  ▶  cat output.txt
f15cbeb418091b9307c44591e15795bd6e2855ad7f2d5817bf9fa851945b5fee55535b1c52147ce018aee9c7f8a232b5
```

## Proses Penyelesaian
1. Melakukan inspeksi terhadap *source code* `not-so-private-key-cryptography.py`. Diketahui bahwa algoritma enkripsi yang digunakan adalah AES (Advanced Encryption Standard) dengan mode operasi ECB (Electronic Codebook).
2. Menemukan celah utama pada *script* enkripsi tersebut, yaitu penggunaan kunci (*key*) yang bersifat statis atau *hardcoded* di dalam program: `c3VwZXJzZWNyZXRwYXNzd29yZDEyMyEh`. Kunci tersebut di-encode menggunakan Base64.
3. Mengetahui bahwa hasil akhir *ciphertext* di-padding ke dalam blok 16 *byte*, lalu diubah menjadi format heksadesimal dan dicetak (disimpan ke dalam file `output.txt`).
4. Karena AES merupakan algoritma kriptografi simetris, dekripsi dapat dilakukan dengan menggunakan *key* yang sama. Proses dekripsi mengharuskan kita untuk:
   - Men-decode *key* dari Base64.
   - Membaca data *ciphertext* heksadesimal dari `output.txt` dan mengonversinya kembali ke dalam bentuk *raw bytes*.
   - Melakukan inisialisasi *cipher* AES dalam mode ECB dengan *key* yang telah didapatkan.
   - Mendekripsi *ciphertext* dan menghapus *padding* (unpad) untuk mendapatkan *plaintext* asli.
5. Menyusun *script solver* menggunakan Python berdasarkan langkah-langkah di atas, dengan membaca file `output.txt` menggunakan mode `rb`.
6. Menjalankan *script solver* melalui terminal WSL untuk mendapatkan *flag* secara otomatis.

## Script Solver
**solver.py**
```python
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def solve():
    # 1. Mendapatkan kunci asli dari string base64 yang ada di source code
    key = b64decode('c3VwZXJzZWNyZXRwYXNzd29yZDEyMyEh')
    
    try:
        # 2. Membaca file output.txt menggunakan mode 'rb' 
        with open('output.txt', 'rb') as f:
            hex_data = f.read().strip()
            
        # 3. Mengubah data hex (dalam bentuk bytes) menjadi raw bytes ciphertext
        ciphertext = bytes.fromhex(hex_data.decode('utf-8'))
        
        # 4. Inisialisasi cipher AES ECB dengan kunci yang didapat
        cipher = AES.new(key, AES.MODE_ECB)
        
        # 5. Proses dekripsi dan hilangkan padding-nya
        decrypted_data = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted_data, 16).decode('utf-8')
        
        print("[*] Berhasil melakukan dekripsi!")
        print(f"[*] Flag : {plaintext}")
        
    except FileNotFoundError:
        print("[!] File output.txt tidak ditemukan. Pastikan file berada di direktori yang sama.")
    except Exception as e:
        print(f"[!] Terjadi kesalahan saat dekripsi: {e}")

if __name__ == '__main__':
    solve()
```

**Output Terminal**
```bash
 󰋑  ▶  ./solver.py
[*] Berhasil melakukan dekripsi!
[*] Flag : VuwCTF{00ps_1_l3ft_th3_s3cr3ts_in}
```

## Flag

```
VuwCTF{00ps_1_l3ft_th3_s3cr3ts_in}
```
