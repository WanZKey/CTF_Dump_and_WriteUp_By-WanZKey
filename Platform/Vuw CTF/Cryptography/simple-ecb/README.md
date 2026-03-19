# WriteUp - simple-ecb

## Overview
- **Judul Challenge:** simple-ecb
- **Kategori:** Cryptography
- **Poin:** 250
- **Author:** tev27
- **Release:** Cryptology Meetup
- **Solves:** 8
- **First Blood:** alcom
- **Deskripsi:** I've heard that ECB mode isn't secure, but I can't see the problem with it?
- **Koneksi / URL:** `nc chals.vuwctf.com 9997`

## Informasi Attachment & Struktur Direktori
Terdapat satu file attachment berupa *source code* Python bernama `simple-ecb.py`. Berikut adalah inspeksi file menggunakan terminal:

```bash
 󰋑  ▶  cat simple-ecb.py
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

FLAG = os.environ.get('FLAG', 'VuwCTF{ecb_test_flag_0123456789abcdef}')
FLAG = FLAG.encode()

key = os.urandom(16)  # get a random key

cipher = AES.new(key, AES.MODE_ECB)

print('Recover my secret :)')
while True:
    msg = input('Enter message to encrypt: ').encode()
    plaintext = pad(msg + FLAG, 16)

    ciphertext = cipher.encrypt(plaintext)

    print(ciphertext.hex())
```

## Proses Penyelesaian
1. Melakukan analisis *source code* pada file `simple-ecb.py`. Diketahui bahwa aplikasi menggunakan enkripsi AES dengan mode operasi ECB (Electronic Codebook) dengan kunci acak yang dibuat saat program dijalankan.
2. Mengidentifikasi kerentanan mode ECB. Dalam mode ini, enkripsi dilakukan per blok (16 byte), dan blok *plaintext* yang persis sama akan selalu menghasilkan blok *ciphertext* yang sama pula.
3. Menemukan celah eksploitasi berupa *Chosen Plaintext Attack* (CPA). Program meminta masukan dari pengguna (`msg`), menggabungkannya tepat di depan `FLAG`, lalu melakukan *padding* dan mengenkripsi gabungan tersebut: `pad(msg + FLAG, 16)`.
4. Merancang serangan **Byte-at-a-time ECB Decryption**. Serangan ini memanfaatkan kontrol terhadap `msg` untuk menggeser posisi *flag* sedemikian rupa sehingga hanya ada satu byte dari *flag* yang berada di dalam sebuah blok yang kita kontrol.
   - Langkah pertama adalah mengirimkan string *padding* berukuran tertentu (misal 15 karakter `A`) agar blok pertama dari *plaintext* berisi 15 karakter `A` ditambah karakter pertama dari *flag*.
   - Menyimpan hasil *ciphertext* dari blok pertama ini sebagai referensi "target".
   - Selanjutnya, mengirimkan *payload* berupa 15 karakter `A` ditambah satu karakter *brute-force* (misalnya dari karakter ASCII yang dapat dicetak). 
   - Jika *ciphertext* yang dihasilkan cocok dengan "target", maka karakter *brute-force* tersebut adalah karakter aktual dari *flag*.
5. Proses ini diulangi dengan mengurangi panjang *padding* (14 karakter, 13 karakter, dan seterusnya) untuk menebak karakter kedua, ketiga, dan karakter-karakter berikutnya secara berurutan.
6. Mengimplementasikan logika eksploitasi tersebut ke dalam *script solver* menggunakan *library* `pwntools` pada Python untuk berinteraksi dengan layanan *remote* (`nc chals.vuwctf.com 9997`) dan melakukan otomatisasi penebakan *byte-per-byte*.
7. Menjalankan *script solver* melalui terminal WSL hingga seluruh karakter *flag* terekstraksi secara utuh dan terverifikasi diakhiri dengan tanda kurung kurawal tutup `}`.

## Script Solver
**solver.py**
```python
from pwn import *
import string
import warnings

# Mengabaikan warning pwntools untuk output yang lebih bersih
warnings.filterwarnings("ignore", category=BytesWarning)

def solve():
    host = 'chals.vuwctf.com'
    port = 9997
    
    # context.log_level = 'error' diatur di luar fungsi untuk menghindari log debug
    io = remote(host, port)
    io.recvuntil(b'Recover my secret :)\n')
    
    flag = ""
    block_size = 16
    
    print("[*] Memulai eksploitasi ECB Byte-at-a-time...")
    
    for i in range(64):
        pad_len = (block_size - 1) - (len(flag) % block_size)
        padding = b"A" * pad_len
        
        io.recvuntil(b'Enter message to encrypt: ')
        io.sendline(padding)
        
        response = io.recvline().strip().decode()
        ciphertext = bytes.fromhex(response)
        
        block_idx = len(flag) // block_size
        start_idx = block_idx * block_size
        end_idx = start_idx + block_size
        
        target_block = ciphertext[start_idx:end_idx]
        found = False
        
        for c in string.printable:
            guess_payload = padding + flag.encode() + c.encode()
            
            io.recvuntil(b'Enter message to encrypt: ')
            io.sendline(guess_payload)
            
            guess_response = io.recvline().strip().decode()
            guess_ciphertext = bytes.fromhex(guess_response)
            guess_block = guess_ciphertext[start_idx:end_idx]
            
            if guess_block == target_block:
                flag += c
                print(f"[*] Flag sementara : {flag}")
                found = True
                break
        
        if not found:
            print("[!] Gagal menemukan karakter selanjutnya. Proses dihentikan.")
            break
            
        if flag.endswith('}'):
            print(f"\n[*] CRACKED! Flag sepenuhnya ditemukan.")
            print(f"[*] Flag Final : {flag}")
            break
            
    io.close()

if __name__ == '__main__':
    context.log_level = 'error'
    solve()
```

**Output Terminal**
```bash
 󰋑  ▶  ./solver.py
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/wanzkey/.cache/.pwntools-cache-3.13/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[*] A newer version of pwntools is available on pypi (4.14.1 --> 4.15.0).
    Update with: $ pip install -U pwntools
[*] Memulai eksploitasi ECB Byte-at-a-time...
[*] Flag sementara : V
[*] Flag sementara : Vu
[*] Flag sementara : Vuw
[*] Flag sementara : VuwC
[*] Flag sementara : VuwCT
[*] Flag sementara : VuwCTF
[*] Flag sementara : VuwCTF{
[*] Flag sementara : VuwCTF{3
[*] Flag sementara : VuwCTF{3c
[*] Flag sementara : VuwCTF{3cb
[*] Flag sementara : VuwCTF{3cb_
[*] Flag sementara : VuwCTF{3cb_c
[*] Flag sementara : VuwCTF{3cb_c4
[*] Flag sementara : VuwCTF{3cb_c4n
[*] Flag sementara : VuwCTF{3cb_c4nt
[*] Flag sementara : VuwCTF{3cb_c4nt_
[*] Flag sementara : VuwCTF{3cb_c4nt_b
[*] Flag sementara : VuwCTF{3cb_c4nt_b3
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_C
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4_
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4_s
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4_s3
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4_s3c
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4_s3cu
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4_s3cur
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4_s3cur3
[*] Flag sementara : VuwCTF{3cb_c4nt_b3_CP4_s3cur3}

[*] CRACKED! Flag sepenuhnya ditemukan.
[*] Flag Final : VuwCTF{3cb_c4nt_b3_CP4_s3cur3}
```

## Flag

```
VuwCTF{3cb_c4nt_b3_CP4_s3cur3}
```
