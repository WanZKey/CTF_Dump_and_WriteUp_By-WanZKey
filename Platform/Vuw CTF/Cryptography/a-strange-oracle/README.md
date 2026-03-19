# WriteUp - a-strange-oracle

## Overview
- **Judul Challenge:** a-strange-oracle
- **Kategori:** Cryptography
- **Poin:** 350
- **Author:** tev27
- **Release:** Cryptology Meetup
- **Solves:** 6
- **First Blood:** alcom
- **Deskripsi:** This login portal gives me a weird looking token, but it doesn't seem to do anything.
- **Koneksi / URL:** `nc chals.vuwctf.com 9994`

## Informasi Attachment & Struktur Direktori
Terdapat sebuah *source code* Python `a-strange-oracle.py` yang bertindak sebagai *backend* dari layanan *login portal*. Berikut adalah isinya yang diinspeksi melalui terminal:

```bash
 󰋑  ▶  cat a-strange-oracle.py
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = os.environ.get('FLAG', 'VuwCTF{cbc_padding_oracle_test_flag}')
key = os.urandom(16)


def encrypt(plaintext):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    ciphertext = ciphertext.hex()

    iv = cipher.iv.hex()

    return iv + ', ' + ciphertext

def decrypt(encrypted):
    iv, ciphertext = encrypted.split(', ')

    iv = bytes.fromhex(iv)

    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext)

    # unpad() raises ValueError on invalid padding
    return unpad(plaintext, AES.block_size)


print(f'Decrypt me!')
print(encrypt(FLAG.encode()))

while 1:
    print()
    print('1. Register')
    print('2. Log in')
    print('3. Quit')
    menu = input('Select an action: ')

    if menu == '1': # Register
        print('Registering, store your token safely!')
        user = input('Username: ').encode()

        pt = b'user=' + user


        token = encrypt(pt)
        print('Copy your token:')
        print(token)

    elif menu == '2': # Log in
        print('Logging in')
        token = input('Enter your token: ')

        try:
            pt = decrypt(token)

        except ValueError:
            # unpad() raises a ValueError on invalid padding
            print('Padding error!')
            continue

        if not pt.startswith(b'user='):
            # valid tokens always start with b'user='
            print('Invalid token!')
            # print(f'{pt}')
            continue

        user = pt.partition(b'user=')[2].decode() # get the right side of 'user='

        print(f'Welcome {user}!')

    elif menu == '3': # quit
        print('Goodbye!')
        exit(0)

    else: # invalid option
        print('Invalid option')
```

## Proses Penyelesaian
1. Menganalisis *source code* `a-strange-oracle.py`. Terlihat bahwa aplikasi menggunakan algoritma enkripsi AES dengan mode operasi **CBC (Cipher Block Chaining)** yang didukung oleh mekanisme *padding* PKCS#7 standar.
2. Saat pertama kali terhubung ke *server* (`nc chals.vuwctf.com 9994`), aplikasi langsung membocorkan *ciphertext* dari `FLAG` di bawah teks `Decrypt me!`.
3. Menemukan celah *side-channel* pada proses dekripsi menu *login* (opsi 2). Fungsi `decrypt()` memisahkan masukan *token* menjadi IV dan *Ciphertext*, lalu mencoba melakukan `unpad()`. Jika aturan PKCS#7 tidak terpenuhi, muncul pesan kesalahan spesifik `Padding error!`. Sebaliknya, jika *padding* valid (meskipun isi teksnya acak), akan muncul pesan `Invalid token!`.
4. Perbedaan respons tersebut menciptakan kerentanan **CBC Padding Oracle Attack**. Hal ini memungkinkan ekstraksi nilai *plaintext* dengan memanfaatkan respons validitas *padding* *server* sebagai sebuah "oracle" tanpa perlu mengetahui kunci *AES* yang digunakan.
5. Serangan dilakukan dengan memecah data *ciphertext* ke dalam blok-blok berukuran 16-byte. Untuk mengekstrak sebuah blok target (`Block N`), modifikasi dilakukan pada satu *byte* di blok sebelumnya (`Block N-1`). *Brute-force* nilai *byte* (0x00 hingga 0xFF) dikirimkan secara berulang hingga server tidak lagi mengembalikan pesan `Padding error!`.
6. Untuk mempercepat proses eksploitasi yang memakan banyak *request*, *script solver* dioptimasi dengan memasukkan *known prefix* dari struktur standar *flag*, yaitu `VuwCTF{`, pada blok pertama sehingga proses kalkulasi *intermediate state* bisa langsung melompat tanpa perlu *brute-force* dari awal.
7. Mengeksekusi *script solver* berbasis Python (`pwntools`) yang menampilkan proses dekripsi per *byte* secara *real-time* hingga seluruh *flag* terekstrak beserta blok sisa *padding*-nya.

## Script Solver
**solver.py**
```python
from pwn import *
import warnings
import sys

# Mengabaikan warning tipe data dari pwntools agar terminal bersih
warnings.filterwarnings("ignore", category=BytesWarning)

def solve():
    host = 'chals.vuwctf.com'
    port = 9994
    
    io = remote(host, port)
    
    # Menangkap ciphertext FLAG dari banner awal
    io.recvuntil(b'Decrypt me!\n')
    encrypted_flag = io.recvline().strip().decode()
    iv_hex, ct_hex = encrypted_flag.split(', ')
    
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    
    # Menggabungkan IV dan Ciphertext menjadi satu kesatuan array blok
    full_data = iv + ct
    blocks = [full_data[i:i+16] for i in range(0, len(full_data), 16)]
    
    decrypted_flag = b''
    known_prefix = b"VuwCTF{"
    
    print(f"[*] Terhubung ke server. Mengeksekusi Padding Oracle Attack...")
    print(f"[*] Jumlah blok yang akan diproses: {len(blocks) - 1}\n")
    
    # Iterasi eksploitasi per blok
    for block_idx in range(1, len(blocks)):
        target_block = blocks[block_idx]
        prev_block = blocks[block_idx - 1]
        
        intermediate_state = bytearray(16)
        plaintext_block = bytearray(16)
        
        print(f"[*] Memproses Blok {block_idx}...")
        
        # Brute-force per byte dari belakang ke depan (index 15 ke 0)
        for byte_idx in range(15, -1, -1):
            padding_value = 16 - byte_idx
            
            # OPTIMASI: Gunakan known prefix jika berada di Blok 1
            if block_idx == 1 and byte_idx < len(known_prefix):
                known_char = known_prefix[byte_idx]
                plaintext_block[byte_idx] = known_char
                intermediate_state[byte_idx] = known_char ^ prev_block[byte_idx]
                
                sys.stdout.write(f"\r[+] Byte {byte_idx} (Known) : {chr(known_char)} -> Isi Blok: {plaintext_block[byte_idx:].decode('latin-1', 'ignore')}")
                sys.stdout.flush()
                continue
            
            # Mempersiapkan blok manipulasi
            manipulated_prev_block = bytearray(16)
            for i in range(byte_idx + 1, 16):
                manipulated_prev_block[i] = intermediate_state[i] ^ padding_value
                
            found = False
            for guess in range(256):
                manipulated_prev_block[byte_idx] = guess
                
                payload = f"{manipulated_prev_block.hex()}, {target_block.hex()}"
                
                io.recvuntil(b'Select an action: ')
                io.sendline(b'2')
                io.recvuntil(b'Enter your token: ')
                io.sendline(payload.encode())
                
                response = io.recvline().decode()
                
                # Jika response BUKAN 'Padding error!', berarti kita menemukan padding yang valid
                if "Padding error!" not in response:
                    # Edge-case untuk byte terakhir untuk menghindari original padding
                    if byte_idx == 15 and guess == prev_block[15]:
                        continue
                        
                    intermediate_state[byte_idx] = guess ^ padding_value
                    plaintext_block[byte_idx] = intermediate_state[byte_idx] ^ prev_block[byte_idx]
                    found = True
                    
                    sys.stdout.write(f"\r[+] Byte {byte_idx} Cracked : {chr(plaintext_block[byte_idx])} -> Isi Blok: {plaintext_block[byte_idx:].decode('latin-1', 'ignore')}")
                    sys.stdout.flush()
                    break
                    
            if not found:
                print(f"\n[!] Gagal menebak byte ke-{byte_idx} pada blok {block_idx}. Server mungkin terputus.")
                io.close()
                return
                
        decrypted_flag += plaintext_block
        print(f"\n[*] Hasil Blok {block_idx} : {plaintext_block}\n")
        
    io.close()
    
    # Menghapus padding PKCS#7 dari flag akhir
    pad_len = decrypted_flag[-1]
    final_flag = decrypted_flag[:-pad_len].decode('utf-8')
    
    print(f"[*] CRACKED! Flag sepenuhnya ditemukan.")
    print(f"[*] Flag Final : {final_flag}")

if __name__ == '__main__':
    context.log_level = 'error'
    solve()
```

**Output Terminal**
```bash
 󰋑  ▶  ./solver.py
[*] Terhubung ke server. Mengeksekusi Padding Oracle Attack...
[*] Jumlah blok yang akan diproses: 3

[*] Memproses Blok 1...
[+] Byte 0 (Known) : V -> Isi Blok: VuwCTF{padding_s
[*] Hasil Blok 1 : bytearray(b'VuwCTF{padding_s')

[*] Memproses Blok 2...
[+] Byte 0 Cracked : i -> Isi Blok: idechannel_attac
[*] Hasil Blok 2 : bytearray(b'idechannel_attac')

[*] Memproses Blok 3...
[+] Byte 6 Cracked : \x0e -> Isi Blok: \x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0[+] Byte 5 Cracked : \x0e -> Isi Blok: \x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0[+] Byte 4 Cracked : \x0e -> Isi Blok: \x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0[+] Byte 3 Cracked : \x0e -> Isi Blok: \x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0[+] Byte 2 Cracked : \x0e -> Isi Blok: \x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0[+] Byte 1 Cracked : } -> Isi Blok: }\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\[+] Byte 0 Cracked : k -> Isi Blok: k}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e
[*] Hasil Blok 3 : bytearray(b'k}\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e')

[*] CRACKED! Flag sepenuhnya ditemukan.
[*] Flag Final : VuwCTF{padding_sidechannel_attack}
```

## Flag

```
VuwCTF{padding_sidechannel_attack}
```
