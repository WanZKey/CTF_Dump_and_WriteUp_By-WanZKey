# WriteUp - hot-off-the-presses

## Overview
- **Judul Challenge:** hot-off-the-presses
- **Kategori:** Cryptography
- **Poin:** 150
- **Author:** ssourced
- **Release:** Cryptology Meetup
- **Solves:** 10
- **First Blood:** alcom
- **Deskripsi:** I only trust my news sources until I blink. Challenge accessible at [http://chals.vuwctf.com:9996](http://chals.vuwctf.com:9996)

## Informasi Attachment & Struktur Direktori
Terdapat sebuah file `hot-off-the-presses.zip` yang berisi *source code* aplikasi web Flask, serta sebuah *attachment* terenkripsi `news.bin` yang diunduh dari situs web *challenge*. Berikut adalah inspeksi awal direktori dan file melalui terminal:

```bash
…anZKey  ～  ~../Cryptography/hot-off-the-presses 󱎫 0s 󱑎 00.16
 󰋑  ▶  unzip -l hot-off-the-presses.zip
Archive:  hot-off-the-presses.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      948  2025-09-22 14:21   app.py
       54  2025-09-11 18:21   requirements.txt
        0  2025-09-11 17:55   templates/
---------                     -------
     1002                     3 files

 󰋑  ▶  file news.bin
news.bin: DOS executable (COM), start instruction 0x8c34beb2 1985ea67

 󰋑  ▶  xxd news.bin
00000000: 8c34 beb2 1985 ea67 c08a f8ed 6798 2400  .4.....g....g.$.
00000010: 5df2 2d80 4ebb 2ad0 31af 7606 72c1 ffaf  ].-.N.*.1.v.r...
00000020: 131d c943 b4b7 81c7 9041 5e02 0a8e f99b  ...C.....A^.....
```

## Proses Penyelesaian
1. Melakukan analisis terhadap *source code* `app.py`. Fokus utama berada pada *route* `/news` yang bertugas melakukan enkripsi *flag* dan mengirimkannya sebagai file `news.bin`.
2. Menemukan kerentanan kriptografi pada implementasi *Pseudorandom Number Generator* (PRNG). Aplikasi menggunakan modul bawaan Python `random` (Mersenne Twister) untuk menghasilkan kunci AES (*key*) dan *Initialization Vector* (IV).
3. Modul `random` tidak dirancang untuk keamanan kriptografi karena nilainya sepenuhnya deterministik jika *seed*-nya diketahui. Parahnya lagi, *seed* yang digunakan hanyalah nilai integer berbasis waktu saat *request* dibuat: `seed = floor(time.time())`.
4. Menyusun skenario serangan eksploitasi waktu (*Time-based PRNG Attack*). Waktu saat file `news.bin` diunduh/dibuat di sistem lokal kita dapat dijadikan acuan (*timestamp*) utama.
5. Membuat *script solver* yang akan mengekstrak *timestamp* file `news.bin`, lalu melakukan proses *brute-force* nilai *seed* dalam rentang waktu terdekat (misalnya +/- 24 jam untuk mengatasi perbedaan *timezone*).
6. Untuk setiap iterasi *seed*, *script* men- *generate* ulang urutan `key` dan `iv`, lalu mencoba mendekripsi *ciphertext* menggunakan algoritma AES-CBC. Jika hasil *unpad* dan *decode* Base64 memunculkan format `VuwCTF{`, proses *brute-force* dihentikan.

## Script Solver
**solver.py**
```python
import os
import random
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def solve():
    try:
        # Load file attachment dalam format raw bytes
        with open("news.bin", "rb") as f:
            ct = f.read()
            
        # Mengambil informasi kapan file tersebut diunduh/dibuat di OS lokal
        file_mtime = int(os.path.getmtime("news.bin"))
        print(f"[*] File news.bin timestamp (epoch): {file_mtime}")
        print("[*] Melakukan brute-force PRNG seed (rentang pencarian +/- 24 jam)...")
        
        for seed in range(file_mtime - 86400, file_mtime + 86400):
            random.seed(seed)
            
            key = random.randbytes(AES.block_size)
            iv = random.randbytes(AES.block_size)
            
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            try:
                pt_padded = cipher.decrypt(ct)
                pt_b64 = unpad(pt_padded, AES.block_size)
                
                flag = base64.b64decode(pt_b64).decode('utf-8')
                
                if "VuwCTF{" in flag:
                    print("\n[*] CRACKED!")
                    print(f"[*] Server Timestamp Seed : {seed}")
                    print(f"[*] Flag : {flag}")
                    return
            except Exception:
                continue
                
        print("\n[!] Gagal menemukan seed.")
        
    except FileNotFoundError:
        print("[!] File news.bin tidak ditemukan.")
    except Exception as e:
        print(f"[!] Terjadi error: {e}")

if __name__ == '__main__':
    solve()
```

**Output Terminal**
```bash
 󰋑  ▶  ./solver.py
[*] File news.bin timestamp (epoch): 1773766906
[*] Melakukan brute-force PRNG seed (rentang pencarian +/- 24 jam)...

[*] CRACKED!
[*] Server Timestamp Seed : 1773766906
[*] Flag : VuwCTF{t1m3_15_of_th3_e55enc3}
```

## Flag

```
VuwCTF{t1m3_15_of_th3_e55enc3}
```

