# CTF Writeup — Legenda Ambatukam

**Category:** Cryptography  
**Challenge ID:** 0x18  
**Status:** ACTIVE  
**Flag:** `ZeroSec{4mb4s1ng..44hh}`

---

## Deskripsi Challenge

> Seorang pria bernama Mas Amba kepergok warga sedang mengkokang senjata ilegal miliknya.
> Kecurigaan warga muncul karena Mas Amba sering berteriak aneh-aneh:
> **Ambatukam… Ambatublow… Ambatufish… ahhhh!**
>
> Terlihat sebuah kertas bertuliskan:
> `8ef84c40db955fdd9e6e5cb1884ce4a2e891e7c5783af02339e7177078909bf7`
>
> Suara **"cruootttt"** seolah menjadi kunci atas kematian Mas Amba.

---

## Analisis Clue

Narasi challenge penuh dengan hint tersembunyi:

| Kata dalam Narasi | Makna |
|---|---|
| `Ambatu`**`blow`** | **Blowfish** cipher |
| `Ambatu`**`fish`** | Konfirmasi → **Blowfish** |
| `"cruootttt"` | **Key** enkripsi |
| Ciphertext 64 hex chars | 32 byte = kelipatan 8 ✅ (block size Blowfish = 8 byte) |

Panjang ciphertext 32 byte adalah kelipatan block size Blowfish (8 byte), semakin memperkuat dugaan bahwa cipher yang digunakan adalah **Blowfish**.

---

## Percobaan Awal (Gagal)

Sebelum menemukan solusi, beberapa pendekatan dicoba dan gagal:

**Repeating-key XOR** dengan key `cruootttt` → non-printable  
**XOR dengan hash** (MD5/SHA1/SHA256) dari key → non-printable  
**SHA256 hash cracking** → tidak ada match  
**Brute force single-byte XOR** → tidak ada output `ZeroSec`

Kesimpulan: ini bukan XOR cipher biasa. Waktunya coba **Blowfish**.

---

## Proses Decrypt

### Mode yang Dicoba

```
Blowfish ECB          → block 1 corrupt, semua non-printable
Blowfish CBC IV=\x00  → block 1 corrupt, block 2 dst = ZeroSec{...} ✓
Blowfish CBC IV=key   → block 1 corrupt, block 2 dst = ZeroSec{...} ✓
```

### Mengapa Block Pertama Corrupt?

Ini adalah perilaku normal **CBC (Cipher Block Chaining) mode**:

```
Decrypt CBC:
  Block[0] = Decrypt(CT[0]) XOR IV
  Block[1] = Decrypt(CT[1]) XOR CT[0]
  Block[2] = Decrypt(CT[2]) XOR CT[1]
  ...
```

Karena IV asli tidak diketahui, block pertama (8 byte) hasil XOR dengan IV yang salah → **rusak**. Namun block ke-2 dan seterusnya hanya bergantung pada ciphertext sebelumnya, **bukan IV** → tetap benar.

Karena flag `ZeroSec{...}` mulai dari byte ke-8, kita cukup skip block pertama.

---

## Exploit Script

```python
#!/usr/bin/env python3
# pip install pycryptodome
from Crypto.Cipher import Blowfish

ciphertext = bytes.fromhex("8ef84c40db955fdd9e6e5cb1884ce4a2e891e7c5783af02339e7177078909bf7")
key = b"cruootttt"

# Blowfish CBC, IV = 8 null bytes (IV asli tidak diketahui, tapi tidak masalah)
cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=b'\x00' * 8)
raw = cipher.decrypt(ciphertext)

# Block pertama (8 byte) corrupt karena IV salah → skip
flag = raw[8:].rstrip(b'\x00').decode('ascii')

print(f"Flag: {flag}")
```

### Output

```
Flag: ZeroSec{4mb4s1ng..44hh}
```

---

## Visualisasi CBC Decrypt

```
Ciphertext:  [Block 0 - 8B] [Block 1 - 8B] [Block 2 - 8B] [Block 3 - 8B]
                  ↓               ↓               ↓               ↓
           Blowfish Dec    Blowfish Dec    Blowfish Dec    Blowfish Dec
                  ↓               ↓               ↓               ↓
              XOR IV         XOR CT[0]       XOR CT[1]       XOR CT[2]
                  ↓               ↓               ↓               ↓
Plaintext:  [CORRUPT  ]     [ZeroSec{]      [4mb4s1ng]      [..44hh}\x00]
             ← skip →       ←────────────── FLAG ──────────────────────→
```

---

## Kesimpulan

| Item | Nilai |
|---|---|
| Cipher | Blowfish |
| Mode | CBC |
| Key | `cruootttt` |
| IV | Tidak diketahui (tidak berpengaruh pada flag) |
| Block size | 8 byte |

**Lesson learned:**
- Nama `Ambatublow` dan `Ambatufish` adalah hint cipher (**Blow**fish + **fish**)
- `"cruootttt"` secara eksplisit disebut sebagai "kunci" dalam narasi
- Di CBC mode, IV yang salah hanya merusak block pertama — sisa plaintext tetap bisa di-recover

### Flag

```
ZeroSec{4mb4s1ng..44hh}
```
