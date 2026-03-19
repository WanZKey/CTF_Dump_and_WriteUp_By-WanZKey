# CTF Writeup — XOR_Master

**Category:** Cryptography  
**Challenge ID:** 0x07  
**Status:** ACTIVE  
**Flag:** `ZeroSec{xor_logic_is_powerful}`

---

## Deskripsi Challenge

> Pesan ini dienkripsi menggunakan operasi XOR dengan kunci satu byte. Kami tahu format flag selalu dimulai dengan `ZeroSec`. Temukan kuncinya, temukan pesannya.

File yang diberikan: `chall_6925541822f60_87fc6b9f.bin`

---

## Analisis File

Pertama, periksa tipe file:

```bash
$ file chall.bin
chall.bin: data
```

File tidak dikenali sebagai format standar — ini wajar karena isinya terenkripsi. Lihat isi raw-nya dengan `xxd`:

```
00000000: 1827 302d 1127 2139 3a2d 301d 2e2d 252b  .'0-.'!9:-0..-%+
00000010: 211d 2b31 1d32 2d35 2730 2437 2e3f       !.+1.2-5'0$7.?
```

Total: **30 byte** data terenkripsi.

---

## Pendekatan Solusi

### Konsep XOR

XOR cipher dengan single-byte key berarti setiap byte plaintext di-XOR dengan byte kunci yang sama:

```
ciphertext[i] = plaintext[i] XOR key
plaintext[i]  = ciphertext[i] XOR key
```

Karena key hanya 1 byte, hanya ada **256 kemungkinan kunci (0x00–0xFF)** — serangan brute force sangat feasible.

### Known Plaintext Attack

Kita tahu flag dimulai dengan `ZeroSec`. Ini adalah **known plaintext**, sehingga kita bisa langsung hitung kunci:

```
key = ciphertext[0] XOR plaintext[0]
key = 0x18 XOR ord('Z')
key = 0x18 XOR 0x5A
key = 0x42  (= 66 desimal = karakter 'B')
```

Kita bisa verifikasi dengan brute force semua 256 kunci dan cek hasilnya.

---

## Exploit Script

```python
#!/usr/bin/env python3

with open("chall.bin", "rb") as f:
    data = f.read()

for key in range(256):
    decrypted = bytes([b ^ key for b in data])
    try:
        text = decrypted.decode('ascii')
        if text.startswith('ZeroSec'):
            print(f"Key found: {key} (0x{key:02x})")
            print(f"Decrypted: {text}")
    except:
        pass
```

---

## Output

```
Key found: 66 (0x42)
Decrypted: ZeroSec{xor_logic_is_powerful}
```

---

## Penjelasan Langkah per Langkah

| Langkah | Detail |
|--------|--------|
| 1. Baca file binary | `open("chall.bin", "rb")` |
| 2. Brute force key | Loop dari 0x00 sampai 0xFF |
| 3. XOR semua byte | `bytes([b ^ key for b in data])` |
| 4. Validasi plaintext | Cek apakah hasil decode ASCII dimulai dengan `ZeroSec` |
| 5. Output flag | Key `0x42`, Flag ditemukan ✅ |

---

## Kesimpulan

XOR cipher dengan single-byte key sangat lemah karena:

- Key space hanya 256 kemungkinan → brute force instan
- Jika ada known plaintext (seperti format flag), key bisa langsung dihitung
- XOR bersifat reversible: `P XOR K = C` dan `C XOR K = P`

### Flag

```
ZeroSec{xor_logic_is_powerful}
```
