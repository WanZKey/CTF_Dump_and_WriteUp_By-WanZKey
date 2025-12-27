https://gemini.google.com/share/f3818452508e
# WriteUp: Crypto 3 - ECB Oracle

## Informasi Tantangan

* **Nama Challenge:** Crypto 3
* **Kategori:** Cryptography
* **Platform:** Practice Digital Security Lab (Unipi)
* **Poin:** 500

## Deskripsi

Tantangan ini menggunakan enkripsi **AES** dalam mode **ECB (Electronic Codebook)**.
Dalam mode ECB, pesan dibagi menjadi blok-blok 16 byte yang dienkripsi secara independen satu sama lain menggunakan kunci yang sama.

Kelemahan fatal ECB adalah:

1. **Pola yang sama menghasilkan Ciphertext yang sama:** Blok plaintext identik akan menghasilkan blok ciphertext identik.
2. **Independensi Blok:** Tidak ada *chaining* (keterkaitan) antar blok (seperti IV pada CBC). Ini memungkinkan penyerang untuk menukar, menghapus, atau menggabungkan blok dari pesan yang berbeda (*Cut-and-Paste Attack*).

Tujuannya adalah memanipulasi ciphertext agar ketika didekripsi server membaca `{"username": "admin"}`.

## Analisis & Strategi

Server membuat token dengan format JSON:

```python
token = pad(json.dumps({"username": username, "access_time": time.time()}))

```

Format string JSON (perhatikan spasi setelah titik dua):
`{"username": "` + `INPUT` + `", "access_time": ...`

Panjang prefix `{"username": "` adalah **14 byte**.
Blok AES berukuran **16 byte**.

Kita ingin menyusun payload `admin`. Kita bisa memecah `admin` menjadi `ad` dan `min` untuk memanipulasi batas blok.

### Rencana Serangan (Cut-and-Paste)

Target Plaintext: `{"username": "admin", "access_t...`

**Langkah 1: Membuat Blok Pertama (`ad`)**
Kita perlu mengisi 14 byte prefix + 2 byte input agar pas 16 byte.

* Input: `ad`
* Plaintext: `{"username": "ad` (Total 16 byte)
* **Aksi:** Ambil Blok 1 (32 karakter hex pertama) dari output ini.

**Langkah 2: Membuat Blok Kedua (`min...`)**
Kita perlu menggeser sisa string `min", "access_t...` agar berada tepat di awal blok baru.
Kita butuh 14 byte prefix + 2 byte *padding* (`aa`) + sisa input (`min`).

* Input: `aamin`
* Plaintext:
* Blok 1: `{"username": "aa` (Sampah/Padding)
* Blok 2: `min", "access_t` (Target kita)


* **Aksi:** Ambil Blok 2 dan seterusnya (karakter hex ke-33 sampai akhir) dari output ini.

**Langkah 3: Penggabungan**
Gabungkan **Blok 1 (dari Langkah 1)** dengan **Blok 2++ (dari Langkah 2)**.

* Hasil Dekripsi: `{"username": "ad` + `min", "access_t...`
* Hasil JSON: `{"username": "admin", "access_time": ...}`

## Solver Script

```python
import requests
import json

# Konfigurasi
URL_BASE = "http://practice-digitalsecuritylab.di.unipi.it:11003/api/"

def solve():
    print("[*] Memulai serangan ECB Cut-and-Paste...")

    # LANGKAH 1: Dapatkan Header Block berisi "ad"
    # Input 'ad' membuat blok pertama penuh (14 byte prefix + 2 byte input)
    # Hasil blok 1: {"username": "ad
    print("[1] Requesting Header Block (input='ad')...")
    res1 = requests.post(URL_BASE + "get_encrypted_message/", json={"username": "ad"})
    token1 = res1.json()['token']
    
    # Ambil 16 byte pertama (32 char hex)
    header_block = token1[:32]
    print(f"    Header Block: {header_block}")

    # LANGKAH 2: Dapatkan Tail Block dimulai dengan "min"
    # Input 'aamin'. 'aa' mengisi blok 1. 'min' terdorong ke awal blok 2.
    # Hasil blok 2 dst: min", "access_t...
    print("[2] Requesting Tail Blocks (input='aamin')...")
    res2 = requests.post(URL_BASE + "get_encrypted_message/", json={"username": "aamin"})
    token2 = res2.json()['token']
    
    # Ambil semua data SETELAH 16 byte pertama (skip 32 char hex)
    tail_blocks = token2[32:]
    print(f"    Tail Blocks: {tail_blocks[:32]}...")

    # LANGKAH 3: Gabungkan (Paste)
    forged_token = header_block + tail_blocks
    print(f"[3] Forged Token: {forged_token[:64]}...")

    # LANGKAH 4: Kirim
    print("[4] Sending forged token...")
    res_final = requests.post(URL_BASE + "decrypt_message/", json={"token": forged_token})
    
    response = res_final.json()
    print("\n[+] Respon Server:")
    print(json.dumps(response, indent=2))

if __name__ == "__main__":
    solve()

```

## Eksekusi dan Hasil

Berikut adalah output terminal saat script dijalankan:

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Digital Security Lab CTF/Cryptography/Crypto 3]
└─$ python3 solver.py
[*] Memulai serangan ECB Cut-and-Paste...
[1] Requesting Header Block (input='ad')...
    Header Block: 2dbbd5dbfba4ea37a5b0d0ea434b725d
[2] Requesting Tail Blocks (input='aamin')...
    Tail Blocks: 700330e68d00cfb732be590360439d0c...
[3] Forged Token: 2dbbd5dbfba4ea37a5b0d0ea434b725d700330e68d00cfb732be590360439d0c...
[4] Sending forged token...

[+] Respon Server:
{
  "flag": "TRT{f3124214e24f9abf}",
  "msg": "Welcome admin!"
}

```

## Panduan Manual (Tanpa Script)

Jika menggunakan tools yang disediakan di website:

1. **Ambil Bagian Depan (`ad`):**
* Menu: `get_encrypted_message`
* Username: `ad`
* Copy **32 karakter pertama** dari token output.
* *Ini adalah ciphertext untuk: `{"username": "ad*`


2. **Ambil Bagian Belakang (`min...`):**
* Menu: `get_encrypted_message`
* Username: `aamin`
* Copy token output **mulai dari karakter ke-33 sampai akhir**. (Hapus 32 karakter awal).
* *Ini adalah ciphertext untuk: `min", "access_t...*`


3. **Gabungkan & Dekripsi:**
* Menu: `decrypt_message`
* Token: Tempel **[Bagian Depan]** lalu langsung tempel **[Bagian Belakang]** tanpa spasi.
* Klik Send. Flag akan muncul.



## Kesimpulan

Serangan **ECB Cut-and-Paste** berhasil dilakukan dengan memanfaatkan sifat blok ECB yang independen. Dengan mengatur panjang input, kita dapat memindahkan potongan data ke batas blok yang diinginkan dan menyusun ulang pesan terenkripsi yang valid.

**Flag:** `TRT{f3124214e24f9abf}`
