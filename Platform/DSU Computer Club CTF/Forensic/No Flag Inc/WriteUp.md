# DSU Computer Club CTF 2025: No Flags, Inc. WriteUp

**Category:** Forensics
**Points:** 150
**Author:** Jacob R.

## Deskripsi Challenge

> Our company, No Flags, Inc., just sent this monthly report out informing us of our continued intentional lack of flags. Unfortunately, we think someone intercepted it and figured out how to add a flag in there. Please find the flag that was hidden in the report so we can get our company back to being completely flag free!

**File:** `no_flags_inc.docm`

---

## Langkah Pengerjaan

### 1. Identifikasi Awal

Langkah pertama adalah memeriksa jenis file yang diberikan untuk memastikan formatnya. Ekstensi `.docm` mengindikasikan bahwa file ini adalah dokumen Microsoft Word yang mendukung fitur Macro (VBA).

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU Computer Club CTF/Forensics/No Flags, Inc.]
└─$ file no_flags_inc.docm
no_flags_inc.docm: Microsoft Word 2007+

```

### 2. Ekstraksi Konten (Unzip)

Dokumen Office modern (OpenXML) pada dasarnya adalah arsip ZIP. Kita dapat mengekstrak isinya untuk melihat struktur folder dan mencari file yang disembunyikan tanpa harus membuka aplikasi Word.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU Computer Club CTF/Forensics/No Flags, Inc.]
└─$ unzip no_flags_inc.docm
...
extracting: word/media/image1.png
extracting: word/media/image2.png
inflating: word/media/flagenc.png
...

```

Ditemukan sebuah file gambar mencurigakan bernama `flagenc.png` di dalam direktori `word/media/`. Berdasarkan namanya (`flag` + `enc`), kemungkinan besar ini adalah gambar flag yang terenkripsi.

### 3. Analisis Macro (VBA)

Karena file ini berekstensi `.docm`, kemungkinan besar kunci dekripsi atau logika penyembunyian terdapat di dalam skrip Macro VBA. Kita menggunakan tool `olevba` untuk membedah kode tersebut.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU Computer Club CTF/Forensics/No Flags, Inc.]
└─$ olevba no_flags_inc.docm
olevba 0.60.2 on Python 3.13.11 - http://decalage.info/python/oletools
===============================================================================
FILE: no_flags_inc.docm
Type: OpenXML
...
VBA MACRO Module1.bas
in file: word/vbaProject.bin - OLE stream: 'VBA/Module1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
' ----------------------------------------------------------------------
' This is a macro, it can run code in your word documents
...
' ----------------------------------------------------------------------

' this function doesn't actually do anything, it just holds some info you need for this challenge
Sub decryption_info_holder()
    Dim hex_key As String
    hex_key = "a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6"
    Dim hex_iv As String
    hex_iv = "f1f2f3f4f5f6f7f8f9f0e1e2e3e4e5e6"
    Dim cipher As String
    cipher = "AES-128-CBC"
    ' use this info in cyberchef or something to decrypt the image with the flag
    ' if you're asking what image? then dig around in the word doc a little more, it's hidden somewhere...
End Sub
...

```

Dari output `olevba`, ditemukan subroutine `decryption_info_holder` yang menyimpan parameter enkripsi:

* **Cipher:** AES-128-CBC
* **Key (Hex):** `a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6`
* **IV (Hex):** `f1f2f3f4f5f6f7f8f9f0e1e2e3e4e5e6`

### 4. Dekripsi (Python Solver)

Untuk mendekripsi file `flagenc.png`, dibuat script Python menggunakan parameter yang ditemukan di atas.

**Script Solver (`solver.py`):**

```python
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def solve():
    # Path ke file terenkripsi hasil unzip
    input_file = "word/media/flagenc.png"
    output_file = "flag_solved.png"
    
    # Kredensial dari Macro VBA
    hex_key = "a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6"
    hex_iv = "f1f2f3f4f5f6f7f8f9f0e1e2e3e4e5e6"

    key = binascii.unhexlify(hex_key)
    iv = binascii.unhexlify(hex_iv)

    print(f"[*] Key: {hex_key}")
    print(f"[*] IV : {hex_iv}")

    if not os.path.exists(input_file):
        print(f"[-] File {input_file} tidak ditemukan.")
        return

    print(f"[*] Membaca {input_file}...")
    with open(input_file, "rb") as f:
        encrypted_data = f.read()

    # Dekripsi AES-128-CBC
    try:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        with open(output_file, "wb") as f:
            f.write(decrypted_data)
        
        print(f"[+] Sukses! Flag disimpan ke: {output_file}")
        
        if decrypted_data.startswith(b'\x89PNG'):
            print("[+] Valid PNG Header detected.")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()

```

**Output Eksekusi:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/DSU Computer Club CTF/Forensics/No Flags, Inc.]
└─$ python3 solver.py
[*] Key: a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6
[*] IV : f1f2f3f4f5f6f7f8f9f0e1e2e3e4e5e6
[*] Membaca word/media/flagenc.png...
[+] Sukses! Flag disimpan ke: flag_solved.png
[+] Valid PNG Header detected.

```

### 5. Hasil Akhir

File `flag_solved.png` berhasil didekripsi menjadi gambar PNG yang valid. Gambar tersebut berisi teks flag.

**Flag:**
`DSU{w4tch_4_th3m_m4cros}`
