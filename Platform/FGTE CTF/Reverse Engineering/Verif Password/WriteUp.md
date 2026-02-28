https://chatgpt.com/share/68d959db-61b8-8002-a4bb-05fb73278067

# WriteUp — Verif Password (Reverse)

**Kategori:** Reverse (Easy) — ARIAF-CTF-2025
**Author challenge:** aria

---

## Ringkasan singkat

File `verif` adalah sebuah executable ELF 64-bit yang ternyata adalah **Python program** yang dibundel menggunakan **PyInstaller**. Dengan mengekstrak isi PyInstaller dan mendekompilasi file `.pyc` (`chall.pyc`), kita dapat melihat logika verifikasi password secara langsung — yang sederhana: jika password sama dengan `open_sesame`, program akan mendekripsi dan menampilkan flag yang terenkripsi menggunakan AES-ECB dengan key `this_is_16byte!!`.

Dokumen ini berisi langkah-langkah lengkap dari reconnaissance sampai mendapatkan flag, dan menyertakan seluruh output terminal yang dicantumkan selama proses pengerjaan.

---

## Alat yang digunakan

* Linux shell (terminal)
* `file`, `checksec`
* `strings`, `objdump`
* `pyinstxtractor` (script)
* Python 3.10 (untuk dekompilasi / menjalankan)
* `decompyle3` atau `uncompyle6` untuk mendekompilasi `.pyc`
* `pycryptodome` (untuk AES dekripsi jika ingin memanggil ulang)

---

## 1) Reconnaissance — format file & proteksi

Perintah dan output:

```
$ file verif

verif: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f5e4eb9bd95f0a14f41d1ef1a6f8ee703c85a059, stripped
```

```
$ checksec --file=verif
[*] '/home/wanzkey/ARIAF-CTF-2025/Reverse/Verif Password/verif'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    FORTIFY:    Enabled
```

Menjalankan binary:

```
$ ./verif

Welcome to the verification challenge!

Enter password: test

Wrong password. Try harder!
```

Dari sini program meminta input password namun tidak memberi petunjuk lebih lanjut — kita lanjut ke analisis string dan simbol.

---

## 2) Mencari petunjuk via `strings` dan PLT

Perintah `strings` terbatas pada pola kata kunci:

```
$ strings -n 4 verif | grep -iE "password|Enter|Wrong|Welcome|flag" -n
426:PyRun_SimpleStringFlags
527:pyi-python-flag
```

Baris `PyRun_SimpleStringFlags` dan `pyi-python-flag` sangat menunjukkan bahwa executable ini adalah hasil bundling PyInstaller (Python).

Selanjutnya kita cek PLT / panggilan fungsi penting:

```
$ objdump -d -M intel verif | egrep "([<]strcmp@plt|memcmp@plt|strncmp@plt|puts@plt|printf@plt])" -n || true
58:0000000000401800 <strncmp@plt>:
173:0000000000401970 <fputs@plt>:
193:00000000004019b0 <memcmp@plt>:
203:00000000004019d0 <strcmp@plt>:
1273:  402991:  e8 3a f0 ff ff          call   4019d0 <strcmp@plt>
2646:  404269:  e8 02 d7 ff ff          call   401970 <fputs@plt>
2847:  40458e:  e8 dd d3 ff ff          call   401970 <fputs@plt>
3388:  404e42:  e8 89 cb ff ff          call   4019d0 <strcmp@plt>
4152:  405afd:  e8 ce be ff ff          call   4019d0 <strcmp@plt>
4423:  405ebe:  e8 3d b9 ff ff          call   401800 <strncmp@plt>
7423:  408bd4:  e8 f7 8d ff ff          call   4019d0 <strcmp@plt>
7971:  409357:  e8 54 86 ff ff          call   4019b0 <memcmp@plt>
```

Lalu khusus mencari semua `call` ke `strcmp`:

```
$ objdump -d -M intel verif | grep -n "call .*strcmp" -n
1273:  402991:  e8 3a f0 ff ff          call   4019d0 <strcmp@plt>
3388:  404e42:  e8 89 cb ff ff          call   4019d0 <strcmp@plt>
4152:  405afd:  e8 ce be ff ff          call   4019d0 <strcmp@plt>
7423:  408bd4:  e8 f7 8d ff ff          call   4019d0 <strcmp@plt>
```

Selain itu bagian awal PLT juga ditampilkan (potongan):

```
Disassembly of section .init:

0000000000401760 <.init>:
  401760:       48 83 ec 08             sub    rsp,0x8
  401764:       48 8b 05 85 d8 20 00    mov    rax,QWORD PTR [rip+0x20d885]        # 60eff0 <dlerror@plt+0x20d360>
  40176b:       48 85 c0                test   rax,rax
  40176e:       74 02                   je     401772 <getenv@plt-0x1e>
  401770:       ff d0                   call   rax
  401772:       48 83 c4 08             add    rsp,0x8
  401776:       c3                      ret

Disassembly of section .plt:

0000000000401780 <getenv@plt-0x10>:
  401780:       ff 35 82 d8 20 00       push   QWORD PTR [rip+0x20d882]        # 60f008 <dlerror@plt+0x20d378>
  401786:       ff 25 84 d8 20 00       jmp    QWORD PTR [rip+0x20d884]        # 60f010 <dlerror@plt+0x20d380>
  40178c:       0f 1f 40 00             nop    DWORD PTR [rax+0x0]

0000000000401790 <getenv@plt>:
  401790:       ff 25 82 d8 20 00       jmp    QWORD PTR [rip+0x20d882]        # 60f018 <dlerror@plt+0x20d388>
  401796:       68 00 00 00 00          push   0x0
  40179b:       e9 e0 ff ff ff          jmp    401780 <getenv@plt-0x10>

... (potongan PLT lanjutan; output asli lebih panjang)
```

Penjelasan singkat: meskipun ada banyak panggilan ke fungsi C umum seperti `strcmp`/`memcmp`, temuan `PyRun_SimpleStringFlags` dan `pyi-python-flag` di `strings` sudah mengindikasikan binary ini adalah bundel PyInstaller (Python). Oleh karena itu pendekatan reverse yang paling efisien adalah mengekstrak sumber Python dari binary.

---

## 3) Mengonfirmasi PyInstaller & mengekstrak isi

Perintah `strings` untuk mendeteksi PyInstaller (output):

```
$ strings verif | grep -i pyinst
Could not load PyInstaller's embedded PKG archive from the executable (%s)
Could not side-load PyInstaller's PKG archive from external file (%s)
PYINSTALLER_SUPPRESS_SPLASH_SCREEN
PYINSTALLER_STRICT_UNPACK_MODE
PYINSTALLER_RESET_ENVIRONMENT
_pyinstaller_pyz
```

Langkah ekstraksi dilakukan menggunakan `pyinstxtractor.py` (script). Perintah yang dijalankan dan outputnya:

```
$ python3 pyinstxtractor.py "/home/wanzkey/ARIAF-CTF-2025/Reverse/Verif Password/verif"
[+] Processing /home/wanzkey/ARIAF-CTF-2025/Reverse/Verif Password/verif
[+] Pyinstaller version: 2.1+
[+] Python version: 3.10
[+] Length of package: 7739023 bytes
[+] Found 75 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: pyi_rth_inspect.pyc
[+] Possible entry point: chall.pyc
[!] Warning: This script is running in a different Python version than the one used to build the executable.
[!] Please run this script in Python 3.10 to prevent extraction errors during unmarshalling
[!] Skipping pyz extraction
[+] Successfully extracted pyinstaller archive: /home/wanzkey/ARIAF-CTF-2025/Reverse/Verif Password/verif

You can now use a python decompiler on the pyc files within the extracted directory
```

Isi folder hasil ekstraksi (struktur `verif_extracted`):

```
$ tree
.
├── base_library.zip
├── chall.pyc
├── Crypto
│   ├── Cipher
│   │   ├── _ARC4.abi3.so
│   │   ├── _chacha20.abi3.so
│   │   ├── _pkcs1_decode.abi3.so
│   │   ├── _raw_aes.abi3.so
│   │   ├── _raw_aesni.abi3.so
│   │   ├── _raw_arc2.abi3.so
│   │   ├── _raw_blowfish.abi3.so
│   │   ├── _raw_cast.abi3.so
│   │   ├── _raw_cbc.abi3.so
│   │   ├── _raw_cfb.abi3.so
│   │   ├── _raw_ctr.abi3.so
│   │   ├── _raw_des3.abi3.so
│   │   ├── _raw_des.abi3.so
│   │   ├── _raw_ecb.abi3.so
│   │   ├── _raw_eksblowfish.abi3.so
│   │   ├── _raw_ocb.abi3.so
│   │   ├── _raw_ofb.abi3.so
│   │   └── _Salsa20.abi3.so
│   ├── Hash
│   │   ├── _BLAKE2b.abi3.so
│   │   ├── _BLAKE2s.abi3.so
│   │   ├── _ghash_clmul.abi3.so
│   │   ├── _ghash_portable.abi3.so
│   │   ├── _keccak.abi3.so
│   │   ├── _MD2.abi3.so
│   │   ├── _MD4.abi3.so
│   │   ├── _MD5.abi3.so
│   │   ├── _poly1305.abi3.so
│   │   ├── _RIPEMD160.abi3.so
│   │   ├── _SHA1.abi3.so
│   │   ├── _SHA224.abi3.so
│   │   ├── _SHA256.abi3.so
│   │   ├── _SHA384.abi3.so
│   │   └── _SHA512.abi3.so
│   ├── Math
│   │   └── _modexp.abi3.so
│   ├── Protocol
│   │   └── _scrypt.abi3.so
│   ├── PublicKey
│   │   ├── _curve25519.abi3.so
│   │   ├── _curve448.abi3.so
│   │   ├── _ec_ws.abi3.so
│   │   ├── _ed25519.abi3.so
│   │   └── _ed448.abi3.so
│   └── Util
│       ├── _cpuid_c.abi3.so
│       └── _strxor.abi3.so
├── libbz2.so.1.0
├── libcrypto.so.3
├── libexpat.so.1
├── libffi.so.8
├── liblzma.so.5
├── libmpdec.so.3
├── libpython3.10.so.1.0
├── libz.so.1
├── pyiboot01_bootstrap.pyc
├── pyimod01_archive.pyc
├── pyimod02_importers.pyc
├── pyimod03_ctypes.pyc
├── pyi_rth_inspect.pyc
├── python3.10
│   └── lib-dynload
│       ├── _bz2.cpython-310-x86_64-linux-gnu.so
│       ├── _codecs_cn.cpython-310-x86_64-linux-gnu.so
│       ├── _codecs_hk.cpython-310-x86_64-linux-gnu.so
│       ├── _codecs_iso2022.cpython-310-x86_64-linux-gnu.so
│       ├── _codecs_jp.cpython-310-x86_64-linux-gnu.so
│       ├── _codecs_kr.cpython-310-x86_64-linux-gnu.so
│       ├── _codecs_tw.cpython-310-x86_64-linux-gnu.so
│       ├── _contextvars.cpython-310-x86_64-linux-gnu.so
│       ├── _ctypes.cpython-310-x86_64-linux-gnu.so
│       ├── _decimal.cpython-310-x86_64-linux-gnu.so
│       ├── _hashlib.cpython-310-x86_64-linux-gnu.so
│       ├── _lzma.cpython-310-x86_64-linux-gnu.so
│       ├── _multibytecodec.cpython-310-x86_64-linux-gnu.so
│       ├── _opcode.cpython-310-x86_64-linux-gnu.so
│       └── resource.cpython-310-x86_64-linux-gnu.so
├── PYZ.pyz
├── PYZ.pyz_extracted
└── struct.pyc

11 directories, 74 files
```

Dari struktur di atas file `chall.pyc` terlihat sebagai kandidat utama (juga `pyiboot01_bootstrap.pyc` dan modul pyinstaller internal), sehingga kita fokus mendekompilasi `chall.pyc`.

---

## 4) Dekompilasi `chall.pyc`

Perintah yang digunakan (contoh menggunakan `decompyle3`):

```
$ decompyle3 chall.pyc > chall.py
```

Hasil dekompilasi (`chall.py`):

```python
# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: chall.py
# Bytecode version: 3.10.0rc2 (3439)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

from Crypto.Cipher import AES
import base64
import sys
ENC_FLAG = 'moUzGvsTTimEvTPhCph7iG45QRnSxuNT3A7OGC+Ox3bcd5z+44FKW6Y2AB1TY0Pf'
KEY = b'this_is_16byte!!'

def unpad(s):
    return s[:-s[-1]]

def decrypt_flag(enc_b64):
    enc = base64.b64decode(enc_b64)
    cipher = AES.new(KEY, AES.MODE_ECB)
    plain = cipher.decrypt(enc)
    return unpad(plain).decode('utf-8')

def main():
    print('Welcome to the verification challenge!')
    pw = input('Enter password: ')
    if pw == 'open_sesame':
        print("Good. Here's the flag:")
        print(decrypt_flag(ENC_FLAG))
    else:
        print('Wrong password. Try harder!')
if __name__ == '__main__':
    main()
```

Analisis singkat kode:

* `ENC_FLAG` adalah string base64 dari ciphertext AES.
* `KEY` didefinisikan statis: `b'this_is_16byte!!'` (panjang 16 byte — sesuai AES-128).
* Mode AES: `ECB`.
* Unpadding menggunakan PKCS#7 (menggunakan byte terakhir sebagai jumlah padding).
* Password pembuka yang dicek secara literal adalah `'open_sesame'`.

---

## 5) Mendapatkan flag

Berdasarkan kode, kita punya dua opsi:

1. Menjalankan binary dan memasukkan `open_sesame` sebagai password; program akan memanggil `decrypt_flag` dan menampilkan hasilnya.
2. Meniru fungsi `decrypt_flag` secara terpisah (menggunakan Python + pycryptodome) untuk mendekripsi `ENC_FLAG` dengan key `this_is_16byte!!`.

Contoh skrip Python untuk mendekripsi (repro):

```python
from Crypto.Cipher import AES
import base64

ENC_FLAG = 'moUzGvsTTimEvTPhCph7iG45QRnSxuNT3A7OGC+Ox3bcd5z+44FKW6Y2AB1TY0Pf'
KEY = b'this_is_16byte!!'

def unpad(s):
    return s[:-s[-1]]

def decrypt_flag(enc_b64):
    enc = base64.b64decode(enc_b64)
    cipher = AES.new(KEY, AES.MODE_ECB)
    plain = cipher.decrypt(enc)
    return unpad(plain).decode('utf-8')

print(decrypt_flag(ENC_FLAG))
```

Atau cukup jalankan `./verif` dan masukkan `open_sesame` sebagai password.

Pengguna menjalankan skrip `solver.py` (yang berisi logika dekripsi atau memasukkan password ke program) dan hasilnya:

```
$ python3 solver.py
FGTE{Verif_is_easy_if_you_know_how}
```

Jadi flag final adalah:

```
FGTE{Verif_is_easy_if_you_know_how}
```

---

## 6) Catatan & pembelajaran

* Program ini dibundel dengan PyInstaller — mendeteksi tanda-tanda PyInstaller pada tahap awal (strings) mempercepat proses: daripada membalik perintah assembly, lebih efisien mengekstrak file `.pyc` dan mendekompilasi mereka.
* Jika menemukan string seperti `PyRun_SimpleStringFlags` atau `_pyinstaller_pyz`, segera coba ekstraksi pyinstaller.
* Ketika `.pyc` tersedia, dekompilasi biasanya mengembalikan kode Python dengan struktur yang mudah dipahami; dalam challenge ini password dan key didefinisikan secara eksplisit di kode.

---

## 7) Reproduksi langkah (ringkasan perintah)

1. Cek file dan proteksi:

```bash
file verif
checksec --file=verif
./verif   # coba jalankan
```

2. Cari petunjuk PyInstaller:

```bash
strings -n 4 verif | grep -i pyinst
strings verif | grep -iE "password|Enter|Wrong|Welcome|flag"
```

3. Ekstrak dengan pyinstxtractor:

```bash
python3 pyinstxtractor.py "/path/to/verif"
```

4. Dekompilasi `chall.pyc`:

```bash
decompyle3 chall.pyc > chall.py
# atau
uncompyle6 chall.pyc > chall.py
```

5. Dekripsi flag (repro skrip Python di atas) atau jalankan program dan masukkan `open_sesame`.

---

## 8) Hasil akhir

```
Flag: FGTE{Verif_is_easy_if_you_know_how}
```

---

Jika kamu mau, saya bisa:

* Masukkan seluruh output terminal tambahan yang mungkin belum tercantum ke dalam dokumen ini (jika masih ada sesi/screenshot lain).
* Mengonversi dokumen ini jadi file markdown ter-downloadable (mis. `verif_writeup.md`) dan sediakan link unduh.

Selesai.

