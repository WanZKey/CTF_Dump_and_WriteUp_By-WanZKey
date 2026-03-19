# WriteUp - Algoritma PT Xien Operation Republic

## Overview

**Title:** Algoritma PT Xien Operation Republic
**Category:** REVERSE ENGINEERING
**Points:** 500 PTS
**Author:** N/A
**Description:** Baru - baru ini, PT Xien Operation Republic telah membuat sistem algoritma yang sangat canggih. tetapi 3 minggu lalu PT Xien Operation Republic kehilangan algoritma nya dan hanya tersisa bahan baku yang tidak dapat di baca.
**URL:** N/A

## Attachment Information

**File:** `chall_6927b7c63d12c_3ac13c6d.zip` (di-ekstrak menjadi `chall.zip`)
**Directory Structure:**

```text
~../Reverse Engineering/Algoritma PT Xien Operation Republic/
├── chall.zip
└── XienOperationRepublic.class

```

## Step-by-Step Solution

Langkah pertama adalah melakukan pengecekan terhadap file attachment yang diberikan dan mengekstrak isinya. Berikut adalah proses analisa awal menggunakan command line:

```bash
…ey  ～  ~../Reverse Engineering/Algoritma PT Xien Operation Republic 󱎫 0s 󱑎 12.19
 󰋑  ▶  file chall.zip
chall.zip: Zip archive data, made by v3.1, extract using at least v2.0, last modified Nov 27 2025 09:25:10, uncompressed size 1778, method=deflate

…ey  ～  ~../Reverse Engineering/Algoritma PT Xien Operation Republic 󱎫 0s 󱑎 12.19
 󰋑  ▶  unzip -l chall.zip
Archive:  chall.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
     1778  2025-11-27 09:25   XienOperationRepublic.class
---------                     -------
     1778                     1 file

…ey  ～  ~../Reverse Engineering/Algoritma PT Xien Operation Republic 󱎫 0s 󱑎 12.19
 󰋑  ▶  unzip chall.zip
Archive:  chall.zip
  inflating: XienOperationRepublic.class

…ey  ～  ~../Reverse Engineering/Algoritma PT Xien Operation Republic 󱎫 0s 󱑎 12.19
 󰋑  ▶  file XienOperationRepublic.class
XienOperationRepublic.class: compiled Java class data, version 67.0 (Java SE 23)

 󰋑  ▶  javap XienOperationRepublic.class
Compiled from "XienOperationRepublic.java"
public class XienOperationRepublic {
  public XienOperationRepublic();
  public static java.lang.String XienOpRep(java.lang.String, java.lang.String);
  public static void main(java.lang.String[]);
}

```

Setelah mengetahui bahwa attachment berisi *compiled Java class data*, langkah selanjutnya adalah men-decompile file tersebut menggunakan CFR Decompiler untuk menganalisa *source code* aslinya.

## Decompile Information

Berikut adalah hasil eksekusi decompile dari `XienOperationRepublic.class` menggunakan CFR di terminal:

```java
 󰋑  ▶  cfr XienOperationRepublic.class
/*
 * Decompiled with CFR 0.152.
 */
import java.util.Base64;

public class XienOperationRepublic {
    public static String XienOpRep(String target, String key) {
        StringBuilder result = new StringBuilder();
        for (int x_lol = 0; x_lol < target.length(); ++x_lol) {
            char Targetchar = target.charAt(x_lol);
            char Keychar = key.charAt(x_lol % key.length());
            result.append((char)(Targetchar ^ Keychar));
        }
        return result.toString();
    }

    public static void main(String[] args) {
        String FlOwowow = "ceSoreZ";
        String ChOwowow = "SAEBMwdeOBUQJ1kHXzYJV0gNJyRdAjYMFUg";
        String KyOwowow = "xiilingxi";
        String ubahubahstring = new String(Base64.getDecoder().decode(ChOwowow));
        String kataXiling = XienOperationRepublic.XienOpRep(ubahubahstring, KyOwowow);
        System.out.println("Your Message : Ahahaha kamu ga bisa baca aku sekarang!");
        System.out.println("Your Message : Tambahkan `Pesan Deskripsi` di dalam flag contoh `ZeroSec{Pesan_Deskripsi}`");
    }
}

```

Dari hasil analisa source code tersebut, program melakukan enkripsi sederhana. Variabel ciphertext `ChOwowow` disimpan dalam format Base64. Program kemudian melakukan decode Base64 pada `ChOwowow` dan memasukkannya ke dalam method `XienOpRep`. Method tersebut akan melakukan operasi XOR per karakter terhadap ciphertext menggunakan *key* dari variabel `KyOwowow` (`xiilingxi`). Program juga memberikan petunjuk bahwa flag dibungkus dengan format string terbalik dari `FlOwowow` yaitu `ZeroSec{...}`.

## Solver Script

Berdasarkan logika dekompilasi di atas, script solver dibuat menggunakan bahasa Python untuk mereplikasi proses decode Base64 dan dekripsi XOR agar mendapatkan isi pesan yang sebenarnya.

Isi file `solver.py`:

```python
import base64

def main():
    # Variabel dari source code Java
    ch_owowow = "SAEBMwdeOBUQJ1kHXzYJV0gNJyRdAjYMFUg"
    key = "xiilingxi"
    
    # Base64 butuh padding kelipatan 4
    padding_needed = (4 - len(ch_owowow) % 4) % 4
    ch_owowow += "=" * padding_needed
    
    # Decode Base64
    decoded_target = base64.b64decode(ch_owowow)
    
    # Proses XOR Decryption
    decrypted_message = ""
    for i in range(len(decoded_target)):
        target_char = decoded_target[i]
        key_char = ord(key[i % len(key)])
        decrypted_message += chr(target_char ^ key_char)
        
    # Formatting Flag
    flag = f"ZeroSec{{{decrypted_message}}}"
    
    print("[*] Proses Decryption Selesai!")
    print(f"[*] Pesan Asli : {decrypted_message}")
    print(f"[*] Flag       : {flag}")

if __name__ == "__main__":
    main()

```

Output eksekusi terminal dari script solver:

```bash
 󰋑  ▶  ./solver.py
[*] Proses Decryption Selesai!
[*] Pesan Asli : 0hh_n0_my_0n3_g00d_M4n_br0
[*] Flag       : ZeroSec{0hh_n0_my_0n3_g00d_M4n_br0}

```

## Flag

`ZeroSec{0hh_n0_my_0n3_g00d_M4n_br0}`
