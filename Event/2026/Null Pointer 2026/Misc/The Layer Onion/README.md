# WriteUp - The Layer Onion

## Overview

* **Judul:** The Layer Onion
* **Kategori:** Misc
* **Poin:** 150 points (Medium)
* **Deskripsi:** Challenge Description
* **Author:** -

## Informasi Attachment

Diberikan sebuah file bernama `onion.zip` yang diklaim sebagai file ZIP, namun berdasarkan hasil recon awal, file ini merupakan POSIX tar archive.

## Proses Penyelesaian

### 1. Recon Awal

Langkah pertama adalah melakukan inspeksi pada file yang diberikan untuk mengetahui jenis file yang sebenarnya.

```text
 WanZKey  ～  ~../Misc/The Layer Onion 󱎫 0s 󱑎 21.36
 󰋑  ▶  file onion.zip
onion.zip: POSIX tar archive

 WanZKey  ～  ~../Misc/The Layer Onion 󱎫 0s 󱑎 21.36
 󰋑  ▶  exiftool -l onion.zip
ExifTool Version Number
      13.50
File Name
      onion.zip
Directory
      .
File Size
      113 kB
File Modification Date/Time
      2026:03:14 16:17:29+07:00
File Access Date/Time
      2026:03:15 21:36:27+07:00
File Inode Change Date/Time
      2026:03:15 21:36:03+07:00
File Permissions
      -rw-r--r--
File Type
      TAR
File Type Extension
      tar
MIME Type
      application/x-tar
Warning
      Unsupported file type

 WanZKey  ～  ~../Misc/The Layer Onion 󱎫 0s 󱑎 21.36
 󰋑  ▶  tar -xvf onion.zip
layer_1999.zip

 WanZKey  ～  ~../Misc/The Layer Onion 󱎫 0s 󱑎 21.36
 󰋑  ▶  file layer_1999.zip
layer_1999.zip: Zip archive data, made by v2.0, extract using at least v2.0, last modified Mar 14 2026 14:52:12, uncompressed size 101461, method=store

 WanZKey  ～  ~../Misc/The Layer Onion 󱎫 0s 󱑎 21.36
 󰋑  ▶  unzip layer_1999.zip
Archive:  layer_1999.zip
 extracting: layer_1998.zip

 WanZKey  ～  ~../Misc/The Layer Onion 󱎫 0s 󱑎 21.36
 󰋑  ▶  file layer_1998.zip
layer_1998.zip: Zip archive data, made by v2.0, extract using at least v2.0, last modified Mar 14 2026 14:52:12, uncompressed size 101335, method=store

```

Terlihat bahwa file terdiri dari ribuan *nested archives* (arsip berlapis), mulai dari layer 1999 yang terus menurun. Ekstraksi secara manual tidak efisien, sehingga diperlukan *script automation*.

### 2. Hambatan Ekstraksi (Perubahan Format)

Ketika script pertama dijalankan, proses berhenti di layer 1499 karena author mengubah format arsip dari `zip` menjadi `gzip`.

```text
xtracting: layer_1506.zip
Extracting: layer_1505.zip
Extracting: layer_1504.zip
Extracting: layer_1503.zip
Extracting: layer_1502.zip
Extracting: layer_1501.zip
Extracting: layer_1500.zip
Extracting: layer_1499.gz

We hit the bottom! The final file is: layer_1499.gz
Trying to read the contents...
Not a standard text file. You might need to check it manually.

󰋑  ▶  file layer_1499.gz
layer_1499.gz: gzip compressed data, was "layer_1499", last modified: Sat Mar 14 09:20:39 2026, max compression, original size modulo 2^32 38545

 󰋑  ▶  7z x layer_1499.gz

7-Zip 26.00 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12
 64-bit locale=en_US.UTF-8 Threads:2 OPEN_MAX:10240, ASM

Scanning the drive for archives:
1 file, 38589 bytes (38 KiB)

Extracting archive: layer_1499.gz
--
Path = layer_1499.gz
Type = gzip
Headers Size = 21

Everything is Ok

Size:       38545
Compressed: 38589

```

### 3. Hambatan Ekstraksi (File Name Too Long)

Script dimodifikasi untuk membaca `gzip`. Namun, karena `gzip` tidak membawa nama file internal, penambahan ekstensi berulang menyebabkan *error* panjang nama file melampaui batas OS.

```text
Extracting: layer_1499_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped
Extracting: layer_1499_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped
Traceback (most recent call last):
  File "/home/wanzkey/CSEMCTF/Event/Null Pointer/Misc/The Layer Onion/./solver.py", line 75, in <module>
    peel_the_onion("layer_1499.gz")
    ~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^
  File "/home/wanzkey/CSEMCTF/Event/Null Pointer/Misc/The Layer Onion/./solver.py", line 47, in peel_the_onion
    with open(extracted_file, 'wb') as f_out:
         ~~~~^^^^^^^^^^^^^^^^^^^^^^
OSError: [Errno 36] File name too long: 'layer_1499_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped_unzipped'

```

### 4. Eksekusi Script Final

Script kemudian diperbaiki dengan metode pembacaan *magic bytes* dan penamaan file menggunakan sistem *counter* (angka) agar nama file hasil ekstrak tidak terlalu panjang, serta bisa mengenali format tar, zip, gzip, dan bzip2.

## Script Solver

```python
import os
import tarfile
import zipfile
import gzip
import bz2
import shutil

def check_magic_bytes(filepath):
    try:
        with open(filepath, 'rb') as f:
            return f.read(2)
    except IOError:
        return b''

def peel_the_onion(start_file):
    current_file = start_file 
    counter = 0 
    
    while True:
        print(f"Extracting: {current_file}")
        
        if not os.path.exists(current_file):
            print(f"Hold up bro, {current_file} is missing.")
            break

        extracted_file = None
        magic_bytes = check_magic_bytes(current_file)

        # Handle tar files
        if tarfile.is_tarfile(current_file):
            with tarfile.open(current_file, 'r') as tar:
                members = tar.getnames()
                if members:
                    extracted_file = members[0]
                    tar.extractall()
                    
        # Handle zip files
        elif zipfile.is_zipfile(current_file):
            with zipfile.ZipFile(current_file, 'r') as zip_ref:
                members = zip_ref.namelist()
                if members:
                    extracted_file = members[0]
                    zip_ref.extractall()
                    
        # Handle gzip files (magic bytes: 1f 8b)
        elif magic_bytes == b'\x1f\x8b':
            extracted_file = f"layer_extracted_{counter}"
            with gzip.open(current_file, 'rb') as f_in:
                with open(extracted_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)

        # Handle bzip2 files (magic bytes: 42 5a / 'BZ')
        elif magic_bytes == b'BZ':
            extracted_file = f"layer_extracted_{counter}"
            with bz2.open(current_file, 'rb') as f_in:
                with open(extracted_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    
        # Hit the bottom layer or unknown format
        else:
            print(f"\nWe hit the bottom! The final file is: {current_file}")
            print("Trying to read the contents...")
            try:
                with open(current_file, 'r') as f:
                    print(f"Flag or Text:\n{f.read()}")
            except UnicodeDecodeError:
                print("Not a standard text file bro. Run 'file' command on it to see what it is.")
            break

        if extracted_file:
            if current_file not in ["onion.zip", "layer_1499.gz"]:
                try:
                    os.remove(current_file)
                except OSError:
                    pass
            current_file = extracted_file
            counter += 1
        else:
            print("Oh my bad, ran into an empty archive.")
            break

if __name__ == "__main__":
    peel_the_onion("layer_1499.gz")

```

## Output Terminal Solver

```text
Extracting: layer_extracted_497
Extracting: layer_extracted_498
/home/wanzkey/CSEMCTF/Event/Null Pointer/Misc/The Layer Onion/./solver.py:36: DeprecationWarning: Python 3.14 will, by default, filter extracted tar archives and reject files or modify their metadata. Use the filter argument to control this behavior.
  tar.extractall()
Extracting: layer_998.tar
Extracting: layer_997.tar
Extracting: layer_996.tar
Extracting: layer_995.tar
Extracting: layer_994.tar
Extracting: layer_993.tar
Extracting: layer_992.tar
Extracting: layer_991.tar
Extracting: layer_990.tar
Extracting: layer_989.tar
Extracting: layer_988.tar
Extracting: layer_987.tar
Extracting: layer_986.tar
Extracting: layer_985.tar
Extracting: layer_984.tar
Extracting: layer_983.tar
Extracting: layer_982.tar
Extracting: layer_981.tar
Extracting: layer_980.tar
Extracting: layer_979.tar
Extracting: layer_978.tar
Extracting: layer_977.tar
Extracting: layer_976.tar
Extracting: layer_975.tar
Extracting: layer_974.tar
Extracting: layer_973.tar
Extracting: layer_972.tar
Extracting: layer_971.tar
Extracting: layer_970.tar

Extracting: layer_7.zip
Extracting: layer_6.zip
Extracting: layer_5.zip
Extracting: layer_4.zip
Extracting: layer_3.zip
Extracting: layer_2.zip
Extracting: layer_1.zip
Extracting: layer_0.zip
Extracting: flag.txt

We hit the bottom! The final file is: flag.txt
Trying to read the contents...
Flag or Text:
STURSEC{4ut0m4t10n_1s_th3_unp4ck1ng_k3y}

```

## Flag

```
STURSEC{4ut0m4t10n_1s_th3_unp4ck1ng_k3y}

```
