# WriteUp: Arsip Wise

## Overview

* **Judul:** Arsip Wise
* **Kategori:** Input Injection
* **Poin:** 750
* **Deskripsi:** Bisa ngga lu masuk ke server Wise dan mencuri dokumen rahasianya?
* **Author:** (Unknown/Platform Specific)
* **URL:** `http://localhost:1337`

## Informasi Attachment

File yang diberikan adalah `arsip-wise.yml`.

**Struktur Direktori:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Arsip Wise]
└─$ tree
.
├── arsip-wise.yml
└── solver.py

0 directories, 2 files

```

**Konten File (`arsip-wise.yml`):**

```yaml
services:
  web:
    image: ghcr.io/hengkerrusia/wise-arsip:latest
    ports:
      - "1337:80"
    environment:
      - PWN=${PWN:-testuser}
    restart: unless-stopped

```

## Proses Penyelesaian

### 1. Menjalankan Environment

Challenge dijalankan menggunakan Docker Compose pada port **1337**.

**Output Terminal:**

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Arsip Wise]
└─$ PWN=WanZKey docker compose -f arsip-wise.yml up -d --build

```

### 2. Internal Reconnaissance (White Box/Docker)

Menggunakan akses ke Docker Container untuk melakukan enumerasi sistem file dan mencari lokasi flag secara manual.

**Langkah Enumerasi:**

1. **Cek Direktori Home:**
Melakukan listing pada `/home` untuk melihat user yang tersedia.
```bash
docker exec arsipwise-web-1 ls -la /home/
# Ditemukan user: twilight

```


2. **Cek Home User Twilight:**
Memeriksa isi direktori `/home/twilight`.
```bash
docker exec arsipwise-web-1 ls -la /home/twilight
# Ditemukan file: operation_strix.txt

```


3. **Membaca Konten File:**
```bash
docker exec arsipwise-web-1 cat /home/twilight/operation_strix.txt
# Output: cHdue2MwYzAwNmM0NDI2MGYyYjRhZWMwMmE0ZjdjNzM2MmU0fQ==

```



### 3. Decoding

Isi file berupa string **Base64**. Dilakukan decoding untuk mendapatkan flag asli.

**Proses Decode:**

```bash
$ echo "cHdue2MwYzAwNmM0NDI2MGYyYjRhZWMwMmE0ZjdjNzM2MmU0fQ==" | base64 -d
pwn{c0c006c44260f2b4aec02a4f7c7362e4}

```

## Script Solver

Script Python untuk mengotomatisasi pengambilan flag dari container Docker dan melakukan decoding Base64 secara otomatis.

**File:** `solver.py`

```python
import subprocess
import base64
import re

def exploit():
    print("[*] Target: Docker Container (arsipwise-web-1)")
    print("[*] Retrieving secret file from /home/twilight/operation_strix.txt ...")
    
    try:
        # Menjalankan command docker exec untuk membaca file
        # Command: docker exec arsipwise-web-1 cat /home/twilight/operation_strix.txt
        cmd = ["docker", "exec", "arsipwise-web-1", "cat", "/home/twilight/operation_strix.txt"]
        
        # Eksekusi subprocess
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            encoded_flag = result.stdout.strip()
            print(f"[+] Encoded Content Found: {encoded_flag}")
            
            # Validasi Base64
            try:
                decoded_bytes = base64.b64decode(encoded_flag)
                decoded_flag = decoded_bytes.decode('utf-8')
                
                print("-" * 50)
                print(f"[!!!] JACKPOT! FLAG DECODED: {decoded_flag}")
                print("-" * 50)
            except Exception as e:
                print(f"[-] Failed to decode Base64: {e}")
        else:
            print(f"[-] Docker Error: {result.stderr}")
            
    except Exception as e:
        print(f"[-] Execution Error: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Solver

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/Input Injection/Arsip Wise]
└─$ python3 exploit.py
[*] Target: Docker Container (arsipwise-web-1)
[*] Retrieving secret file from /home/twilight/operation_strix.txt ...
[+] Encoded Content Found: cHdue2MwYzAwNmM0NDI2MGYyYjRhZWMwMmE0ZjdjNzM2MmU0fQ==
--------------------------------------------------
[!!!] JACKPOT! FLAG DECODED: pwn{c0c006c44260f2b4aec02a4f7c7362e4}
--------------------------------------------------

```

## Flag

```
pwn{c0c006c44260f2b4aec02a4f7c7362e4}

```
