# WriteUp - Accountador

## Overview

* **Name:** Accountador
* **Category:** Security Operations Center (SoC)
* **Point:** 500
* **Author:** Aseng
* **Desc:** You need to use SIEM to solve this challenge, otherwise you get 0. Which Account that creates the user daya.aili and what event ID occurs on that user creation? Answer: LKS{domain\nameaccountlowercase_eventidnumer} Example: LKS{setiabudi\bukalapakacc_1337}
* **URL:** Local Attachment (Security.evtx)

## Reconnaissance

```text
$ file Security.evtx
Security.evtx: MS Windows Vista-8.1 Event Log, 286 chunks (no. 285 in use), next record no. 29448

$ exiftool Security.evtx
ExifTool Version Number         : 13.50
File Name                       : Security.evtx
Directory                       : .
File Size                       : 19 MB
File Modification Date/Time     : 2026:04:02 19:45:20+07:00
File Access Date/Time           : 2026:06:11 17:59:37+07:00
File Inode Change Date/Time     : 2026:06:11 17:59:34+07:00
File Permissions                : -rw-r--r--
Error                           : Unknown file type

```

## Step by Step Solution

### 1. Analisis Target Informasi Windows Log

**Identifikasi Kebutuhan Insiden:** Berdasarkan deskripsi tantangan, fokus utama adalah menemukan identitas entitas sistem atau *user* yang bertanggung jawab atas pembuatan akun bernama `daya.aili` beserta mencatat identifikasi peristiwa (Event ID) dari insiden tersebut melalui format Windows Event Log (`.evtx`).

### 2. Korelasi Event ID untuk User Creation

**Pemetaan Event ID 4720:** Pada arsitektur pencatatan keamanan sistem operasi Microsoft Windows, setiap aktivitas pembuatan akun pengguna lokal maupun basis direktori aktif (Active Directory) akan selalu memicu dan dicatat di bawah Event ID **4720**. Log ini akan memuat atribut kritis di dalam `EventData`, secara spesifik `TargetUserName` (pengguna yang dibuat) serta `SubjectUserName` dan `SubjectDomainName` (aktor pengeksekusi).

### 3. Otomatisasi Parsing EVTX Berbasis CLI

**Ekstraksi Data Terprogram:** Alih-alih mendeploy perangkat lunak SIEM terpusat, ekstraksi log EVTX dieksekusi melalui skrip parser Python. Skrip secara dinamis membaca file biner EVTX, mengonversinya menjadi objek JSON, dan memfilter kemunculan Event ID 4720 yang mengikat parameter `daya.aili`. Output JSON mengungkap bahwa domain kreator adalah `setiabudi` dan pengguna kreator adalah `Administrator`. Penggabungan atribut dalam huruf kecil (*lowercase*) sesuai struktur `LKS{domain\nameaccountlowercase_eventidnumer}` menghasilkan bendera secara utuh.

## Script Solver

```python
#!/usr/bin/env python3
import json
import sys
try:
    from evtx import PyEvtxParser
except ImportError:
    print("[!] Install library dulu bro: pip install evtx")
    sys.exit(1)

def solve():
    file_path = "Security.evtx"
    print("[*] Parsing EVTX file, please wait...")
    
    try:
        parser = PyEvtxParser(file_path)
        for record in parser.records_json():
            record_str = record['data']
            
            # Kita filter cepat dengan string matching buat Event ID 4720 dan user daya.aili
            if "4720" in record_str and "daya.aili" in record_str:
                data = json.loads(record_str)
                system = data.get('Event', {}).get('System', {})
                event_data = data.get('Event', {}).get('EventData', {})
                
                event_id = system.get('EventID')
                
                # Validasi ulang dari JSON parsed data
                if event_id == 4720:
                    print("\n[*] Match Found!")
                    
                    subject_domain = event_data.get('SubjectDomainName', '')
                    subject_user = event_data.get('SubjectUserName', '')
                    target_user = event_data.get('TargetUserName', '')
                    
                    print(f"[-] Target User Created: {target_user}")
                    print(f"[-] Created By Domain  : {subject_domain}")
                    print(f"[-] Created By User    : {subject_user}")
                    print(f"[-] Event ID           : {event_id}")
                    
                    # Build the flag
                    flag_domain = subject_domain.lower()
                    flag_user = subject_user.lower()
                    
                    flag = f"LKS{{{flag_domain}\\{flag_user}_{event_id}}}"
                    print(f"\n[*] Flag: {flag}")
                    return
                    
        print("[-] Target tidak ditemukan di dalam log.")
        
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == '__main__':
    solve()

```

## Output Terminal Solver

```bash
$ ./solver.py
[*] Parsing file...

[*] Match Found!
[-] Target User Created: daya.aili
[-] Created By Domain  : setiabudi
[-] Created By User    : Administrator
[-] Event ID           : 4720

[*] Flag: LKS{setiabudi\administrator_4720}

```

## Flag

`LKS{setiabudi\administrator_4720}`
