# Invitation

## Overview

* **Judul**: Invitation
* **Kategori**: Blockchain / Reverse Engineering
* **Poin**: 1000 pts
* **Author**: Kiinzu
* **Deskripsi**: Mencari "lokasi" yang tepat dalam bytecode untuk mendapatkan undangan pesta. Kita harus menemukan nama fungsi yang diawali dengan string `TCP1P`.

## Informasi Attachment

* `Invitation.txt`: File berisi *raw EVM Bytecode*.
* `101.txt`: Instruksi format flag. Flag didapatkan dari nama fungsi yang ditemukan, dengan format tertentu.

## Analisis Challenge

1. **Petunjuk Awal**:
Saat melakukan decoding hex ke string pada `Invitation.txt`, muncul teks:
* *"The 4 bytes, it's fishy!"*
* *"Function db? never heard em"*


Ini mengindikasikan bahwa kita tidak mencari string text biasa, melainkan **Function Selector** (4-byte signature) yang umum dalam Ethereum Smart Contract.
2. **Mekanisme Function Selector**:
Dalam EVM, nama fungsi di-hash menggunakan Keccak-256, dan 4 byte pertamanya diambil sebagai identifier. Opcode untuk memuat 4 byte selector ke stack adalah `PUSH4` (Hex: `0x63`).
3. **Strategi**:
Kita perlu mengekstrak semua data 4-byte yang muncul setelah opcode `63` di dalam file bytecode, lalu mencocokkannya di Database Signature Ethereum.

## Script Solver (`solve_selector.py`)

Script berikut memparsing bytecode dan mengekstrak kandidat selector.

```python
def extract_selectors():
    try:
        with open('Invitation.txt', 'r') as f:
            bytecode = f.read().strip()
    except FileNotFoundError:
        print("[-] File not found")
        return

    # Bersihkan newline
    bytecode = bytecode.replace('\n', '').replace('\r', '')
    
    print("[*] Scanning for Function Selectors (PUSH4 - 0x63)...")
    
    i = 0
    found_selectors = []
    
    # Loop bytecode, cari opcode 63
    while i < len(bytecode):
        if bytecode[i:i+2] == '63':
            # Ambil 4 byte (8 karakter hex) setelahnya
            selector = bytecode[i+2:i+10]
            if len(selector) == 8:
                found_selectors.append("0x" + selector)
            i += 10 # Skip instruksi PUSH4 + datanya
        else:
            i += 2 # Geser 1 byte

    print(f"[*] Found {len(found_selectors)} candidates.")
    print("[*] Checking relevant selectors...")
    
    # Cetak semua, tapi fokus kita pada selector yang valid nanti
    for s in found_selectors:
        print(f" - {s}")

if __name__ == "__main__":
    extract_selectors()

```

### Output Script

Salah satu selector yang ditemukan adalah: `0xb00d78a5`.

## Database Lookup

Langkah selanjutnya adalah melakukan *Reverse Lookup* selector tersebut di database signature Ethereum.

* **Database URL**: [https://www.4byte.directory](https://www.4byte.directory)
* **Query**: `0xb00d78a5`

**Hasil Pencarian:**

```text
TCP1P_4_Bytes_SigNAtuRe_aS_4n_Invitation_congratz_()

```

Fungsi ini cocok dengan kriteria soal karena diawali dengan string `TCP1P`.

## Formatting Flag

Berdasarkan instruksi pada `101.txt`:

1. **Original**: `TCP1P_4_Bytes_SigNAtuRe_aS_4n_Invitation_congratz_()`
2. Hapus `()`: `TCP1P_4_Bytes_SigNAtuRe_aS_4n_Invitation_congratz_`
3. Ganti `_` pertama dengan `{`: `TCP1P{4_Bytes_SigNAtuRe_aS_4n_Invitation_congratz_`
4. Ganti `_` terakhir dengan `}`: `TCP1P{4_Bytes_SigNAtuRe_aS_4n_Invitation_congratz}`

**FLAG:** `TCP1P{4_Bytes_SigNAtuRe_aS_4n_Invitation_congratz}`
