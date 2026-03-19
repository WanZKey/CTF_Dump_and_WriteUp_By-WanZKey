# WriteUp - no_debugging

---

## Overview
- **Judul:** no_debugging
- **Kategori:** Reverse Engineering
- **Poin:** 300
- **Author:** Aterlone
- **Release:** Site Release
- **Deskripsi:** You’ve stumbled upon a mysterious program called no_debug. It seems simple at first, but things quickly get interesting. The program checks some strange condition and decides whether to reveal the real flag or just a fake one. Good Luck Debugger!

---

## Informasi Attachment
**Struktur Direktori:**
```text
.
└── no_debug (ELF 64-bit executable)
```

**File & Checksec Info:**
```text
 󰋑  ▶  file no_debug
no_debug: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=b4c3e7c6da42ec9452c376bf254072314cb86558, for GNU/Linux 4.4.0, stripped

 󰋑  ▶  checksec --file=no_debug
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/no_debugging/no_debug'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

---

## Analisis Decompile (IDA Pro)

### 1. Fungsi main
Fungsi `main` memeriksa kondisi argumen (argc/argv) dan memanggil fungsi pengecekan debugger. Bergantung pada hasilnya, program akan memuat array byte yang berbeda untuk didekripsi.

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v4, v5, v6;
  unsigned __int64 v7 = __readfsqword(0x28u);

  // a1 adalah argc, a2 adalah argv. 
  // Memeriksa apakah argc memadai dan argv[2][1] memenuhi kondisi matematika.
  if ( 22 * (_DWORD)a1 == a2[2][1] ) 
  {
    if ( (unsigned int)sub_11A9(a1) ) // Pengecekan Debugger
    {
      // [REAL FLAG DATA] - Dimuat jika debugger terdeteksi
      v4 = 0x6B211C0E192D2F0CLL;
      v5 = 0x3F2E05693705292ELL;
      v6 = 0x273D3B6B3C0532LL;
    }
    else
    {
      // [FAKE FLAG DATA]
      v4 = 0x1C211C0E192D2F0CLL;
      v5 = 0x3D3B361C053F313BLL;
      LOWORD(v6) = 39;
    }
    sub_129A(&v4, 90LL); // Fungsi dekripsi & print dengan key 90 (0x5A)
  }
  else
  {
    // [FAKE FLAG DATA] - Dimuat jika argumen tidak sesuai
    v4 = 0x1C211C0E192D2F0CLL;
    v5 = 0x3D3B361C053F313BLL;
    LOWORD(v6) = 39;
    sub_129A(&v4, 90LL);
  }
  printf("Aw come on, do the first step already ;-;.");
  return 0LL;
}
```

### 2. Fungsi sub_11A9 (Anti-Debugging)
Fungsi ini membaca `/proc/self/status` dan mencari baris `TracerPid:`. Teknik ini digunakan untuk mendeteksi apakah program sedang dijalankan di bawah pengawasan *debugger* (seperti GDB atau `strace`).

```c
_BOOL8 sub_11A9()
{
  // ...
  stream = fopen("/proc/self/status", "r");
  if ( !stream ) return 0LL;

  while ( fgets(s1, 4096, stream) )
  {
    if ( !strncmp(s1, "TracerPid:", 0xAuLL) ) // Cek PID dari Tracer
    {
      v1 = atoi(v4);
      fclose(stream);
      return v1 != 0; // Return True jika sedang di-debug (TracerPid != 0)
    }
  }
  // ...
}
```

### 3. Fungsi sub_129A (XOR Decryptor)
Fungsi ini mengambil array byte (`a1`) dan sebuah key XOR (`a2`), kemudian melakukan XOR per byte hingga menemukan null terminator (`0x00`), lalu mencetaknya.

```c
unsigned __int64 __fastcall sub_129A(__int64 a1, char a2)
{
  // a2 pada main() diisi dengan 90LL (0x5A)
  for ( i = 0; *(_BYTE *)(i + a1); ++i )
    s[i] = *(_BYTE *)(i + a1) ^ a2;
  s[i] = 0;
  puts(s);
  // ...
}
```

---

## Proses Penyelesaian Step-by-Step

1. **Memahami Alur Eksekusi:** Normalnya, jika dijalankan tanpa *debugger* atau argumen yang spesifik, program akan mendekripsi *Fake Flag*. Agar *Real Flag* dieksekusi, dua kondisi harus terpenuhi: argumen terminal yang tepat dan program harus sedang di-debug.
2. **Static Analysis (Bypass Execution):** Karena kita sudah memiliki data mentah dari *Real Flag* langsung dari dekompilasi IDA, kita tidak perlu repot melakukan teknik *dynamic bypass* atau mencari nilai `argv` yang valid. Kita cukup melakukan ekstraksi data tersebut secara statis.
3. **Ekstraksi Data Hex (Little Endian):**
   - `v4` = `0x6B211C0E192D2F0C` $\to$ `0C 2F 2D 19 0E 1C 21 6B`
   - `v5` = `0x3F2E05693705292E` $\to$ `2E 29 05 37 69 05 2E 3F`
   - `v6` = `0x273D3B6B3C0532` $\to$ `32 05 3C 6B 3B 3D 27` (7 byte)
4. **Dekripsi:** Kunci dekripsi dikirimkan sebagai parameter kedua pada `sub_129A`, yaitu `90` (atau `0x5A` dalam hex). Setiap byte array di atas akan di-XOR dengan `0x5A`.

---

## Script Solver & Output Terminal

**solver.py**
```python
#!/usr/bin/env python3
import struct

def solve():
    # Data dari blok REAL FLAG (v4, v5, v6)
    v4 = 0x6B211C0E192D2F0C
    v5 = 0x3F2E05693705292E
    v6 = 0x273D3B6B3C0532 # 7 bytes

    # Packing data menjadi byte array dengan format Little Endian (<)
    # v6 dipack sebagai QWORD (8 bytes) lalu diambil 7 byte pertamanya agar sesuai
    raw_bytes = struct.pack('<Q', v4) + struct.pack('<Q', v5) + struct.pack('<Q', v6)[:7]
    
    key = 90 # 0x5A
    flag = ""
    
    # Decrypt dengan operasi XOR
    for b in raw_bytes:
        flag += chr(b ^ key)
        
    print(f"Flag: {flag}")

if __name__ == "__main__":
    solve()
```

**Output Terminal Solver:**
```text
 WanZKey  ～  ~../Reverse Engineering/no_debugging
 󰋑  ▶  python3 solver.py
Flag: VuwCTF{1ts_m3_teh_f1ag}
```

---

## Flag

```
VuwCTF{1ts_m3_teh_f1ag}
```
