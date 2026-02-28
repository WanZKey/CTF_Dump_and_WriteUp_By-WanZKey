# WriteUp - Linear

## Overview

* **Judul:** Linear
* **Kategori:** Reverse Engineering
* **Poin:** 200
* **Deskripsi:** you don't even need math tbh.
* **Author:** Unknown

## Attachment

* **Direktori:** `~../Reverse/Linear`
* **File:** `linear`

## Proses Penyelesaian

### 1. Reconnaissance & Behavior Analysis

Langkah pertama adalah melakukan identifikasi jenis file dan proteksi keamanan yang diterapkan pada binary `linear`.

```bash
WanZKey  ～  ~../Reverse/Linear 󱎫 0s 󱑎 16.13
 󰋑  ▶  file linear
linear: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c902392d8ca664cd08dcd1f4f4fdf048d1ce8469, for GNU/Linux 3.2.0, with debug_info, not stripped

WanZKey  ～  ~../Reverse/Linear 󱎫 0s 󱑎 16.13
 󰋑  ▶  checksec --file=linear
[*] '/home/wanzkey/ARIAF CTF 2025/Reverse/Linear/linear'
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       No canary found
    NX:          NX enabled
    PIE:         No PIE (0x400000)
    FORTIFY:     Enabled
    SHSTK:       Enabled
    IBT:         Enabled
    Stripped:    No
    Debuginfo:   Yes

```

Selanjutnya, mencoba menjalankan program untuk memahami input yang diharapkan dan menggunakan `ltrace` untuk melihat library call yang terjadi.

```bash
WanZKey  ～  ~../Reverse/Linear 󱎫 2s 󱑎 16.13
 󰋑  ▶  ./linear
Flag: test
Wrong.

WanZKey  ～  ~../Reverse/Linear 󱎫 1s 󱑎 16.13
 󰋑  ▶  ltrace ./linear
__printf_chk(2, "Flag: ")                               = 6
fgets(Flag: test
"test\n", 256, 0x7dbbc3e158e0)                          = 0x7ffdee34b900
strcspn("test\n", "\n")                                 = 4
strlen("test")                                          = 4
puts("Wrong."Wrong.
)                                  = 7
+++ exited (status 1) +++

```

Program membaca input menggunakan `fgets`, menghitung panjang string dengan `strlen`, dan membandingkannya. Input `test` (4 char) dianggap salah.

Mengecek simbol program karena file tidak di-strip (`not stripped`):

```bash
WanZKey  ～  ~../Reverse/Linear 󱎫 0s 󱑎 16.14
 󰋑  ▶  nm linear
000000000040038c r __abi_tag
0000000000404040 B __bss_start
0000000000404048 b completed.0
0000000000404028 D __data_start
0000000000404028 W data_start
0000000000401350 t deregister_tm_clones
0000000000401340 T _dl_relocate_static_pie
00000000004013c0 t __do_global_dtors_aux
0000000000403e00 d __do_global_dtors_aux_fini_array_entry
0000000000404030 D __dso_handle
0000000000403e08 d _DYNAMIC
0000000000404038 D _edata
0000000000404050 B _end
                 U fgets@GLIBC_2.2.5
00000000004013f8 T _fini
00000000004013f0 t frame_dummy
0000000000403df0 d __frame_dummy_init_array_entry
0000000000402208 r __FRAME_END__
0000000000403fe8 d _GLOBAL_OFFSET_TABLE_
                 w __gmon_start__
0000000000402100 r __GNU_EH_FRAME_HDR
0000000000401000 T _init
0000000000402000 R _IO_stdin_used
                 U __libc_start_main@GLIBC_2.34
00000000004010d0 T main
                 U __printf_chk@GLIBC_2.3.4
                 U puts@GLIBC_2.2.5
0000000000401380 t register_tm_clones
00000000004012f0 t set_fast_math
0000000000401310 T _start
0000000000404040 B stdin@GLIBC_2.2.5
                 U strcspn@GLIBC_2.2.5
                 U strlen@GLIBC_2.2.5
0000000000404038 D __TMC_END__

```

### 2. Reverse Engineering (IDA Pro)

Analisis mendalam dilakukan menggunakan IDA Pro. Berikut adalah hasil dekompilasi fungsi utama.

**Main Function:**

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v6; // rax
  bool v7; // cf
  __m256 v60; // [rsp+0h] [rbp-110h] BYREF

  __asm
  {
    vpxor   xmm0, xmm0, xmm0
    vmovdqa [rsp+110h+var_110], ymm0
    vmovdqa [rsp+110h+var_F0], ymm0
    vmovdqa [rsp+110h+var_D0], ymm0
    vmovdqa [rsp+110h+var_B0], ymm0
    vmovdqa [rsp+110h+var_90], ymm0
    vmovdqa [rsp+110h+var_70], ymm0
    vmovdqa [rsp+110h+var_50], ymm0
    vmovdqa [rsp+110h+var_30], ymm0
    vzeroupper
  }
  __printf_chk(2LL, "Flag: ", envp, *(double *)&_XMM0);
  if ( fgets((char *)&v60, 256, _bss_start) )
  {
    *((_BYTE *)v60.m256_f32 + strcspn((const char *)&v60, "\n")) = 0;
    v6 = strlen((const char *)&v60);
    v7 = v6 < 0x20;
    if ( v6 == 32 )
    {
      __asm
      {
        vpmovzxbd ymm0, qword ptr [rsp+110h+var_110]
        vmovaps ymm2, cs:ymmword_402040
        vmovaps ymm1, cs:ymmword_402060
      }
      _RAX = *(_OWORD *)&v60.m256_f32[2];
      __asm { vcvtdq2ps ymm0, ymm0 }
      _RCX = *(_QWORD *)&v60.m256_f32[6];
      __asm
      {
        vfmadd132ps ymm0, ymm1, ymm2
        vfmadd213ps ymm0, ymm0, cs:ymmword_402080
        vmulps  ymm0, ymm0, ymm0
        vextractf128 xmm3, ymm0, 1
        vaddps  xmm0, xmm3, xmm0
        vmovhlps xmm3, xmm0, xmm0
        vaddps  xmm3, xmm3, xmm0
        vshufps xmm0, xmm3, xmm3, 55h ; 'U'
        vaddps  xmm0, xmm0, xmm3
        vcomiss xmm0, cs:dword_402004
      }
      if ( v7 )
      {
        __asm
        {
          vmovq   xmm0, rax
          vpmovzxbd ymm0, xmm0
          vcvtdq2ps ymm0, ymm0
          vfmadd132ps ymm0, ymm1, ymm2
          vfmadd213ps ymm0, ymm0, cs:ymmword_4020A0
          vmulps  ymm0, ymm0, ymm0
          vextractf128 xmm3, ymm0, 1
          vaddps  xmm0, xmm3, xmm0
          vmovhlps xmm3, xmm0, xmm0
          vaddps  xmm3, xmm3, xmm0
          vshufps xmm0, xmm3, xmm3, 55h ; 'U'
          vaddps  xmm0, xmm0, xmm3
          vcomiss xmm0, cs:dword_402004
          vmovq   xmm0, rdx
          vpmovzxbd ymm0, xmm0
          vcvtdq2ps ymm0, ymm0
          vfmadd132ps ymm0, ymm1, ymm2
          vfmadd213ps ymm0, ymm0, cs:ymmword_4020C0
          vmulps  ymm0, ymm0, ymm0
          vextractf128 xmm3, ymm0, 1
          vaddps  xmm0, xmm3, xmm0
          vmovhlps xmm3, xmm0, xmm0
          vaddps  xmm3, xmm3, xmm0
          vshufps xmm0, xmm3, xmm3, 55h ; 'U'
          vaddps  xmm0, xmm0, xmm3
          vcomiss xmm0, cs:dword_402004
          vmovq   xmm0, rcx
          vpmovzxbd ymm0, xmm0
          vcvtdq2ps ymm0, ymm0
          vfmadd132ps ymm0, ymm1, ymm2
          vfmadd213ps ymm0, ymm0, cs:ymmword_4020E0
          vmulps  ymm0, ymm0, ymm0
          vextractf128 xmm1, ymm0, 1
          vaddps  xmm0, xmm1, xmm0
          vmovhlps xmm1, xmm0, xmm0
          vaddps  xmm1, xmm1, xmm0
          vshufps xmm0, xmm1, xmm1, 55h ; 'U'
          vaddps  xmm0, xmm0, xmm1
          vcomiss xmm0, cs:dword_402004
          vzeroupper
        }
        puts("Correct!");
        return 0;
      }
      __asm { vzeroupper }
    }
    puts("Wrong.");
  }
  return 1;
}

```

**Konstanta (.rodata):**

```asm
.rodata:0000000000402004 dword_402004    dd 3D4CCCCDh             ; Threshold (approx 0.05)
.rodata:0000000000402040 ymmword_402040  ymmword D7B3DD3FBD1B0F40F304B53FDA0F4940F204353FBC1BCF3F54F82D4067C4133F ; (A)
.rodata:0000000000402060 ymmword_402060  ymmword 000028C285EB55410000E0C0CDCCC7420000003F333353C0B81ED5400000A0BF ; (B)
.rodata:0000000000402080 ymmword_402080  ymmword 696E07C6E09ADBC68A4743C6F329BCC7C68946C5B4DB65C6EA3644C7BC0598C5 ; Chunk 1 (C)
.rodata:00000000004020A0 ymmword_4020A0  ymmword 8FCC21C65A266CC6E83922C6FFFDBFC7661F8FC5713100C789729AC79FB38BC5 ; Chunk 2 (C)
.rodata:00000000004020C0 ymmword_4020C0  ymmword F1A46AC6F2ED8EC7A0BAAFC6F0F61AC88F7BC6C53370B8C64BCF98C67C2472C5 ; Chunk 3 (C)
.rodata:00000000004020E0 ymmword_4020E0  ymmword 93AF8DC6BDB193C76BEDA5C6F0F61AC856A1A1C5D9A1D4C6FB88A3C7B3189DC5 ; Chunk 4 (C)

```

**Analisis Logika:**
Program menggunakan instruksi AVX (Advanced Vector Extensions) untuk memproses input 32 karakter yang dibagi menjadi 4 chunk (masing-masing 8 byte).

1. **Load Input**: Input dikonversi dari integer (char) ke floating point (`vcvtdq2ps`).
2. **Operasi Linear**: Dilakukan operasi FMA (Fused Multiply-Add) menggunakan `vfmadd132ps` yang merepresentasikan `(Input * A + B)`.
3. **Kuadrat & Konstanta**: Hasil operasi sebelumnya dikuadratkan dan ditambah konstanta C per-chunk (`vfmadd213ps`), menghasilkan persamaan `((Input * A + B)^2 + C)`.
4. **Validasi**: Hasil akhir dikuadratkan lagi (`vmulps`) dan dijumlahkan secara horizontal, lalu dibandingkan dengan nilai ambang batas (`0.05`). Tujuannya adalah mencari input yang membuat hasil persamaan ini mendekati 0.

Karena operasi dilakukan secara element-wise (setiap karakter diproses independen pada posisi vektornya masing-masing), kita bisa melakukan brute-force per karakter tanpa perlu membalikkan matriks.

## Solver Script & Execution

Script Python berikut dibuat untuk melakukan brute-force karakter ASCII (32-126) yang meminimalkan hasil persamaan linear tersebut.

```python
import struct

# Constants from Binary Analysis (IDA Pro Data)
# A = ymmword_402040 (Multipliers)
A_hex = "D7B3DD3FBD1B0F40F304B53FDA0F4940F204353FBC1BCF3F54F82D4067C4133F"
# B = ymmword_402060 (Addends)
B_hex = "000028C285EB55410000E0C0CDCCC7420000003F333353C0B81ED5400000A0BF"

# C = Constant per chunk (Offsets)
C_hexs = [
    "696E07C6E09ADBC68A4743C6F329BCC7C68946C5B4DB65C6EA3644C7BC0598C5", # Chunk 1
    "8FCC21C65A266CC6E83922C6FFFDBFC7661F8FC5713100C789729AC79FB38BC5", # Chunk 2
    "F1A46AC6F2ED8EC7A0BAAFC6F0F61AC88F7BC6C53370B8C64BCF98C67C2472C5", # Chunk 3
    "93AF8DC6BDB193C76BEDA5C6F0F61AC856A1A1C5D9A1D4C6FB88A3C7B3189DC5"  # Chunk 4
]

def hex_to_floats(h):
    # Convert hex string to 8 floats (Little Endian)
    return struct.unpack('<8f', bytes.fromhex(h))

# Load Global Constants
A = hex_to_floats(A_hex)
B = hex_to_floats(B_hex)

flag = ""

print("[*] Cracking Linear Equation...")

# Process each of the 4 chunks
for chunk_idx, C_hex in enumerate(C_hexs):
    C = hex_to_floats(C_hex)
    chunk_str = ""
    
    # Process each of the 8 characters in the chunk
    for i in range(8):
        best_char = '?'
        min_diff = float('inf')
        
        # Brute force printable ASCII to find the one that minimizes the equation
        for char_code in range(32, 127): 
             # Logic from assembly: vfmadd132ps (dest*src3 + src2) -> (char * A + B)
             val = (char_code * A[i] + B[i])
             
             # Equation: (val^2) + C
             # We want this to be 0 (or cancel out, but usually 0 per term)
             result = (val * val) + C[i]
             
             # Check absolute value (distance to 0)
             if abs(result) < min_diff:
                 min_diff = abs(result)
                 best_char = chr(char_code)
        
        chunk_str += best_char
    
    print(f"Chunk {chunk_idx+1}: {chunk_str}")
    flag += chunk_str

print(f"\n[+] Flag Found: {flag}")

```

**Output Terminal Solver:**

```bash
 󰋑  ▶  ./solver.py
[*] Cracking Linear Equation...
Chunk 1: NETCOMP{
Chunk 2: S1MD_rev
Chunk 3: _so_pa1n
Chunk 4: ful_ehh}

[+] Flag Found: NETCOMP{S1MD_rev_so_pa1nful_ehh}

```

## Flag

```
NETCOMP{S1MD_rev_so_pa1nful_ehh}

```
