# WriteUp - math-solver

---

## Overview
- **Judul:** math-solver
- **Kategori:** Reverse Engineering
- **Poin:** 300
- **Author:** maxster
- **Release:** VuwCTF 2025
- **Deskripsi:** Program yang mengeksekusi algoritma *brute-force* besar-besaran untuk mendekripsi *hidden flag*. Operasi ini diklaim memakan waktu miliaran tahun.

---

## Informasi Attachment
**File & Checksec Info:**
```text
 󰋑  ▶  file solver
solver: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=00a2eee43e01b062db005fe3be8349e2fac31b04, for GNU/Linux 3.2.0, stripped

 󰋑  ▶  checksec --file=solver
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/math-solver/solver'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
```

---

## Analisis Decompile (IDA Pro)

### 1. Fungsi Utama (`sub_401790`)
Program memuat sebuah *array* berukuran 121 byte (`byte_4AB0E0`) yang akan dipecahkan. Kode menunjukkan sebuah *nested loop* masif yang berupaya mencari kombinasi nilai yang tepat untuk menggantikan setiap byte `0xFA` dengan nilai antara `0` hingga `248` (`0xF8`).

```c
// Inisialisasi proses cracking
v12 = byte_4AB0E0;
v13 = 0;
do
{
  if ( *v12 == 0xFA ) // 0xFA adalah variabel yang harus di-solve
  {
    for ( i = 248LL; ; i = v22 )
    {
      byte_4AB0E0[v24] = i;
      // Memanggil sub_401B60 sebagai Constraint Checker
      if ( (unsigned int)sub_401B60(...) )
        goto LABEL_19; // Flag Cracked!
//...
```

### 2. Constraint Checker (`sub_401B60`) - The Math Crossword
Fungsi ini membaca memori berukuran 121 byte sebagai sebuah struktur **Grid 11x11**. Array ini merupakan sebuah **Teka-Teki Silang Matematika (Math Crossword)**.

Operator matematika direpresentasikan melalui *byte-code* khusus:
- `0xFA`: Variabel yang tidak diketahui (Target)
- `0xFF`: Sama dengan (`=`)
- `0xFE`: Tambah (`+`)
- `0xFD`: Kurang (`-`)
- `0xFC`: Kali (`*`)
- `0xFB`: Bagi (`/`)
- `0xF9`: Spasi Kosong / *Padding*

Program melakukan pengecekan secara horizontal (selisih indeks `1`, `2`, `3`) dan vertikal (selisih indeks `11`, `22`, `33`) dengan pola: `[Operand 1] [Operator] [Operand 2] [=] [Hasil]`.

---

## Analisis Algoritma Constraint (Ekstraksi Grid)

Mengekstrak 121 byte `byte_4AB0E0` dari memori data (dari `0x4AB0E0` hingga `0x4AB158`) menghasilkan matriks 11x11 sebagai berikut:

```text
[V02]  [-]  [V04]  [=]   47
 [+]         [*]         [*]
  5           1           9
 [=]         [=]         [=]
 105         [V44] [+]  [V46]  [=]  [V48]
             [/]         [/]
[V60]  [-]    1    [=]  [V64]       [V66]  [/]  [V68]  [=]  [V610]
 [+]         [/]         [=]         [*]         [+]
 55         [V84]  [=]  [V86]         5           54
 [=]         [=]         [=]         [=]         [=]
 130          2           2           2           59
```

Berdasarkan matriks tersebut, kita dapat menyusun persamaan dasar dan memecahkannya secara manual/skrip:
1. $V_{0,2} + 5 = 105 \implies V_{0,2} = 100$
2. $V_{0,2} - V_{0,4} = 47 \implies 100 - V_{0,4} = 47 \implies V_{0,4} = 53$
3. $V_{0,4} \times 1 = V_{4,4} \implies V_{4,4} = 53$
4. $17 \times 9 = V_{4,8} \implies V_{4,8} = 153$
5. $V_{4,4} + V_{4,6} = V_{4,8} \implies 53 + V_{4,6} = 153 \implies V_{4,6} = 100$
6. $55 + V_{6,0} = 130 \implies V_{6,0} = 75$
7. $V_{6,0} - 1 = V_{6,4} \implies 75 - 1 = V_{6,4} \implies V_{6,4} = 74$
8. $40 - 38 = V_{10,4} \implies V_{10,4} = 2$
9. $V_{6,4} / V_{8,4} = V_{10,4} \implies 74 / V_{8,4} = 2 \implies V_{8,4} = 37$
10. $39 - V_{8,4} = V_{8,6} \implies 39 - 37 = V_{8,6} \implies V_{8,6} = 2$
11. $V_{4,6} / V_{6,6} = V_{8,6} \implies 100 / V_{6,6} = 2 \implies V_{6,6} = 50$
12. $84 \times V_{10,8} = 168 \implies V_{10,8} = 2$
13. $V_{6,8} / 5 = V_{10,8} \implies V_{6,8} / 5 = 2 \implies V_{6,8} = 10$
14. $54 + V_{6,10} = 59 \implies V_{6,10} = 5$

Semua variabel (awalnya `0xFA`) telah terjawab.

---

## Pembentukan String Flag

Setelah algoritma "Cracked", program melakukan operasi *hashing* (FNV-1a 32-bit) pada seluruh *array* grid yang telah dimodifikasi (121 byte) untuk mencetak flag akhir:

```c
v19 = -2128831035; // 0x811C9DC5
do {
  v20 = (unsigned __int8)*v6++;
  v19 = 16777619 * (v20 ^ v19);
} while ( v8 != v6 );

sub_41B2D0(..., "VuwCTF{m4th_when_%08lX_acr0ss_%02d_is_aw3s0ME}\n", v19, byte_4AB13C + 30);
```

- `%08lX` adalah *Hash FNV-1a* dari grid.
- `%02d` adalah `byte_4AB13C + 30`. `byte_4AB13C` adalah sel $V_{8,4}$ yang bernilai `37`. Jadi `37 + 30 = 67`.

## Solver Script (Python)
Script ini mensimulasikan nilai final grid dan menghasilkan fungsi kalkulasi Hash secara lokal.

```python
#!/usr/bin/env python3

def solve():
    # Grid 11x11 yang telah dipecahkan menggunakan operasi di atas
    grid = [
        0xF9, 0xF9, 100, 0xFD,  53, 0xFF,  47, 0xF9,  17, 0xF9, 0xF9,
        0xF9, 0xF9, 0xFE, 0xF9, 0xFC, 0xF9, 0xF9, 0xF9, 0xFC, 0xF9, 0xF9,
        0xF9, 0xF9,   5, 0xF9,   1, 0xF9, 0xF9, 0xF9,   9, 0xF9, 0xF9,
        0xF9, 0xF9, 0xFF, 0xF9, 0xFF, 0xF9, 0xF9, 0xF9, 0xFF, 0xF9, 0xF9,
          55, 0xF9, 105, 0xF9,  53, 0xFE, 100, 0xFF, 153, 0xF9,  54,
        0xFE, 0xF9, 0xF9, 0xF9, 0xF9, 0xF9, 0xFB, 0xF9, 0xF9, 0xF9, 0xFE,
          75, 0xFD,   1, 0xFF,  74, 0xF9,  50, 0xFB,  10, 0xFF,   5,
        0xFF, 0xF9, 0xF9, 0xF9, 0xFB, 0xF9, 0xFF, 0xF9, 0xFB, 0xF9, 0xFF,
         130, 0xF9,  39, 0xFD,  37, 0xFF,   2, 0xF9,   5, 0xF9,  59,
        0xF9, 0xF9, 0xF9, 0xF9, 0xFF, 0xF9, 0xF9, 0xF9, 0xFF, 0xF9, 0xF9,
          40, 0xFD,  38, 0xFF,   2, 0xF9,  84, 0xFC,   2, 0xFF, 168
    ]

    # Kalkulasi FNV-1a 32-bit Hash
    fnv_hash = 0x811c9dc5
    for b in grid:
        fnv_hash ^= b
        fnv_hash = (fnv_hash * 0x01000193) & 0xffffffff

    # byte_4AB13C (index 92 pada grid, atau V_8_4) adalah 37
    # Second param = 37 + 30 = 67
    param2 = 67

    flag = f"VuwCTF{{m4th_when_{fnv_hash:08X}_acr0ss_{param2:02d}_is_aw3s0ME}}"
    print(flag)

if __name__ == "__main__":
    solve()
```
---

## Flag

```
VuwCTF{m4th_when_3643BAFC_acr0ss_67_is_aw3s0ME}
```
