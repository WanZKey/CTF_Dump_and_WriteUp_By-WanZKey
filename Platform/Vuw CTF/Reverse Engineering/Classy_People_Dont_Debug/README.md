# WriteUp - Classy_People_Dont_Debug

---

## Overview
- **Judul:** Classy_People_Dont_Debug
- **Kategori:** Reverse Engineering
- **Poin:** 450
- **Author:** Aterlone
- **Deskripsi:** Program yang dilengkapi dengan berbagai teknik *anti-debugging* yang agresif dan melakukan obfuskasi pada operasi matematika dasar untuk menyembunyikan algoritma dekripsi flag.

---

## Analisis Anti-Debugging
Program ini mencegah *dynamic analysis* menggunakan:
1.  **`ptrace(PTRACE_TRACEME)`**: Pengecekan aktif debugger.
2.  **Pengecekan TracerPid**: Melalui pembacaan `/proc/<pid>/status` menggunakan proses `fork()`.
3.  **Timing Check**: Menghitung delta waktu eksekusi menggunakan `clock_gettime`.
4.  **Process Name Scan**: Memeriksa nama proses parent (`gdb`, `ida`, `strace`, dll) di `/proc/ppid/comm`.
5.  **Memory Maps Scan**: Memeriksa injeksi library (`frida`, `libasan`) dari `/proc/self/maps`.

Oleh karena itu, penyelesaian menggunakan *static analysis* mutlak diperlukan pada blok algoritma generator flag.

---

## Deobfuskasi Fungsi Matematika
Fungsi dekripsi utama memanggil 5 sub-rutin misterius yang terlihat rumit, namun setelah dianalisis strukturnya, fungsi-fungsi tersebut merupakan pembungkus (*wrapper*) dari operasi aritmatika dan logika dasar:
- **`sub_38C0`**: Melakukan penambahan berulang dalam sebuah loop $\implies$ **Perkalian (`*`)**
- **`sub_3936`**: Manipulasi `a2` dan `a3` dengan kompensasi penambahan/pengurangan $\implies$ **Penjumlahan (`+`)**
- **`sub_39C0`**: Pengurangan berulang hingga nilainya kurang dari pembagi $\implies$ **Modulo (`%`)**
- **`sub_3AAA`**: Operasi logika perbandingan ketidaksamaan (`!=`) pada ekstraksi bit individual $\implies$ **Bitwise XOR (`^`)**
- **`sub_3BEC`**: Evaluasi pembalikan nilai dan jarak $\implies$ **Pengurangan (`-`)**

Dengan mengganti fungsi-fungsi obfuskasi di dalam `sub_2F88` dengan operator asli, alur dekripsi dapat disederhanakan menjadi rumus matematika linier untuk diekstrak per karakternya:
- $v_{19} = 193 + (i \times 13)$
- $v_{20} = 163 + (i \times 5)$
- $v_{21} = \text{byte\_4120}[i \pmod{64}]$
- $\text{Expected Char} = \text{byte\_4180}[i \times 6] \oplus v_{19} \oplus v_{20} \oplus v_{21}$

---

## Solver Script (Python)
Script ini secara otomatis mereplikasi algoritma generator karakter tanpa perlu melakukan bypass debugger.

```python
#!/usr/bin/env python3

def solve():
    # Array data diekstrak dari .rodata:0000000000004120
    byte_4120 = bytes.fromhex(
        "10 22 33 44 55 66 77 88 90 AB BC CD DE EF FA 0F "
        "11 21 31 41 51 61 71 81 92 A2 B2 C2 D2 E2 F2 02 "
        "13 23 33 43 53 63 73 83 94 A4 B4 C4 D4 E4 F4 04 "
        "15 25 35 45 55 65 75 85 96 A6 B6 C6 D6 E6 F6 06 "
        "C1 A3 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    )

    # Array target diekstrak dari .rodata:0000000000004180
    byte_4180 = bytes.fromhex(
        "24 41 44 64 45 5B 31 56 22 69 5D 58 32 16 7F 5D 5E 90 "
        "5D 0B 5C 58 54 71 43 5A BA 5B 66 58 9E BC 4C 58 5A 6B "
        "C2 52 5B 6F 79 03 24 63 5F 69 03 19 17 4D 6B 1D 6F A5 "
        "3F 58 6C 60 44 A2 53 64 60 44 A2 62 18 6D 43 67 61 76 "
        "3F 61 65 7F 60 B3 0D 66 8E 6F B2 A1 05 84 69 A4 B3 FE "
        "16 61 B4 A3 FE D5 00 45 A4 F7 E6 F9 3E 94 E7 FE F9 98 "
        "38 FA F9 BC 9B 7E 9F E1 BC 9B 7E 76 A3 BE BD 70 44 71 "
        "98 BF 42 5A 77 00 D1 79 5B 60 71 8E 0F 41 76 87 8C 95 "
        "2F 86 87 F4 85 AA B2 95 E2 8B 88 89 EB EA CB 88 89 6E "
        "BD C3 88 89 6E 36 8F ED 8E 13 05 10 9F 8E 03 0D 10 03 "
        "BF 09 0B 26 31 5C 5B 03 16 01 5C 57 4C 05 04 53 42 99"
    )

    flag = ""
    for i in range(33):
        # Mengeksekusi rumus deobfuskasi dengan masking 8-bit
        v19 = (193 + i * 13) & 0xFF
        v20 = (163 + i * 5) & 0xFF
        v21 = byte_4120[i % 64]
        
        # Array byte_4180 dilompati dengan kelipatan 6
        target_byte = byte_4180[i * 6]
        
        # Dekripsi dengan XOR
        char_val = (target_byte ^ v19 ^ v20 ^ v21) & 0xFF
        flag += chr(char_val)
        
    print(flag)

if __name__ == "__main__":
    solve()
```

---

## Flag

```
VuwCTF{very_classy_d0'nt_6ou_s33}

```
