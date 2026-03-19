# WriteUp - potato_cloner

---

## Overview
- **Judul:** potato_cloner
- **Kategori:** Reverse Engineering
- **Poin:** 350
- **Author:** Aterlone
- **Release:** Reverse Engineering Meetup
- **Deskripsi:** I love potatoes, but only have one. My father found a found a way to clone them, and taught me the ways. Infinite potatoes for me!

---

## Informasi Attachment
**Struktur Direktori:**
```text
.
└── potato_cloner (ELF 64-bit executable)
```

**File & Checksec Info:**
```text
 WanZKey  ～  ~../Reverse Engineering/potato_cloner
 󰋑  ▶  file potato_cloner
potato_cloner: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=31afa434d00fd228667b08cbc7de2cfca036bd22, for GNU/Linux 3.2.0, stripped

 󰋑  ▶  checksec --file=potato_cloner
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/potato_cloner/potato_cloner'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

---

## Analisis Decompile (IDA Pro)

### 1. Fungsi main
Fungsi utama menggunakan `fork()` untuk membagi eksekusi menjadi dua proses: Parent dan Child.

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // [rsp+1Ch] [rbp-24h] BYREF
  __pid_t v8; // [rsp+3Ch] [rbp-4h]

  v8 = fork();
  v7 = getpid();
  v6 = getppid();
  if ( v8 ) // Parent Process
  {
    if ( v8 != -1 )
    {
      wait(0LL);
      printf("Enter the potato's ID:");
      __isoc99_scanf("%d", &v3);
    }
  }
  else // Child Process
  {
    printf("Enter the cloned potato's ID: ");
    __isoc99_scanf("%d", &v3);
  }

  if ( !v8 && v7 == v3 ) // Child check
  {
    puts("Hello, I am the cloned potato.");
    sub_12CF(); // Lokasi Flag Asli
    exit(0);
  }
  if ( v8 && v7 == v3 ) // Parent check
  {
    printf("Hello, I am the potato, and the cloned potato's id is %d.\n", v8);
    sub_122A(); // Decoy / Fake Flag
    exit(0);
  }
  puts("Please pass the potato's ID >:(.");
  exit(0);
}
```

### 2. Fungsi sub_11B9 (Logika Matematika)
Fungsi ini dipanggil di akhir proses dekripsi untuk mengubah nilai byte hasil XOR.

```c
__int64 __fastcall sub_11B9(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+Ch] [rbp-Ch]
  for ( i = 0; i <= 14; ++i )
  {
    v2 = *(_DWORD *)(4LL * i + a1) / 2;
    for ( j = 0; ; ++j )
    {
      result = (unsigned int)j;
      if ( j >= v2 ) break;
      --*(_DWORD *)(4LL * i + a1);
    }
  }
  return result;
}
```
**Analisis Logika:** Fungsi ini melakukan $val = val - \lfloor val / 2 \rfloor$. Secara matematis, ini sama dengan melakukan operasi **$\lceil val / 2 \rceil$** (pembulatan ke atas hasil bagi 2).

### 3. Fungsi sub_12CF (Flag Generator)
Fungsi ini menggunakan teknik *overlapping writes* pada stack untuk menyembunyikan data mentah.

**Assembly View:**
```nasm
.text:00000000000012E8  mov  rax, 6D754F4B5D050107h
.text:00000000000012F2  mov  [rbp+var_1F], rax        ; Menulis 8 byte di offset 0
.text:00000000000012F6  mov  rax, 516171154D4D616Dh
.text:0000000000001300  mov  [rbp+var_1F+7], rax      ; Menulis 8 byte di offset 7 (Overlap 1 byte)
```

---

## Proses Penyelesaian Step-by-Step

1.  **Analisis Forking:** Program membagi diri menjadi dua. Bagian yang berisi flag asli berada di Child Process (`v8 == 0`), yang memanggil fungsi `sub_12CF`.
2.  **Ekstraksi Byte Mentah:** Dari assembly `sub_12CF`, kita mendapatkan dua nilai 64-bit yang ditulis secara bertumpuk di memori.
    - Nilai 1 (Little Endian): `07 01 05 5D 4B 4F 55 6D`
    - Nilai 2 (Little Endian): `6D 61 4D 4D 15 71 61 51`
    - Gabungan (Overlap pada byte `0x6D`): `07 01 05 5D 4B 4F 55 6D 61 4D 4D 15 71 61 51`
3.  **Reverse Algoritma:**
    - Setiap byte di-XOR dengan `0xAB`.
    - Hasilnya dimasukkan ke fungsi `sub_11B9` (pembagian dua dengan pembulatan ke atas).
4.  **Eksekusi Solver:** Membuat script untuk mengotomatisasi perhitungan tersebut untuk mendapatkan string flag.

---

## Script Solver & Output Terminal

**solver.py**
```python
#!/usr/bin/env python3

def solve():
    # Data dari sub_12CF (Child Process)
    # 0x6D754F4B5D050107 overlap dengan 0x516171154D4D616D pada indeks ke-7
    enc_bytes = [
        0x07, 0x01, 0x05, 0x5d, 0x4b, 0x4f, 0x55, # 7 byte pertama
        0x6d, # byte overlap
        0x61, 0x4d, 0x4d, 0x15, 0x71, 0x61, 0x51  # 7 byte sisanya
    ]
    
    flag = ""
    for b in enc_bytes:
        # Step 1: XOR dengan 0xAB
        temp = b ^ 0xAB
        # Step 2: Implementasi sub_11B9 (ceil(temp / 2))
        res = temp - (temp // 2)
        flag += chr(res)
        
    print(f"Flag: {flag}")

if __name__ == "__main__":
    solve()
```

**Output Terminal Solver:**
```text
 WanZKey  ～  ~../Reverse Engineering/potato_cloner
 󰋑  ▶  python3 solver.py
Flag: VUW{process_me}
```

---

## Output Terminal Program (Validation)
```text
 WanZKey  ～  ~../Reverse Engineering/potato_cloner
 󰋑  ▶  ./potato_cloner
Enter the cloned potato's ID: [PID_CHILD]
Hello, I am the cloned potato.
VUW{process_me}
```

---

## Flag
**`VUW{process_me}`**


