# Classy_People_Dont_Debug

## Overview

| Field      | Detail                          |
|------------|---------------------------------|
| **Judul**  | Classy_People_Dont_Debug        |
| **Kategori** | Reverse Engineering           |
| **Poin**   | 450                             |
| **Author** | Aterlone                        |
| **Event**  | VuwCTF 2025                     |
| **Solves** | 0 (First Blood: Han Shangyan Solo Run / Han Shangyan) |

**Deskripsi:**
> Classy people never debug. Debugging is for people who aren't skilled enough to analyse binaries statically. It is not a useful skill to have.
> "I'm going to dynamically analyse this anyway" - famous last words.
> Just for clarification, static analysis is the intended way to solve the challenge.

---

## Reconnaissance

### File Info

```
❯ file Classy
Classy: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=6b39b10ca7cfedd6d0d7c2c3cb28147e69728295,
for GNU/Linux 4.4.0, stripped
```

```
❯ checksec --file=Classy
[*] 'Classy'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

### strace

```
❯ strace ./Classy
...
prctl(PR_SET_DUMPABLE, SUID_DUMP_DISABLE) = 0
ptrace(PTRACE_TRACEME)                  = -1 EPERM (Operation not permitted)
exit_group(1)                           = ?
+++ exited with 1 +++
```

**Observasi kritis:** Program langsung exit ketika `ptrace(PTRACE_TRACEME)` gagal — yang terjadi karena strace sendiri sudah attach ke proses. Ini adalah layer anti-debug pertama.

Library yang digunakan: `libssl.so.3`, `libcrypto.so.3`, `libstdc++.so.6` — mengindikasikan penggunaan SHA256 dan C++.

---

## Analisis Decompile (IDA Pro)

### start

```c
void __fastcall __noreturn start(__int64 a1, __int64 a2, void (*a3)(void))
{
  __int64 v3; // rax
  int v4; // esi
  __int64 v5; // [rsp-8h] [rbp-8h] BYREF
  char *retaddr; // [rsp+0h] [rbp+0h] BYREF

  v4 = v5;
  v5 = v3;
  _libc_start_main(main, v4, &retaddr, 0LL, 0LL, a3, &v5);
  __halt();
}
```

---

### main

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // ebx
  bool v4; // al
  // ... (variables omitted)

  v20 = __readfsqword(0x28u);
  qword_6380 = 16329LL;
  prctl(4, 0LL);                          // PR_SET_DUMPABLE = 0 -> disable core dump
  sub_2369(&dword_0, qword_6380, v19);    // SHA256 hash sesuatu

  if ( ptrace(PTRACE_TRACEME, 0LL, 0LL, 0LL) == -1 )
    return 1;                             // Exit jika sudah di-debug

  v17 = getpid();
  sub_26B7(v17);                          // Fork watchdog anti-debug

  v4 = (unsigned __int8)sub_243B() || (unsigned __int8)sub_2584();
  if ( v4 || (unsigned __int8)sub_2991() != 1 )
  {
    sub_33DC();
    return 1;
  }

  std::string::basic_string(v18);
  std::operator<<<std::char_traits<char>>(&std::cout, "Enter flag: ");
  std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v18);

  if ( std::string::size(v18) == 33 )
  {
    if ( (unsigned __int8)sub_28EA()
      || (!(unsigned int)sub_2A1B() && !(unsigned int)sub_2BBD() ? (v6=0) : (v6=1), v6) )
    {
      sub_33DC();
      v3 = 1;
    }
    else
    {
      for ( i = 0; i <= 32; ++i )
      {
        v11 = byte_4180[6 * i];
        if ( (unsigned int)sub_2BBD() ) { v3=0; goto LABEL_31; }
        v12 = sub_2F88((unsigned int)i, 0LL, v11);
        if ( (unsigned int)sub_2BBD() ) { v3=0; goto LABEL_31; }
        v13 = 0;
        sub_37BE(v15, v12);
        v7 = (char *)std::string::operator[](v18, i);
        sub_37BE(v14, (unsigned int)*v7);
        sub_3BEC(&v13, v14, v15);
        if ( (unsigned int)sub_2BBD() ) { v3=0; goto LABEL_31; }
        if ( (unsigned int)sub_3926(&v13) )
        {
          // Print "Wrong!" dan exit
          v3 = 0;
          goto LABEL_31;
        }
      }
      // Print "Correct!"
      v3 = 0;
    }
  }
  // ...
}
```

**Observasi:** Flag harus 33 karakter. Loop mengecek setiap karakter dengan `sub_2F88`, lalu `sub_3BEC` membandingkan hasilnya.

---

### sub_33DC (output ketika anti-debug triggered)

```c
int sub_33DC()
{
  return printf("Static analysis above all!\n ");
}
```

---

### Anti-Debug Layer 1 — sub_26B7 (Fork Watchdog)

```c
unsigned __int64 __fastcall sub_26B7(unsigned int a1)
{
  // ...
  if ( !fork() )
  {
    // Child process:
    for ( i = 0; ; ++i )
    {
      if ( i > 49 ) goto LABEL_7;
      if ( !ptrace(PTRACE_ATTACH, a1, 0LL, 0LL) ) break;  // Coba attach ke parent
      usleep(0x4E20u);
    }
    waitpid(a1, 0LL, 0);
    ptrace(PTRACE_DETACH, a1, 0LL, 0LL);
    while ( 1 )
    {
LABEL_7:
      // Baca /proc/PID/status setiap 100ms
      snprintf(s, 0x40uLL, "/proc/%d/status", a1);
      stream = fopen(s, "r");
      if ( !stream ) _exit(0);
      // Cari field "TracerPid:"
      do {
        if ( !fgets(s1, 256, stream) ) goto LABEL_13;
      } while ( strncmp(s1, "TracerPid:", 0xAuLL) );
      if ( atoi(v7) ) v2 = 1;   // Jika TracerPid != 0 -> ada debugger!
LABEL_13:
      fclose(stream);
      if ( v2 ) { kill(a1, 9); _exit(1); }  // Kill parent!
      usleep(0x186A0u);
    }
  }
}
```

Fork child process yang terus memonitor `/proc/PID/status`. Jika `TracerPid != 0`, langsung `kill(parent, SIGKILL)`.

---

### Anti-Debug Layer 2 — sub_28EA (Timing Check)

```c
bool sub_28EA()
{
  // ...
  clock_gettime(1, &tp);
  v1 = 0;
  for ( i = 0; i <= 9999; ++i )
    v1 += i;
  clock_gettime(1, &v4);
  return 1000000000*(v4.tv_sec-tp.tv_sec) + v4.tv_nsec-tp.tv_nsec > 20000000;
}
```

Jika loop sederhana 10000 iterasi memakan waktu lebih dari **20ms** → terdeteksi debugger (breakpoint/single-step).

---

### Anti-Debug Layer 3 — sub_2A1B (Parent Process Check)

```c
__int64 sub_2A1B()
{
  // ...
  v0 = getppid();
  snprintf(s, 0x100uLL, "/proc/%d/comm", v0);
  stream = fopen(s, "r");
  if ( stream )
  {
    if ( fgets(haystack, 256, stream) )
    {
      needle[0] = "gdb";
      needle[1] = "pwndbg";
      needle[2] = "lldb";
      needle[3] = "ida";
      needle[4] = "r2";
      needle[5] = "radare";
      needle[6] = "frida";
      needle[7] = "strace";
      needle[8] = 0LL;
      for ( i = 0; needle[i]; ++i )
        if ( strstr(haystack, needle[i]) )
        {
          fclose(stream);
          return 1LL;
        }
    }
    fclose(stream);
  }
  return 0LL;
}
```

Cek `/proc/PPID/comm` apakah parent process adalah debugger yang dikenal.

---

### Anti-Debug Layer 4 — sub_2584 (Memory Map Check)

```c
__int64 sub_2584()
{
  // ...
  stream = fopen("/proc/self/maps", "r");
  while ( fgets(haystack, 512, stream) )
  {
    if ( strstr(haystack, "libfrida")
      || strstr(haystack, "frida")
      || strstr(haystack, "gadget")
      || strstr(haystack, "libasan") )
    {
      fclose(stream);
      return 1LL;
    }
  }
  // ...
}
```

Scan `/proc/self/maps` untuk deteksi Frida, gadget injection, atau AddressSanitizer.

---

### Anti-Debug Layer 5 — sub_2BBD (Timing Check Ketat)

```c
_BOOL8 sub_2BBD()
{
  // ...
  clock_gettime(1, &tp);
  v1 = 0;
  for ( i = 0; i <= 999; ++i )
    v1 += i;
  clock_gettime(1, &v4);
  return 1000000000*(v4.tv_sec-tp.tv_sec) + v4.tv_nsec-tp.tv_nsec > 100000000;
}
```

Dipanggil berkali-kali di dalam loop verifikasi flag. Threshold lebih ketat: **100ms** untuk 1000 iterasi.

---

### sub_2991 (Integrity Check)

```c
__int64 sub_2991()
{
  // ...
  if ( !qword_6380 ) return 0LL;
  sub_2369((__int64)&dword_0, qword_6380, (__int64)v2);  // SHA256
  for ( i = 0; i <= 31; ++i )
  {
    if ( v2[i] ) return 1LL;  // Jika SHA256 != all-zeros -> return 1 (OK)
  }
  return 0LL;
}
```

Compute SHA256 dari data di binary. Jika hash bukan all-zeros maka return 1 (lanjut). Ini adalah integrity check untuk memastikan binary tidak dimodifikasi.

---

### Fungsi Helper Matematika

#### sub_37BE — Assignment

```c
_DWORD *__fastcall sub_37BE(_DWORD *a1, int a2)
{
  *a1 = a2;
  return a1;
}
```

#### sub_3926 — Dereference

```c
__int64 __fastcall sub_3926(unsigned int *a1)
{
  return *a1;
}
```

#### sub_3E92 — Dereference (sama dengan sub_3926)

#### sub_38C0 — Multiply (MUL)

```c
__int64 __fastcall sub_38C0(_DWORD *a1, __int64 a2, __int64 a3)
{
  // Loop: *a1 += v6 sebanyak v7 kali = v6 * v7
  v6 = sub_3E92(a2);
  v7 = sub_3E92(a3);
  *a1 = 0;
  for ( i = 0; (int)i < v7; ++i )
    *a1 += v6;
  return i;
}
```

#### sub_3936 — Add (ADD)

```c
_DWORD *__fastcall sub_3936(_DWORD *a1, __int64 a2, __int64 a3)
{
  // Obfuscated: hasil akhir = *a2 + *a3
  v3 = sub_3E92(a2);
  *a1 = v3 - sub_3E92(a3);
  v4 = sub_3E92(a3);
  v5 = v4 + sub_3E92(a3) + *a1;
  v6 = sub_3E92(a2) + v5;
  v7 = v6 - sub_3E92(a2);
  *a1 = v7;   // = *a2 + *a3
  return a1;
}
```

#### sub_39C0 — Modulo (MOD)

```c
int *__fastcall sub_39C0(int *a1, __int64 a2, __int64 a3)
{
  // Throws "Modulo by zero" jika a3==0
  // Loop compute: *a1 = *a2 % *a3
  // ...
}
```

#### sub_3AAA — XOR (bit by bit)

```c
_DWORD *__fastcall sub_3AAA(_DWORD *a1, __int64 a2, __int64 a3)
{
  v6 = sub_3E92(a2);
  v7 = sub_3E92(a3);
  *a1 = 0;
  for ( i = 0; i <= 31; ++i )
    *a1 |= (((v6 >> i) & 1) != ((v7 >> i) & 1)) << i;
  return a1;  // = *a2 ^ *a3
}
```

#### sub_3BEC — Subtract (SUB) untuk comparison

```c
_DWORD *__fastcall sub_3BEC(_DWORD *a1, __int64 a2, __int64 a3)
{
  // Obfuscated, hasil akhir: *a1 = *a2 - *a3
  v3 = sub_3E92(a2);
  *a1 = v3 - sub_3E92(a3);
  // ... (obfuscation steps)
  *a1 = v7;  // = *a2 - *a3
  return a1;
}
```

Dipakai di main: `sub_3BEC(&v13, v14, v15)` → `v13 = flag[i] - expected`. Jika `v13 != 0` → **Wrong!**

---

### Inti Verifikasi — sub_2F88

```c
__int64 __fastcall sub_2F88(unsigned int a1, unsigned int a2, unsigned __int8 a3)
{
  // a1 = i (index), a2 = 0, a3 = byte_4180[6*i]

  // Block 1: v19 = 193 + (a1 * 13) + (a2 * 7)
  sub_38C0(&v14, a1, 13);         // v14 = a1 * 13
  sub_3936(&v15, 193, v14);       // v15 = 193 + v14
  sub_38C0(&v16, a2, 7);          // v16 = a2 * 7
  sub_3936(&v14, v15, v16);       // v14 = v15 + v16
  v19 = sub_3926(&v14);           // v19 = v14

  // Block 2: v20 = 163 + (a1 * 5) + (a2 * 11)
  sub_38C0(&v14, a1, 5);          // v14 = a1 * 5
  sub_3936(&v15, 163, v14);       // v15 = 163 + v14
  sub_38C0(&v16, a2, 11);         // v16 = a2 * 11
  sub_3936(&v14, v15, v16);       // v14 = v15 + v16
  v20 = sub_3926(&v14);           // v20 = v14

  // Block 3: v21 = byte_4120[(a1 + a2) % 64]
  sub_3936(&v14, a1, a2);         // v14 = a1 + a2
  sub_39C0(&v15, v14, 64);        // v15 = v14 % 64
  v21 = byte_4120[sub_3926(&v15)];

  // Block 4: XOR chain
  sub_3AAA(&v14, a3, v19);        // v14 = a3 ^ v19
  sub_3AAA(&v15, v14, v20);       // v15 = v14 ^ v20
  sub_3AAA(&v16, v15, v21);       // v16 = v15 ^ v21

  return sub_3926(&v16);          // return final XOR result
}
```

**Dengan `a2 = 0` (selalu):**
```
v19 = (193 + i*13) & 0xFF
v20 = (163 + i*5)  & 0xFF
v21 = byte_4120[(i + 0) % 64] = byte_4120[i % 64]
expected_char[i] = byte_4180[6*i] ^ v19 ^ v20 ^ v21
```

---

### Data Tables

**byte_4120** (lookup table, 64 explicit entries):
```
10 22 33 44 55 66 77 88 90 AB BC CD DE EF FA 0F
11 21 31 41 51 61 71 81 92 A2 B2 C2 D2 E2 F2 02
13 23 33 43 53 63 73 83 94 A4 B4 C4 D4 E4 F4 04
15 25 35 45 55 65 75 85 96 A6 B6 C6 D6 E6 F6 06
C1 A3 [00 x30...]
```

**byte_4180** (flag verification data, diambil setiap 6 byte):
```
i= 0: 0x24  i= 1: 0x31  i= 2: 0x32  i= 3: 0x5D
i= 4: 0x43  i= 5: 0x9E  i= 6: 0xC2  i= 7: 0x24
...
```

---

## Proses Solve

### Strategi

Karena challenge melarang dynamic analysis, kita lakukan static analysis penuh:

1. Identifikasi semua anti-debug mechanism (tidak perlu di-bypass, cukup dipahami)
2. Trace logic `sub_2F88` secara manual
3. Identifikasi operasi matematika yang di-obfuscate
4. Reverse formula untuk setiap karakter flag

### Reverse Formula

Dari analisis `sub_2F88` dengan `a2=0`:

```
flag[i] = byte_4180[6*i] ^ v19 ^ v20 ^ v21
```

di mana:
```
v19 = (193 + i*13) & 0xFF
v20 = (163 + i*5)  & 0xFF
v21 = byte_4120[i % 64]
```

### Script Solver

```python
#!/usr/bin/env python3
# Classy_People_Dont_Debug - VuwCTF 2025

byte_4120 = [
    0x10,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x90,0xAB,0xBC,0xCD,0xDE,0xEF,0xFA,0x0F,
    0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81,
    0x92,0xA2,0xB2,0xC2,0xD2,0xE2,0xF2,0x02,
    0x13,0x23,0x33,0x43,0x53,0x63,0x73,0x83,
    0x94,0xA4,0xB4,0xC4,0xD4,0xE4,0xF4,0x04,
    0x15,0x25,0x35,0x45,0x55,0x65,0x75,0x85,
    0x96,0xA6,0xB6,0xC6,0xD6,0xE6,0xF6,0x06,
    0xC1,0xA3,
] + [0x00]*190

byte_4180 = [
    0x24,0x41,0x44,0x64,0x45,0x5B,
    0x31,0x56,0x22,0x69,0x5D,0x58,
    0x32,0x16,0x7F,0x5D,0x5E,0x90,
    0x5D,0x0B,0x5C,0x58,0x54,0x71,
    0x43,0x5A,0xBA,0x5B,0x66,0x58,
    0x9E,0xBC,0x4C,0x58,0x5A,0x6B,
    0xC2,0x52,0x5B,0x6F,0x79,0x03,
    0x24,0x63,0x5F,0x69,0x03,0x19,
    0x17,0x4D,0x6B,0x1D,0x6F,0xA5,
    0x3F,0x58,0x6C,0x60,0x44,0xA2,
    0x53,0x64,0x60,0x44,0xA2,0x62,
    0x18,0x6D,0x43,0x67,0x61,0x76,
    0x3F,0x61,0x65,0x7F,0x60,0xB3,
    0x0D,0x66,0x8E,0x6F,0xB2,0xA1,
    0x05,0x84,0x69,0xA4,0xB3,0xFE,
    0x16,0x61,0xB4,0xA3,0xFE,0xD5,
    0x00,0x45,0xA4,0xF7,0xE6,0xF9,
    0x3E,0x94,0xE7,0xFE,0xF9,0x98,
    0x38,0xFA,0xF9,0xBC,0x9B,0x7E,
    0x9F,0xE1,0xBC,0x9B,0x7E,0x76,
    0xA3,0xBE,0xBD,0x70,0x44,0x71,
    0x98,0xBF,0x42,0x5A,0x77,0x00,
    0xD1,0x79,0x5B,0x60,0x71,0x8E,
    0x0F,0x41,0x76,0x87,0x8C,0x95,
    0x2F,0x86,0x87,0xF4,0x85,0xAA,
    0xB2,0x95,0xE2,0x8B,0x88,0x89,
    0xEB,0xEA,0xCB,0x88,0x89,0x6E,
    0xBD,0xC3,0x88,0x89,0x6E,0x36,
    0x8F,0xED,0x8E,0x13,0x05,0x10,
    0x9F,0x8E,0x03,0x0D,0x10,0x03,
    0xBF,0x09,0x0B,0x26,0x31,0x5C,
    0x5B,0x03,0x16,0x01,0x5C,0x57,
    0x4C,0x05,0x04,0x53,0x42,0x99,
]

def sub_2F88(a1, a2, a3):
    a1 &= 0xFF; a2 &= 0xFF; a3 &= 0xFF

    # Block 1: v19 = 193 + (a1*13) + (a2*7)
    v14 = (a1 * 13)    & 0xFFFFFFFF
    v15 = (193 + v14)  & 0xFFFFFFFF
    v16 = (a2 * 7)     & 0xFFFFFFFF
    v19 = ((v15 + v16) & 0xFF)

    # Block 2: v20 = 163 + (a1*5) + (a2*11)
    v14 = (a1 * 5)     & 0xFFFFFFFF
    v15 = (163 + v14)  & 0xFFFFFFFF
    v16 = (a2 * 11)    & 0xFFFFFFFF
    v20 = ((v15 + v16) & 0xFF)

    # Block 3: v21 = byte_4120[(a1+a2) % 64]
    v14 = (a1 + a2)    & 0xFFFFFFFF
    v15 = v14 % 64
    v21 = byte_4120[v15 & 0xFF]

    # Block 4: XOR chain
    v14 = (a3  ^ v19)  & 0xFF
    v15 = (v14 ^ v20)  & 0xFF
    v16 = (v15 ^ v21)  & 0xFF

    return v16

flag = ""
for i in range(33):
    a3 = byte_4180[6 * i]
    c  = sub_2F88(i, 0, a3)
    flag += chr(c)

print(f"[+] Flag: {flag}")
```

### Output

```
[+] Flag: VuwCTF{very_classy_d0'nt_6ou_s33}
```

---

## Flag

```
VuwCTF{very_classy_d0'nt_6ou_s33}
```
