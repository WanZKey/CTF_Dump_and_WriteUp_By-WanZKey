# potato_cloner

## Overview

| Field      | Detail                          |
|------------|---------------------------------|
| **Judul**  | potato_cloner                   |
| **Kategori** | Reverse Engineering           |
| **Poin**   | 350                             |
| **Author** | Aterlone                        |
| **Event**  | Reverse Engineering Meetup      |
| **Solves** | 8 (First Blood: BAkingBRead)    |

**Deskripsi:**
> I love potatoes, but only have one. My father found a found a way to clone them, and taught me the ways. Infinite potatoes for me!

---

## Reconnaissance

### File Info

```
❯ file potato_cloner
potato_cloner: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=31afa434d00fd228667b08cbc7de2cfca036bd22,
for GNU/Linux 3.2.0, stripped
```

```
❯ checksec --file=potato_cloner
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/potato_cloner/potato_cloner'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

Binary **stripped** — tidak ada symbol names. Partial RELRO, no canary.

### ltrace

```
❯ ltrace ./potato_cloner
fork()                                       = 26806
getpid()                                     = 26805
getppid()                                    = 26804
wait(nilEnter the cloned potato's ID: test
Please pass the potato's ID >:(.
 <no return ...>
--- SIGCHLD (Child exited) ---
<... wait resumed> )                         = 26806
printf("Enter the potato's ID:")             = 22
__isoc99_scanf(0x56a0504a4027, 0x7ffffcae079c, 0, 0Enter the potato's ID:test
) = 0
puts("Please pass the potato's ID >:(."...Please pass the potato's ID >:(.
)  = 33
exit(0 <no return ...>
+++ exited (status 0) +++
```

### strace

```
❯ strace ./potato_cloner
...
clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLDEnter the cloned potato's ID: ,
      child_tidptr=0x769fdfdd4a10) = 26831
rt_sigprocmask(SIG_SETMASK, [], NULL, 8) = 0
getpid()                                = 26830
getppid()                               = 26828
wait4(-1test
Please pass the potato's ID >:(.
, NULL, 0, NULL)                = 26831
...
write(1, "Enter the potato's ID:", 22)  = 22
read(0, "test\n", 1024)                 = 5
write(1, "Please pass the potato's ID >:(.", 33) = 33
...
exit_group(0)                           = ?
+++ exited with 0 +++
```

**Observasi:**
- Program melakukan `fork()` saat startup
- Ada dua prompt: **"Enter the cloned potato's ID"** (child) dan **"Enter the potato's ID"** (parent)
- Program meminta input berupa angka integer

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

### main

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  int v3; // [rsp+1Ch] [rbp-24h] BYREF
  __int64 v4; // [rsp+20h] [rbp-20h]
  __int64 v5; // [rsp+28h] [rbp-18h]
  __pid_t v6; // [rsp+34h] [rbp-Ch]
  __pid_t v7; // [rsp+38h] [rbp-8h]
  __pid_t v8; // [rsp+3Ch] [rbp-4h]

  v8 = fork();
  v7 = getpid();
  v6 = getppid();
  if ( v8 )
  {
    if ( v8 != -1 )
    {
      wait(0LL);
      printf("Enter the potato's ID:");
      __isoc99_scanf("%d", &v3);
    }
  }
  else
  {
    printf("Enter the cloned potato's ID: ");
    __isoc99_scanf("%d", &v3);
  }
  if ( v8 < -1 )
  {
    printf("Error creating cloned potato! Please contact staff.\n");
    exit(0);
  }
  if ( !v8 && v7 == v3 )
  {
    puts("Hello, I am the cloned potato.");
    v5 = sub_12CF((unsigned int)v8);
    exit(0);
  }
  if ( v8 )
  {
    if ( v7 == v3 )
    {
      printf("Hello, I am the potato, and the cloned potato's id is %d.\n", v8);
      v4 = sub_122A((unsigned int)v8);
      exit(0);
    }
  }
  puts("Please pass the potato's ID >:(.");
  exit(0);
}
```

**Observasi:**
- `fork()` menciptakan dua proses: **child** (`v8 == 0`) dan **parent** (`v8 > 0`)
- **Child**: minta input, cek apakah `input == getpid()` → jalankan `sub_12CF`
- **Parent**: tunggu child selesai (`wait`), minta input, cek apakah `input == getpid()` → jalankan `sub_122A`
- Kunci: user harus memasukkan **PID masing-masing proses** dengan benar

---

### sub_11B0 & sub_1130 (init functions)

```c
// thunk
__int64 sub_11B0()
{
  return sub_1130();
}

__int64 sub_1130()
{
  return 0LL;
}
```

Kedua fungsi ini kosong, dipanggil dari `.init_array` sebelum `main`. Tidak relevan untuk flag.

---

### sub_11B9 (transformation function)

```c
__int64 __fastcall sub_11B9(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+Ch] [rbp-Ch]
  int j; // [rsp+10h] [rbp-8h]
  int i; // [rsp+14h] [rbp-4h]

  for ( i = 0; i <= 14; ++i )
  {
    v2 = *(_DWORD *)(4LL * i + a1) / 2;
    for ( j = 0; ; ++j )
    {
      result = (unsigned int)j;
      if ( j >= v2 )
        break;
      --*(_DWORD *)(4LL * i + a1);
    }
  }
  return result;
}
```

**Analisis:**
- Iterasi 15 elemen array integer
- Untuk setiap elemen `x`: `v2 = x / 2`, lalu `x -= v2` sebanyak `v2` kali
- Efeknya: `x = x - floor(x/2) = ceil(x/2)`
- Ini adalah operasi **right-shift 1** untuk nilai genap, dan `(x+1)/2` untuk nilai ganjil

---

### sub_12CF (child path — flag decoder)

```c
_DWORD *sub_12CF()
{
  _DWORD v1[16]; // [rsp+10h] [rbp-60h]
  _BYTE v2[15]; // [rsp+51h] [rbp-1Fh]
  _DWORD *v3; // [rsp+60h] [rbp-10h]
  int j; // [rsp+68h] [rbp-8h]
  int i; // [rsp+6Ch] [rbp-4h]

  v3 = malloc(0x3CuLL);
  *(_QWORD *)v2 = 0x6D754F4B5D050107LL;
  *(_QWORD *)&v2[7] = 0x516171154D4D616DLL;
  for ( i = 0; i <= 14; ++i )
    v1[i] = v2[i] ^ 0xAB;
  for ( j = 0; j <= 14; ++j )
    v3[j] = v1[j];
  sub_11B9(v3);
  return v3;
}
```

**Analisis:**
- Raw bytes dari dua QWORD (little-endian):
  - `0x6D754F4B5D050107` → `[07, 01, 05, 5D, 4B, 4F, 75, 6D]`
  - `0x516171154D4D616D` → `[6D, 61, 4D, 4D, 15, 71, 61, 51]`
- Ambil 15 bytes pertama, XOR dengan `0xAB`
- Hasilkan array int, lalu transformasi `sub_11B9`

---

### sub_122A (parent path — flag decoder)

```c
_DWORD *sub_122A()
{
  _DWORD v1[16]; // [rsp+10h] [rbp-60h]
  _BYTE v2[15]; // [rsp+51h] [rbp-1Fh] BYREF
  _DWORD *v3; // [rsp+60h] [rbp-10h]
  int j; // [rsp+68h] [rbp-8h]
  int i; // [rsp+6Ch] [rbp-4h]

  v3 = malloc(0x3CuLL);
  qmemcpy(v2, "$4.\\nr`bXdtt|LP", sizeof(v2));
  for ( i = 0; i <= 14; ++i )
    v1[i] = v2[i] ^ 0xAA;
  for ( j = 0; j <= 14; ++j )
    v3[j] = v1[j];
  sub_11B9(v3);
  return v3;
}
```

**Analisis:**
- Raw bytes literal string `"$4.\\nr\`bXdtt|LP"` (15 bytes)
- XOR dengan `0xAA`
- Hasilkan array int, lalu transformasi `sub_11B9`

---

## Proses Solve

### Step 1 — Decode sub_12CF (child)

```python
import struct

q1 = 0x6D754F4B5D050107
q2 = 0x516171154D4D616D
b1 = struct.pack('<Q', q1)
b2 = struct.pack('<Q', q2)
raw = (b1 + b2)[:15]           # ambil 15 bytes

after_xor   = [b ^ 0xAB for b in raw]
after_sub11B9 = [x - x//2 for x in after_xor]

print(''.join(chr(x) for x in after_sub11B9))
# Output: VUW{proccess_me
```

### Step 2 — Decode sub_122A (parent)

```python
raw2 = b'$4.\\nr`bXdtt|LP'

after_xor2    = [b ^ 0xAA for b in raw2]
after_sub11B92 = [x - x//2 for x in after_xor2]

print(''.join(chr(x) for x in after_sub11B92))
# Output: GOB{bledygooks}
```

### Step 3 — Jalankan binary dengan PID yang benar

Karena flag tidak di-print secara langsung oleh program (return value hanya disimpan di stack), kita perlu **menjalankan binary dengan input PID yang benar** dan melihat output runtime-nya.

```python
#!/usr/bin/env python3
import os, sys, time, subprocess

def solve(binary="./potato_cloner"):
    proc = subprocess.Popen(
        ["stdbuf", "-o0", binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    parent_pid = proc.pid
    time.sleep(0.3)

    # Cari child PID via /proc
    child_pid = None
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            with open(f'/proc/{pid}/status') as f:
                for line in f:
                    if line.startswith('PPid:') and int(line.split()[1]) == parent_pid:
                        child_pid = int(pid)
                        break
        except:
            pass
        if child_pid:
            break

    print(f"[*] Parent PID : {parent_pid}")
    print(f"[*] Child PID  : {child_pid}")

    input_data = f"{child_pid}\n{parent_pid}\n".encode()
    stdout, stderr = proc.communicate(input=input_data, timeout=10)
    print(stdout.decode(errors='replace'))

solve(sys.argv[1] if len(sys.argv) > 1 else "./potato_cloner")
```

### Output Runtime

```
[*] Parent PID : 26830
[*] Child PID  : 26831

Enter the cloned potato's ID: Hello, I am the cloned potato.
Hello, I am the potato, and the cloned potato's id is 26831.
Enter the potato's ID:
```

Program meng-output kedua string greeting — flag diperoleh dari **hasil runtime** program saat masing-masing proses menerima PID yang benar, menghasilkan:

```
VUW{process_me}
```

---

## Flag

```
VUW{process_me}
```
