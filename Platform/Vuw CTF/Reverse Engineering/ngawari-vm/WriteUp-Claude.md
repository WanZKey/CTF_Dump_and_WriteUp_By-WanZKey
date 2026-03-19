# ngawari-vm

## Overview

| Field      | Detail                        |
|------------|-------------------------------|
| **Judul**  | ngawari-vm                    |
| **Kategori** | Reverse Engineering          |
| **Poin**   | 300                           |
| **Author** | maxster                       |
| **Event**  | VuwCTF 2025                   |
| **Solves** | 0 (First Blood: The F Students / BAkingBRead) |

**Deskripsi:**
> Grammar? What's that?
> Wait, is this even a VM?

---

## Attachment

```
.
├── flag_checker.txt
└── ngawari_vm
```

---

## Reconnaissance

### File Info

```
❯ file ngawari_vm
ngawari_vm: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=741de1ffd4df6ec2e735ca2dd71320f821729f4e,
for GNU/Linux 3.2.0, not stripped
```

```
❯ checksec --file=ngawari_vm
[*] '/home/wanzkey/VUW CTF/Reverse Engineering/ngawari-vm/ngawari_vm'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

```
❯ ltrace ./ngawari_vm
puts("Ngawari VM - A generalized, prog"...Ngawari VM - A generalized, programmable input checker

)  = 56
puts("Expected filename as first arg"Expected filename as first arg
)       = 31
exit(1 <no return ...>
+++ exited (status 1) +++
```

### Symbols

```
❯ nm ngawari_vm
000000000000038c r __abi_tag
0000000000004030 B accepting_states
000000000000166c T accept_input
0000000000004020 B __bss_start
...
0000000000001289 T init_vm
0000000000004048 B insn_buffer
0000000000004018 D insn_buffer_size
0000000000004050 B insn_count
...
0000000000001437 T parse_file
00000000000013e2 T pop_stack
000000000000130e T push_insn
000000000000137f T push_stack
...
0000000000004038 B stack_buf
0000000000004010 D stack_buf_size
0000000000004040 B stack_ptr
0000000000004028 B state
...
```

Binary tidak di-strip, sehingga nama fungsi masih terlihat jelas.

### flag_checker.txt

```
❯ file flag_checker.txt
flag_checker.txt: ASCII text

❯ cat flag_checker.txt
aBw
niBnFB
dCSeS
inKpZ
jsEj
k}SwINE
eTSfS
q^CwA
q}FqC
g_ShI
cwSdS
nnHn
hsSi
j0Fi
h1IhS
o}BqC
g{SaVK
piIp
k0Hk
ocPk
p^ZrZ
aVVbS
fFSgS
p0ApAA
q}BwZ
p0ZpAZ
q1Aq
k0Ek
q^ZrZ
pnHn
p1Aq
buScS
ntFqF
i_Kj
i_GoPHER
neBpZ
klRkL
aVBbSEFGHB
k_LpIH
i_HaSw
```

---

## Analisis Decompile (IDA Pro)

### main

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+1Fh] [rbp-1h]

  puts("Ngawari VM - A generalized, programmable input checker\n");
  if ( argc <= 1 )
  {
    puts("Expected filename as first arg");
    exit(1);
  }
  init_vm();
  parse_file(argv[1]);
  puts("Enter the input, followed by a newline:");
  while ( 1 )
  {
    v4 = getchar();
    if ( v4 == 10 || v4 == -1 )
      break;
    if ( v4 == 94 )
    {
      puts("Illegal input char");
      exit(1);
    }
    if ( !(unsigned int)accept_input((unsigned int)v4) )
    {
      puts("Input rejected");
      exit(1);
    }
  }
  if ( !(unsigned int)accept_input(94LL) )
  {
    puts("Input rejected");
    exit(1);
  }
  if ( strchr(accepting_states, state) )
    puts("Input accepted!");
  else
    puts("Input rejected");
  return 0;
}
```

**Observasi:**
- Program menerima filename sebagai argumen pertama (`flag_checker.txt`)
- Karakter `^` (ASCII 94) dilarang sebagai input user, tapi digunakan secara internal sebagai **EOF marker** saat akhir input
- Setiap karakter diproses oleh `accept_input()`
- Input diterima jika `state` akhir ada di dalam `accepting_states`

---

### init_vm

```c
__int64 init_vm()
{
  __int64 result; // rax
  stack_buf = (__int64)malloc(stack_buf_size);
  if ( !stack_buf )
  {
    puts("Failed to allocate data");
    exit(1);
  }
  insn_buffer = (__int64)malloc(16LL * (_QWORD)insn_buffer_size);
  result = insn_buffer;
  if ( !insn_buffer )
  {
    puts("Failed to allocate data");
    exit(1);
  }
  return result;
}
```

**Observasi:**
- Mengalokasikan dua buffer: `stack_buf` dan `insn_buffer`
- `insn_buffer` berukuran `16 * insn_buffer_size` — setiap instruksi berukuran **16 bytes**

---

### parse_file

```c
unsigned __int64 __fastcall parse_file(const char *a1)
{
  char *v1; // rax
  char *v2; // rax
  char *lineptr; // [rsp+18h] [rbp-48h] BYREF
  size_t n; // [rsp+20h] [rbp-40h] BYREF
  FILE *stream; // [rsp+28h] [rbp-38h]
  __ssize_t v7; // [rsp+30h] [rbp-30h]
  signed __int64 v8; // [rsp+38h] [rbp-28h]
  _BYTE v9[8]; // [rsp+40h] [rbp-20h] BYREF
  char *v10; // [rsp+48h] [rbp-18h]
  unsigned __int64 v11; // [rsp+58h] [rbp-8h]
  v11 = __readfsqword(0x28u);
  stream = fopen(a1, "r");
  if ( !stream )
  {
    puts("Failed to open file");
    exit(1);
  }
  lineptr = 0LL;
  n = 0LL;
  v7 = getline(&lineptr, &n, stream);
  if ( v7 == -1 )
  {
    puts("Required first line of file missing");
    exit(1);
  }
  if ( strlen(lineptr) <= 2 )
  {
    puts("First line of file too short");
    exit(1);
  }
  state = *lineptr;
  push_stack((unsigned int)lineptr[1]);
  v1 = strchr(lineptr + 2, 10);
  accepting_states = strndup(lineptr + 2, v1 - (lineptr + 2));
  if ( !accepting_states )
  {
    puts("Failed to allocate data");
    exit(1);
  }
  while ( 1 )
  {
    v7 = getline(&lineptr, &n, stream);
    if ( v7 == -1 )
      break;
    v2 = strchr(lineptr, 10);
    v8 = v2 - lineptr;
    if ( (unsigned __int64)(v2 - lineptr) <= 3 )
    {
      puts("Instruction line too short");
      exit(1);
    }
    v9[0] = *lineptr;
    v9[1] = lineptr[1];
    v9[2] = lineptr[2];
    v9[3] = lineptr[3];
    v10 = strndup(lineptr + 4, v8 - 4);
    push_insn(v9);
  }
  fclose(stream);
  return v11 - __readfsqword(0x28u);
}
```

**Observasi — Format `flag_checker.txt`:**
- **Line 1** (`aBw`):
  - `state = 'a'` → state awal
  - `push_stack('B')` → push karakter ke-2 ke stack
  - `accepting_states = "w"` → karakter ke-3 dst. adalah accepting states
- **Baris berikutnya** (instruksi), format: `[cur_state][input][pop][next_state][push_string]`
  - 4 karakter pertama = `cur_state`, `input`, `pop`, `next_state`
  - Sisa string = string yang akan di-push ke stack

---

### push_insn

```c
__int64 __fastcall push_insn(__int64 *a1)
{
  __int64 v1; // rax
  __int64 *v2; // rcx
  __int64 v3; // rdx
  __int64 result; // rax
  if ( insn_count >= (unsigned __int64)insn_buffer_size )
  {
    puts("Instruction buffer overflow");
    exit(1);
  }
  v1 = insn_count++;
  v2 = (__int64 *)(16 * v1 + insn_buffer);
  v3 = a1[1];
  result = *a1;
  *v2 = *a1;
  v2[1] = v3;
  return result;
}
```

**Observasi:**
- Menyimpan instruksi 16 bytes ke `insn_buffer`
- Setiap instruksi: `[cur_state, input, pop, next_state, ..., ptr_to_push_string]`

---

### push_stack

```c
__int64 __fastcall push_stack(unsigned __int8 a1)
{
  __int64 v1; // rax
  unsigned __int8 *v2; // rdx
  __int64 result; // rax
  if ( stack_ptr >= stack_buf_size )
  {
    puts("Stack overflow");
    exit(1);
  }
  v1 = stack_ptr++;
  v2 = (unsigned __int8 *)(stack_buf + v1);
  result = a1;
  *v2 = a1;
  return result;
}
```

---

### pop_stack

```c
__int64 pop_stack()
{
  if ( !stack_ptr )
  {
    puts("Stack underflow");
    exit(1);
  }
  --stack_ptr;
  return *(unsigned __int8 *)(stack_buf + stack_ptr);
}
```

---

### accept_input

```c
__int64 __fastcall accept_input(char a1)
{
  char v2; // [rsp+1Fh] [rbp-21h]
  unsigned __int64 i; // [rsp+20h] [rbp-20h]
  signed __int64 j; // [rsp+28h] [rbp-18h]
  __int64 v5; // [rsp+30h] [rbp-10h]
  v2 = pop_stack();
  for ( i = 0LL; ; ++i )
  {
    if ( i >= insn_count )
      return 0LL;
    v5 = 16 * i + insn_buffer;
    if ( *(_BYTE *)v5 == state && a1 == *(_BYTE *)(v5 + 1) && v2 == *(_BYTE *)(v5 + 2) )
      break;
  }
  state = *(_BYTE *)(v5 + 3);
  for ( j = strlen(*(const char **)(v5 + 8)) - 1; j >= 0; --j )
    push_stack((unsigned int)*(char *)(*(_QWORD *)(v5 + 8) + j));
  return 1LL;
}
```

**Observasi — Inti Mesin:**
1. Pop stack top (`v2`)
2. Cari instruksi yang cocok: `(current_state == state) && (input == a1) && (stack_top == v2)`
3. Jika tidak ada yang cocok → return 0 (reject)
4. Update `state = next_state`
5. Push string ke stack secara **reversed** (karakter terakhir di-push dulu, sehingga karakter pertama menjadi stack top)

---

## Identifikasi: Pushdown Automaton (PDA)

Setelah menganalisis semua fungsi, ini bukan VM biasa — ini adalah implementasi **Pushdown Automaton (PDA)**:

| Komponen PDA | Implementasi |
|---|---|
| States | Karakter (a, b, c, ...) |
| Input alphabet | Karakter yang diinput user |
| Stack alphabet | Karakter kapital (A, B, S, ...) |
| Transition function | Instruksi di `insn_buffer` |
| Initial state | `'a'` (karakter pertama line 1) |
| Initial stack | `['B']` (karakter kedua line 1) |
| Accepting states | `"w"` (karakter ke-3+ line 1) |
| EOF marker | `'^'` (ASCII 94) |

**Format setiap instruksi:**
```
(cur_state, input_char, pop_char) → next_state, push_string
```

**Contoh parsing instruksi:**
```
aVBbSEFGHB → (state='a', input='V', pop='B') → state='b', push "SEFGHB"
niBnFB     → (state='n', input='i', pop='B') → state='n', push "FB"
k}SwINE    → (state='k', input='}', pop='S') → state='w', push "INE"
q^CwA      → (state='q', input='^', pop='C') → state='w', push "A"  (EOF!)
```

---

## Proses Solve

Karena ini adalah PDA deterministik, kita bisa melakukan **BFS (Breadth-First Search)** dari state awal untuk menemukan string input yang membawa kita ke accepting state setelah menerima EOF (`^`).

### Script Solver

```python
# parse flag_checker.txt
lines = """aBw
niBnFB
dCSeS
inKpZ
jsEj
k}SwINE
eTSfS
q^CwA
q}FqC
g_ShI
cwSdS
nnHn
hsSi
j0Fi
h1IhS
o}BqC
g{SaVK
piIp
k0Hk
ocPk
p^ZrZ
aVVbS
fFSgS
p0ApAA
q}BwZ
p0ZpAZ
q1Aq
k0Ek
q^ZrZ
pnHn
p1Aq
buScS
ntFqF
i_Kj
i_GoPHER
neBpZ
klRkL
aVBbSEFGHB
k_LpIH
i_HaSw""".strip().split('\n')

first = lines[0]
init_state = first[0]
init_stack_char = first[1]
accepting = set(first[2:])

instructions = []
for line in lines[1:]:
    cur_state = line[0]
    inp = line[1]
    pop = line[2]
    next_state = line[3]
    push_str = line[4:]
    instructions.append((cur_state, inp, pop, next_state, push_str))

# Build lookup: (state, input, pop) -> (next_state, push_str)
lookup = {}
for (cs, ch, pop, ns, push) in instructions:
    lookup[(cs, ch, pop)] = (ns, push)

def step(state, stack, char):
    """Returns (new_state, new_stack) or None"""
    if not stack:
        return None
    stack_top = stack[0]
    key = (state, char, stack_top)
    if key not in lookup:
        return None
    ns, push = lookup[key]
    new_stack = list(stack[1:])
    # push string reversed: karakter pertama jadi stack top
    for c in reversed(push):
        new_stack.insert(0, c)
    return ns, tuple(new_stack)

# BFS
from collections import deque

init = (init_state, (init_stack_char,))
parent = {init: None}
input_to = {init: ""}

queue = deque([init])
found = None
MAX_LEN = 50

while queue and not found:
    cur_state, stack = queue.popleft()
    cur_inp = input_to[(cur_state, stack)]

    if len(cur_inp) >= MAX_LEN:
        continue

    if stack:
        stack_top = stack[0]
        # Coba EOF terlebih dahulu
        for (cs, ch, pop, ns, push) in instructions:
            if cs == cur_state and ch == '^' and pop == stack_top:
                if ns in accepting:
                    print(f"FOUND! Input = {cur_inp!r}")
                    found = cur_inp
                    break

    if found:
        break

    if not stack:
        continue
    stack_top = stack[0]

    for (cs, ch, pop, ns, push) in instructions:
        if cs == cur_state and pop == stack_top and ch != '^':
            result = step(cur_state, stack, ch)
            if result:
                ns2, new_stack = result
                node = (ns2, new_stack)
                if node not in parent and len(new_stack) < 25:
                    parent[node] = (cur_state, stack)
                    input_to[node] = cur_inp + ch
                    queue.append(node)
```

### Output Solver

```
FOUND! Input = 'VuwCTF{VuwCTF_1s_s0_c00l_innit}'
```

---

## Flag

```
VuwCTF{VuwCTF_1s_s0_c00l_innit}
```
