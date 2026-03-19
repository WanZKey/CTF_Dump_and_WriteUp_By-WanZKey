# WriteUp - ngawari-vm

## Overview
- **Judul:** ngawari-vm
- **Kategori:** Reverse Engineering
- **Poin:** 300
- **Author:** maxster
- **Release:** VuwCTF 2025
- **Deskripsi:** Grammar? What's that? Wait, is this even a VM?

## Informasi Attachment
```text
 WanZKey  ～  ~../Reverse Engineering/ngawari-vm 󱎫 0s 󱑎 14.46
 󰋑  ▶  file ngawari_vm
ngawari_vm: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=741de1ffd4df6ec2e735ca2dd71320f821729f4e, for GNU/Linux 3.2.0, not stripped

 WanZKey  ～  ~../Reverse Engineering/ngawari-vm 󱎫 0s 󱑎 14.46
 󰋑  ▶  checksec --file=ngawari_vm
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

## Proses Penyelesaian

Berdasarkan deskripsi soal dan analisis awal menggunakan `nm`, program ini bukanlah sebuah *Virtual Machine* (VM) tradisional yang mengeksekusi *opcode*. Melainkan, program ini mengimplementasikan sebuah **Pushdown Automaton (PDA)**, yaitu varian dari *Finite State Machine* (FSM) yang dilengkapi dengan memori tambahan berupa *stack* (tumpukan). Program membaca aturan tata bahasa (*grammar*) dari *file* `flag_checker.txt` dan menggunakannya untuk memvalidasi *input* dari pengguna.

### Analisis Decompile (IDA Pro)

Program membaca *file* eksternal melalui fungsi `parse_file`. Struktur *file* `flag_checker.txt` dirancang sebagai berikut:
1.  **Baris Pertama (`aBw`):**
    - `a` = *Initial State* (Status awal).
    - `B` = *Initial Stack Symbol* (Karakter pertama di dalam *stack*).
    - `w` = *Accepting States* (Status akhir/kemenangan).
2.  **Baris Kedua dan Seterusnya (Aturan Transisi):**
    Setiap baris berisi instruksi dengan format: `<Current State><Input Char><Pop Stack><Next State><String to Push>`.
    Contoh dari instruksi `niBnFB`:
    - `n`: Jika *state* saat ini adalah 'n'
    - `i`: Dan pengguna meng-*input* karakter 'i'
    - `B`: Dan karakter paling atas di *stack* adalah 'B'
    - `n`: Maka ubah *state* menjadi 'n'
    - `FB`: Lalu *push* 'FB' ke dalam *stack* (secara terbalik, B lalu F, sesuai logika `push_stack` pada `accept_input`).

Fungsi `accept_input` bertugas mencocokkan karakter demi karakter yang kita masukkan dengan aturan-aturan ini. Jika input kita bisa membawa mesin dari *state* `a` menuju *state* `w` dengan kondisi *stack* kosong dan diakhiri dengan karakter EOF `^`, maka *flag* dianggap valid.

### Jebakan CRLF (Gotcha)

Satu hal krusial yang perlu diperhatikan adalah *file* `flag_checker.txt` menggunakan format *line ending* Windows (CRLF / `\r\n`). Jika dieksekusi atau di-*parsing* mentah-mentah di sistem Linux, karakter *carriage return* (`\r`) akan ikut terbaca sebagai bagian dari `<String to Push>`, sehingga memenuhi *stack* dengan karakter sampah dan menyebabkan algoritma pencarian tersesat (*infinite loop* atau Out-of-Memory). Kita harus membersihkan karakter `\r` saat melakukan *parsing* di dalam *script*.

### Script Solver

Untuk mendapatkan *flag*, kita menggunakan algoritma *Breadth-First Search* (BFS). BFS sangat cocok karena ia menelusuri semua kemungkinan transisi *state* level demi level, sehingga terhindar dari *infinite loop* (seperti transisi yang terus-menerus mem-*push* karakter ke *stack* tanpa batas).

```python
#!/usr/bin/env python3
from collections import deque

def solve_pda():
    with open("flag_checker.txt", "r") as f:
        # Membersihkan jebakan CRLF (\r)
        lines = [line.replace('\r', '') for line in f.read().splitlines()]

    init_line = lines[0]
    start_state = init_line[0]
    start_stack_sym = init_line[1]
    accept_states = init_line[2:]

    transitions = []
    for line in lines[1:]:
        if len(line) < 4:
            continue
        cur_state = line[0]
        input_char = line[1]
        pop_char = line[2]
        next_state = line[3]
        push_str = line[4:]
        transitions.append((cur_state, input_char, pop_char, next_state, push_str))

    # Queue menyimpan tuple: (state, stack_sebagai_tuple, string_flag)
    queue = deque([(start_state, (start_stack_sym,), "")])

    while queue:
        state, stack, input_str = queue.popleft()
        
        if not stack:
            continue

        for (cs, ic, st, ns, pc) in transitions:
            if cs == state and st == stack[-1]:
                # Copy stack dan pop elemen terakhir
                new_stack = list(stack[:-1])
                
                # Push karakter baru secara terbalik
                for c in reversed(pc):
                    new_stack.append(c)
                
                # Cek kondisi menang: input adalah EOF '^' dan next state valid
                if ic == '^' and ns in accept_states:
                    return input_str
                # Teruskan penelusuran jika bukan EOF
                elif ic != '^':
                    queue.append((ns, tuple(new_stack), input_str + ic))

    return "Flag not found"

if __name__ == "__main__":
    flag = solve_pda()
    print(f"Decrypted Flag: {flag}")
```

### Output Terminal Solver

```text
 󰋑  ▶  ./solver.py
Decrypted Flag: VuwCTF{VuwCTF_1s_s0_c00l_innit}
```

## Flag

```text
VuwCTF{VuwCTF_1s_s0_c00l_innit}
```


