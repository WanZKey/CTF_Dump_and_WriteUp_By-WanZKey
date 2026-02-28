https://chatgpt.com/share/68d96468-b064-8002-9ea7-ebe846d6b5e7

# Write-up: **question 2** — quiz_2 (Reverse, Easy)

**Author:** aria
**Kategori:** Reverse (Easy) — 250 points

---

## Ringkasan singkat

Binary `quiz_2` adalah sebuah kuis 10 soal aritmetika. Program mencetak sebuah seed (nilai `time()`), lalu membuat 10 soal dengan memanggil `rand()` beberapa kali per soal. Bila semua jawaban benar, program men-decode dan menampilkan flag.

Saya membuat solver otomatis yang:

1. Menjalankan `./quiz_2` untuk mengambil seed yang dicetak.
2. Memanggil `srand(seed)` di Python (melalui `ctypes` ke `libc`) lalu mereplikasi panggilan `rand()` untuk merekonstruksi soal & jawaban.
3. Mengirim semua jawaban sekaligus ke program (non-interaktif) agar langsung menampilkan flag.

Output akhir: **`FGTE{Hidden_Math_Flag}`**

---

## 1) Informasi file (dari lingkungan)

```text
$ file quiz_2
quiz_2: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=a6ad35a4b32ce5fbf6264e94a11bd85263f40c46, for GNU/Linux 3.2.0, stripped
```

Proteksi (checksec):

```text
$ checksec --file=quiz_2
[*] '/home/wanzkey/ARIAF-CTF-2025/Reverse/question 2/quiz_2'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

Program **stripped** dan **PIE enabled**, tetapi kita tidak perlu patching atau exploit — cukup menganalisis logika pembuat soal.

---

## 2) Decompile (potongan dari Ghidra)

Berikut potongan decompile yang relevan (dari bahan soal):

**entry**

```c
void processEntry entry(undefined8 param_1,undefined8 param_2)
{
  undefined1 auStack_8 [8];
  __libc_start_main(FUN_00101120,param_2,&stack0x00000008,0,0,param_1,auStack_8);
  do { } while( true );
}
```

**FUN_00101120**

```c
undefined8 FUN_00101120(void)
{
  int iVar1;
  puts("Quiz Verification");
  puts("Answer all questions correctly to see the flag.");
  iVar1 = FUN_00101350();
  if (iVar1 == 0) {
    puts("Verification failed. Try again.");
  }
  else {
    FUN_00101260();
  }
  return 0;
}
```

**FUN_00101260** (membangun dan mencetak flag)

```c
void FUN_00101260(void)
{
  byte bVar1;
  ulong uVar2;
  ulong uVar3;
  byte bVar4;
  long in_FS_OFFSET;
  undefined1 local_98 [16];
  undefined1 local_88 [16];
  ...
  bVar4 = 4;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_98 = 0x0;
  bVar1 = 0x42;
  ...
  uVar2 = 0;
  while( true ) {
    local_98[uVar2] = bVar4 ^ bVar1;
    uVar3 = uVar2 + 1;
    if (uVar3 == 0x16) break;
    bVar4 = (&DAT_00102131)[uVar2];
    bVar1 = (&DAT_00102120)[uVar3 % 0xd];
    uVar2 = uVar3;
  }
  local_88[6] = 0;
  __printf_chk(1,"Good. Here\'s the flag: %s\n",local_98);
  ...
}
```

**FUN_00101350** (membangun soal & verifikasi jawaban)

```c
undefined4 FUN_00101350(void)
{
  int iVar1,iVar2,iVar3,iVar4,iVar8;
  uint uVar5;
  ulong uVar6;
  long local_40;
  long local_98 [11];
  uVar10 = 1;
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  uVar6 = time((time_t *)0x0);
  srand((uint)uVar6);
  printf("Welcome to quiz verification. You will be asked %d questions.\n",10);
  printf("(Seed: %u)\n",uVar6 & 0xffffffff);
  uVar9 = 1;
  while( true ) {
    iVar3 = rand();
    iVar2 = iVar3 % 100 + 1;
    iVar4 = rand();
    iVar1 = iVar4 % 0x32 + 1;
    uVar5 = rand();
    iVar8 = (int)uVar5 % 4;
    if (iVar8 == 2) {
      unaff_RBX = (long)iVar2 * (long)iVar1;
      printf("Q%d: %d * %d = ?\n",uVar9 & 0xffffffff);
    }
    else if (iVar8 == 3) {
      unaff_RBX = (long)(iVar2 % iVar1);
      printf("Q%d: %d %% %d = ?\n",uVar9 & 0xffffffff);
    }
    else if ((uVar5 & 3) == 0) {
      unaff_RBX = (long)(iVar2 + iVar1);
      printf("Q%d: %d + %d = ?\n",uVar9 & 0xffffffff);
    }
    else if (iVar8 == 1) {
      unaff_RBX = (long)(iVar3 % 100 - iVar4 % 0x32);
      printf("Q%d: %d - %d = ?\n",uVar9 & 0xffffffff);
    }
    iVar2 = scanf("%ld",plVar7);
    if (iVar2 != 1) break;
    if (*plVar7 != unaff_RBX) {
      uVar10 = 0;
    }
    uVar9 = uVar9 + 1;
    plVar7 = plVar7 + 1;
    if (uVar9 == 0xb) return uVar10;
  }
  uVar10 = 0;
  return uVar10;
}
```

---

## 3) Interpretasi & strategi

Dari decompile di atas kita dapat menarik beberapa kesimpulan penting:

* Program memanggil `time()` dan kemudian `srand((uint)time)` sehingga `rand()` bersifat deterministik jika seed diketahui.
* Program mencetak `(Seed: %u)` sehingga kita **bisa** membaca seed secara langsung dari output program.
* Untuk setiap soal ada 3 panggilan `rand()`:

  1. `iVar3 = rand()` → `iVar2 = iVar3 % 100 + 1`  (nilai A)
  2. `iVar4 = rand()` → `iVar1 = iVar4 % 0x32 + 1` (nilai B)
  3. `uVar5 = rand()` → `iVar8 = uVar5 % 4` → menentukan operator ( +, -, *, % )
* Jika operator adalah pengurangan (case `iVar8 == 1`), hasil yang diperlihatkan pada soal adalah `iVar3 % 100 - iVar4 % 0x32` (perhatikan berbeda dari `iVar2` dan `iVar1` yang berisi `+1` offset). Jadi kita harus mengikuti persis rumus di decompile.
* Setelah semua jawaban benar, fungsi `FUN_00101260` akan membangun local_98 (string) dengan operasi XOR dari beberapa data statis dan mencetaknya sebagai flag.

Strategi implementasi solver:

1. Jalankan `./quiz_2` sekali untuk mengambil seed yang dicetak.
2. Di Python, panggil `libc.srand(seed)` lalu panggil `libc.rand()` persis urutan yang sama sebanyak yang dilakukan program untuk mendapatkan angka-angka yang sama.
3. Derivasi setiap jawaban sesuai kondisi (operator) dan kumpulkan 10 jawaban.
4. Kirim semua jawaban sekaligus ke `./quiz_2` melalui stdin pipe sehingga program tidak perlu menunggu interaktif.

---

## 4) Solver (Python) — otomatis, cepat

Skrip berikut saya gunakan untuk mengambil seed, merekonstruksi jawaban, lalu menjalankan `./quiz_2` lagi dengan semua jawaban dikirim sekaligus.

> Simpan sebagai `solver.py` dan jalankan `python3 solver.py` (pastikan `quiz_2` executable berada di folder yang sama).

```python
#!/usr/bin/env python3
import ctypes
import subprocess
import re

# 1) Jalankan binary sekali untuk ambil seed (program akan mencetak seed)
p = subprocess.run(["./quiz_2"], input="\n", text=True, capture_output=True)
seed_match = re.search(r"\(Seed: (\d+)\)", p.stdout)
if not seed_match:
    print("Gagal menemukan seed. Output:\n", p.stdout)
    raise SystemExit(1)
seed = int(seed_match.group(1))
print(f"[+] Seed ditemukan: {seed}")

# 2) Muat libc dan lakukan srand(seed) lalu panggil rand() persis urutan decompile
libc = ctypes.CDLL("libc.so.6")
libc.srand.argtypes = [ctypes.c_uint]
libc.rand.restype = ctypes.c_int
libc.srand(seed)

answers = []
for _ in range(10):
    iVar3 = libc.rand()
    iVar2 = iVar3 % 100 + 1
    iVar4 = libc.rand()
    iVar1 = iVar4 % 0x32 + 1
    uVar5 = libc.rand()
    iVar8 = uVar5 % 4

    if iVar8 == 2:
        ans = iVar2 * iVar1
    elif iVar8 == 3:
        ans = iVar2 % iVar1
    elif (uVar5 & 3) == 0:
        ans = iVar2 + iVar1
    else:
        # iVar8 == 1 : subtraction uses iVar3%100 and iVar4%0x32
        ans = (iVar3 % 100) - (iVar4 % 0x32)
    answers.append(str(ans))

# 3) Kirim semua jawaban sekaligus dan tampilkan output program
answer_input = "\n".join(answers) + "\n"
print("[+] Mengirim jawaban:")
print(answer_input)
result = subprocess.run(["./quiz_2"], input=answer_input, text=True, capture_output=True)
print(result.stdout)
```

---

## 5) Alternatif: satu-liner (jika jawaban sudah diketahui)

Jika kamu sudah tahu deretan jawaban, cukup gunakan pipe dari shell:

```bash
printf "%s\n" 25 2 2788 32 95 -8 3 17 232 1 | ./quiz_2
```

(angka di atas adalah contoh untuk seed yang dijalankan di lingkungan saya; seed dapat berbeda tiap run.)

---

## 6) Output terminal (hasil eksekusi `solver.py` di lingkungan saya)

Berikut output yang dihasilkan ketika saya menjalankan `python3 solver.py` pada target binary (ikut ditampilkan persis):

```text
$ python3 solver.py
[+] Seed ditemukan: 1759077334
[+] Mengirim jawaban:
25
2
2788
32
95
-8
3
17
232
1

Quiz Verification
Answer all questions correctly to see the flag.
Welcome to quiz verification. You will be asked 10 questions.
(Seed: 1759077334)
Q1: 56 % 31 = ?
Q2: 40 - 38 = ?
Q3: 82 * 34 = ?
Q4: 47 - 15 = ?
Q5: 61 + 34 = ?
Q6: 26 - 34 = ?
Q7: 75 % 9 = ?
Q8: 17 % 21 = ?
Q9: 29 * 8 = ?
Q10: 1 % 23 = ?
Good. Here's the flag: FGTE{Hidden_Math_Flag}
```

> **Flag ditemukan:** `FGTE{Hidden_Math_Flag}`

---

## 7) Catatan & penjelasan tambahan

* Seed bergantung pada `time()`. Jika kamu menjalankan `./quiz_2` langsung dan tidak menyimpan seed, maka nilai `rand()` berbeda tiap proses (kecuali kamu mem-override seed). Oleh karena itu pendekatan yang aman adalah: ambil seed dari output program, lalu re-run program (atau reimplementasi) dengan `srand(seed)` untuk mereproduksi urutan `rand()`.
* Penting: ketika meniru perilaku program, ikuti persis semua operasi modulus/penggeseran yang ada (contoh: operator subtraction menggunakan `iVar3 % 100` dan `iVar4 % 0x32` — jangan ganti dengan `iVar2`/`iVar1` yang memiliki `+1` offset).
* Fungsi pembentuk flag (`FUN_00101260`) memakai data statis internal dan operasi XOR untuk membangun string flag. Karena program hanya mengekspose flag ketika semua jawaban benar, kita cukup mencari cara memberi input benar — tidak perlu membalikkan XOR statis tersebut.

---

## 8) File yang saya sertakan

* `solver.py` — skrip Python otomatis (di atas) yang mengambil seed, menghitung jawaban, lalu mengirimkan semuanya ke `quiz_2`.

---

Jika kamu mau, saya bisa juga:

* Menambahkan langkah-langkah Ghidra lebih detail (mis. menelusuri `&DAT_00102131` / `&DAT_00102120` jika ingin mendekode flag tanpa menjalankan program), atau
* Mengemas write-up ini plus `solver.py` dalam satu ZIP untuk diunduh.

---

**Selesai.**

