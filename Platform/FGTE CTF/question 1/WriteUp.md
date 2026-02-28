https://g.co/gemini/share/03f0783e8027
-----

# Write-Up CTF: question 1 (Reverse)

## Informasi Challenge

  * **Nama**: question 1
  * **Kategori**: Reverse
  * **Poin**: 100
  * **Author**: aria

> Binary ini menjalankan kuis 10 soal

-----

## Analisis Awal

Tantangan ini memberikan sebuah file *binary* ELF 64-bit. Langkah pertama adalah melakukan analisis dasar untuk memahami jenis file dan proteksi yang digunakan.

### 1\. Informasi File

Menggunakan perintah `file` untuk melihat tipe file.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Reverse/question 1]
└─$ file quiz_1
quiz_1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e591826a6ce29a000c08af044bda42f54c8d1028, for GNU/Linux 3.2.0, with debug_info, not stripped
```

Dari sini kita tahu bahwa file ini **tidak di-strip** dan memiliki **debug\_info**, yang akan sangat membantu saat dekompilasi.

### 2\. Proteksi Binary

Menggunakan `checksec` untuk memeriksa proteksi yang ada.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Reverse/question 1]
└─$ checksec --file=quiz_1
[*] '/home/wanzkey/ARIAF-CTF-2025/Reverse/question 1/quiz_1'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

Semua proteksi modern aktif, namun untuk tantangan reverse engineering sederhana ini, hal tersebut tidak terlalu menjadi masalah.

-----

## Analisis Statis dengan Ghidra

Karena file tidak di-strip, dekompilasi menggunakan Ghidra memberikan hasil yang sangat bersih dan mudah dibaca. Terdapat tiga fungsi utama yang menjadi kunci.

### 1\. Fungsi `main`

Fungsi ini adalah titik masuk program. Logikanya sangat sederhana: memanggil fungsi `ask_and_check()`, dan jika berhasil (mengembalikan nilai bukan 0), ia akan memanggil `decrypt_and_print()`.

```c
int main(void) {
  int iVar1;
  
  puts("Quiz Verification");
  puts("Answer all questions correctly to see the flag.");
  iVar1 = ask_and_check();
  if (iVar1 == 0) {
    puts("Verification failed. Try again.");
  }
  else {
    decrypt_and_print();
  }
  return 0;
}
```

### 2\. Fungsi `ask_and_check`

Ini adalah inti dari kuis. Fungsi ini menghasilkan 10 pertanyaan matematika acak.

```c
int ask_and_check(void) {
  // ... inisialisasi variabel ...
  
  // Mengambil seed dari waktu saat ini dan menginisialisasi rand()
  tVar3 = time((time_t *)0x0);
  seed = (uint)tVar3;
  srand((uint)tVar3);
  
  // Mencetak seed ke layar (PETUNJUK KUNCI!)
  printf("Welcome to quiz verification. You will be asked %d questions.\n",10);
  printf("(Seed: %u)\n",seed);
  
  i = 0;
  do {
    // ...
    
    // Menghasilkan angka dan operator acak
    iVar2 = rand();
    a = iVar2 % 100 + 1;
    iVar2 = rand();
    b = iVar2 % 0x32 + 1; // 0x32 adalah 50
    iVar2 = rand();
    op = iVar2 % 4;
    
    // Logika pertanyaan berdasarkan operator (0:+, 1:-, 2:*, 3:%)
    if (op == 3) {
      correct = (long)(a % b);
      // ...
    }
    // ...
    
    // Membaca input dan membandingkan dengan jawaban yang benar
    __isoc99_scanf(&DAT_001020bc,plVar4);
    if (correct != *(long *)(answers + (long)i * 8)) {
      ok = 0; // Jika salah, set ok menjadi 0
    }
    i = i + 1;
  } while( true );
}
```

**Temuan Kunci**:

1.  Program menggunakan `rand()` untuk membuat soal.
2.  **Seed** untuk `rand()` diambil dari `time()` dan **dicetak ke layar**. Ini berarti kita bisa mereplikasi urutan soal yang sama jika kita tahu seed-nya.

### 3\. Fungsi `decrypt_and_print`

Fungsi ini hanya akan berjalan jika kuis berhasil diselesaikan. Tugasnya adalah mendekripsi dan mencetak flag.

```c
void decrypt_and_print(void) {
  // ... inisialisasi ...
  
  // Loop dekripsi
  for (i = 0; i < 0x13; i = i + 1) { // 0x13 adalah 19
    out[i] = enc_flag[i] ^ KEY[i % 0xd]; // 0xd adalah 13
  }

  // Mencetak flag yang sudah didekripsi
  printf("Good. Here's the flag: %s\n",out);
  // ...
  return;
}
```

**Temuan Kunci**: Flag didekripsi menggunakan **cipher XOR** sederhana. Flag terenkripsi (`enc_flag`) sepanjang 19 byte di-XOR dengan kunci (`KEY`) sepanjang 13 byte.

-----

## Metode Penyelesaian

Berdasarkan analisis, ada dua cara utama untuk mendapatkan flag:

1.  **Ekstrak `enc_flag` dan `KEY` dari Ghidra** lalu lakukan dekripsi XOR secara manual.
2.  **Selesaikan kuisnya**. Karena *seed* diberikan, kita bisa membuat skrip untuk menghasilkan jawaban yang benar.

Pendekatan kedua lebih menarik dan bisa diotomatisasi sepenuhnya. Rencananya adalah membuat skrip Python yang:

1.  Menjalankan binary `quiz_1` secara otomatis.
2.  Menangkap outputnya dan mengekstrak **seed** menggunakan *regular expression*.
3.  Menggunakan *library* `ctypes` untuk memanggil fungsi `srand()` dan `rand()` dari C dengan seed yang sama, sehingga bisa menghasilkan 10 jawaban yang identik dengan soal.
4.  Menjalankan ulang binary `quiz_1`, lalu mengirim semua 10 jawaban sebagai input.
5.  Menangkap output akhir yang berisi flag.

-----

## Skrip Solver

Berikut adalah skrip akhir yang mengimplementasikan metode di atas secara otomatis.

```python
#!/usr/bin/env python3
import ctypes
import subprocess
import re
import sys

# Nama binary target
BINARY_NAME = "./quiz_1"

# === LANGKAH 1: Jalankan binary sekali untuk mengekstrak seed ===
print(f"[*] Menjalankan {BINARY_NAME} untuk mengambil seed...")
try:
    # `subprocess.run` akan menjalankan program, menunggu hingga selesai, dan menangkap outputnya
    p = subprocess.run([BINARY_NAME], input="", text=True, capture_output=True, timeout=5)
except FileNotFoundError:
    print(f"[!] Error: File '{BINARY_NAME}' tidak ditemukan. Pastikan skrip ada di folder yang sama.")
    sys.exit(1)

# Cari baris "(Seed: <angka>)" di output menggunakan regular expression
seed_match = re.search(r"\(Seed: (\d+)\)", p.stdout)
if not seed_match:
    print("[!] Gagal menemukan seed di output program. Pastikan binary berjalan dengan benar.")
    sys.exit(1)

# Ambil angka seed dari hasil pencarian
seed = int(seed_match.group(1))
print(f"[+] Seed berhasil ditemukan: {seed}")


# === LANGKAH 2: Hasilkan 10 jawaban berdasarkan seed yang ditemukan ===
libc = ctypes.CDLL("libc.so.6")
libc.srand(seed)  # Inisialisasi generator angka acak dengan seed yang sama
answers = []

print("[*] Menghasilkan 10 jawaban yang benar...")
for _ in range(10):
    # Ini adalah LOGIKA KHUSUS UNTUK quiz_1
    a = libc.rand() % 100 + 1
    b = libc.rand() % 50 + 1  # 0x32 dalam hex adalah 50
    op = libc.rand() % 4

    if op == 0:
        ans = a + b
    elif op == 1:
        ans = a - b
    elif op == 2:
        ans = a * b
    else:  # op == 3
        ans = a % b
    
    answers.append(str(ans))


# === LANGKAH 3: Jalankan ulang binary dan kirim semua jawaban sekaligus ===
# Gabungkan semua jawaban menjadi satu string, dipisahkan oleh karakter newline (\n)
answer_input = "\n".join(answers) + "\n"

print(f"\n[+] Mengirim semua jawaban ke {BINARY_NAME}...")
# Jalankan ulang program, kali ini dengan semua jawaban sebagai input
result = subprocess.run(
    [BINARY_NAME],
    input=answer_input,
    text=True,
    capture_output=True,
    timeout=5
)


# === LANGKAH 4: Tampilkan output akhir yang berisi flag ===
print("\n[+] Output akhir dari program:")
print("---------------------------------")
# Cari baris yang mengandung flag untuk tampilan yang lebih rapi
flag_found = False
for line in result.stdout.splitlines():
    if "FGTE{" in line:
        print(line)
        flag_found = True
        break

# Jika flag tidak ditemukan dalam format yang diharapkan, cetak semua output
if not flag_found:
    print(result.stdout)
print("---------------------------------")

```

-----

## Eksekusi dan Hasil

Menjalankan skrip `solver.py` akan secara otomatis melakukan semua langkah dan memberikan flag.

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Reverse/question 1]
└─$ python3 solver.py
[*] Menjalankan ./quiz_1 untuk mengambil seed...
[+] Seed berhasil ditemukan: 1759077713
[*] Menghasilkan 10 jawaban yang benar...

[+] Mengirim semua jawaban ke ./quiz_1...

[+] Output akhir dari program:
---------------------------------
Good. Here's the flag: FGTE{Quiz_Mathster}
---------------------------------
```

## Flag

```
FGTE{Quiz_Mathster}
```
