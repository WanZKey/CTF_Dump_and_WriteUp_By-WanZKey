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
