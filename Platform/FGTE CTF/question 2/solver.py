#!/usr/bin/env python3
import ctypes
import subprocess
import re

# Jalankan binary dan tangkap seed
p = subprocess.run(["./quiz_2"], input="\n", text=True, capture_output=True)
seed_match = re.search(r"\(Seed: (\d+)\)", p.stdout)
if not seed_match:
    print("Gagal menemukan seed.")
    exit(1)
seed = int(seed_match.group(1))
print(f"[+] Seed ditemukan:", seed)

# Gunakan libc srand/rand
libc = ctypes.CDLL("libc.so.6")
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
        ans = (iVar3 % 100) - (iVar4 % 0x32)
    answers.append(str(ans))

# Jalankan ulang binary dan kirim semua jawaban sekaligus
answer_input = "\n".join(answers) + "\n"
print(f"[+] Mengirim jawaban:\n{answer_input}")
result = subprocess.run(["./quiz_2"], input=answer_input, text=True, capture_output=True)
print(result.stdout)
