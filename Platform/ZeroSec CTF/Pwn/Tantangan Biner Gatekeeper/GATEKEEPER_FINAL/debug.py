#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Debug: verifikasi generate_key dengan ltrace data yang diketahui
Dari ltrace kita punya seed dan rand() values untuk session 0x52e895c9
"""

import ctypes, ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library("c"))
def c_srand(seed): libc.srand(ctypes.c_uint(seed))
def c_rand():      return libc.rand()

MOD      = 2**32
MULT     = 0xDEADBEEF
INV_MULT = pow(MULT, -1, MOD)

# Dari ltrace: session_id = 0x52e895c9
# srand dipanggil dengan seed = time ^ pid
# ltrace menunjukkan srand(1771665095) → 1771665095 = 0x699976C7
known_seed = 0x699976C7

# Verifikasi recover:
recovered = (0x52e895c9 * INV_MULT) % MOD
print(f"[*] Known seed    : {hex(known_seed)}")
print(f"[*] Recovered seed: {hex(recovered)}")
print(f"[*] Match         : {known_seed == recovered}")

# rand() values dari ltrace (urutan pertama 32 nilai):
ltrace_rand = [
    1520496079, 1444858788,  51323616, 718655503,
     958803573,  398033340, 1646063838, 1115715371,
    1470608147, 1959404068, 1468613376, 1449935996,
     156207153,  598643820, 1289716844,  832093643,
    1469351681, 2054319201,  594384815,  520199589,
     229717652,  844213750, 1861942081,   63978395,
     808870414, 1199568714,  125273450, 1818576432,
    1779355360, 1661924638, 1089881883, 1152367791,
]

# Test rand() lokal
c_srand(known_seed)
local_rand = [c_rand() for _ in range(32)]

print(f"\n[*] rand() comparison (ltrace vs local libc):")
all_match = True
for i in range(32):
    match = "✓" if ltrace_rand[i] == local_rand[i] else "✗ MISMATCH"
    if ltrace_rand[i] != local_rand[i]:
        all_match = False
    print(f"  [{i:2d}] ltrace={ltrace_rand[i]:12d}  local={local_rand[i]:12d}  {match}")

print(f"\n[*] All rand() match: {all_match}")

if not all_match:
    print("\n[!] rand() berbeda! Glibc version mismatch.")
    print("    Kita perlu reimplementasi manual glibc rand()")
else:
    print("\n[*] rand() identik, masalah di XOR logic")

# ── Test semua variasi XOR ──────────────────────────────────
print("\n[*] Testing XOR variations dengan ltrace rand():")
seed = known_seed

variants = {
    "rand() ^ (seed >> (i & 7))":         lambda r,i: r ^ (seed >> (i & 7)),
    "rand() ^ (seed >> (i % 8))":         lambda r,i: r ^ (seed >> (i % 8)),
    "(rand() & 0xFF) ^ (seed >> (i&7))":  lambda r,i: (r & 0xFF) ^ (seed >> (i & 7)),
    "rand() ^ seed":                       lambda r,i: r ^ seed,
    "(rand() ^ seed) & 0xFF":             lambda r,i: (r ^ seed) & 0xFF,
    "rand() & 0xFF":                       lambda r,i: r & 0xFF,
}

for name, fn in variants.items():
    key = bytearray(32)
    for i in range(32):
        val = fn(ltrace_rand[i], i) & 0xFF
        key[i] = val
    print(f"  {name}")
    print(f"    → {key.hex()}")
EOF
