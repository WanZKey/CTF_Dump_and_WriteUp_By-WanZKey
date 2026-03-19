#!/usr/bin/env python3
from pwn import *
import ctypes

def main():
    # Setup libc bawaan sistem dan pastikan tipe datanya pakai unsigned int
    libc = ctypes.CDLL("libc.so.6")
    libc.srand.argtypes = [ctypes.c_uint]
    libc.srand.restype = None
    libc.rand.argtypes = []
    libc.rand.restype = ctypes.c_int

    # Jalankan binary
    p = process('./challenge')

    # Tangkap Session ID
    p.recvuntil(b"Session ID: ")
    session_id_hex = p.recvline().strip().decode()
    session_id = int(session_id_hex, 16)
    log.info(f"Got Session ID: {session_id_hex}")

    # Kalkulasi Modular inverse dari 0xDEADBEEF mod 2^32 yang 100% presisi
    inverse = pow(0xDEADBEEF, -1, 1 << 32)
    seed = (session_id * inverse) & 0xFFFFFFFF
    log.info(f"Calculated Seed (v2): {hex(seed)}")

    # Set seed
    libc.srand(seed)

    # Generate 32 bytes key
    key_bytes = []
    for i in range(32):
        r = libc.rand()
        shift_val = (seed >> (i & 7)) & 0xFFFFFFFF
        byte_val = (r ^ shift_val) & 0xFF
        key_bytes.append(byte_val)

    hex_key = "".join(f"{b:02x}" for b in key_bytes)
    log.info(f"Generated Hex Key: {hex_key}")

    # Kirim key
    p.recvuntil(b"Key: ")
    p.sendline(hex_key.encode())

    # Masuk ke shell
    p.interactive()

if __name__ == "__main__":
    main()
