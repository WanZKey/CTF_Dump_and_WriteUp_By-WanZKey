from pwn import *

# Set log level
context.log_level = 'info'

# Start process
io = process('./chall')

# Flag yang ditemukan dari IDA Pro
key = "flag{c0mpil4t1on_is_n0t_3ncrypt1on}"

# Tunggu sampai program meminta input
io.recvuntil(b"Enter the key: ")

# Kirim flag
io.sendline(key.encode())

# Terima respon
output = io.recvline().decode().strip()
print(f"Server Response: {output}")

if "That's it!" in output:
    print("[+] Flag accepted!")
else:
    print("[-] Flag rejected.")

io.close()
