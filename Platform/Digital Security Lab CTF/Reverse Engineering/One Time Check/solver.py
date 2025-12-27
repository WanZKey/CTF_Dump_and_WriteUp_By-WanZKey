from pwn import *

# Muat file binary
elf = ELF('./chall')

try:
    # Ambil alamat dari simbol 'key' dan 'enc_flag'
    # Karena binary tidak di-strip, simbol ini tersedia.
    key_addr = elf.symbols['key']
    enc_flag_addr = elf.symbols['enc_flag']

    # Baca data dari alamat tersebut sebanyak 33 byte (sesuai panjang loop)
    # Kita menggunakan elf.read(alamat, jumlah_byte)
    key_data = elf.read(key_addr, 33)
    enc_flag_data = elf.read(enc_flag_addr, 33)

    # Lakukan operasi XOR untuk mendapatkan flag asli
    # flag = key ^ enc_flag
    flag = xor(key_data, enc_flag_data)

    # Cetak hasil
    print(f"Flag found: {flag.decode('utf-8')}")

except Exception as e:
    print(f"Error: {e}")
