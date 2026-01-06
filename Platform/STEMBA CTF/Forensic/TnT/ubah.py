from PIL import Image
import struct
import math

# Baca file binari
with open("chall.txt", "rb") as f:
    data = f.read()

# Ambil setiap 2-byte (16 bit), endianness LITTLE
words = [int.from_bytes(data[i:i+2], "little") for i in range(0, len(data), 2)]

# Ubah ke bentuk binary string 16-bit, lalu gabungkan semua
bitstream = "".join(f"{w:016b}" for w in words)

# Ubah ke bit list dan BALIKKAN (0 -> 1, 1 -> 0)
bits = [1 - int(b) for b in bitstream]

# Hitung ukuran gambar (asumsi persegi)
length = len(bits)
size = int(math.sqrt(length))
print(f"Gambar ukuran: {size}x{size}")

# Pangkas bit sesuai ukuran
bits = bits[:size*size]

# Buat gambar 1-bit
img = Image.new("1", (size, size))
img.putdata(bits)
img = img.transpose(Image.FLIP_TOP_BOTTOM)
img.save("output.png")
print("[+] Gambar disimpan sebagai output.png")
