with open("gmbr1.bmp", "rb") as f1, open("gmbr2.bmp", "rb") as f2:
    data1 = f1.read()
    data2 = f2.read()

# XOR kedua file
xor_result = bytes([b1 ^ b2 for b1, b2 in zip(data1, data2)])

# Simpan hasilnya
with open("result_xor.bin", "wb") as f:
    f.write(xor_result)
