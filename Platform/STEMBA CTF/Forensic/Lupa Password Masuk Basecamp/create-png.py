from PIL import Image
import numpy as np

# Load kedua gambar
img1 = Image.open("gmbr1.bmp")
img2 = Image.open("gmbr2.bmp")

# Konversi ke array numpy
arr1 = np.array(img1)
arr2 = np.array(img2)

# XOR pixel-by-pixel
result = np.bitwise_xor(arr1, arr2)

# Buat gambar baru dari hasil XOR
result_img = Image.fromarray(result)

# Simpan hasilnya
result_img.save("gabungan.png")
