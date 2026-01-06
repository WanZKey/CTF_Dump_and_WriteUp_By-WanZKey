import numpy as np

# 1. Masukkan 134 integer dari alamat 0x7fd320 ke sini
# (Ini hanya contoh, Anda HARUS mendapatkannya dari Ghidra)
C_target_list = [
    54, 126, 216, 288, 360, 468, 558, 648, 649, 586, 584, 522, 
    523, 604, 638, 597, 613, 640, 684, 729, 693, 730, 720, 684, 
    648, 612, 576, 540, 568, 568, 597, 577, 557, 537, 517, 497, 
    477, 457, 437, 453, 532, 584, 618, 588, 587, 586, 585, 584, 
    583, 582, 581, 570, 612, 636, 612, 613, 640, 684, 729, 693, 
    730, 720, 684, 648, 612, 576, 540, 568, 568, 597, 577, 557, 
    537, 517, 497, 477, 457, 437, 453, 532, 584, 618, 588, 587, 
    586, 585, 584, 583, 582, 581, 570, 612, 636, 612, 613, 640, 
    684, 729, 693, 730, 720, 684, 648, 612, 576, 540, 504, 521, 
    538, 555, 572, 589, 606, 623, 640, 657, 674, 621, 600, 516, 
    518, 520, 477, 450, 405, 360, 315, 270, 225, 180, 135, 90, 
    45, 18, 24, 0
]
C_target = np.array(C_target_list, dtype=np.int64)

# 2. Definisikan Polinomial Q
Q_list = [9, 8, 7, 6, 5, 4, 3, 2, 1]
Q = np.array(Q_list, dtype=np.int64)

# 3. Lakukan dekonvolusi
# Kita membalik array (np.flip) karena numpy.polydiv memperlakukan
# elemen pertama sebagai koefisien pangkat tertinggi.
# Program ini menyimpannya dari pangkat terendah (indeks 0).
P_reversed, remainder = np.polydiv(np.flip(C_target), np.flip(Q))

# Balikkan hasilnya kembali ke urutan semula dan ubah ke integer
P = np.flip(P_reversed).astype(int)

# 4. Verifikasi dan Rekonstruksi Flag
print(f"Panjang Polinomial P: {len(P)}")
print(f"Padding di akhir P: {P[-3:]}")

# Harusnya [2, 3, 0]
if list(P[-3:]) != [2, 3, 0]:
    print("Error: Dekonvolusi gagal atau C_target salah.")
else:
    # Ambil 123 koefisien pertama (41 karakter * 3)
    coeffs = P[:123]
    
    flag = ""
    for i in range(0, 123, 3):
        # Balikkan transformasi: c = d0 + (d1 * 10) + (d2 * 100)
        p0 = coeffs[i]
        p1 = coeffs[i+1]
        p2 = coeffs[i+2]
        
        ascii_val = p0 + (p1 * 10) + (p2 * 100)
        flag += chr(ascii_val)
        
    print(f"\nFlag: {flag}")
