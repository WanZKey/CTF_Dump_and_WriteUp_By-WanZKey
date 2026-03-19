#!/usr/bin/env python3
import re
from Crypto.Util.number import long_to_bytes

# Fungsi untuk mencari akar pangkat tiga (cube root) dari sebuah integer
def integer_cube_root(n):
    low = 0
    high = n
    while low < high:
        mid = (low + high) // 2
        if mid**3 < n:
            low = mid + 1
        else:
            high = mid
    return low

def solve():
    try:
        # Load output.txt dengan mode 'rb' agar clean
        with open("output.txt", "rb") as f:
            content = f.read().decode('utf-8')
        
        # Ekstrak nilai c menggunakan regex (kita hanya butuh c untuk cube root attack)
        c_match = re.search(r'c=(\d+)', content)
        
        if c_match:
            c = int(c_match.group(1))
            print("[*] Berhasil mengekstrak nilai c dari output.txt.")
            print("[*] Melakukan eksekusi Cube Root Attack...")
            
            # Mendapatkan plaintext integer m dari ciphertext c
            m = integer_cube_root(c)
            
            # Validasi apakah m^3 benar-benar sama dengan c (perfect cube)
            if m**3 == c:
                # Mengubah integer kembali menjadi string/bytes
                flag = long_to_bytes(m).decode('utf-8')
                print("[*] Dekripsi berhasil!")
                print(f"[*] Flag : {flag}")
            else:
                print("[!] Dekripsi gagal. c bukan perfect cube.")
        else:
            print("[!] Gagal menemukan nilai c di dalam file output.txt.")
            
    except FileNotFoundError:
        print("[!] File output.txt tidak ditemukan. Pastikan ada di direktori yang sama.")
    except Exception as e:
        print(f"[!] Terjadi error: {e}")

if __name__ == '__main__':
    solve()
