#!/usr/bin/env python3
import os
import re
import subprocess

def solve():
    folder = "serpihankode"
    cache_file = "scanned_full.txt"
    full_text = ""

    # Cek apakah sudah ada file cache biar gak usah scan dari awal
    if os.path.exists(cache_file):
        print(f"[*] Ketemu file {cache_file}, ngebaca dari sini biar cepet bro...")
        with open(cache_file, "r") as f:
            full_text = f.read()
    else:
        if not os.path.exists(folder):
            print("[-] Folder 'serpihankode' gak ketemu.")
            return
        
        files = [f for f in os.listdir(folder) if f.endswith('.png')]
        # Sortir numerik secara akurat
        files.sort(key=lambda x: int(re.sub(r'\D', '', x)))
        
        print(f"[*] Melakukan scanning {len(files)} QR codes dan menyimpan hasilnya...")
        for f in files:
            filepath = os.path.join(folder, f)
            result = subprocess.run(['zbarimg', '-q', '--raw', filepath], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            if result.stdout:
                full_text += result.stdout.decode('utf-8').strip()
                
        # Simpan full text ke file cache
        with open(cache_file, "w") as f:
            f.write(full_text)
        print(f"[+] Scan selesai! Teks disimpan ke {cache_file}")

    print(f"\n[*] Total panjang karakter: {len(full_text)}")
    
    # Mencoba faktor pembagi dari 1254 untuk membentuk ASCII Art
    dimensions = [(19, 66), (22, 57), (33, 38), (38, 33), (57, 22), (66, 19)]
    
    print("[*] Menyusun ulang menjadi ASCII Art...\n")
    
    for rows, cols in dimensions:
        print(f"==================================================")
        print(f"=== Dimensi: {cols} Kolom x {rows} Baris ===")
        print(f"==================================================\n")
        
        for i in range(rows):
            # Potong string berdasarkan lebar kolom
            baris_text = full_text[i*cols : (i+1)*cols]
            print(baris_text)
        print("\n")

if __name__ == "__main__":
    solve()
