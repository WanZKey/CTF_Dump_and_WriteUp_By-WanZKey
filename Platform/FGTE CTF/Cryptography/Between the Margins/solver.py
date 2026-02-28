import re

def solve():
    filename = "referensi.txt"
    
    try:
        with open(filename, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] File {filename} tidak ditemukan.")
        return

    # Menggunakan Regex untuk mengambil hanya kata-kata (alfanumerik)
    # Ini otomatis membuang '#', tanda baca, dan spasi
    words = re.findall(r"[a-zA-Z0-9]+", content)
    
    # Target indeks dari soal
    indices = [234, 235, 1, 237, 238]
    
    flag_parts = []
    
    print(f"[+] Total kata bersih ditemukan: {len(words)}")
    
    for idx in indices:
        # Konversi ke index 0 (Python list dimulai dari 0)
        py_idx = idx - 1
        
        if 0 <= py_idx < len(words):
            found_word = words[py_idx]
            flag_parts.append(found_word)
            print(f"Index {idx}: {found_word}")
        else:
            print(f"Index {idx} OUT OF RANGE!")

    # Susun kata-kata dengan pemisah underscore
    # Gunakan .upper() untuk mengubah menjadi Huruf Besar Semua
    flag_content = "_".join(flag_parts).upper()
    
    print(f"\n[+] Flag Result: FGTE{{{flag_content}}}")

if __name__ == "__main__":
    solve()
