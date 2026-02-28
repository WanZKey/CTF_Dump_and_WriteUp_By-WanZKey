import re

def solve():
    filename = "referensi.txt"
    
    try:
        with open(filename, "r") as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] File {filename} tidak ditemukan.")
        return

    # PERBAIKAN: Gunakan Regex untuk mengambil hanya kata (alfanumerik).
    # Ini akan membuang '#', '---', '.', ',' dan spasi secara otomatis.
    words = re.findall(r"[a-zA-Z0-9]+", content)
    
    # Target indeks dari soal
    indices = [234, 235, 1, 237, 238]
    
    flag_parts = []
    
    print(f"[+] Total kata bersih ditemukan: {len(words)}")
    
    for idx in indices:
        # Konversi ke index 0 (Python start dari 0)
        py_idx = idx - 1
        
        if 0 <= py_idx < len(words):
            found_word = words[py_idx]
            flag_parts.append(found_word)
            print(f"Index {idx}: {found_word}")
        else:
            print(f"Index {idx} OUT OF RANGE!")

    # Susun Flag
    flag_content = "_".join(flag_parts)
    print(f"\n[+] Flag Result: FGTE{{{flag_content}}}")

if __name__ == "__main__":
    solve()
