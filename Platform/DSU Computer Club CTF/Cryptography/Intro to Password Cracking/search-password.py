import hashlib
import os

# Target Hash: Whirlpool
target_hash = "3f75894e753e2cf0f23f72bef6806c8757b167a62074de5743570149d4893179a7fbf5ca6613fdd1f09dd88688c5d097c41255ff08083c22f871712a9d1ee9d6"

def solve():
    filename = "wordlist.txt"
    print(f"[*] Membaca file {filename}...")
    
    if not os.path.exists(filename):
        print(f"[-] Error: File {filename} belum didownload! Jalanin wget dulu.")
        return

    # Baca file line by line
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        # Ambil setiap baris, hilangkan spasi/newline
        animals = [line.strip() for line in f if line.strip()]

    print(f"[*] Total {len(animals)} nama hewan dimuat.")
    print("[*] Memulai cracking Whirlpool... (Sabar ya)")

    if 'whirlpool' not in hashlib.algorithms_available:
        print("[-] Error: Algoritma 'whirlpool' tidak didukung di Python ini.")
        return

    for animal in animals:
        # Kita coba 3 variasi casing untuk setiap nama hewan:
        # 1. Persis sesuai file (biasanya lowercase) -> "aardvark"
        # 2. Huruf depan besar (Title) -> "Aardvark"
        # 3. Huruf besar semua (Upper) -> "AARDVARK"
        variations = list(set([animal, animal.lower(), animal.capitalize(), animal.upper()]))
        
        for base in variations:
            # Brute force 3 digit angka (000 - 999)
            for i in range(1000):
                suffix = f"{i:03d}"
                candidate = base + suffix
                
                # Proses Hashing Whirlpool
                h = hashlib.new('whirlpool')
                h.update(candidate.encode('utf-8'))
                result = h.hexdigest()
                
                if result == target_hash:
                    print(f"\n[+] KETEMU BRO!!! AKHIRNYA!")
                    print(f"========================================")
                    print(f"[+] Animal      : {base}")
                    print(f"[+] Digits      : {suffix}")
                    print(f"[+] PASSWORD    : {candidate}")
                    print(f"========================================")
                    print(f"[+] FLAG FINAL  : DSU{{{candidate}}}")
                    print(f"========================================")
                    return

    print("[-] Masih belum ketemu di list ini. Coba cek lagi variasi namanya.")

if __name__ == "__main__":
    solve()
