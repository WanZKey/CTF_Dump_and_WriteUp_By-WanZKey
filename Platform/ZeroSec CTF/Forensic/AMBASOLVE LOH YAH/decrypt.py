#!/usr/bin/env python3
def solve():
    print("[*] Decrypting hidden comment data...")
    
    # Angka desimal panjang yang ditemukan oleh zsteg
    secret_decimal = 145261217193339700092274108114674177042872914472564540419893373
    
    try:
        # Convert Long Integer ke Bytes
        # Menghitung jumlah byte yang dibutuhkan, lalu diubah ke format big-endian
        flag_bytes = secret_decimal.to_bytes((secret_decimal.bit_length() + 7) // 8, 'big')
        
        # Decode bytes ke string utf-8
        flag = flag_bytes.decode('utf-8')
        
        print("[+] Message decoded successfully!")
        print("FLAG :", flag)
        
    except Exception as e:
        print("[-] Oops, something went wrong:", e)

if __name__ == "__main__":
    solve()
