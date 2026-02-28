import sys

def solve():
    filename = "ASING.txt"
    
    # 1. Load File
    # Gue baca sebagai utf-8 biar karakternya kebaca bener buat di-ROT
    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read().strip()
    except FileNotFoundError:
        print(f"File {filename} ga ada bro.")
        return

    print(f"[+] File loaded. Panjang: {len(content)}")

    # 2. Decode ROT8000
    # Geser codepoint sebanyak 0x8000 (32768)
    rotated_string = ""
    for char in content:
        val = ord(char)
        # Operasi ROT8000: (char + 0x8000) % 0x10000
        new_val = (val + 0x8000) % 0x10000
        rotated_string += chr(new_val)
    
    print("[+] ROT8000 Done.")

    # 3. Base 65536 Decode
    # Ubah setiap karakter jadi 2 bytes (Big Endian)
    flag_bytes = bytearray()
    for char in rotated_string:
        val = ord(char)
        flag_bytes.extend(val.to_bytes(2, byteorder='big'))

    print("[+] Base65536 Done.")
    
    # 4. Output Flag
    print("\n" + "="*30)
    print("RESULT:")
    try:
        # Coba tampilin sebagai string
        print(flag_bytes.decode('utf-8'))
    except:
        # Kalau ada byte aneh, tampilin raw-nya
        print(flag_bytes)
    print("="*30)

if __name__ == "__main__":
    solve()
