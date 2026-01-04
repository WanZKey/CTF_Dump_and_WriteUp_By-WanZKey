import ast

def solve():
    # 1. Membaca data dari output.txt
    try:
        with open('output.txt', 'r') as f:
            file_content = f.read()
            data = ast.literal_eval(file_content)
    except FileNotFoundError:
        print("[-] File output.txt tidak ditemukan.")
        return

    print(f"[+] Loaded {len(data)} entries from output.txt")
    
    recovered_bits = ""

    # 2. Iterasi setiap entry untuk recover bit asli
    for i, item in enumerate(data):
        hex_str = item[0]
        given_idx = item[1] # Index error palsu/asli yang diberikan soal

        # Konversi hex ke integer
        val = int(hex_str, 16)
        
        # Konversi ke binary string dan reverse (karena chall.py melakukan flipped[::-1])
        # Kita ambil [2:] untuk membuang '0b'
        bin_str = bin(val)[2:][::-1]

        # Hitung Hamming Syndrome (Posisi Error Sebenarnya)
        calculated_error_pos = 0
        for idx, bit in enumerate(bin_str):
            if bit == '1':
                # Posisi Hamming adalah 1-based
                calculated_error_pos ^= (idx + 1)
        
        # Konversi ke 0-based index python
        real_idx = calculated_error_pos - 1

        # Jika posisi error hasil hitungan SAMA dengan yang di output.txt -> Bit Flag = '1'
        # Jika BEDA -> Bit Flag = '0'
        if real_idx == given_idx:
            recovered_bits += "1"
        else:
            recovered_bits += "0"

    # [FIX] KOREKSI LEADING ZERO
    # Karena bin() di soal menghapus bit '0' di awal (MSB dari huruf 'T'),
    # jumlah bit menjadi ganjil (303 bit). Kita harus menambahkan '0' di depan.
    # TCP1P... -> T (01010100). Bit 0 hilang, jadi kita tambahkan manual.
    pad_length = 8 - (len(recovered_bits) % 8)
    if pad_length != 8:
        recovered_bits = "0" * pad_length + recovered_bits
        print(f"[+] Added {pad_length} bit(s) padding to fix alignment.")

    # 3. Konversi bits ke String ASCII
    flag = ""
    for i in range(0, len(recovered_bits), 8):
        byte = recovered_bits[i:i+8]
        if len(byte) == 8:
            flag += chr(int(byte, 2))

    print(f"[+] Recovered Flag: {flag}")

if __name__ == "__main__":
    solve()
