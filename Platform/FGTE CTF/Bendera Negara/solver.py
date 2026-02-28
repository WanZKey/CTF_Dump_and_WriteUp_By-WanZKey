#!/usr/bin/env python3
def solve():
    # Data mentah dari soal
    raw_data = "char(77)karakter(52)char(82)char(49)char(49)char(84)char(49)char(77)char(51)char(53)char(49)char(71)char(78)char(52)char(76)char(53)char(67)char(48)char(68)char(51)char(52)char(78)char(68)char(78)char(52)char(55)char(79)char(52)char(76)char(80)char(72)char(52)char(66)char(51)char(55)"
    
    # Normalisasi 'karakter' menjadi 'char'
    normalized_data = raw_data.replace("karakter", "char")
    
    # Ekstrak angka dalam kurung
    import re
    ascii_codes = re.findall(r'char\((\d+)\)', normalized_data)
    
    # Convert ke karakter
    decoded_chars = [chr(int(code)) for code in ascii_codes]
    decoded_string = "".join(decoded_chars)
    
    print(f"Decoded String: {decoded_string}")
    
    # Manual formatting suggestion based on Leetspeak reading
    # M4R11T1M3 51GN4L5 C0D3 4ND N47O 4LPH4B37
    print(f"Flag Format   : FGTE{{{decoded_string[:9]}_{decoded_string[9:16]}_{decoded_string[16:20]}_{decoded_string[20:23]}_{decoded_string[23:27]}_{decoded_string[27:]}}}")

if __name__ == "__main__":
    solve()
