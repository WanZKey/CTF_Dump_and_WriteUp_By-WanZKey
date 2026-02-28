import unicodedata
import base64

cipher = "=︪ڔౢ︪ɫ൸ծౢݚ卑ɬE൸୞︦神ѡݚ酤"

def analyze_string(s):
    print(f"String Asli: {s}")
    print(f"Panjang: {len(s)} karakter")
    print("-" * 60)
    print(f"{'Char':<5} | {'Codepoint':<10} | {'Category':<5} | {'Name'}")
    print("-" * 60)
    
    for char in s:
        try:
            name = unicodedata.name(char)
        except ValueError:
            name = "UNKNOWN"
        
        # Cetak detail per karakter
        print(f"{char:<5} | {hex(ord(char)):<10} | {unicodedata.category(char):<5} | {name}")

def try_decoding_patterns(s):
    print("\n" + "=" * 60)
    print("[+] Percobaan Pola Sederhana")
    print("-" * 60)
    
    # 1. Cek Reverse (karena ada '=' di depan, siapa tahu itu padding Base64 yang terbalik)
    reversed_s = s[::-1]
    print(f"1. Reverse String: {reversed_s}")
    
    # 2. Cek apakah ini Raw Bytes yang diterjemahkan sebagai UTF-8
    try:
        utf8_bytes = s.encode('utf-8')
        print(f"\n2. Raw Hex (UTF-8 Bytes):")
        print(utf8_bytes.hex())
        print(f"   ASCII Representation (jika ada): {utf8_bytes}")
    except Exception as e:
        print(f"Error encode UTF-8: {e}")

    # 3. Cek Raw Bytes (UTF-16/LE) - Sering digunakan di Windows/Java
    try:
        utf16_bytes = s.encode('utf-16le')
        print(f"\n3. Raw Hex (UTF-16 LE Bytes):")
        print(utf16_bytes.hex())
    except Exception as e:
        print(f"Error encode UTF-16: {e}")

if __name__ == "__main__":
    analyze_string(cipher)
    try_decoding_patterns(cipher)
