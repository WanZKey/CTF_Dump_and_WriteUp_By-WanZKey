#!/usr/bin/env python3
import zipfile

def find_password_hint(zip_path, target_file):
    try:
        with zipfile.ZipFile(zip_path, 'r') as z:
            for info in z.infolist():
                if info.filename == target_file:
                    print(f"Target Found: {info.filename}")
                    print(f"CRC32 (Decimal): {info.CRC}")
                    print(f"CRC32 (Hex): {hex(info.CRC)[2:]}")
                    return info.CRC
    except:
        return None

# Kita harus bongkar lagi sedikit dari layer_1000.zip 
# Tapi tenang bro, kita cuma cari layer_2.zip
print("Searching for layer_1.zip's metadata inside layer_2.zip...")
# Karena layer_2 sudah hilang, kamu bisa ekstrak layer_2.zip manual 
# atau jalankan script solver kamu lagi tapi STOP di layer 2.
