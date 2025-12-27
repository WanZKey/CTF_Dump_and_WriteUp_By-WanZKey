import struct

filename = "fix_it.png"

# Signature PNG standar
png_signature = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'

# Dimensi Target (400x400)
# 'I' format untuk unsigned int (4 bytes), big-endian (>)
width = struct.pack('>I', 400)
height = struct.pack('>I', 400)

with open(filename, 'r+b') as f:
    # 1. Perbaiki Magic Bytes (Offset 0)
    print(f"[*] Fixing Magic Bytes at offset 0...")
    f.seek(0)
    f.write(png_signature)
    
    # 2. Perbaiki Width (Offset 16)
    # Header IHDR mulai di offset 8.
    # Length (4) + Type (4) = 8 bytes. Jadi data IHDR mulai offset 16.
    print(f"[*] Fixing Width to 400 at offset 16...")
    f.seek(16)
    f.write(width)
    
    # 3. Perbaiki Height (Offset 20)
    print(f"[*] Fixing Height to 400 at offset 20...")
    f.seek(20)
    f.write(height)

print("[+] Selesai! Coba buka gambar fix_it.png sekarang.")
