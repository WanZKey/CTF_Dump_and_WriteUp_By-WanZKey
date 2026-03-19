#!/usr/bin/env python3
import struct

def solve():
    # Data dari blok REAL FLAG (v4, v5, v6)
    v4 = 0x6B211C0E192D2F0C
    v5 = 0x3F2E05693705292E
    v6 = 0x273D3B6B3C0532 # 7 bytes

    # Packing data menjadi byte array dengan format Little Endian (<)
    # v6 dipack sebagai QWORD (8 bytes) lalu diambil 7 byte pertamanya agar sesuai
    raw_bytes = struct.pack('<Q', v4) + struct.pack('<Q', v5) + struct.pack('<Q', v6)[:7]
    
    key = 90 # 0x5A
    flag = ""
    
    # Decrypt dengan operasi XOR
    for b in raw_bytes:
        flag += chr(b ^ key)
        
    print(f"Flag: {flag}")

if __name__ == "__main__":
    solve()
