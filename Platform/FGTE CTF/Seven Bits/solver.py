#!/usr/bin/env python3
def solve():
    print("[*] Solver Seven Bits")
    
    # Input Binary
    binary_data = "1111100 0110000 0110111 1110111 0110001 1101110 0001000 0000111 0001000 0111111 0000110"
    chunks = binary_data.split()
    
    # Mapping Manual (Biner -> Karakter)
    # Berdasarkan visualisasi 7-segment (gfedcba)
    segment_map = {
        "1111100": "b",
        "0110000": "1", # Left-aligned 1 or 'l'
        "0110111": "n",
        "1110111": "A",
        "0110001": "r",
        "1101110": "y",
        "0001000": "_",
        "0000111": "7",
        "0111111": "0",
        "0000110": "1"  # Right-aligned 1
    }
    
    decoded = ""
    for chunk in chunks:
        if chunk in segment_map:
            decoded += segment_map[chunk]
        else:
            decoded += "?"
            
    print(f"Decoded String: {decoded}")
    print(f"Flag Format   : FGTE{{{decoded}}}")

if __name__ == "__main__":
    solve()
