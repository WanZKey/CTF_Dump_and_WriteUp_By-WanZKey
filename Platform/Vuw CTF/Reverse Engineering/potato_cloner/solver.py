#!/usr/bin/env python3

def solve():
    # Data dari sub_12CF (Child Process)
    # 0x6D754F4B5D050107 overlap dengan 0x516171154D4D616D pada indeks ke-7
    enc_bytes = [
        0x07, 0x01, 0x05, 0x5d, 0x4b, 0x4f, 0x55, # 7 byte pertama
        0x6d, # byte overlap
        0x61, 0x4d, 0x4d, 0x15, 0x71, 0x61, 0x51  # 7 byte sisanya
    ]
    
    flag = ""
    for b in enc_bytes:
        # Step 1: XOR dengan 0xAB
        temp = b ^ 0xAB
        # Step 2: Implementasi sub_11B9 (ceil(temp / 2))
        res = temp - (temp // 2)
        flag += chr(res)
        
    print(f"Flag: {flag}")

if __name__ == "__main__":
    solve()
