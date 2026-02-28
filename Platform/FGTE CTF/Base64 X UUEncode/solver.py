#!/usr/bin/env python3
import base64
import binascii

def solve():
    print("[*] Solver Base64 X UUEncode")
    
    # 1. Input awal
    ct = "TTFEPTQxN00iODctRS1DMT82JV01NTQ1TjhWXUQ5NV0zPTYtQzk3LVM5RzVMOydFPzEmNUM7VjFFOSIlXQ=="
    
    try:
        # 2. Decode Base64
        print("[*] Decoding Base64...")
        step1 = base64.b64decode(ct).decode('utf-8')
        print(f"    [>] Result: {step1}")
        
        # 3. Decode UUEncode
        print("[*] Decoding UUEncode...")
        # a2b_uu menangani raw line UUEncode
        flag_bytes = binascii.a2b_uu(step1)
        flag = flag_bytes.decode('utf-8')
        
        print("\n" + "="*40)
        print(f"SOLVED FLAG: {flag}")
        print("="*40 + "\n")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
