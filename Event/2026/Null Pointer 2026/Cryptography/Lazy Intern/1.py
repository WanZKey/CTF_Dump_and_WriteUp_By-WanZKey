#!/usr/bin/env python3
import base64

def solve():
    enc = "w`txwJp$sb8HA2~_@`hJ{zpdza(=+&_l"
    
    print("[*] Hustling Base85 (b85decode)...")
    try:
        flag_b85 = base64.b85decode(enc).decode('utf-8')
        print(f"Result: {flag_b85}")
    except Exception as e:
        print(f"Failed: {e}")

    print("\n[*] Hustling Ascii85 (a85decode)...")
    try:
        flag_a85 = base64.a85decode(enc).decode('utf-8')
        print(f"Result: {flag_a85}")
    except Exception as e:
        print(f"Failed: {e}")

    print("\n[*] Hustling ROT47...")
    rot47_res = []
    for char in enc:
        if 33 <= ord(char) <= 126:
            rot47_res.append(chr(33 + ((ord(char) + 14) % 94)))
        else:
            rot47_res.append(char)
    print(f"Result: {''.join(rot47_res)}")

if __name__ == "__main__":
    solve()
