#!/usr/bin/env python3
import base64
import codecs

def solve():
    enc = "w`txwJp$sb8HA2~_@`hJ{zpdza(=+&_l"
    
    print("[*] Hustling ROT47...")
    rot47_res = []
    for char in enc:
        if 33 <= ord(char) <= 126:
            rot47_res.append(chr(33 + ((ord(char) + 14) % 94)))
        else:
            rot47_res.append(char)
    step1 = ''.join(rot47_res)
    print(f"ROT47 Output: {step1}")

    print("\n[*] Hustling ROT13 on the ROT47 output...")
    step2 = codecs.encode(step1, 'rot_13')
    print(f"ROT13 Output: {step2}")

    print("\n[*] Hustling Base64 decode on the final output...")
    try:
        flag = base64.b64decode(step2).decode('utf-8')
        print(f"Result: {flag}")
    except Exception as e:
        print(f"Failed: {e}")

if __name__ == "__main__":
    solve()
