#!/usr/bin/env python3
def solve():
    enc = "Y(XBYhJ_U*z)k^_)m( eJDU)N+B+G*F"
    
    print("[*] Hustling All ASCII Shifts (32-126 range)...")
    for shift in range(1, 95):
        res = ""
        for char in enc:
            if 32 <= ord(char) <= 126:
                # Shifting within the printable ASCII range
                res += chr(32 + (ord(char) - 32 - shift) % 95)
            else:
                res += char
        if "STURSEC" in res.upper():
            print(f"[+] Found with Shift {shift}: {res}")

    print("\n[*] Hustling Vigenere with key '25' (Numerical shifts 2 and 5)...")
    key = [2, 5]
    res_vig = ""
    for i, char in enumerate(enc):
        res_vig += chr(ord(char) - key[i % 2])
    print(f"Result: {res_vig}")

    print("\n[*] Hustling Vigenere with key '25' (Numerical shifts 25 and 25)...")
    res_vig2 = ""
    for char in enc:
        res_vig2 += chr((ord(char) - 25) % 256)
    print(f"Result: {res_vig2}")

if __name__ == "__main__":
    solve()
