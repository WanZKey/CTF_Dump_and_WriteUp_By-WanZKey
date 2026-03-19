#!/usr/bin/env python3
import binascii

def solve():
    enc = "簾簼 簾簽 簾簾 簾簻 簾簼 簽簾 簽簼 籀籫 簿簽 簿簿 簿簿 簿籀 簿籬 簿籯 簼簹 簼簹 簼籂 簼籁 籀籭"
    
    print("[*] Hustling Custom Shift (0x7C09)...")
    hex_str = ""
    
    # Hilangin spasi dan balikin ke hex awal
    for char in enc.replace(" ", ""):
        # Kurangi code point dengan offset custom dari author
        hex_str += chr(ord(char) - 0x7C09)
        
    print(f"[*] Recovered Hex: {hex_str}")
    
    print("\n[*] Hustling Hex to ASCII decode...")
    try:
        flag = binascii.unhexlify(hex_str).decode('utf-8')
        print(f"[+] Decoded Flag: {flag}")
    except Exception as e:
        print(f"[-] Failed: {e}")

if __name__ == "__main__":
    solve()
