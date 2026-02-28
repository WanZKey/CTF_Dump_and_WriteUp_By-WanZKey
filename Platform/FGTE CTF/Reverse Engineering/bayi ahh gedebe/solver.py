#!/usr/bin/env python3
# Solver untuk menghitung nilai desimal dari Hex EAX
eax_hex = 0x8793

print(f"[*] Hex Value (EAX): {hex(eax_hex)}")
print(f"[*] Decimal Value  : {eax_hex}")
print(f"[+] Flag: FGTE{{{eax_hex}}}")
