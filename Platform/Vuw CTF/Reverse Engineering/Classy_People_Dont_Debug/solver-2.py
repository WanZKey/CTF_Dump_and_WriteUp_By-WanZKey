#!/usr/bin/env python3
with open('Classy', 'rb') as f:
    f.seek(0x4120)
    data_404120 = f.read(64)
    f.seek(0x4180)
    data_404180 = f.read(200)

flag = []
for i in range(33):
    lookup_val = data_404180[i * 6]
    val1 = (193 + i * 13) & 0xFF
    val2 = (163 + i * 5) & 0xFF
    val3 = data_404120[i % 64]
    char = lookup_val ^ val1 ^ val2 ^ val3
    flag.append(chr(char))

print(''.join(flag))
