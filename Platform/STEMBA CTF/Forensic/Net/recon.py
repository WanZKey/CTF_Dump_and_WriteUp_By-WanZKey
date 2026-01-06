import re

data = """
example4comFexample8comB1 example12comG0  example16com03  example20comfW  example24comhH  example28com61  example32comUD  example36comz1  example40comyG  example44commW  example48comfG  example52comlS  example56com9=
"""

# Temukan semua pola dengan karakter ganda (bisa angka atau huruf)
matches = re.findall(r'example(\d+)com([a-zA-Z0-9=]{1,2})', data)

# Convert ke (index, karakter)
pairs = []
for index, chars in matches:
    for i, c in enumerate(chars):
        pairs.append((int(index) + i, c))

# Urutkan dan susun flag
ordered = sorted(pairs)
flag = ''.join(char for _, char in ordered)

print(f"[+] Flag: STEMBACTF{{{flag}}}")
