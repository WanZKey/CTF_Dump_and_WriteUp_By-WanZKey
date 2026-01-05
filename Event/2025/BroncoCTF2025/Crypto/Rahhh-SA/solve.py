from Crypto.Util.number import long_to_bytes
from sympy import mod_inverse

# Diberikan
e = 65537
n = 3429719
c = [-53102, -3390264, -2864697, -3111409, -2002688, -2864697, -1695722, -1957072, -1821648, -1268305, -3362005, -712024, -1957072, -1821648, -1268305, -732380, -2002688, -967579, -271768, -3390264, -712024, -1821648, -3069724, -732380, -892709, -271768, -732380, -2062187, -271768, -292609, -1599740, -732380, -1268305, -712024, -271768, -1957072, -1821648, -3418677, -732380, -2002688, -1821648, -3069724, -271768, -3390264, -1847282, -2267004, -3362005, -1764589, -293906, -1607693]

# Asumsi p positif
p = 811
q = n // p
assert p * q == n

# Hitung phi(n)
phi = (p - 1) * (q - 1)

# Cari private key d
d = mod_inverse(e, phi)

# Dekripsi
flag = ""
for i in c:
    if i < 0:
        i = n + i
    m = pow(i, d, n)
    flag += long_to_bytes(m).decode(errors='ignore')

print(f"Flag: {flag}")
