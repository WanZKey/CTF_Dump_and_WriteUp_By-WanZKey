from os import getenv
from Crypto.Util.number import getPrime, bytes_to_long

p = getPrime(2048)
q = getPrime(2048)
n = p * q
e = 3
flag = bytes(getenv("FLAG"), "utf8") # VuwCTF{XXXXXXXX}
c = pow(bytes_to_long(flag), e, n)
print(f"{n=}, {e=}")
print(f"{c=}")
