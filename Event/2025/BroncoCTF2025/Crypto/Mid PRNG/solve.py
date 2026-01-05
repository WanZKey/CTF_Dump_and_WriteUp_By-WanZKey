from pwn import *
r = remote('bad-prng.nc.broncoctf.xyz', 8000)
c = bytes.fromhex(r.recvall().strip().decode())
r.close()
next = c[0] ^ ord("b")
flag = "b"
for el in c[1:]:
    next = (next*3)%256
    flag += chr(next ^ el)
print(flag)
