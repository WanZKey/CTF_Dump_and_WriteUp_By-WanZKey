from pwn import *

def solve_prng():
    r = remote('bad-prng.nc.broncoctf.xyz', 8000)
    enc_hex = r.recvline().strip().decode()
    enc_bytes = bytes.fromhex(enc_hex)

    known = b'bronco{'
    key_start = bytes([a ^ b for a, b in zip(enc_bytes[:7], known)])
    seed = key_start[0]

    for C in range(256):
        key = bytearray(key_start)
        for i in range(7, len(enc_bytes)):
            next_byte = (key[i - 1] + C) % 256
            key.append(next_byte)

        flag = ''.join(chr(enc_bytes[i] ^ key[i]) for i in range(len(enc_bytes)))

        if '}' in flag and all(32 <= ord(c) <= 126 or c in '{}_' for c in flag):
            print(f"[+] C = {C}")
            print(f"[+] FLAG: {flag}")
            break

    r.close()

if __name__ == "__main__":
    solve_prng()
