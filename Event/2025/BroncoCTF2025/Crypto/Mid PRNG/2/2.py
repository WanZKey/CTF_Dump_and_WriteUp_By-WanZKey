from pwn import *

def collect_ciphertexts(n):
    samples = []
    for _ in range(n):
        r = remote('bad-prng.nc.broncoctf.xyz', 8000)
        enc_hex = r.recvline().strip().decode()
        samples.append(enc_hex)
        r.close()
        print(enc_hex)
    
    with open("ciphertexts.txt", "w") as f:
        for sample in samples:
            f.write(sample + "\n")

if __name__ == "__main__":
    collect_ciphertexts(20)
