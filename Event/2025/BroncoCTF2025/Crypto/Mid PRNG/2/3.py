from pwn import xor

ciphertexts = [
    "55d780a3045ae4edfc9a7e99b40a91cd83bac87f14412b60",
    "7b398ecd8ad44aa3d274b0f7fac4bf432d5446111a4f052e",
    # masukkan semua ciphertext lainnya
]

# Misal kamu tahu keystream dari ciphertext pertama
keystream_hex = "26725602061236dafea2466a8e32d6fa9ec2e68ac0f6ac62"

for cipher in ciphertexts:
    cipher_bytes = bytes.fromhex(cipher)
    keystream = bytes.fromhex(keystream_hex)[:len(cipher_bytes)]
    plaintext = xor(cipher_bytes, keystream)
    print(f"Plaintext for {cipher}: {plaintext}")
