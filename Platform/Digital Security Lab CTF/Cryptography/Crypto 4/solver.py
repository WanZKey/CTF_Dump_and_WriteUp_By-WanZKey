import requests
import json
from Crypto.Util.number import long_to_bytes
from pwn import xor

# URL Target
URL = "http://practice-digitalsecuritylab.di.unipi.it:11004/api/dh_exchange/"

# Parameter Diffie-Hellman (Dari saran soal)
P_STR = "101264875096291756590724160710266238607742308517803523368410730143610813157544871108800681242310021754893641284891313106040348046843467119852986330168576405484604905473258559094972474777116950163245724407474846725895361246270063255973321572589185857691867743767640291346478044611088448612145846051361865736827"
P = int(P_STR)
G = 2

def solve():
    print("[*] Memulai serangan Diffie-Hellman Parameter Injection...")

    # Kita set A = G. 
    # Server menghitung Shared Key (k) = A^b mod p
    # Karena A = G, maka k = G^b mod p
    # G^b mod p ADALAH nilai B (Public Key Server) yang dikirim balik ke kita.
    # Jadi, Shared Key (k) == B
    
    payload = {
        "p": P,
        "g": G,
        "A": G  # Vulnerability exploit
    }

    print(f"[+] Mengirim A = {G}...")
    try:
        response = requests.post(URL, json=payload)
        data = response.json()

        if "error" in data:
            print(f"[-] Error Server: {data['error']}")
            return

        # Ambil data respon
        enc_flag_hex = data['enc_flag']
        server_public_B = int(data['B'])
        
        print(f"[+] Terima Encrypted Flag (Hex): {enc_flag_hex}")
        print(f"[+] Terima Public Key Server (B): {server_public_B}")

        # Dekripsi
        # Kunci dekripsi adalah B itu sendiri
        key_bytes = long_to_bytes(server_public_B)
        enc_flag_bytes = bytes.fromhex(enc_flag_hex)
        
        # Karena zip() di python berhenti di panjang terpendek,
        # dan Flag pasti lebih pendek dari Key (B adalah 1024 bit / 128 bytes),
        # maka kita bisa langsung XOR.
        flag = xor(enc_flag_bytes, key_bytes[:len(enc_flag_bytes)])

        print("\n[+] Hasil Dekripsi:")
        print(flag.decode())

    except Exception as e:
        print(f"[-] Terjadi kesalahan: {e}")

if __name__ == "__main__":
    solve()
