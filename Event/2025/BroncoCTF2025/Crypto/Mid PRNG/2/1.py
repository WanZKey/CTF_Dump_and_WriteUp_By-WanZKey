from pwn import *

def solve_prng():
    # Connect ke server
    r = remote('bad-prng.nc.broncoctf.xyz', 8000)

    # Ambil output hex dari server
    enc_hex = r.recvline().strip().decode()
    print(f"Received hex: {enc_hex}")

    # Convert hex ke bytes
    enc_bytes = bytes.fromhex(enc_hex)

    # Kita tahu bahwa flag dimulai dengan 'bronco{'
    known = b'bronco{'

    # Dapatkan 7 byte pertama dari key dengan XOR
    key_start = bytes([a ^ b for a, b in zip(enc_bytes[:7], known)])
    print(f"First 7 bytes of key: {key_start.hex()}")

    # Build keystream
    key = bytearray(key_start)

    # Cari differences yang pasti dari 7 byte awal
    key_differences = []
    for i in range(len(key) - 1):
        key_differences.append(key[i + 1] - key[i])

    # Lanjutkan prediksi keystream
    for i in range(7, len(enc_bytes)):
        next_byte = (key[-1] + key_differences[-1]) % 256
        key.append(next_byte)
        key_differences.append(next_byte - key[-2])

        # Cek apakah hasil XOR printable
        decrypted_byte = enc_bytes[i] ^ next_byte
        if not (32 <= decrypted_byte <= 126 or decrypted_byte == ord('}')):
            # Jika gak printable, brute-force sampai ketemu printable
            found = False
            for adj in range(-128, 128):
                trial_byte = (next_byte + adj) % 256
                decrypted_byte = enc_bytes[i] ^ trial_byte
                if 32 <= decrypted_byte <= 126 or decrypted_byte == ord('}'):
                    key[-1] = trial_byte
                    key_differences[-1] = trial_byte - key[-2]
                    found = True
                    break
            if not found:
                print(f"[!] Gagal menemukan printable byte di index {i}")
                break

    # XOR untuk dapetin flag
    flag = ''.join([chr(c ^ key[i]) for i, c in enumerate(enc_bytes)])

    print(f"[+] Full Keystream: {key.hex()}")
    print(f"[+] Possible flag: {flag}")

    r.close()

if __name__ == "__main__":
    solve_prng()
