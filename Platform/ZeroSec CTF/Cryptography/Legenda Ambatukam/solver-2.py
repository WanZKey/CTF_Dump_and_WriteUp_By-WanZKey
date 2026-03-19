#!/usr/bin/env python3
#!/usr/bin/env python3
# pip install pycryptodome
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import unpad

ciphertext = bytes.fromhex("8ef84c40db955fdd9e6e5cb1884ce4a2e891e7c5783af02339e7177078909bf7")
key = b"cruootttt"

print("=" * 55)
print("  Solver Blowfish - Legenda Ambatukam")
print("=" * 55)

modes = {
    "ECB": Blowfish.MODE_ECB,
    "CBC (IV=0)": Blowfish.MODE_CBC,
}

for mode_name, mode in modes.items():
    print(f"\n[Mode: {mode_name}]")
    try:
        if mode == Blowfish.MODE_ECB:
            cipher = Blowfish.new(key, mode)
        else:
            cipher = Blowfish.new(key, mode, iv=b'\x00' * 8)

        # Coba tanpa unpad
        raw = cipher.decrypt(ciphertext)
        print(f"  raw      : {raw}")
        try:
            print(f"  ascii    : {raw.decode('ascii')}")
        except:
            print(f"  ascii    : (non-printable)")

        # Coba dengan unpad PKCS7
        if mode == Blowfish.MODE_ECB:
            cipher2 = Blowfish.new(key, mode)
        else:
            cipher2 = Blowfish.new(key, mode, iv=b'\x00' * 8)
        try:
            unpadded = unpad(cipher2.decrypt(ciphertext), Blowfish.block_size)
            print(f"  unpadded : {unpadded}")
            print(f"  ascii    : {unpadded.decode('ascii')}")
        except Exception as e:
            print(f"  unpad err: {e}")

    except Exception as e:
        print(f"  ERROR: {e}")

# Coba juga CBC dengan IV dari key
print(f"\n[Mode: CBC (IV=key[:8])]")
try:
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=key[:8])
    raw = cipher.decrypt(ciphertext)
    print(f"  raw  : {raw}")
    try:
        print(f"  ascii: {raw.decode('ascii')}")
    except:
        print(f"  ascii: (non-printable)")
except Exception as e:
    print(f"  ERROR: {e}")

print("\n[Done]")
