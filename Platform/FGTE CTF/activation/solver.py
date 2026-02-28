import base64
import hashlib
import hmac
from Crypto.Cipher import AES

# data dari program
username = "RANI"
salt = b"salt_part_1_from_cre"
encryptedBlob = bytes([
    167,164,179,68,122,43,220,205,221,237,252,140,94,60,228,168,
    158,24,12,211,42,196,123,129,112,31,108,142,85,169,138,71,
    23,244,193,140,102,155,201,244,183,5,176,49,163,24,215,196,
    212,215,159,80,85,221,12,234,16,7,169,163,172,218,85,246
])

# 1. license
digest = hmac.new(salt, username.encode(), hashlib.sha256).digest()
license_key = ''.join(f'{b:02X}' for b in digest[:8])
print(f"License: {license_key}")

# 2. derive key
salt_b64 = base64.b64encode(salt).decode()
data = (license_key + salt_b64).encode()
sha = hashlib.sha256(data).digest()
key = sha[:16]

# 3. decrypt blob
iv = encryptedBlob[:16]
ciphertext = encryptedBlob[16:]

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = cipher.decrypt(ciphertext)
# remove PKCS7 padding
pad_len = plaintext[-1]
plaintext = plaintext[:-pad_len]

print("Decrypted flag:", plaintext.decode())
