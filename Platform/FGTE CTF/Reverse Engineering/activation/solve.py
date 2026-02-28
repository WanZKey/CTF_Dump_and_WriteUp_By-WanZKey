import base64
import hmac
import hashlib
from Crypto.Cipher import AES

# Variabel statis dari dekompilasi
user_chunks = ["UkFOSQ=="]
salt_chunks = ["c2FsdF9w", "YXJ0XzFf", "ZnJvbV9j", "cmU="]
encrypted_blob = bytes([
    167, 164, 179, 68, 122, 43, 220, 205, 221, 237, 252, 140, 94, 60, 228, 168,
    158, 24, 12, 211, 42, 196, 123, 129, 112, 31, 108, 142, 85, 169, 138, 71,
    23, 244, 193, 140, 102, 155, 201, 244, 183, 5, 176, 49, 163, 24, 215, 196,
    212, 215, 159, 80, 85, 221, 12, 234, 16, 7, 169, 163, 172, 218, 85, 246
])

# Langkah 1: Mendapatkan username
username_b64 = "".join(user_chunks)
username = base64.b64decode(username_b64).decode('utf-8')
print(f"[*] Username ditemukan: {username}")

# Langkah 2: Mendapatkan salt
salt_b64 = "".join(salt_chunks)
salt = base64.b64decode(salt_b64)
print(f"[*] Salt ditemukan: {salt.decode('utf-8')}")

# Langkah 3: Menghasilkan lisensi
h = hmac.new(salt, username.encode('utf-8'), hashlib.sha256)
license_key = h.digest()[:8].hex().upper()
print(f"[+] Lisensi yang valid: {license_key}")

# Langkah 4: Mendapatkan kunci dekripsi (AES key)
data_to_hash = license_key.encode('utf-8') + base64.b64encode(salt)
aes_key = hashlib.sha256(data_to_hash).digest()[:16]
print(f"[*] Kunci AES (16 bytes): {aes_key.hex()}")

# Langkah 5: Mendekripsi flag
iv = encrypted_blob[:16]
ciphertext = encrypted_blob[16:]
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
decrypted_bytes = cipher.decrypt(ciphertext)

# Hapus padding PKCS7
padding_len = decrypted_bytes[-1]
flag = decrypted_bytes[:-padding_len].decode('utf-8')

print("\n" + "="*40)
print(f"🚩 FLAG: {flag}")
print("="*40)
