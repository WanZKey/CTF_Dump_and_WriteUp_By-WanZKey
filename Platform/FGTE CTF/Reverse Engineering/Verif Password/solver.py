from Crypto.Cipher import AES
import base64

ENC_FLAG = 'moUzGvsTTimEvTPhCph7iG45QRnSxuNT3A7OGC+Ox3bcd5z+44FKW6Y2AB1TY0Pf'
KEY = b'this_is_16byte!!'

def unpad(s):
    return s[:-s[-1]]

def decrypt_flag(enc_b64):
    enc = base64.b64decode(enc_b64)
    cipher = AES.new(KEY, AES.MODE_ECB)
    plain = cipher.decrypt(enc)
    return unpad(plain).decode('utf-8')

print(decrypt_flag(ENC_FLAG))
