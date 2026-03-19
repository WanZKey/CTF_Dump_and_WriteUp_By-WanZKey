import os
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

FLAG = os.environ.get('FLAG', 'VuwCTF{not_so_private_key_test_flag}')
FLAG = FLAG.encode()
key = b64decode('c3VwZXJzZWNyZXRwYXNzd29yZDEyMyEh')

cipher = AES.new(key, AES.MODE_ECB)

ciphertext = cipher.encrypt(pad(FLAG, 16))

print(ciphertext.hex())

