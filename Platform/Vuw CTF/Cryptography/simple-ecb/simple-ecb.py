import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


FLAG = os.environ.get('FLAG', 'VuwCTF{ecb_test_flag_0123456789abcdef}')
FLAG = FLAG.encode()

key = os.urandom(16)  # get a random key

cipher = AES.new(key, AES.MODE_ECB)


print('Recover my secret :)')
while True:
    msg = input('Enter message to encrypt: ').encode()
    plaintext = pad(msg + FLAG, 16)

    ciphertext = cipher.encrypt(plaintext)

    print(ciphertext.hex())

