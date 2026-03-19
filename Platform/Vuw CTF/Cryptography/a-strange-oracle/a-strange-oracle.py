import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

FLAG = os.environ.get('FLAG', 'VuwCTF{cbc_padding_oracle_test_flag}')
key = os.urandom(16)


def encrypt(plaintext):
    cipher = AES.new(key, AES.MODE_CBC)

    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    ciphertext = ciphertext.hex()

    iv = cipher.iv.hex()

    return iv + ', ' + ciphertext

def decrypt(encrypted):
    iv, ciphertext = encrypted.split(', ')

    iv = bytes.fromhex(iv)

    ciphertext = bytes.fromhex(ciphertext)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    plaintext = cipher.decrypt(ciphertext)

    # unpad() raises ValueError on invalid padding
    return unpad(plaintext, AES.block_size)


print(f'Decrypt me!')
print(encrypt(FLAG.encode()))

while 1:
    print()
    print('1. Register')
    print('2. Log in')
    print('3. Quit')
    menu = input('Select an action: ')

    if menu == '1': # Register
        print('Registering, store your token safely!')
        user = input('Username: ').encode()

        pt = b'user=' + user


        token = encrypt(pt)
        print('Copy your token:')
        print(token)

    elif menu == '2': # Log in
        print('Logging in')
        token = input('Enter your token: ')

        try:
            pt = decrypt(token)

        except ValueError:
            # unpad() raises a ValueError on invalid padding
            print('Padding error!')
            continue

        if not pt.startswith(b'user='):
            # valid tokens always start with b'user='
            print('Invalid token!')
            # print(f'{pt}')
            continue

        user = pt.partition(b'user=')[2].decode() # get the right side of 'user='

        print(f'Welcome {user}!')

    elif menu == '3': # quit
        print('Goodbye!')
        exit(0)

    else: # invalid option
        print('Invalid option')

