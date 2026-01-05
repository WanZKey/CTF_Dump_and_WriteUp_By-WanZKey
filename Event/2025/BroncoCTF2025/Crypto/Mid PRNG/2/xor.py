from pwn import xor
import binascii

ciphertext = bytes.fromhex("4400396c657d4d928ded2736b50d98d2d2adb1f0b5a6c25f")
keystream = bytes.fromhex("26725602061236dafea2466a8e32d6fa9ec2e68ac0f6ac62")

plaintext = xor(ciphertext, keystream)
print(plaintext)

