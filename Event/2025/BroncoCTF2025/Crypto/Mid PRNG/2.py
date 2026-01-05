def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Sample outputs dari server
sample1 = bytes.fromhex('d16b248fc086c001f8e61af5f0d6f5e107066c53501d0f0c')
sample2 = bytes.fromhex('7341f6a5024c120bda4c08df725c672b25acbef992d7dd86')

# XOR kedua sample untuk menghilangkan flag
xored = xor_bytes(sample1, sample2)

# Known flag format: 'bronco{'
known_text = b'bronco{'
possible_key1 = xor_bytes(sample1[:len(known_text)], known_text)
possible_key2 = xor_bytes(sample2[:len(known_text)], known_text)

print("Possible key1:", possible_key1.hex())
print("Possible key2:", possible_key2.hex())

# Coba decrypt sample1
decrypted1 = xor_bytes(sample1, possible_key1 * (len(sample1) // len(possible_key1) + 1))
print("\nTrying to decrypt sample1:", decrypted1)

# Coba decrypt sample2
decrypted2 = xor_bytes(sample2, possible_key2 * (len(sample2) // len(possible_key2) + 1))
print("Trying to decrypt sample2:", decrypted2)
