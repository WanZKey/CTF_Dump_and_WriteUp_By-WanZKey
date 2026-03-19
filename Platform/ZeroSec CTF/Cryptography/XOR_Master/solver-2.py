#!/usr/bin/env python3
#!/usr/bin/env python3

data = bytes.fromhex("1827302d112721393a2d301d2e2d252b211d2b311d322d35273024372e3f")

# Flag starts with "ZeroSec", find the key by XORing first byte with 'Z'
for key in range(256):
    decrypted = bytes([b ^ key for b in data])
    try:
        text = decrypted.decode('ascii')
        if text.startswith('ZeroSec'):
            print(f"Key found: {key} (0x{key:02x})")
            print(f"Decrypted: {text}")
    except:
        pass
