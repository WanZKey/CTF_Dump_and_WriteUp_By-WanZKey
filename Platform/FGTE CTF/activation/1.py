import hmac, hashlib, base64

username = "RANI"
salt = b"salt_part_1_from_cre"

digest = hmac.new(salt, username.encode(), hashlib.sha256).digest()
license_key = ''.join(f'{b:02X}' for b in digest[:8])
print(license_key)
