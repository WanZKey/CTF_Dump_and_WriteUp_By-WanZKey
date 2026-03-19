#!/usr/bin/env python3
import hashlib

salt_bytes = bytes.fromhex("334aa758c52bb2f862f1607ff098e954")
target = "09be2259e0224f41b96b633b73e7138b50b4be0a1ae20c0eb6a7434e8fc47303"

for i in range(10000):
    pwd = f"ratatouille{i:04d}"
    h = hashlib.sha256(pwd.encode() + salt_bytes).hexdigest()
    if h == target:
        print(f"Password: {pwd}")  # ratatouille6281
        break
