#!/usr/bin/env python3
import base64
import urllib.parse

leak = "7b797f537b1a63466741646e607e606e7b537f537b1a634667416f607e606e78697f537b1a6f466741646f607e606e7b437f537b1a634667416468607e606e7b797f537b1a67466741646e607e606e7b537f537b1a7b4667416468607e606e7b437f537b1a7b17"

# Step 1: hex → bytes
data = bytes.fromhex(leak)

# Step 2: XOR with 42
xored = bytes([b ^ 42 for b in data])

# Step 3: Add padding if needed
b64 = xored.decode()
while len(b64) % 4 != 0:
    b64 += "="

# Step 4: Base64 decode
decoded = base64.b64decode(b64)

# Step 5: URL-decode and split answers
text = decoded.decode()
urldec = urllib.parse.unquote(text)
answers = [x.strip() for x in urldec.split(",")]

print("[*] Base64 (with padding):", b64)
print("[*] Decoded text:", text)
print("[*] URL-decoded:", urldec)
print("[*] Final answers:", answers)
