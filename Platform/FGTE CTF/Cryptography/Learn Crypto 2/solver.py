#!/usr/bin/env python3
import base64
import base92
import re

def rot47(data):
    decoded = []
    for char in data:
        n = ord(char)
        if 33 <= n <= 126:
            decoded.append(chr(33 + ((n + 14) % 94)))
        else:
            decoded.append(char)
    return "".join(decoded)

def caesar_decrypt(text, shift):
    result = []
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            # Shift backwards for decrypt
            decoded_char = chr(start + (ord(char) - start - shift) % 26)
            result.append(decoded_char)
        else:
            result.append(char)
    return "".join(result)

def vigenere_decrypt(ciphertext, key):
    key_length = len(key)
    plaintext = ''
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            key_char = key[key_index % key_length]
            key_offset = 65 if key_char.isupper() else 97
            
            # (Cipher - Key) mod 26
            val = (ord(char) - offset) - (ord(key_char) - key_offset)
            val = (val % 26) + offset
            plaintext += chr(val)
            key_index += 1
        else:
            plaintext += char
    return plaintext

def solve():
    print("[*] Starting Full Auto Solver...")
    print("-" * 40)

    try:
        # STEP 1: Load File
        with open("ct.txt", "r") as f:
            content = f.read().strip()
        
        # STEP 2: Layer 1 (Base64) -> Output: Next Base64 + Hint Base92
        print("[1] Decoding Layer 1 (Base64)...")
        l1_out = base64.b64decode(content).decode('utf-8', errors='ignore')
        l1_payload = l1_out.split('\n')[0].strip()

        # STEP 3: Layer 2 (Base64) -> Output: Raw Bytes for Base92
        print("[2] Decoding Layer 2 (Base64 wrapper)...")
        l2_bytes = base64.b64decode(l1_payload)

        # STEP 4: Layer 3 (Base92) -> Output: Next Base64 + Hint ROT47
        print("[3] Decoding Layer 3 (Base92)...")
        l3_out = base92.decode(l2_bytes)
        if isinstance(l3_out, bytes): # Handle output type
            l3_out = l3_out.decode('utf-8')
        
        # Output l3 is a Base64 string that wraps the ROT47 payload
        l3_payload_b64 = l3_out.strip() # It seems it's just the B64 string

        # STEP 5: Layer 4 (Base64 -> ROT47)
        print("[4] Decoding Layer 4 (ROT47)...")
        # Decode B64 first
        l4_rot_encoded = base64.b64decode(l3_payload_b64).decode('utf-8')
        # Apply ROT47
        l4_plain = rot47(l4_rot_encoded)
        
        # l4_plain contains: [Base64 Payload] \n [Caesar Hint]
        lines = l4_plain.strip().split('\n')
        l5_input_b64 = lines[0].strip()
        print(f"    [>] Hint Found: {lines[1]}")

        # STEP 6: Layer 5 (Base64 -> Caesar Shift 10)
        print("[5] Decoding Layer 5 (Caesar Shift 10)...")
        l5_cipher = base64.b64decode(l5_input_b64).decode('utf-8')
        l5_plain = caesar_decrypt(l5_cipher, 10)
        
        # l5_plain contains: [Base64 Payload] \n [Vigenere Hint]
        lines = l5_plain.strip().split('\n')
        l6_input_b64 = lines[0].strip()
        hint_vigenere = lines[1].strip()
        
        # Extract Key
        key_match = re.search(r'"(.*?)"', hint_vigenere)
        key = key_match.group(1) if key_match else "cryptoisfun"
        print(f"    [>] Key Found : {key}")

        # STEP 7: Layer 6 (Base64 -> Vigenere)
        print("[6] Decoding Layer 6 (Vigenere)...")
        l6_cipher = base64.b64decode(l6_input_b64).decode('utf-8')
        flag = vigenere_decrypt(l6_cipher, key)

        print("\n" + "="*50)
        print(f"SOLVED FLAG: {flag}")
        print("="*50 + "\n")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()
