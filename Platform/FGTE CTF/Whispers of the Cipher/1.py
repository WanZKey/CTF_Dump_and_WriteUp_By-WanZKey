#!/usr/bin/env python3
"""
Whispers of the Cipher - CTF Crypto Challenge Solver
Decrypts Vigenere + XOR encrypted message
"""

def vigenere_decrypt(text, key):
    """Decrypt Vigenere cipher - works on ASCII text"""
    result = []
    key = key.lower()
    key_length = len(key)
    key_index = 0
    
    for char in text:
        if char.isalpha():
            # Get the shift value from key
            shift = ord(key[key_index % key_length]) - ord('a')
            
            if char.isupper():
                # Decrypt uppercase letter
                decrypted = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            else:
                # Decrypt lowercase letter
                decrypted = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
            
            result.append(decrypted)
            key_index += 1
        else:
            # Non-alphabetic characters remain unchanged
            result.append(char)
    
    return ''.join(result)

def xor_decrypt(data, key):
    """XOR decrypt data with repeating key"""
    result = []
    key_bytes = key.encode('ascii')
    key_length = len(key_bytes)
    
    for i, byte in enumerate(data):
        result.append(byte ^ key_bytes[i % key_length])
    
    return bytes(result)

def main():
    # Cipher data from cipher.txt
    cipher_hex = "7C CD BB DF 27 AF 9B 21 EC ED DF 07 85 7D 30 15 86 DC 17 29 6E CF CF A2 0E BD 87 53 E4 92 A0 00 85 6F 12"
    
    # Convert hex string to bytes
    cipher_bytes = bytes.fromhex(cipher_hex.replace(' ', ''))
    
    # Key from mysterious.wav metadata
    key = "solitude"
    
    print("="*70)
    print("Whispers of the Cipher - Decryption Tool")
    print("="*70)
    print(f"Key: {key}")
    print(f"Mode: Vigenere + XOR")
    print(f"Ciphertext: {cipher_hex}")
    print(f"Length: {len(cipher_bytes)} bytes\n")
    
    # CORRECT ORDER: XOR first (to undo XOR), then Vigenere decrypt
    print("="*70)
    print("DECRYPTION PROCESS")
    print("="*70)
    
    # Step 1: XOR decrypt
    print("\nStep 1: XOR Decryption")
    print("-"*70)
    xor_result = xor_decrypt(cipher_bytes, key)
    print(f"After XOR (hex): {xor_result.hex()}")
    print(f"After XOR (raw): {xor_result}")
    
    # Try to decode as text
    try:
        xor_text = xor_result.decode('ascii')
        print(f"After XOR (text): {xor_text}")
        
        # Step 2: Vigenere decrypt
        print("\nStep 2: Vigenere Decryption")
        print("-"*70)
        plaintext = vigenere_decrypt(xor_text, key)
        print(f"PLAINTEXT: {plaintext}")
        print("\n" + "="*70)
        print(f"🚩 FLAG FOUND: {plaintext}")
        print("="*70)
        
    except UnicodeDecodeError:
        print("⚠️  XOR result contains non-ASCII bytes")
        print("Trying to decode with error handling...")
        xor_text = xor_result.decode('ascii', errors='replace')
        print(f"After XOR (text): {xor_text}")
        
        plaintext = vigenere_decrypt(xor_text, key)
        print(f"\nAfter Vigenere decrypt: {plaintext}")
    
    # Additional analysis
    print("\n" + "="*70)
    print("BYTE-BY-BYTE ANALYSIS")
    print("="*70)
    print(f"{'Index':<6} {'Cipher':<8} {'Key':<6} {'XOR Result':<12} {'Char':<6}")
    print("-"*70)
    
    for i in range(min(len(cipher_bytes), 40)):
        cipher_byte = cipher_bytes[i]
        key_char = key[i % len(key)]
        key_byte = ord(key_char)
        xor_byte = cipher_byte ^ key_byte
        char_repr = chr(xor_byte) if 32 <= xor_byte < 127 else f"\\x{xor_byte:02x}"
        
        print(f"{i:<6} 0x{cipher_byte:02X}    '{key_char}'    0x{xor_byte:02X}        {char_repr}")

if __name__ == "__main__":
    main()
