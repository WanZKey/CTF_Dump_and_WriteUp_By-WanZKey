#!/usr/bin/env python3
def vigenere_decrypt(ciphertext, key):
    key_length = len(key)
    plaintext = ''
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            key_char = key[key_index % key_length]
            key_offset = 65 if key_char.isupper() else 97
            
            # P = (C - K) mod 26
            val = (ord(char) - offset) - (ord(key_char) - key_offset)
            val = (val % 26) + offset
            plaintext += chr(val)
            key_index += 1
        else:
            plaintext += char
    return plaintext

def solve():
    print("[*] Solver 10 Kunci Jawaban (Final Logic)")
    
    cipher = "F4mc_B1d4_M3ab3rR4k4y_S04y_E4w4j4n_J4nt_O3p4b"
    key = "jawaban"
    
    # Analisis Matematis:
    # Cipher 'F' (5) -> Plain 'k' (10) dengan Key 'j' (9).
    # Butuh pergeseran +5.
    # 1x Decrypt (-9) -> -4 (W).
    # 11x Decrypt (-99) -> -99 mod 26 = 5. (COCOK!)
    # Jadi total butuh 11 kali putaran.
    
    total_rounds = 11
    
    current_text = cipher
    print(f"Original: {current_text}")
    
    for i in range(1, total_rounds + 1):
        current_text = vigenere_decrypt(current_text, key)
        # print(f"Round {i}: {current_text}")
        
    print(f"\n[+] Result after {total_rounds} rounds:")
    print(current_text)
    
    flag = f"FGTE{{{current_text}}}"
    print("\n" + "="*50)
    print(f"SOLVED FLAG: {flag}")
    print("="*50 + "\n")

if __name__ == "__main__":
    solve()
