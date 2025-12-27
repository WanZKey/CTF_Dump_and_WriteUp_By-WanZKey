import hashlib
import json
import base64
import sys

def try_decode_without_invalid_chars(payload):
    """Try removing characters that aren't valid Base85"""
    # Base85 RFC alphabet
    b85_alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
    
    # ASCII85 alphabet (different)
    a85_alphabet = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu"
    
    cleaned_b85 = ''.join([chr(b) for b in payload if chr(b) in b85_alphabet])
    cleaned_a85 = ''.join([chr(b) for b in payload if chr(b) in a85_alphabet])
    
    return cleaned_b85, cleaned_a85

def main():
    k = 98765
    print(f"[+] Using k = {k}\n")
    
    with open('enigma_curves_generated.bin', 'rb') as f:
        data = f.read()
    
    # Mari kita lihat struktur lebih teliti
    # Dari output sebelumnya, last byte adalah 7b = '{'
    # Berarti ada struktur: ... ciphertext {
    # 
    # Tunggu! Byte terakhir 7b bisa jadi CLOSING BRACE untuk JSON yang terbuka di awal!
    
    print("[*] NEW APPROACH: Maybe the { at start and { at end frame the whole structure")
    print(f"[+] First byte with {{: position 20")
    print(f"[+] Last byte: {data[-1]:02x} = '{chr(data[-1]) if data[-1] < 128 else '?'}'")
    
    if data[-1] == 0x7b:
        print("[!] Wait... last byte is 7b which is '{' not '}'!")
        print("[!] This is unusual. Let me check if there's a } elsewhere...")
    
    # Cari semua kemunculan { dan }
    all_braces = []
    for i, byte in enumerate(data):
        if byte == 0x7b:  # {
            all_braces.append((i, '{'))
        elif byte == 0x7d:  # }
            all_braces.append((i, '}'))
    
    print(f"\n[+] All braces found: {all_braces}")
    
    # OK, jadi tidak ada closing brace }
    # Mungkin struktur JSON-nya incomplete atau ter-encode
    
    print(f"\n{'='*60}")
    print("[*] HYPOTHESIS: Maybe we need to GUESS the init_positions")
    print(f"{'='*60}\n")
    
    # Dari params.json ada rotor_signatures
    # Mari kita coba dengan asumsi ada 3 rotors (dari rotor_signatures count)
    
    # Ciphertext adalah byte terakhir sebelum 7b
    ciphertext = data[148:-1]  # Dari pos 148 sampai sebelum byte terakhir
    print(f"[+] Ciphertext (adjusted): {ciphertext.hex()}")
    print(f"[+] Ciphertext length: {len(ciphertext)} bytes\n")
    
    # Brute force init_positions
    # Biasanya rotor positions adalah nilai kecil (0-25 atau 0-31)
    print("[*] Brute forcing init_positions...")
    
    found_flags = []
    
    for pos0 in range(32):
        for pos1 in range(32):
            for pos2 in range(32):
                test_positions = [pos0, pos1, pos2]
                
                # Derive key
                concat_pos = "".join([str(x) for x in test_positions])
                key_input = (str(k) + concat_pos).encode()
                keystream = hashlib.sha256(key_input).digest()
                
                # Decrypt
                plaintext = bytearray()
                for i in range(len(ciphertext)):
                    plaintext.append(ciphertext[i] ^ keystream[i % len(keystream)])
                
                result = plaintext.decode('latin-1', errors='ignore')
                
                # Check for flag markers
                if 'DSU{' in result:
                    print(f"\n{'='*60}")
                    print(f"[FOUND FLAG!]")
                    print(f"[+] Positions: {test_positions}")
                    print(f"[+] Flag: {result}")
                    print(f"{'='*60}")
                    found_flags.append((test_positions, result))
                elif result.isprintable() and len(result) > 10:
                    # Could be valid plaintext
                    if 'flag' in result.lower() or result.startswith('The '):
                        print(f"[?] Possible with {test_positions}: {result[:50]}")
    
    if not found_flags:
        print("\n[-] No flag found with brute force. Let's try different k values too...")
        
        # Try k +/- 10
        for k_offset in range(-10, 11):
            k_try = k + k_offset
            if k_offset == 0:
                continue
            
            for pos0 in range(16):  # Reduced search space
                for pos1 in range(16):
                    for pos2 in range(16):
                        test_positions = [pos0, pos1, pos2]
                        
                        concat_pos = "".join([str(x) for x in test_positions])
                        key_input = (str(k_try) + concat_pos).encode()
                        keystream = hashlib.sha256(key_input).digest()
                        
                        plaintext = bytearray()
                        for i in range(len(ciphertext)):
                            plaintext.append(ciphertext[i] ^ keystream[i % len(keystream)])
                        
                        result = plaintext.decode('latin-1', errors='ignore')
                        
                        if 'DSU{' in result:
                            print(f"\n{'='*60}")
                            print(f"[FOUND with k={k_try}!]")
                            print(f"[+] Positions: {test_positions}")
                            print(f"[+] Flag: {result}")
                            print(f"{'='*60}")
                            return
    
    print("\n[*] Search complete!")

if __name__ == "__main__":
    main()
