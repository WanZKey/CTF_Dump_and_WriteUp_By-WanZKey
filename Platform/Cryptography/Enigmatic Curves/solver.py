import hashlib
import json
import sys

def main():
    k = 98765
    print(f"[+] Using k = {k}\n")
    
    with open('enigma_curves_generated.bin', 'rb') as f:
        data = f.read()
    
    print(f"[+] File length: {len(data)} bytes")
    print(f"[+] File hex: {data.hex()}\n")
    
    # Ciphertext location analysis
    # Dari output sebelumnya: ciphertext di posisi 148 sampai sebelum byte terakhir
    # Tapi mari kita pastikan dengan melihat semua data setelah null bytes
    
    # Cari posisi setelah sequence "21 00 00 00" (! followed by null bytes)
    pattern = b'!\x00\x00\x00'
    pattern_pos = data.find(pattern)
    
    if pattern_pos != -1:
        ciphertext_start = pattern_pos + len(pattern)
        print(f"[+] Found pattern '!\\x00\\x00\\x00' at position {pattern_pos}")
        print(f"[+] Ciphertext starts at position {ciphertext_start}")
    else:
        ciphertext_start = 148
        print(f"[+] Using default ciphertext start: {ciphertext_start}")
    
    # Ciphertext adalah dari posisi tersebut sampai akhir file
    ciphertext = data[ciphertext_start:]
    print(f"[+] Ciphertext: {ciphertext.hex()}")
    print(f"[+] Ciphertext length: {len(ciphertext)} bytes\n")
    
    print("[*] Brute forcing init_positions (0-31 for each rotor)...\n")
    
    best_results = []
    
    for pos0 in range(32):
        if pos0 % 8 == 0:
            print(f"[*] Progress: testing pos0={pos0}/32...")
        
        for pos1 in range(32):
            for pos2 in range(32):
                test_positions = [pos0, pos1, pos2]
                
                # Derive keystream
                concat_pos = "".join([str(x) for x in test_positions])
                key_input = (str(k) + concat_pos).encode()
                keystream = hashlib.sha256(key_input).digest()
                
                # Decrypt
                plaintext = bytearray()
                for i in range(len(ciphertext)):
                    plaintext.append(ciphertext[i] ^ keystream[i % len(keystream)])
                
                # Try to decode as UTF-8
                try:
                    result = plaintext.decode('utf-8')
                except:
                    result = plaintext.decode('latin-1', errors='ignore')
                
                # Check for flag
                if 'DSU{' in result:
                    best_results.append({
                        'positions': test_positions,
                        'flag': result,
                        'printable': result.isprintable()
                    })
    
    # Display results
    print(f"\n{'='*70}")
    print(f"[SUCCESS] Found {len(best_results)} potential flag(s)!")
    print(f"{'='*70}\n")
    
    for idx, res in enumerate(best_results, 1):
        print(f"Result #{idx}:")
        print(f"  Positions: {res['positions']}")
        print(f"  Printable: {res['printable']}")
        print(f"  Flag: {res['flag']}")
        print(f"  Flag (repr): {repr(res['flag'])}")
        print(f"  Flag length: {len(res['flag'])} chars")
        print()
    
    # Verify which one is most likely correct
    if best_results:
        print(f"{'='*70}")
        print("[*] FINAL FLAG:")
        print(f"{'='*70}")
        
        # Pick the most complete-looking flag
        complete_flag = None
        for res in best_results:
            flag = res['flag']
            # Check if flag has proper format DSU{...}
            if flag.startswith('DSU{') and '}' in flag:
                complete_flag = flag
                print(f"\n✓ Positions: {res['positions']}")
                print(f"✓ Complete Flag: {flag}\n")
                break
        
        if not complete_flag:
            # Maybe closing brace is missing, try to find it
            print("[!] No complete flag with closing brace found")
            print("[*] Best candidate:")
            flag = best_results[0]['flag']
            print(f"    {flag}")
            
            # Check if last byte might be the closing brace
            if data[-1] == 0x7b:
                print(f"\n[!] Last byte is 0x7b = '{{' (should be '}}' = 0x7d)")
                print(f"[*] Manually adding closing brace...")
                complete_flag = flag + '}'
                print(f"✓ Complete Flag: {complete_flag}\n")
    
    # Also verify by unmasking (if we can decode the payload)
    print(f"\n{'='*70}")
    print("[*] Verification: Checking if positions match masked values")
    print(f"{'='*70}\n")
    
    if best_results:
        real_positions = best_results[0]['positions']
        print(f"[+] Found positions: {real_positions}")
        print(f"[+] Verifying mask operation...")
        
        # Reverse: what would be the masked values?
        for i, pos in enumerate(real_positions):
            seed = b"note" + str(i).encode()
            mask = hashlib.sha256(seed).digest()[0] & 0x1F
            masked_val = pos ^ mask
            print(f"    Rotor {i}: real={pos}, mask={mask}, masked_value={masked_val}")

if __name__ == "__main__":
    main()
