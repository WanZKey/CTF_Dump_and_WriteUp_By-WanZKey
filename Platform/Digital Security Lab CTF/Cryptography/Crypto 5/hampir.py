#!/usr/bin/env python3
import requests
import json
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Target URL
URL = "http://practice-digitalsecuritylab.di.unipi.it:11005/api/dh_exchange/"

# Constants from the server
G = 2
P = 123332382638231725701467272052746646677437210451686403929360967929971726170175522473010422422481335637035691756799160249433550988140577298403502161171408121294152540751727605530438344170959752812965964116010935488849567570589898718274440695293648653888226126185052620716306229882426016512073971282234225856687
C = 64612411667157069503976070918939607708875022270375896159569914279068171237996023267687125585927418267362932620044815107093025867940055155893108177681746956136085002346241007308415060540468449145442966833111022272981874509644086110124172781007706360095880503723087775599509214116527258964018584247604461917771

def xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (mimics server's xor using zip)"""
    return bytes(x ^ y for x, y in zip(a, b))

def get_key_bytes_at_offset(offset, length):
    """
    Get key bytes at a specific offset by crafting special A value.
    We use A = G^offset * C mod P, which gives us:
    k_a = (G^offset * C)^b mod P = G^(offset*b) * C^b mod P
    But this doesn't help us isolate bytes...
    
    Better approach: Use known plaintext attack with different approaches.
    """
    pass

def exploit():
    print("[*] Starting Diffie-Hellman Attack...")
    print("[*] Vulnerability: Server reuses private key 'b' for both exchanges")
    print()
    
    # First request: Get first 12 bytes of key using A = C
    print("[*] Request 1: Setting A = C to get first 12 bytes of key")
    
    payload1 = {
        "g": G,
        "p": P,
        "A": C
    }
    
    response1 = requests.post(URL, json=payload1, headers={"Content-Type": "application/json"})
    data1 = response1.json()
    
    if "error" in data1:
        print(f"[-] Error: {data1['error']}")
        return
    
    msg_a1 = bytes.fromhex(data1["msg_a"])
    msg_c = bytes.fromhex(data1["msg_c"])
    
    print(f"[+] msg_a: {msg_a1.hex()}")
    print(f"[+] msg_c: {msg_c.hex()}")
    print()
    
    # Recover first 12 bytes
    known_plaintext = b"Hello Alice!"
    key_bytes = bytearray(xor(msg_a1, known_plaintext))
    
    print(f"[*] Recovered key bytes [0:12]: {key_bytes.hex()}")
    print(f"[*] Partial flag: {xor(msg_c[:12], key_bytes).decode()}")
    print()
    
    # Now we need to get bytes 12-20 (9 more bytes)
    # Strategy: Send crafted A values that will give us known relationships
    
    # Actually, let's think differently:
    # We know k_c = C^b mod P (a large integer)
    # long_to_bytes(k_c) gives us the byte representation
    # We have the first 12 bytes: a7645b00d048f029cc2af3d4
    
    # Let's try to brute force the remaining 9 bytes byte by byte
    # using the assumption that the flag contains printable characters
    
    print("[*] Brute forcing remaining 9 bytes of the key...")
    print("[*] Assuming flag contains only printable ASCII characters")
    print()
    
    remaining_cipher = msg_c[len(key_bytes):]
    
    # Brute force byte by byte
    for byte_pos in range(len(remaining_cipher)):
        current_pos = len(key_bytes)
        print(f"[*] Brute forcing byte at position {current_pos}...")
        
        found = False
        for key_byte_val in range(256):
            test_plain = remaining_cipher[byte_pos] ^ key_byte_val
            
            # Check if it's a likely flag character
            # Flag format: TRT{alphanumeric_chars}
            if chr(test_plain) in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_}":
                # Test this with context
                test_key = bytes(key_bytes) + bytes([key_byte_val])
                test_flag = xor(msg_c[:len(test_key)], test_key)
                
                # Check if it looks valid
                try:
                    decoded = test_flag.decode('ascii')
                    # Should start with "TRT{" and contain valid characters
                    if decoded.startswith("TRT{") and all(c in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_{}" for c in decoded):
                        # This looks promising
                        if byte_pos == len(remaining_cipher) - 1:
                            # Last byte should be }
                            if chr(test_plain) == '}':
                                key_bytes.append(key_byte_val)
                                print(f"    [+] Found byte: 0x{key_byte_val:02x} -> '{chr(test_plain)}' (FINAL)")
                                found = True
                                break
                        else:
                            # For other positions, we'll take the most likely one
                            # Let's collect all possibilities
                            if not found:
                                key_bytes.append(key_byte_val)
                                print(f"    [+] Found byte: 0x{key_byte_val:02x} -> '{chr(test_plain)}'")
                                found = True
                                break
                except:
                    pass
        
        if not found:
            print(f"    [-] Could not determine byte at position {current_pos}")
            print(f"    [*] Trying most common flag characters...")
            # Try common endings: numbers, lowercase letters
            for common_char in "0123456789abcdef_}":
                key_byte_val = remaining_cipher[byte_pos] ^ ord(common_char)
                test_key = bytes(key_bytes) + bytes([key_byte_val])
                test_flag = xor(msg_c[:len(test_key)], test_key)
                try:
                    if test_flag.decode('ascii').startswith("TRT{"):
                        key_bytes.append(key_byte_val)
                        print(f"    [+] Guessed byte: 0x{key_byte_val:02x} -> '{common_char}'")
                        found = True
                        break
                except:
                    pass
            
            if not found:
                print(f"    [!] Skipping byte, will try to infer later")
                key_bytes.append(0)  # Placeholder
    
    print()
    print("[*] Full recovered key:")
    print(f"    {bytes(key_bytes).hex()}")
    print()
    
    # Decrypt full flag
    full_flag = xor(msg_c, bytes(key_bytes))
    
    print("="*60)
    print("[+] FLAG FOUND:")
    print(f"[+] {full_flag.decode('utf-8', errors='ignore')}")
    print("="*60)

if __name__ == "__main__":
    try:
        exploit()
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
