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

def is_valid_flag_char(c, is_last=False):
    """Check if character is valid for a flag"""
    if is_last:
        return c == '}'
    return c in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"

def exploit():
    print("[*] Starting Diffie-Hellman Attack...")
    print("[*] Vulnerability: Server reuses private key 'b' for both exchanges")
    print()
    
    # Request: Get first 12 bytes of key using A = C
    print("[*] Setting A = C to match Charlie's key")
    
    payload = {
        "g": G,
        "p": P,
        "A": C
    }
    
    response = requests.post(URL, json=payload, headers={"Content-Type": "application/json"})
    data = response.json()
    
    if "error" in data:
        print(f"[-] Error: {data['error']}")
        return
    
    msg_a = bytes.fromhex(data["msg_a"])
    msg_c = bytes.fromhex(data["msg_c"])
    
    print(f"[+] msg_a: {msg_a.hex()}")
    print(f"[+] msg_c: {msg_c.hex()}")
    print(f"[+] Flag length: {len(msg_c)} bytes")
    print()
    
    # Recover first 12 bytes
    known_plaintext = b"Hello Alice!"
    key_bytes = list(xor(msg_a, known_plaintext))
    
    print(f"[*] Recovered key bytes [0:12]: {bytes(key_bytes).hex()}")
    print(f"[*] Partial flag: '{xor(msg_c[:12], bytes(key_bytes)).decode()}'")
    print()
    
    # Brute force remaining bytes
    print("[*] Brute forcing remaining bytes...")
    remaining_cipher = msg_c[len(key_bytes):]
    
    # We know the flag format: TRT{XXXXXXXXXXXXXXXXX}
    # Where X are alphanumeric or underscore
    # And the last character MUST be }
    
    for byte_idx in range(len(remaining_cipher)):
        pos = len(key_bytes)
        is_last_byte = (byte_idx == len(remaining_cipher) - 1)
        
        cipher_byte = remaining_cipher[byte_idx]
        
        candidates = []
        
        # Try all possible key bytes
        for key_val in range(256):
            plain_byte = cipher_byte ^ key_val
            plain_char = chr(plain_byte)
            
            # Check if this produces a valid flag character
            if is_valid_flag_char(plain_char, is_last_byte):
                # Build test key and flag
                test_key = bytes(key_bytes + [key_val])
                test_flag = xor(msg_c[:len(test_key)], test_key)
                
                # Validate the full flag so far
                try:
                    flag_str = test_flag.decode('ascii')
                    # Must start with TRT{
                    if flag_str.startswith("TRT{"):
                        # All characters must be valid
                        valid = True
                        for i, c in enumerate(flag_str):
                            if i < 4:  # TRT{
                                continue
                            if i == len(flag_str) - 1 and is_last_byte:
                                # Last char must be }
                                if c != '}':
                                    valid = False
                                    break
                            else:
                                # Other chars must be alphanumeric or _
                                if c not in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_":
                                    valid = False
                                    break
                        
                        if valid:
                            candidates.append((key_val, plain_char, flag_str))
                except:
                    pass
        
        if len(candidates) == 0:
            print(f"[!] No valid candidates for byte {pos}")
            key_bytes.append(0)
        elif len(candidates) == 1:
            key_val, plain_char, flag_str = candidates[0]
            key_bytes.append(key_val)
            print(f"[+] Byte {pos}: 0x{key_val:02x} -> '{plain_char}' | Flag so far: {flag_str}")
        else:
            # Multiple candidates, pick the most likely
            # Prefer lowercase letters and numbers over uppercase
            best = candidates[0]
            for cand in candidates:
                _, char, _ = cand
                if char.islower() or char.isdigit():
                    best = cand
                    break
            
            key_val, plain_char, flag_str = best
            key_bytes.append(key_val)
            print(f"[+] Byte {pos}: 0x{key_val:02x} -> '{plain_char}' | Flag so far: {flag_str} ({len(candidates)} candidates)")
    
    print()
    print("[*] Full recovered key:")
    print(f"    {bytes(key_bytes).hex()}")
    print()
    
    # Decrypt full flag
    full_key = bytes(key_bytes)
    full_flag = xor(msg_c, full_key)
    
    print("="*60)
    print("[+] FINAL FLAG:")
    print(f"[+] {full_flag.decode('utf-8', errors='ignore')}")
    print("="*60)

if __name__ == "__main__":
    try:
        exploit()
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
