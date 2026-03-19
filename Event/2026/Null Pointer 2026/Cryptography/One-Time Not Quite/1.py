#!/usr/bin/env python3
import binascii

def strxor(b1, b2):
    return bytes([a ^ b for a, b in zip(b1, b2)])

def solve():
    c1_hex = "73b38970473151c752982490b356d92a194d35286015d129d3b414de113ce6fbc30643"
    c2_hex = "548fb90265017bdf56cc36bdae44c2791a4612636f19cf06c1e61ef7102b"
    
    c1 = bytes.fromhex(c1_hex)
    c2 = bytes.fromhex(c2_hex)
    
    print("[*] Hustling Crib Dragging...")
    
    # Get the XOR of the two ciphertexts (up to the length of the shortest one)
    min_len = min(len(c1), len(c2))
    c1_c2_xor = strxor(c1[:min_len], c2[:min_len])
    
    # Step 1: Drag the known flag format
    crib_m1 = b"STURSEC{"
    partial_m2 = strxor(c1_c2_xor[:len(crib_m1)], crib_m1)
    print(f"[*] If M1 starts with '{crib_m1.decode()}', M2 starts with: '{partial_m2.decode(errors='ignore')}'")
    
    # Step 2: "the quic" is a dead giveaway for the classic pangram
    guess_m2 = b"the quick brown fox jumps over"
    print(f"[*] Guessing M2 is the classic phrase: '{guess_m2.decode()}'")
    
    # Step 3: XOR our M2 guess back against the combined string to get M1
    partial_m1 = strxor(c1_c2_xor, guess_m2)
    print(f"[*] Recovered partial M1: '{partial_m1.decode(errors='ignore')}'")
    
    # Step 4: The recovered M1 is 30 bytes, but C1 is 35 bytes.
    # We have "STURSEC{otp_reused_keys_are_de", so we can easily guess the last 5 bytes.
    guessed_flag = partial_m1.decode(errors='ignore') + "adly}"
    print(f"\n[+] We got the bag! Full Flag Guess: {guessed_flag}")

if __name__ == "__main__":
    solve()
