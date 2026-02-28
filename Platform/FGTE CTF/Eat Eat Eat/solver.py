#!/usr/bin/env python3
def solve():
    # Target string output
    target = "E10a23t9090t9ae0140"
    
    print("[*] Target:", target)
    
    # Step 1: Extract 'String 2' (indices 0, 3, 6...)
    # Logic: if eateat % 3 == 0: take from String 2
    s2_indices = [i for i in range(len(target)) if i % 3 == 0]
    string2 = "".join([target[i] for i in s2_indices])
    print(f"[*] Extracted String 2 (Ate): {string2}")
    # string2 is "Eat9900"
    # Ate function = "Eat9" + rev_input[:3]
    # So, rev_input[:3] is "900"
    
    # Step 2: Extract 'String 1' (remaining indices)
    s1_indices = [i for i in range(len(target)) if i % 3 != 0]
    string1 = "".join([target[i] for i in s1_indices])
    print(f"[*] Extracted String 1 (eaT): {string1}")
    # string1 is "1023900tae14"
    # eaT function = Product + rev_input
    # We know rev_input starts with "900"
    # So "1023900tae14" splits into "1023" (Product) and "900tae14" (Partial Rev)
    
    product_str = "1023"
    partial_rev = "900tae14"
    
    # Step 3: Recover first 3 digits
    # Product = int(input[:3]) * 3
    first_three = str(int(product_str) // 3)
    print(f"[*] Input first 3 chars: {first_three}")
    
    # Step 4: Recover full reversed string
    # We have partial_rev "900tae14" (length 8). Need length 9.
    # The last char of rev_input MUST be the first char of input.
    last_char_rev = first_three[0] # '3'
    full_rev = partial_rev + last_char_rev
    print(f"[*] Full Reversed Input: {full_rev}")
    
    # Step 5: Final Input
    final_input = full_rev[::-1]
    print(f"\n[+] FOUND INPUT: {final_input}")
    print(f"[+] Flag: FGTE{{eat_python_{final_input}}}")

if __name__ == "__main__":
    solve()
