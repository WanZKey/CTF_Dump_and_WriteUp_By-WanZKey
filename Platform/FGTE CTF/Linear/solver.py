#!/usr/bin/env python3
import struct

# Constants from Binary Analysis (IDA Pro Data)
# A = ymmword_402040 (Multipliers)
A_hex = "D7B3DD3FBD1B0F40F304B53FDA0F4940F204353FBC1BCF3F54F82D4067C4133F"
# B = ymmword_402060 (Addends)
B_hex = "000028C285EB55410000E0C0CDCCC7420000003F333353C0B81ED5400000A0BF"

# C = Constant per chunk (Offsets)
C_hexs = [
    "696E07C6E09ADBC68A4743C6F329BCC7C68946C5B4DB65C6EA3644C7BC0598C5", # Chunk 1
    "8FCC21C65A266CC6E83922C6FFFDBFC7661F8FC5713100C789729AC79FB38BC5", # Chunk 2
    "F1A46AC6F2ED8EC7A0BAAFC6F0F61AC88F7BC6C53370B8C64BCF98C67C2472C5", # Chunk 3
    "93AF8DC6BDB193C76BEDA5C6F0F61AC856A1A1C5D9A1D4C6FB88A3C7B3189DC5"  # Chunk 4
]

def hex_to_floats(h):
    # Convert hex string to 8 floats (Little Endian)
    return struct.unpack('<8f', bytes.fromhex(h))

# Load Global Constants
A = hex_to_floats(A_hex)
B = hex_to_floats(B_hex)

flag = ""

print("[*] Cracking Linear Equation...")

# Process each of the 4 chunks
for chunk_idx, C_hex in enumerate(C_hexs):
    C = hex_to_floats(C_hex)
    chunk_str = ""
    
    # Process each of the 8 characters in the chunk
    for i in range(8):
        best_char = '?'
        min_diff = float('inf')
        
        # Brute force printable ASCII to find the one that minimizes the equation
        for char_code in range(32, 127): 
             # Logic from assembly: vfmadd132ps (dest*src3 + src2) -> (char * A + B)
             val = (char_code * A[i] + B[i])
             
             # Equation: (val^2) + C
             # We want this to be 0 (or cancel out, but usually 0 per term)
             result = (val * val) + C[i]
             
             # Check absolute value (distance to 0)
             if abs(result) < min_diff:
                 min_diff = abs(result)
                 best_char = chr(char_code)
        
        chunk_str += best_char
    
    print(f"Chunk {chunk_idx+1}: {chunk_str}")
    flag += chunk_str

print(f"\n[+] Flag Found: {flag}")
