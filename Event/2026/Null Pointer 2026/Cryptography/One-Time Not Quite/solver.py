#!/usr/bin/env python3
#!/usr/bin/env python3

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

if __name__ == "__main__":
    # c1 ^ c2 yang sudah disediakan oleh deskripsi challenge (30 bytes)
    target_xor_hex = "273c307222302a180454122d1d121b53030b274b0f0c1e2f12520a290117"
    target_xor = bytes.fromhex(target_xor_hex)
    
    # Plaintext 2 yang sudah kita pastikan dari hasil recon sebelumnya (30 bytes)
    p2_known = b"the quick brown fox jumps over"
    
    # Menghitung 30 byte pertama dari P1 (Flag) menggunakan sifat P1 = (C1 ^ C2) ^ P2
    p1_partial = xor_bytes(target_xor, p2_known)
    
    print("=== One-Time Not Quite Solver ===")
    print(f"[*] Known Plaintext 2 : {p2_known.decode('ascii')}")
    print(f"[*] Partial Flag (30b): {p1_partial.decode('ascii')}")
    
    # Konteks 30 byte pertama flag berakhir dengan "de"
    # Sisa 5 byte untuk melengkapi 35 byte dari C1 ditebak berdasarkan kosakata bahasa Inggris
    guessed_remainder = "adly}"
    final_flag = p1_partial.decode('ascii') + guessed_remainder
    
    print(f"\n[+] Final Flag        : {final_flag}")
