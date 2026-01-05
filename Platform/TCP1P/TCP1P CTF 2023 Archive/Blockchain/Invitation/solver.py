def extract_selectors():
    try:
        with open('Invitation.txt', 'r') as f:
            bytecode = f.read().strip()
    except FileNotFoundError:
        print("[-] File not found")
        return

    # Bersihkan bytecode
    bytecode = bytecode.replace('\n', '').replace('\r', '')
    
    # Opcode untuk PUSH4 adalah '63'
    # Kita cari pola '63' diikuti 8 karakter hex (4 byte)
    # Ini cara kasar tapi efektif untuk CTF
    
    print("[*] Scanning for Function Selectors (PUSH4)...")
    
    i = 0
    selectors = []
    while i < len(bytecode):
        # Cari opcode 63 (PUSH4)
        if bytecode[i:i+2] == '63':
            # Ambil 4 byte (8 char) setelahnya
            selector = bytecode[i+2:i+10]
            if len(selector) == 8:
                selectors.append("0x" + selector)
            i += 10 # Skip instruction ini
        else:
            i += 2 # Geser 1 byte

    print(f"[*] Found {len(selectors)} selectors:")
    for s in selectors:
        print(f" - {s}")

    print("\n[!] TASK: Cek selector di atas ke https://www.4byte.directory/")
    print("[!] Cari yang namanya diawali 'TCP1P'")

if __name__ == "__main__":
    extract_selectors()
