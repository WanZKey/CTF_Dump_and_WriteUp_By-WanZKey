def solve():
    # Data byte yang diekstrak dari pola "31 XX 44" di file hex
    # Sumber: Output xxd baris 00000090 - 00000160
    encrypted_bytes = [
        0x63, # T
        0x74, # C
        0x67, # P
        0x06, # 1
        0x67, # P
        0x4c, # {
        0x56, # a
        0x68, # _
        0x54, # c
        0x42, # u
        0x45, # r
        0x5e, # i
        0x58, # o
        0x42, # u
        0x44, # s
        0x68, # _
        0x40, # w
        0x56, # a
        0x59, # n
        0x53, # d
        0x52, # e
        0x45, # r
        0x52, # e
        0x45, # r
        0x68, # _
        0x5e, # i
        0x43, # t
        0x68, # _
        0x44, # s
        0x52, # e
        0x52, # e
        0x5a, # m
        0x44, # s
        0x4a  # }
    ]

    # Key yang kita temukan
    key = 0x37
    
    flag = ""
    for b in encrypted_bytes:
        flag += chr(b ^ key)
        
    print(f"FLAG: {flag}")

if __name__ == "__main__":
    solve()
