# Daftar nilai desimal ASCII dari IDA Pro
ascii_values = [
    102, 108, 97, 103, 123, # flag{
    51, 97, 115, 121, 95,   # 3asy_
    99, 48, 110, 116, 114,  # c0ntr
    48, 108, 95,            # 0l_
    102, 108, 48, 119, 125  # fl0w}
]

# Konversi ke karakter
flag = "".join([chr(c) for c in ascii_values])

print(f"Flag Found: {flag}")
