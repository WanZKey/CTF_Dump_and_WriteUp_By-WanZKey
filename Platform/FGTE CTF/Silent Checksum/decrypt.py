# Data terenkripsi dari byte_4040
encrypted_data = b"\x71\x70\x63\x72\x4C\x65\x72\x61\x04\x65\x02\x04\x68\x74\x7F\x04\x74\x7C\x02\x62\x7A\x68\x7B\x07\x70\x06\x74\x4A"

flag = ""
checksum = 0

# Loop dekripsi (XOR dengan 0x37)
for byte in encrypted_data:
    decrypted_byte = byte ^ 0x37
    flag += chr(decrypted_byte)
    checksum += decrypted_byte

print(f"Flag: {flag}")

# Ini adalah verifikasi dari "Silent Checksum"
print(f"Checksum Asli: {checksum & 0xFF}")
print(f"Checksum Target: {90}") # 90 adalah 'Z'

if (checksum & 0xFF) == 90:
    print("Checksum Lolos!")
else:
    print("Checksum Gagal! (Ini adalah bagian dari jebakan)")
