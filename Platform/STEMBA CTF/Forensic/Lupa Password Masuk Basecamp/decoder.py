import base64

# Baca file flag.txt dalam mode biner
with open("flag.txt", "rb") as f:
    data = f.read()

# Decode base32 sebanyak 14 kali
for i in range(14):
    try:
        data = base64.b32decode(data)
        print(f"[+] Iterasi ke-{i+1}: berhasil decode")
    except Exception as e:
        print(f"[!] Gagal decode pada iterasi ke-{i+1}: {e}")
        break

# Cetak hasil akhir
try:
    hasil_akhir = data.decode()
    print("\n[+] Hasil akhir decoding:")
    print(hasil_akhir)
except UnicodeDecodeError:
    print("\n[!] Tidak bisa decode ke UTF-8, kemungkinan data masih terenkripsi atau bukan string.")
