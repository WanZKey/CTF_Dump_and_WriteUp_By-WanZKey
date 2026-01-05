import hashlib

# Basis password setelah partial leetspeak dan tambahan karakter khusus
base_password = "y0sh13th3h0m13!"

# Hash yang diberikan
target_hash = "ea23f261fff0ebc5b0a5d74621218e413a694ed0815a90615cf6edd7b49e6d0d"

# Mencoba semua kombinasi 4-digit PIN
for pin in range(100000):
    pin_str = f"{pin:04}"  # Format 4-digit dengan leading zeros
    password = base_password + pin_str
    # Hash password dengan SHA-256
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    # Cetak setiap percobaan untuk memastikan skrip berjalan
    print(f"Mencoba: {password} -> {hashed_password}")
    if hashed_password == target_hash:
        print(f"Password ditemukan: {password}")
        break
else:
    print("Password tidak ditemukan setelah mencoba semua kombinasi 4-digit PIN.")
