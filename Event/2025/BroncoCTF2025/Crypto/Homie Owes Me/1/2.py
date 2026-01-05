import hashlib

# Hash target
target_hash = "ea23f261fff0ebc5b0a5d74621218e413a694ed0815a90615cf6edd7b49e6d0d"

# Daftar basis password yang mungkin
base_passwords = [
    "yoshiethehomie",
    "yoshie_the_homie",
    "yoshiehomie",
    "y0shiethehomie",
    "y0sh13thehom13",
    "y0sh13th3hom13"
]

# Daftar karakter khusus yang mungkin
special_chars = ["!", "@", "#", "$", "%", "^", "&", "*"]

# Mencoba semua kombinasi
for base in base_passwords:
    for char in special_chars:
        for pin in range(10000):
            pin_str = f"{pin:04}"  # Format 4-digit dengan leading zeros
            password = base + char + pin_str
            # Hash password dengan SHA-256
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            # Cetak setiap percobaan untuk memastikan skrip berjalan
            print(f"Mencoba: {password} -> {hashed_password}")
            if hashed_password == target_hash:
                print(f"Password ditemukan: {password}")
                exit()
print("Password tidak ditemukan setelah mencoba semua kombinasi.")
