import wave

# Buka file WAV
with wave.open("mysterious.wav", "rb") as wav:
    frames = wav.readframes(wav.getnframes())
    samples = list(frames)

# Ambil 1 bit terakhir dari setiap byte
bits = [s & 1 for s in samples]

# Gabungkan tiap 8 bit jadi 1 byte
bytes_out = bytes(int("".join(str(b) for b in bits[i:i+8]), 2) for i in range(0, len(bits), 8))

# Lihat sebagian hasil
print(bytes_out[:100])
