#!/usr/bin/env python3
# solver_jp8000_full.py
#
# Solver lengkap untuk challenge "JP_8000"
# By: wanzkey (dibantu GPT-5)
#
# Tahapan:
# 1. Base32 decode dari isi file
# 2. Interpret hasil sebagai Shift_JIS → teks Jepang (ドット, ダッシュ, 空間)
# 3. Ganti jadi morse ('.', '-', ' ')
# 4. Decode morse → menghasilkan base32 string baru
# 5. Base32 decode → hasilkan karakter CJK
# 6. Decode ROT8000 → dapat flag!

import base64

# ===== Step 1: Baca file JP_8000.txt =====
with open("JP_8000.txt", "r", encoding="utf-8") as f:
    data = f.read().strip()

print("[1] Read file content length:", len(data))

# ===== Step 2: Base32 decode =====
try:
    b32_decoded = base64.b32decode(data)
except Exception as e:
    print("❌ Base32 decode error:", e)
    exit(1)

# ===== Step 3: Interpret sebagai Shift_JIS =====
try:
    jp_text = b32_decoded.decode("shift_jis")
except Exception as e:
    print("❌ Shift_JIS decode error:", e)
    exit(1)

print("[2] Shift_JIS decoded Japanese text (preview):")
print(jp_text[:200], "...\n")

# ===== Step 4: Konversi ドット, ダッシュ, 空間 ke simbol Morse =====
mapping = {
    "ドット": ".",
    "ダッシュ": "-",
    "空間": " ",
}
for jp, sym in mapping.items():
    jp_text = jp_text.replace(jp, sym)

morse_string = jp_text.strip()
print("[3] Morse string preview:")
print(morse_string[:100], "...\n")

# ===== Step 5: Decode Morse ke Base32 string =====
MORSE_TABLE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z",
    "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
    ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
}

base32_text = ""
for word in morse_string.split(" "):
    base32_text += MORSE_TABLE.get(word, "")

print("[4] Decoded Morse → Base32 string preview:")
print(base32_text[:60], "...\n")

# ===== Step 6: Base32 decode lagi ke bytes =====
try:
    cjk_bytes = base64.b32decode(base32_text)
except Exception as e:
    print("❌ Base32 decode (2nd) error:", e)
    exit(1)

cjk_text = cjk_bytes.decode("utf-8")
print("[5] CJK string (ROT8000 encoded):")
print(cjk_text, "\n")

# ===== Step 7: ROT8000 decode =====
def decode_rot8000(s: str) -> str:
    result = ""
    for ch in s:
        val = ord(ch) - 0x7C00  # offset correction
        val = (val - 9) % 256   # Caesar shift -9
        result += chr(val)
    return result

flag = decode_rot8000(cjk_text)
print("[6] ✅ FLAG FOUND:", flag)
