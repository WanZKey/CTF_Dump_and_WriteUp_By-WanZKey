def caesar_decrypt(text, shift):
    result = ''
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result += chr((ord(c) - base - shift) % 26 + base)
        else:
            result += c
    return result

cipher = "Kv uqog ogcp kp rjkejv vjg ugetgv!"
for s in range(1, 26):
    print(f"Shift {s}: {caesar_decrypt(cipher, s)}")
