import os
import re

def decode_custom(encoded_text):
    # Ganti semua ![[XX dengan chr(int(XX, 16))
    return re.sub(r'!\[\[([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), encoded_text)

def main():
    folder = '.'  # folder kerja saat ini
    files = sorted(f for f in os.listdir(folder) if f.endswith('.txt') and f.startswith('![['))

    results = []

    for file in files:
        filepath = os.path.join(folder, file)
        with open(filepath, 'r', encoding='latin1', errors='ignore') as f:
            content = f.read()
            decoded = decode_custom(content)
            if 'P4rt' in decoded or 'SIJAWARA' in decoded:
                results.append((file, decoded.strip()))

    for file, line in results:
        print(f"==> {file}")
        print(line)
        print()

if __name__ == '__main__':
    main()
