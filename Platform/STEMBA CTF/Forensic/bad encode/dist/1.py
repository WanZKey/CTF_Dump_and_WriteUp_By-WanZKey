import re
import os

def decode_custom(text):
    return re.sub(r'!\[\[([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), text)

for fname in sorted(os.listdir('.')):
    if fname.startswith('![[') and fname.endswith('.txt'):
        with open(fname, 'r', encoding='latin1') as f:
            content = f.read()
            decoded = decode_custom(content)
            print(f"==> {fname}")
            print(decoded)
            print()
