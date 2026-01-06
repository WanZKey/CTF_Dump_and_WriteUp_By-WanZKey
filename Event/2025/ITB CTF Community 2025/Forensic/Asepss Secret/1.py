#!/usr/bin/env python3
# extract_usb_strings.py
import sys
import re
from binascii import unhexlify

def is_printable_ascii(b):
    return 32 <= b <= 126

def find_ascii_strings(data, min_len=4):
    res = []
    cur = bytearray()
    for byte in data:
        if is_printable_ascii(byte):
            cur.append(byte)
        else:
            if len(cur) >= min_len:
                res.append(cur.decode('ascii', errors='ignore'))
            cur = bytearray()
    if len(cur) >= min_len:
        res.append(cur.decode('ascii', errors='ignore'))
    return res

def find_utf16le_strings(data, min_len=4):
    res = []
    # search for sequences where every second byte is 0x00 (common ASCII in UTF-16LE)
    i = 0
    L = len(data)
    while i+1 < L:
        # try to detect a run of printable ascii chars encoded as UTF-16LE
        j = i
        chars = []
        while j+1 < L:
            lo = data[j]
            hi = data[j+1]
            # allow hi==0x00 or hi in range (UTF-16LE typical ASCII hi byte)
            if hi == 0x00 and is_printable_ascii(lo):
                chars.append(chr(lo))
                j += 2
            else:
                break
        if len(chars) >= min_len:
            s = ''.join(chars)
            res.append((i, s))
            i = j
        else:
            i += 2
    return res

def main(fname):
    with open(fname, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # line may start with frame number and a tab or spaces
            parts = re.split(r'\s+', line, maxsplit=1)
            if len(parts) == 1:
                continue
            frame = parts[0]
            hexdata = parts[1].strip()
            # normalize hex (remove 0x, colons, spaces)
            hexdata = hexdata.replace('0x','').replace(':','').replace(' ','')
            if hexdata == '':
                continue
            try:
                raw = unhexlify(hexdata)
            except Exception as e:
                continue
            ascii_found = find_ascii_strings(raw, min_len=4)
            utf16_found = find_utf16le_strings(raw, min_len=4)
            if ascii_found or utf16_found:
                print(f"--- Frame {frame} ---")
                if ascii_found:
                    print("ASCII strings found:")
                    for s in ascii_found:
                        print("  ", s)
                if utf16_found:
                    print("UTF-16LE strings (offset: string):")
                    for off, s in utf16_found:
                        print(f"  {off:04x}: {s}")
                print()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 extract_usb_strings.py usb_fragments.txt")
        sys.exit(1)
    main(sys.argv[1])
