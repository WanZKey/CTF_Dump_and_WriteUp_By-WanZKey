#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Extrak strings & info menarik langsung dari raw bytes .pyc
Tidak perlu Python versi tertentu - works dengan python3 apapun
"""

import sys
import re
import struct

def extract_raw_strings(data, min_len=4):
    """Extract printable ASCII strings dari raw bytes"""
    results = []
    current = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append(''.join(current))
            current = []
    if len(current) >= min_len:
        results.append(''.join(current))
    return results

def try_marshal(data):
    """Coba load marshal dari berbagai offset"""
    import marshal
    for off in [16, 12, 8, 20, 4]:
        try:
            obj = marshal.loads(data[off:])
            return obj, off
        except:
            pass
    # Scan for code object marker
    for i in range(len(data)):
        if data[i] in (0xe3, 0x63, 0xf3):
            try:
                obj = marshal.loads(data[i:])
                return obj, i
            except:
                pass
    return None, -1

def walk_code(obj, depth=0):
    """Walk code objects dan extract semua info"""
    indent = "  " * depth
    if hasattr(obj, 'co_consts'):
        print(f"{indent}[code] {getattr(obj,'co_name','?')!r} @ line {getattr(obj,'co_firstlineno','?')}")
        print(f"{indent}  names   : {list(getattr(obj,'co_names',()))}")
        print(f"{indent}  varnames: {list(getattr(obj,'co_varnames',()))}")
        consts = list(getattr(obj, 'co_consts', ()))
        print(f"{indent}  consts  : {[c for c in consts if not hasattr(c,'co_consts')]}")
        for c in consts:
            if hasattr(c, 'co_consts'):
                walk_code(c, depth+1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            walk_code(item, depth)

def main():
    filename = sys.argv[1] if len(sys.argv) > 1 else "chall.pyc"

    with open(filename, 'rb') as f:
        data = f.read()

    magic_num = struct.unpack('<H', data[:2])[0]
    print(f"[*] File        : {filename}")
    print(f"[*] Size        : {len(data)} bytes")
    print(f"[*] Magic num   : {magic_num} ({magic_num:#06x})")
    print()

    # Python version dari magic
    magic_map = {
        3413: "3.4", 3379: "3.5", 3413: "3.5.3",
        3379: "3.6", 3393: "3.6", 3394: "3.6",
        3411: "3.7", 3422: "3.7", 3425: "3.7",
        3413: "3.8", 3419: "3.9", 3425: "3.9",
        3437: "3.10", 3439: "3.10",
        3495: "3.11", 3510: "3.11", 3531: "3.11",
        3541: "3.12", 3551: "3.12",
        3570: "3.13", 3571: "3.13",
        3600: "3.14", 3601: "3.14", 3603: "3.14",
        3614: "3.14", 3619: "3.14", 3620: "3.14",
        3621: "3.14", 3625: "3.14", 3626: "3.14",
        3627: "3.14",
    }
    py_ver = magic_map.get(magic_num, "unknown")
    print(f"[*] Python ver  : {py_ver} (magic={magic_num})")
    print()

    # Raw string extraction
    print("[*] === Raw strings dari bytes (min 4 chars) ===")
    strings = extract_raw_strings(data, min_len=4)
    for s in strings:
        # Filter yang menarik
        interesting = any([
            'flag' in s.lower(),
            'ctf' in s.lower(),
            '{' in s,
            '}' in s,
            'vuw' in s.lower(),
            'input' in s.lower(),
            'correct' in s.lower(),
            'wrong' in s.lower(),
            'key' in s.lower(),
            'pass' in s.lower(),
            len(s) > 8,
        ])
        if interesting:
            print(f"  {s!r}")

    print()
    print("[*] === Marshal walk (butuh Python versi yang sama) ===")
    try:
        obj, off = try_marshal(data)
        if obj:
            print(f"[+] Loaded dari offset {off}")
            walk_code(obj)
        else:
            print("[-] marshal.loads gagal - perlu Python 3.14")
            print("[!] Install: pyenv install 3.14.0 atau pakai Docker")
            print("[!] docker run --rm -v $(pwd):/work python:3.14-rc python3 /work/decompile_pyc.py /work/chall.pyc")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
