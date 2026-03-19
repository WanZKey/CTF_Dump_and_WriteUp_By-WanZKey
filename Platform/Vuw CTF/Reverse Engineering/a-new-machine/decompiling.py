#!/usr/bin/env python3
"""
Decompiler/disassembler untuk chall.pyc (Python 3.14 magic)
Jalankan dengan: python3.14 decompile_pyc.py chall.pyc
Atau fallback:   python3 decompile_pyc.py chall.pyc
"""

import sys
import dis
import marshal
import struct
import io

def read_pyc(filename):
    with open(filename, 'rb') as f:
        data = f.read()

    magic  = data[0:4]
    flags  = struct.unpack('<I', data[4:8])[0]
    print(f"[*] Magic bytes : {magic.hex()} ({struct.unpack('<H', magic[:2])[0]})")
    print(f"[*] Flags       : {flags:#010x}")

    # Offset header pyc bisa berbeda tergantung flag
    # Python 3.8+: 16 bytes header
    # Jika flag bit 0 set = hash-based pyc (12 bytes setelah magic)
    # Standard: magic(4) + flags(4) + mtime(4) + size(4) = 16 bytes

    offset = 16
    if flags & 0x1:  # hash-based
        offset = 16
        print("[*] Hash-based pyc detected")
    else:
        mtime  = struct.unpack('<I', data[8:12])[0]
        size   = struct.unpack('<I', data[12:16])[0]
        print(f"[*] mtime       : {mtime}")
        print(f"[*] source size : {size}")

    code_data = data[offset:]

    # Coba dengan berbagai offset jika gagal
    for off in [offset, 8, 12, 16, 20]:
        try:
            code = marshal.loads(data[off:])
            print(f"[+] marshal.loads sukses pada offset {off}")
            return code
        except Exception as e:
            pass

    # Fallback: cari magic bytes marshal object (0x63 = code object)
    for i in range(len(data) - 4):
        if data[i] == 0xe3 or data[i] == 0x63:
            try:
                code = marshal.loads(data[i:])
                print(f"[+] marshal.loads sukses pada offset {i} (scan)")
                return code
            except:
                pass

    print("[-] Gagal parse marshal object")
    return None

def dump_code(code, indent=0):
    prefix = "  " * indent
    print(f"\n{prefix}{'='*60}")
    print(f"{prefix}Code object: {getattr(code, 'co_name', '?')!r}")
    print(f"{prefix}  filename   : {getattr(code, 'co_filename', '?')}")
    print(f"{prefix}  firstlineno: {getattr(code, 'co_firstlineno', '?')}")
    print(f"{prefix}  argcount   : {getattr(code, 'co_argcount', '?')}")
    print(f"{prefix}  varnames   : {getattr(code, 'co_varnames', ())}")
    print(f"{prefix}  constants  :")
    for i, c in enumerate(getattr(code, 'co_consts', ())):
        print(f"{prefix}    [{i}] {c!r}")
    print(f"{prefix}  names      : {getattr(code, 'co_names', ())}")
    print(f"{prefix}  freevars   : {getattr(code, 'co_freevars', ())}")
    print(f"{prefix}  cellvars   : {getattr(code, 'co_cellvars', ())}")

    print(f"\n{prefix}--- Disassembly ---")
    try:
        dis.dis(code)
    except Exception as e:
        print(f"{prefix}[!] dis failed: {e}")
        # Manual bytecode dump
        bc = getattr(code, 'co_code', None) or getattr(code, 'co_rawbytecode', None)
        if bc:
            print(f"{prefix}Raw bytecode: {bc.hex()}")

    # Rekursif untuk nested code objects
    for const in getattr(code, 'co_consts', ()):
        if hasattr(const, 'co_code') or hasattr(const, 'co_rawbytecode'):
            dump_code(const, indent + 1)

def extract_strings(code, found=None):
    """Ekstrak semua string menarik dari code object"""
    if found is None:
        found = set()
    for const in getattr(code, 'co_consts', ()):
        if isinstance(const, str) and len(const) > 2:
            found.add(const)
        if hasattr(const, 'co_consts'):
            extract_strings(const, found)
    return found

def main():
    filename = sys.argv[1] if len(sys.argv) > 1 else "chall.pyc"
    print(f"[*] Reading {filename}...")
    print(f"[*] Python version: {sys.version}")
    print()

    code = read_pyc(filename)
    if not code:
        print("[-] Could not load code object")
        sys.exit(1)

    print("\n[*] === Interesting strings ===")
    strings = extract_strings(code)
    for s in sorted(strings):
        print(f"  {s!r}")

    print("\n[*] === Full disassembly ===")
    dump_code(code)

if __name__ == "__main__":
    main()
