#!/usr/bin/env python3
# rot8000_decode.py
# Decode "ROT8000" style string like:
# 籏籐籝籎粄类籮籹... -> FGTE{...}

import sys

cjk_string = "籏籐籝籎粄类籮籹籵籪籬籮籨籭籪籼籱籨籭籸籽籨籼籹籪籬籮籨米籪籹籪籷籮籼粆"

def decode_rot8000(s: str) -> str:
    out_chars = []
    for ch in s:
        code = ord(ch)
        # step 1: subtract 0x7C00
        v = code - 0x7C00
        # step 2: ROT / Caesar -9 within byte space
        v = (v - 9) % 256
        out_chars.append(chr(v))
    return "".join(out_chars)

if __name__ == "__main__":
    # allow optional input from CLI
    if len(sys.argv) > 1:
        # treat full argument as the CJK string (no quotes)
        cjk_string = sys.argv[1]
    flag = decode_rot8000(cjk_string)
    print("Decoded:", flag)
