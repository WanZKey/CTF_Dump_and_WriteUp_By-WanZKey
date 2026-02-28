#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes, inverse
import sys
import os

def parse_output_file(path="output.txt"):
    with open(path, "rb") as f:
        raw = f.read().decode("utf-8", errors="ignore")
    vals = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().lower()
        v = v.strip()
        # try to parse integer, ignore non-int lines
        try:
            vals[k] = int(v)
        except ValueError:
            pass
    return vals

def solve_from_vals(vals):
    # required keys: n, e, c, bonus (or c_bonus)
    if "n" not in vals or "e" not in vals or "c" not in vals:
        raise KeyError("File must contain n, e, c")
    n = vals["n"]
    e = vals["e"]
    c = vals["c"]

    # accept several possible names for bonus
    bonus_key = None
    for k in ("bonus", "c_bonus", "cbonus"):
        if k in vals:
            bonus_key = k
            break
    if bonus_key is None:
        raise KeyError("File must contain BONUS (or c_bonus)")

    BONUS = vals[bonus_key]

    # replicate the algebra from your working sage/py example
    k_val = (1 - BONUS + 8 * c) % n

    inv12 = inverse(12, n)
    a = (6 * inv12) % n
    b = (k_val * inv12) % n

    m_coeff = (a * a - b) % n
    const_coeff = (a * b - c) % n

    # check invertibility
    try:
        inv_m_coeff = inverse(m_coeff, n)
    except ValueError:
        raise ValueError("m_coeff is not invertible modulo n; cannot solve with this method.")

    m = (-const_coeff * inv_m_coeff) % n
    return m

def pretty_print_flag(m):
    # try decode as bytes -> utf-8, fallback to repr
    try:
        flag_bytes = long_to_bytes(int(m))
    except Exception as ex:
        print("Error converting m to bytes:", ex)
        return
    try:
        flag_text = flag_bytes.decode("utf-8")
        print("m =", m)
        print("Flag:", flag_text)
    except UnicodeDecodeError:
        # show hex and raw repr if not valid utf-8
        print("m =", m)
        print("Flag bytes (hex):", flag_bytes.hex())
        print("Flag bytes (repr):", repr(flag_bytes))

def main(path="output.txt"):
    if not os.path.isfile(path):
        print(f"File not found: {path}")
        sys.exit(1)
    vals = parse_output_file(path)
    try:
        m = solve_from_vals(vals)
    except Exception as e:
        print("Error while solving:", e)
        sys.exit(1)
    pretty_print_flag(m)

if __name__ == "__main__":
    # allow passing filename as arg
    fname = sys.argv[1] if len(sys.argv) > 1 else "output.txt"
    main(fname)
