#!/usr/bin/env python3
# solve_janedoe_final.py
# Final auto-decrypt for "Jane Doe" CTF challenge
# Uses extend_mt19937_predictor for MT backtrack/predict
# Auto-detects flag in decrypted output

import re, ast, sys, json, time
from extend_mt19937_predictor import ExtendMT19937Predictor

# ---------------- helper utils ----------------
def parse_output_bytes(path="output.txt"):
    with open(path, "rb") as f:
        raw = f.read().decode('utf-8', errors='ignore')
    m_b = re.search(r"b\s*=\s*([0-9]+)", raw)
    m_p = re.search(r"p\s*=\s*([0-9]+)", raw)
    m_enc = re.search(r"enc\s*=\s*(\[[^\]]*\])", raw, re.DOTALL)
    m_hint = re.search(r"hint\s*=\s*(\[[^\]]*\])", raw, re.DOTALL)
    if not (m_b and m_p and m_enc and m_hint):
        raise ValueError("Couldn't parse output.txt structure")
    b = int(m_b.group(1))
    p = int(m_p.group(1))
    enc = ast.literal_eval(m_enc.group(1))
    hint = ast.literal_eval(m_hint.group(1))
    return b, p, enc, hint

def inv_mod(a, p): return pow(a, -1, p)

def big_to_u32_words(x, nwords=16):
    bs = x.to_bytes(nwords*4, 'big')
    return [int.from_bytes(bs[i*4:(i+1)*4], 'big') for i in range(nwords)]

def byteswap_u32(w): return int.from_bytes(w.to_bytes(4,'big')[::-1],'big')

def build_m_list_from_hint(b, p, hint):
    m_list = []
    for i in range(len(hint)-1):
        s_i, s_ip1 = hint[i], hint[i+1]
        m_i = ((s_ip1 - b) * inv_mod(s_i, p)) % p
        m_list.append(m_i)
    return m_list

def decrypt_blocks(enc_list, s_list):
    plaintext = b""
    for e, s in zip(enc_list, s_list):
        # use only lowest 64 bits
        eb = (int(e) & ((1<<64)-1)).to_bytes(8, 'big')
        sb = (int(s) & ((1<<64)-1)).to_bytes(8, 'big')
        plaintext += bytes([x ^ y for x, y in zip(eb, sb)])
    return plaintext

def detect_flag(pt_bytes):
    try:
        text = pt_bytes.decode('utf-8', errors='ignore')
    except:
        return None
    import re
    pattern = re.compile(r'(?:ITBCTF|CTFITB2025|CTFITB2025{|BakaCTF|FLAG|CTF)\{[A-Za-z0-9_\-!@#\$%\^\&\*\(\)\+\=\?\.,]*\}') 
    m = pattern.search(text)
    return m.group(0) if m else None

# ---------- MAIN ----------
def main():
    print("🧠 [Jane Doe Decryptor] Starting...")
    t0 = time.time()
    b, p, enc, hint = parse_output_bytes("output.txt")
    print(f"[*] Parsed output.txt → b({b.bit_length()} bits), p({p.bit_length()} bits), enc={len(enc)} blocks, hint={len(hint)}")

    # compute m_list
    m_list = build_m_list_from_hint(b, p, hint)
    print(f"[*] Computed {len(m_list)} multipliers m_i")

    # The variant discovered from your previous run:
    variant = {'endian': 'big', 'rotation': 0, 'per_chunk_rev': True, 'byte_swap': False, 'stream_rev': False}
    print(f"[*] Using discovered variant: {variant}")

    # build 32-bit words stream
    words = []
    for m in m_list:
        ws = big_to_u32_words(m)
        ws = list(reversed(ws))  # per_chunk_rev=True
        words.extend(ws)

    # reconstruct MT predictor
    predictor = ExtendMT19937Predictor()
    for i in range(624):
        predictor.setrandbits(words[i], 32)
    print("[*] Predictor seeded with 624 words.")

    # alignment found at match_idx = 39 (from your run)
    match_idx = 39
    chunks_to_m9 = -39
    back_needed = -chunks_to_m9 + 9
    print(f"[*] Backtracking {back_needed} chunks to recover m0..m8...")

    m0_to_m8 = []
    for _ in range(back_needed):
        predictor.backtrack_getrandbits(512)
    # Now we can collect the 9 earliest chunks (oldest first)
    for _ in range(9):
        m0_to_m8.append(predictor.predict_getrandbits(512))
    print("[*] m0..m8 recovered.")

    # compute s_0..s_8 using s_9 from hint[0]
    s = {}
    s[9] = hint[0]
    for i in reversed(range(0,9)):
        si = ((s[i+1] - b) * inv_mod(m0_to_m8[i], p)) % p
        s[i] = si
    print("[*] Computed s_0..s_8")

    # decrypt enc blocks
    plaintext = decrypt_blocks(enc, [s[i] for i in range(9)])
    print("[+] Decrypted bytes:", plaintext)
    try:
        decoded = plaintext.decode('utf-8', errors='ignore')
        print("[+] UTF-8 decode:", decoded)
    except:
        decoded = None

    flag = detect_flag(plaintext)
    if flag:
        print("\033[92m🏁 FLAG FOUND:", flag, "\033[0m")
    else:
        print("\033[91m⚠️  No flag pattern detected.\033[0m")
        if decoded:
            print("[*] Maybe plaintext:", decoded)

    print(f"⏱️  Done in {time.time()-t0:.2f}s")

if __name__ == "__main__":
    main()
