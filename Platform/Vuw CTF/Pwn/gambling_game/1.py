#!/usr/bin/env python3
#!/usr/bin/env python3
"""
CTF Solver: gambling_game (VUW CTF)
Strategi:
  1. Integer overflow / negative bet
  2. Float exploit (misal: 1e9)
  3. Seed prediction (srand(time(NULL)) C rand)
  4. Brute-force dengan prediksi seed lokal
"""

import socket
import time
import ctypes
import os

HOST = "chals.vuwctf.com"
PORT = 9999
TIMEOUT = 10

# ─── Helpers ───────────────────────────────────────────────────────────────────

def recvuntil(s, delim: bytes, timeout=TIMEOUT) -> bytes:
    s.settimeout(timeout)
    buf = b""
    while delim not in buf:
        try:
            chunk = s.recv(1)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            break
    return buf

def send(s, data: str):
    s.sendall((data + "\n").encode())

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    return s

# ─── Seed prediction (C rand) ──────────────────────────────────────────────────

def c_rand_sequence(seed: int, n: int) -> list[int]:
    """Replicate glibc rand() / MSVC rand() dengan seed tertentu."""
    try:
        libc = ctypes.CDLL("libc.so.6")   # Linux
    except OSError:
        try:
            libc = ctypes.CDLL("libc.dylib")  # macOS
        except OSError:
            # Fallback: implementasi manual LCG (MSVC rand)
            return msvc_rand_sequence(seed, n)
    libc.srand(seed)
    return [libc.rand() % 2 for _ in range(n)]

def msvc_rand_sequence(seed: int, n: int) -> list[int]:
    """MSVC / Windows rand() fallback."""
    state = seed & 0xFFFFFFFF
    results = []
    for _ in range(n):
        state = (state * 214013 + 2531011) & 0xFFFFFFFF
        results.append(((state >> 16) & 0x7FFF) % 2)
    return results

# ─── Strategi 1: Integer / Float Overflow ─────────────────────────────────────

def try_overflow():
    """Coba kirim bet yang sangat besar, negatif, atau float untuk overflow."""
    weird_bets = [
        "99999999999999999999",   # integer overflow
        "-1",                     # negative
        "-100",                   # negative besar
        "1e9",                    # scientific notation
        "9999999999999999",       # large positive
        "0",                      # nol
        "2147483647",             # INT_MAX
        "-2147483648",            # INT_MIN
        "4294967295",             # UINT_MAX
    ]
    for bet in weird_bets:
        print(f"\n[*] Mencoba bet: {bet!r}")
        try:
            s = connect()
            banner = recvuntil(s, b"bet?")
            print(f"    Banner: {banner[-80:].decode(errors='replace').strip()}")
            send(s, bet)
            resp = recvuntil(s, b"?", timeout=5)
            resp_str = resp.decode(errors='replace')
            print(f"    Resp: {resp_str[:200].strip()}")
            if any(x in resp_str.lower() for x in ["flag", "ctf", "jackpot", "10,000", "won"]):
                print(f"[!] FLAG DITEMUKAN dengan bet={bet!r}!")
                rest = recvuntil(s, b"}", timeout=5)
                print(rest.decode(errors='replace'))
                s.close()
                return True
            # Kalau diminta pilih heads/tails, jawab 1
            if "heads" in resp_str.lower() or "tails" in resp_str.lower():
                send(s, "1")
                result = recvuntil(s, b"balance:", timeout=5)
                result_str = result.decode(errors='replace')
                print(f"    Result: {result_str[:200].strip()}")
                if any(x in result_str.lower() for x in ["flag", "ctf", "jackpot", "10,000", "won"]):
                    print("[!] FLAG DITEMUKAN!")
                    rest = recvuntil(s, b"}", timeout=5)
                    print(rest.decode(errors='replace'))
                    s.close()
                    return True
            s.close()
        except Exception as e:
            print(f"    Error: {e}")
    return False

# ─── Strategi 2: Seed Prediction ──────────────────────────────────────────────

def try_seed_prediction():
    """
    Asumsi server memakai srand(time(NULL)) sebelum tiap game.
    Kita coba seed di sekitar waktu koneksi, prediksi hasil coin flip,
    dan selalu bet maksimum pada sisi yang benar.
    """
    print("\n[*] Mencoba seed prediction...")
    for delta in range(-5, 6):
        seed = int(time.time()) + delta
        preds = c_rand_sequence(seed, 200)
        print(f"    Seed {seed} (delta={delta:+d}) → {preds[:10]}...")
        try:
            result = play_with_predictions(preds, verbose=(delta == 0))
            if result:
                return True
        except Exception as e:
            print(f"    Error: {e}")
    return False

def play_with_predictions(preds: list[int], verbose=True):
    """Mainkan game dengan prediksi urutan coin flip."""
    s = connect()
    balance = 100
    target = 10000
    flip_idx = 0

    banner = recvuntil(s, b"bet?")
    if verbose:
        print(f"    Terkoneksi. Banner:\n    {banner.decode(errors='replace').strip()}\n")

    while balance < target and flip_idx < len(preds):
        # Bet semua / double up sampai menang
        bet = min(balance, target - balance)
        bet = balance  # all-in setiap ronde

        prompt = recvuntil(s, b"bet?", timeout=5).decode(errors='replace')
        if any(x in prompt.lower() for x in ["broke", "game over", "flag", "ctf"]):
            if verbose:
                print(f"    Prompt akhir: {prompt[:200]}")
            if "flag" in prompt.lower() or "ctf" in prompt.lower():
                rest = recvuntil(s, b"}", timeout=5)
                print("[!] FLAG:", prompt + rest.decode(errors='replace'))
                s.close()
                return True
            s.close()
            return False

        # Cek balance dari prompt
        import re
        bal_match = re.search(r"balance[:\s]+\$?([\d,]+)", prompt.lower())
        if bal_match:
            balance = int(bal_match.group(1).replace(",", ""))

        bet_amt = balance
        send(s, str(bet_amt))

        choice_prompt = recvuntil(s, b"?", timeout=5).decode(errors='replace')
        # pred: 0 = heads, 1 = tails (tergantung implementasi)
        pred = preds[flip_idx]
        choice = "1" if pred == 0 else "2"
        flip_idx += 1
        send(s, choice)

        result = recvuntil(s, b"balance", timeout=5).decode(errors='replace')
        won = "won" in result.lower() or "doubled" in result.lower() or "heads" in result.lower() and choice == "1"

        if verbose:
            print(f"    Bet ${bet_amt}, choice={choice} ({'H' if choice=='1' else 'T'}), pred={pred} → {result[:80].strip()}")

        # Cek flag
        if any(x in result.lower() for x in ["flag", "ctf{", "jackpot"]):
            rest = recvuntil(s, b"}", timeout=5)
            print("[!] FLAG DITEMUKAN:", result + rest)
            s.close()
            return True

        bal2_match = re.search(r"balance[:\s]+\$?([\d,]+)", result.lower())
        if bal2_match:
            balance = int(bal2_match.group(1).replace(",", ""))

        if balance >= target:
            rest = recvuntil(s, b"}", timeout=8)
            print("[!] Mencapai target! Output:", result + rest)
            s.close()
            return True

        if balance <= 0:
            s.close()
            return False

    s.close()
    return False

# ─── Strategi 3: Brute force / lucky guess ────────────────────────────────────

def try_always_heads():
    """Coba selalu pilih Heads dan bet semua. Kalau win rate > 50%, ada bug."""
    print("\n[*] Mencoba always-heads dengan all-in...")
    for attempt in range(5):
        try:
            result = play_always(choice="1")
            if result:
                return True
        except Exception as e:
            print(f"    Attempt {attempt+1} error: {e}")
    return False

def play_always(choice="1"):
    import re
    s = connect()
    banner = recvuntil(s, b"bet?")
    balance = 100
    target = 10000

    while balance < target:
        prompt = recvuntil(s, b"bet?", timeout=5).decode(errors='replace')
        if any(x in prompt.lower() for x in ["broke", "game over"]):
            s.close()
            return False
        if any(x in prompt.lower() for x in ["flag", "ctf{"]):
            rest = recvuntil(s, b"}", timeout=5)
            print("[!] FLAG:", prompt + rest)
            s.close()
            return True

        bal_match = re.search(r"balance[:\s]+\$?([\d,]+)", prompt.lower())
        if bal_match:
            balance = int(bal_match.group(1).replace(",", ""))

        send(s, str(balance))
        recvuntil(s, b"?", timeout=5)
        send(s, choice)

        result = recvuntil(s, b"balance", timeout=5).decode(errors='replace')
        if any(x in result.lower() for x in ["flag", "ctf{", "jackpot"]):
            rest = recvuntil(s, b"}", timeout=5)
            print("[!] FLAG:", result + rest)
            s.close()
            return True

        bal_match = re.search(r"balance[:\s]+\$?([\d,]+)", result.lower())
        if bal_match:
            balance = int(bal_match.group(1).replace(",", ""))
        print(f"    Balance: ${balance}")

        if balance >= target:
            rest = recvuntil(s, b"}", timeout=8)
            print("[!] Menang! Output:", result + rest)
            s.close()
            return True
        if balance <= 0:
            s.close()
            return False

    s.close()
    return False

# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  CTF Solver: gambling_game")
    print("  Target:", HOST, PORT)
    print("=" * 60)

    # Strategi 1: Overflow
    print("\n[STRATEGI 1] Integer/Float Overflow")
    if try_overflow():
        return

    # Strategi 2: Seed Prediction
    print("\n[STRATEGI 2] Seed Prediction (srand(time))")
    if try_seed_prediction():
        return

    # Strategi 3: Lucky
    print("\n[STRATEGI 3] Always Heads All-In")
    if try_always_heads():
        return

    print("\n[!] Semua strategi gagal. Tips:")
    print("    - Coba jalankan manual: nc chals.vuwctf.com 9999")
    print("    - Cek apakah ada pola pada coin flip (catat beberapa ronde)")
    print("    - Coba input string / karakter khusus sebagai bet")

if __name__ == "__main__":
    main()
