#!/usr/bin/env python3
#!/usr/bin/env python3
import string
from pwn import *

context.log_level = 'error'

HOST = "chals.vuwctf.com"
PORT = 9989

charset = string.ascii_letters + string.digits + "_}"

known = "VuwCTF{"
print(f"[*] Starting from: '{known}' (len={len(known)})", flush=True)

while len(known) < 21 and not known.endswith("}"):
    pos = len(known)
    print(f"\n[*] Finding char at position {pos+1}...", flush=True)

    # Build candidate list for this position
    candidates = [c for c in charset if not (c == '}' and pos < 20)]
    eliminated = set()

    found = False
    total_attempts = 0
    connections = 0

    while not found:
        # Connect and get flag bytes for this session
        connections += 1
        r = remote(HOST, PORT)
        r.recvuntil(b"Encoded flag: ")
        flag_enc = r.recvline().strip().decode()
        flag_bytes = bytes.fromhex(flag_enc)[:21]

        # First, quickly check if this connection can hit the flag's mode
        # IMPORTANT: Use the KNOWN prefix to test
        probe_msg = (known + "A" * (21 - pos)).encode()
        can_match = False
        for _ in range(50):
            r.recvuntil(b"Enter something to encode: ")
            r.sendline(probe_msg)
            r.recvuntil(b"Encoded: ")
            enc = r.recvline().strip().decode()
            enc_bytes = bytes.fromhex(enc)[:21]
            total_attempts += 1
            # Only check the known prefix bytes
            if enc_bytes[:pos] == flag_bytes[:pos]:
                can_match = True
                break

        if not can_match:
            r.close()
            if connections % 5 == 0:
                print(f"  [{connections} conns] Searching for reachable mode...", flush=True)
            continue

        print(f"  [Conn {connections}] Mode reachable! Testing candidates...", flush=True)

        # This connection can hit the mode - now test candidates
        remaining = [c for c in candidates if c not in eliminated]
        session_attempts = 0
        max_session = 2000

        cand_idx = 0
        while session_attempts < max_session and not found and remaining:
            c = remaining[cand_idx % len(remaining)]
            test = known + c + "A" * (20 - pos)

            r.recvuntil(b"Enter something to encode: ")
            r.sendline(test.encode())
            r.recvuntil(b"Encoded: ")
            enc = r.recvline().strip().decode()
            enc_bytes = bytes.fromhex(enc)[:21]

            session_attempts += 1
            total_attempts += 1

            if enc_bytes[:pos] == flag_bytes[:pos]:
                if enc_bytes[pos] == flag_bytes[pos]:
                    known += c
                    print(f"[+] Found '{c}' -> '{known}'", flush=True)
                    found = True
                    break
                else:
                    if c not in eliminated:
                        eliminated.add(c)
                        remaining = [x for x in remaining if x != c]
                        print(f"  Eliminated '{c}' ({len(remaining)} left)", flush=True)
                        cand_idx = 0
                        continue

            cand_idx += 1

        r.close()

        if not remaining:
            print(f"  [!] All candidates eliminated!", flush=True)
            break

print(f"\n[*] FLAG: {known}", flush=True)
