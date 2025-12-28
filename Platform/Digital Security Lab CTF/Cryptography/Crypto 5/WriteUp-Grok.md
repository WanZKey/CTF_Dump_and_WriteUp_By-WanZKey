https://grok.com/share/c2hhcmQtNA_5479d6f9-d8fe-4e03-b1cb-ab50ef5be848
# Crypto 5: Diffie-Hellman Key Exchange CTF Writeup

## Challenge Overview
- **Category**: Cryptography
- **Points**: 500
- **URL**: http://practice-digitalsecuritylab.di.unipi.it:11005/
- **Description**: The service implements a Diffie-Hellman key exchange. The server allows clients to send parameters `g`, `p`, and public key `A`. It then computes its public key `B` using a fixed private key `b`, derives the shared key, and sends an encrypted message ("Hello Alice!") along with the encrypted flag (shared with another user "Charlie" using the same `b`).

The server reuses the same private key `b` for both the client's exchange and Charlie's exchange. Charlie's public key `C` is provided in the source code.

Key constants:
- `G = 2`
- `P = 123332382638231725701467272052746646677437210451686403929360967929971726170175522473010422422481335637035691756799160249433550988140577298403502161171408121294152540751727605530438344170959752812965964116010935488849567570589898718274440695293648653888226126185052620716306229882426016512073971282234225856687`
- `C = 64612411667157069503976070918939607708875022270375896159569914279068171237996023267687125585927418267362932620044815107093025867940055155893108177681746956136085002346241007308415060540468449145442966833111022272981874509644086110124172781007706360095880503723087775599509214116527258964018584247604461917771`

The flag is encrypted as `msg_c = XOR(FLAG, long_to_bytes(k_c))` where `k_c = pow(C, b, P)`.

The client's message is `msg_a = XOR(b"Hello Alice!", long_to_bytes(k_a))` where `k_a = pow(A, b, P)`.

## Vulnerability
The server reuses the same private key `b` for multiple key exchanges. By carefully choosing parameters in the client's request, we can manipulate the computation to reveal the shared key `k_c` directly.

## Exploitation Approach
Normally, in Diffie-Hellman:
- Server's public for client: `B_a = pow(g, b, p)`
- Shared key for client: `k_a = pow(A, b, p)`

But notice that `k_c = pow(C, b, P)`.

If we set `g = C` (Charlie's public key) and `A = G` (which is 2), then:
- `B_a = pow(g, b, p) = pow(C, b, P) = k_c`

This directly gives us `k_c` as `B_a` in the response!

We can then convert `k_c` to bytes using `long_to_bytes(k_c)`, and XOR it with `msg_c` to recover the flag.

Note: The key is 128 bytes long, but the flag is shorter, so we truncate the key to match `msg_c`'s length.

## Exploit Script
```python
#!/usr/bin/env python3
import requests
import json
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Target URL
URL = "http://practice-digitalsecuritylab.di.unipi.it:11005/api/dh_exchange/"

# Constants from the server
G = 2
P = 123332382638231725701467272052746646677437210451686403929360967929971726170175522473010422422481335637035691756799160249433550988140577298403502161171408121294152540751727605530438344170959752812965964116010935488849567570589898718274440695293648653888226126185052620716306229882426016512073971282234225856687
C = 64612411667157069503976070918939607708875022270375896159569914279068171237996023267687125585927418267362932620044815107093025867940055155893108177681746956136085002346241007308415060540468449145442966833111022272981874509644086110124172781007706360095880503723087775599509214116527258964018584247604461917771

def xor(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings (mimics server's xor using zip)"""
    return bytes(x ^ y for x, y in zip(a, b))

def exploit():
    print("[*] Starting Diffie-Hellman Attack...")
    print("[*] Vulnerability: Server reuses private key 'b' for both exchanges")
    print()
    # Request: Setting g = C to get B_a = C^b mod P = k_c
    print("[*] Request: Setting g = C to recover full k_c as B_a")
    payload = {
        "g": C,
        "p": P,
        "A": G  # A can be anything, using G=2
    }
    response = requests.post(URL, json=payload, headers={"Content-Type": "application/json"})
    data = response.json()
    if "error" in data:
        print(f"[-] Error: {data['error']}")
        return
    msg_c_hex = data["msg_c"]
    msg_c = bytes.fromhex(msg_c_hex)
    k_c = int(data["B_a"])
    print(f"[+] Recovered k_c: {k_c}")
    print()
    # Compute key bytes
    key = long_to_bytes(k_c)
    print(f"[*] Key bytes (hex): {key.hex()}")
    print(f"[*] Key length: {len(key)} bytes")
    print()
    # Decrypt flag
    flag = xor(msg_c, key[:len(msg_c)])
    print("="*60)
    print("[+] FLAG FOUND:")
    print(f"[+] {flag.decode('utf-8', errors='ignore')}")
    print("="*60)

if __name__ == "__main__":
    try:
        exploit()
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()
```

## Execution Output
```
[*] Starting Diffie-Hellman Attack...
[*] Vulnerability: Server reuses private key 'b' for both exchanges

[*] Request: Setting g = C to recover full k_c as B_a
[+] Recovered k_c: 20551296460179613145336387750984705064569266879546516246792729153923132974064507137354101686209536292696192100808732543977651637845104070511817406234638572130014241522570149728074429909648821416863402317162754921583998373595290888262536383968994006332662326994216576708108028090240493464193275524554732530044

[*] Key bytes (hex): 1d4419badd154c8f8b3fef9c71879a3e6b9f06b5e697cfd6ad40a645b64daa274f946ed7b44a26f3c8d8d32cf78239f790bd7f2d1695abb0ea28d98e7594b4ed4e8a3fd67b5b13effaf1f5528a65944115456cdbbc2cfbbe81726325d047c7d0d5709e95f8eae843be0032314aa65f6ec6813dc61552394363b65d1f2d1ee97c
[*] Key length: 128 bytes

============================================================
[+] FLAG FOUND:
[+] TRT{938939e4a0dbafd8}
============================================================
```

## Flag
`TRT{938939e4a0dbafd8}`

## Lessons Learned
- Reusing private keys in Diffie-Hellman across sessions is dangerous.
- By controlling `g` and `A`, we can force the server to compute values that reveal sensitive information like the shared key.
