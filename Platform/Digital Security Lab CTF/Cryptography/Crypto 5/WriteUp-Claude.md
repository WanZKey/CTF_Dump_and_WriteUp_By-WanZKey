https://claude.ai/share/57cf52c9-1992-4cde-815a-dd110103fbd8
# CTF Writeup - Crypto 5: Diffie-Hellman Key Exchange

**Challenge:** Crypto 5  
**Points:** 500  
**Category:** Cryptography  
**Flag:** `TRT{938939e4a0dbafd8}`

---

## Challenge Description

Server melakukan pertukaran kunci Diffie-Hellman dan mengenkripsi pesan dengan shared key yang dihasilkan. Server melakukan dua pertukaran kunci:
1. Dengan Alice (client/kita) 
2. Dengan Charlie (internal user) - dan mengenkripsi FLAG dengan shared key ini

**Kerentanan:** Server menggunakan **private key `b` yang sama** untuk kedua pertukaran kunci.

---

## Analysis

### Source Code Review

```python
# Server constants
G = 2
P = [large prime]
b = random.randint(1, P)  # Bob's private key (SAMA untuk semua exchange!)

# Exchange dengan Charlie (FLAG)
C = [Charlie's public key]
k_c = pow(C, b, P)  # Shared key dengan Charlie
msg_c = xor(FLAG, long_to_bytes(k_c))  # FLAG dienkripsi
B_c = pow(G, b, P)  # Bob's public untuk Charlie

# Exchange dengan Alice (kita)
def get_encrypted_message():
    p = int(request.json["p"])
    g = int(request.json["g"])
    A = int(request.json["A"])
    
    B_a = pow(g, b, p)  # Bob's public untuk Alice
    k_a = pow(A, b, p)  # Shared key dengan Alice
    msg_a = xor(b"Hello Alice!", long_to_bytes(k_a))
    
    return {"msg_a": msg_a.hex(), "B_a": B_a, 
            "msg_c": msg_c.hex(), "B_c": B_c}
```

### Key Vulnerability

Server menggunakan **private key `b` yang sama** untuk:
- Menghitung `k_c = C^b mod P` (key dengan Charlie)
- Menghitung `k_a = A^b mod p` (key dengan kita)

Dan kita bisa **mengontrol parameter `g`, `p`, dan `A`**!

---

## Solution Strategy

### Failed Approaches ❌

**Attempt 1:** Set `A = C` (Charlie's public key)
- Hasil: `k_a = C^b mod P = k_c` 
- Masalah: Kita hanya bisa recover 12 bytes pertama dari key karena `xor()` menggunakan `zip()` yang berhenti di string terpendek
- `msg_a = xor(b"Hello Alice!", long_to_bytes(k_a))` → hanya 12 bytes
- `msg_c` butuh 21 bytes key untuk decrypt penuh

**Attempt 2:** Brute force byte-by-byte
- Masalah: Terlalu banyak kandidat valid (16 per byte)
- Tidak ada cara untuk validate kandidat mana yang benar

### Winning Approach ✅

**Insight Kunci:** Kita bisa set `g = C` untuk mendapatkan:

```
B_a = pow(g, b, p) = pow(C, b, P) = k_c
```

Dengan setting `g = C` dan `p = P`, maka `B_a` yang dikembalikan server **adalah `k_c` itu sendiri**!

---

## Exploit

### Step-by-Step

1. **Kirim request dengan parameter khusus:**
   ```python
   payload = {
       "g": C,      # Set generator = Charlie's public key
       "p": P,      # Set modulus = server's prime
       "A": G       # A bisa apa saja (kita pakai G=2)
   }
   ```

2. **Extract `k_c` dari response:**
   ```python
   k_c = int(data["B_a"])  # B_a = g^b mod p = C^b mod P = k_c
   ```

3. **Convert `k_c` ke bytes:**
   ```python
   key = long_to_bytes(k_c)  # Full key dalam bentuk bytes
   ```

4. **Decrypt FLAG:**
   ```python
   flag = xor(msg_c, key[:len(msg_c)])
   ```

### Final Exploit Code

```python
#!/usr/bin/env python3
import requests
from Crypto.Util.number import long_to_bytes

URL = "http://practice-digitalsecuritylab.di.unipi.it:11005/api/dh_exchange/"

G = 2
P = 123332382638231725701467272052746646677437210451686403929360967929971726170175522473010422422481335637035691756799160249433550988140577298403502161171408121294152540751727605530438344170959752812965964116010935488849567570589898718274440695293648653888226126185052620716306229882426016512073971282234225856687
C = 64612411667157069503976070918939607708875022270375896159569914279068171237996023267687125585927418267362932620044815107093025867940055155893108177681746956136085002346241007308415060540468449145442966833111022272981874509644086110124172781007706360095880503723087775599509214116527258964018584247604461917771

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Attack: Set g = C to get B_a = C^b mod P = k_c
payload = {"g": C, "p": P, "A": G}
response = requests.post(URL, json=payload, headers={"Content-Type": "application/json"})
data = response.json()

# Extract k_c from B_a
k_c = int(data["B_a"])
key = long_to_bytes(k_c)

# Decrypt flag
msg_c = bytes.fromhex(data["msg_c"])
flag = xor(msg_c, key[:len(msg_c)])

print(f"FLAG: {flag.decode()}")
```

---

## Execution

```bash
$ python3 solver.py
[*] Starting Diffie-Hellman Attack...
[*] Vulnerability: Server reuses private key 'b' for both exchanges
[*] Request: Setting g = C to recover full k_c as B_a
[+] Recovered k_c: 205512964601796131453...
[*] Key length: 128 bytes
============================================================
[+] FLAG FOUND:
[+] TRT{938939e4a0dbafd8}
============================================================
```

---

## Key Takeaways

1. **Never reuse private keys** across different Diffie-Hellman exchanges
2. **Validate parameters** - Server seharusnya validate bahwa `g` adalah generator yang valid
3. **Don't expose internal keys** - Server mengirim `B_c` dan `msg_c` ke client yang tidak seharusnya punya akses
4. **Think creatively** - Solution yang elegan seringkali lebih sederhana daripada brute force

---

## Flag

```
TRT{938939e4a0dbafd8}
```

**Challenge solved!** 🚩
