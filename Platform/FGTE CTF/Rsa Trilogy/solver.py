import base64
import math
import sys

# Fungsi bantuan konversi bytes-integer
def bytes_to_long(b):
    return int.from_bytes(b, 'big')

def long_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def inverse(a, m):
    return pow(a, -1, m)

# Fungsi akar integer (untuk Part 1 dan 3)
def integer_nth_root(y, n):
    if y < 0: raise ValueError("y must be non-negative")
    if n < 1: raise ValueError("n must be positive")
    if y == 0: return 0, True
    L = y.bit_length()
    x = 1 << (L // n + 1)
    while True:
        next_x = ((n - 1) * x + y // pow(x, n - 1)) // n
        if next_x >= x:
            return x, (x**n == y)
        x = next_x

def integer_sqrt(y):
    return integer_nth_root(y, 2)

# Parser sederhana untuk mengambil integer dari format DER (Part 1 key)
def extract_integers_from_der(der_data):
    integers = []
    i = 0
    while i < len(der_data):
        if der_data[i] == 0x02: # Integer Tag
            try:
                i += 1
                length = der_data[i]
                i += 1
                if length & 0x80:
                    n_len_bytes = length & 0x7f
                    length = int.from_bytes(der_data[i:i+n_len_bytes], 'big')
                    i += n_len_bytes
                value_bytes = der_data[i:i+length]
                integers.append(int.from_bytes(value_bytes, 'big'))
                i += length
            except: pass
        else:
            i += 1
    return integers

# --- PART 1: Small Exponent ---
def solve_part1():
    try:
        with open('part1_pubkey.pem', 'r') as f:
            lines = f.readlines()
            b64_data = "".join([l.strip() for l in lines if "-----" not in l])
            der_data = base64.b64decode(b64_data)
        
        # Ambil modulus n dari public key
        integers = extract_integers_from_der(der_data)
        n = max(integers) 
        e = 3 # Diketahui dari soal/analisis

        with open('part1_ciphertext.enc', 'r') as f:
            c = bytes_to_long(base64.b64decode(f.read().strip()))

        # Serangan m = c^(1/3)
        m, exact = integer_nth_root(c, e)
        if exact:
            return long_to_bytes(m).decode('utf-8', errors='ignore')
    except Exception as e:
        return str(e)

# --- PART 2: Wiener's Attack ---
def solve_part2():
    def continued_fractions(n, d):
        while d:
            q = n // d
            yield q
            n, d = d, n % d

    def convergents(cf):
        n0, n1 = 0, 1
        d0, d1 = 1, 0
        for q in cf:
            n_k, d_k = q * n1 + n0, q * d1 + d0
            yield n_k, d_k
            n0, n1, d0, d1 = n1, n_k, d1, d_k

    try:
        data = {}
        with open('part2.txt', 'r') as f:
            for line in f:
                if '=' in line:
                    k, v = line.split('=', 1)
                    data[k.strip()] = int(v.strip())
        
        n, e, c = data['n'], data['e'], data['ciphertext']
        
        # Wiener's attack
        for k, d in convergents(continued_fractions(e, n)):
            if k == 0: continue
            if (e * d - 1) % k == 0:
                phi = (e * d - 1) // k
                # Cek apakah phi valid dengan membentuk persamaan kuadrat
                b = n - phi + 1
                delta = b*b - 4*n
                if delta >= 0:
                    sqrt_delta, exact = integer_sqrt(delta)
                    if exact and (b + sqrt_delta) % 2 == 0:
                        m = pow(c, d, n)
                        return long_to_bytes(m).decode('utf-8', errors='ignore')
    except Exception as e:
        return str(e)

# --- PART 3: Sum of Primes (p+q) ---
def solve_part3():
    try:
        data = {}
        with open('part3.txt', 'r') as f:
            for line in f:
                if '=' in line:
                    k, v = line.split('=', 1)
                    val = v.strip()
                    data[k.strip()] = int(val, 16 if val.startswith('0x') else 10)

        n, e, c, x = data['n'], data['e'], data['ciphertext'], data['x']
        
        # x diberikan sebagai p + q
        # Persamaan: P^2 - xP + n = 0
        delta = x*x - 4*n
        if delta >= 0:
            diff, exact = integer_sqrt(delta)
            if exact:
                p = (x + diff) // 2
                q = (x - diff) // 2
                if p * q == n:
                    phi = (p - 1) * (q - 1)
                    d = inverse(e, phi)
                    m = pow(c, d, n)
                    return long_to_bytes(m).decode('utf-8', errors='ignore')
    except Exception as e:
        return str(e)

# Main Execution
flag1 = solve_part1()
flag2 = solve_part2()
flag3 = solve_part3()

print(f"Flag Part 1: {flag1}")
print(f"Flag Part 2: {flag2}")
print(f"Flag Part 3: {flag3}")
print(f"\nFull Flag: {flag1}{flag2}{flag3}")
