https://gemini.google.com/app/fb0336804503fe83?hl=id
# Write-Up: RSA Trilogy (Crypto)

**Challenge:** RSA Trilogy
**Category:** Cryptography
**Author:** aria

## Deskripsi Challenge

Challenge ini terdiri dari tiga bagian yang masing-masing mengeksploitasi kerentanan implementasi RSA yang berbeda. Tujuan akhirnya adalah menggabungkan hasil dekripsi dari ketiga bagian tersebut menjadi satu flag utuh.

Berikut adalah analisis dan penyelesaian untuk setiap bagian berdasarkan file yang diberikan.

-----

## Part 1: Small Public Exponent

**Analisis:**
[cite_start]Berdasarkan file `part1_pubkey.pem`[cite: 3], kita dapat mengekstrak informasi Public Key. Ditemukan bahwa modulus $n$ berukuran standar, namun eksponen publiknya sangat kecil, yaitu $e = 3$.

[cite_start]File `part1_ciphertext.enc` [cite: 2] berisi ciphertext yang di-encode dengan Base64.

**Kerentanan:**
Jika $e$ bernilai kecil (seperti 3) dan pesan $m$ tidak memiliki padding yang cukup (atau $m^3 < n$), maka enkripsi RSA hanya berupa pemangkatan biasa: $c = m^3$. Serangan ini dikenal sebagai **Cube Root Attack**.

**Penyelesaian:**
Kita dapat memulihkan pesan asli $m$ dengan menghitung akar pangkat tiga dari ciphertext $c$:
$$m = \sqrt[3]{c}$$

**Snippet Solver:**

```python
# Load Key & Cipher
with open('part1_pubkey.pem', 'r') as f:
    key = RSA.importKey(f.read())
with open('part1_ciphertext.enc', 'r') as f:
    c = bytes_to_long(base64.b64decode(f.read()))

# Attack: m = c^(1/3)
m, exact = integer_nth_root(c, key.e)
flag1 = long_to_bytes(m).decode()
```

-----

## Part 2: Wiener's Attack (Huge Public Exponent)

**Analisis:**
[cite_start]File `part2.txt` [cite: 1] memberikan nilai $n$, $e$, dan $ciphertext$.
Nilai $e$ yang diberikan sangat besar, hampir sebanding dengan besarnya $n$. Dalam RSA standar, $e$ biasanya kecil (misalnya 65537).

**Kerentanan:**
Ketika $e$ sangat besar, kemungkinan besar nilai private exponent $d$ sangat kecil. Jika $d < \frac{1}{3} n^{1/4}$, sistem rentan terhadap **Wiener's Attack**. Serangan ini menggunakan ekspansi pecahan berlanjut (continued fractions) dari $\frac{e}{n}$ untuk mendekati dan menemukan $d$.

**Penyelesaian:**

1.  Hitung ekspansi pecahan berlanjut dari $\frac{e}{n}$.
2.  Dapatkan konvergen $\frac{k}{d}$.
3.  Uji setiap $d$ untuk melihat apakah dapat memfaktorkan $n$ atau mendekripsi pesan dengan benar.

**Snippet Solver:**

```python
# Wiener's Attack implementation using continued fractions
# ... (fungsi continued_fractions dan convergents) ...
for k, d in convergents(continued_fractions(e, n)):
    if k == 0: continue
    if (e * d - 1) % k == 0:
        phi = (e * d - 1) // k
        # Cek validitas d dan dekripsi
        m = pow(c, d, n)
```

-----

## Part 3: Sum of Primes Leak ($x = p + q$)

**Analisis:**
[cite_start]File `part3.txt` [cite: 4] memberikan nilai $n$, $e$, $ciphertext$, dan sebuah variabel tambahan $x$.
Setelah dianalisis, nilai $x$ ternyata adalah jumlah dari faktor-faktor prima $n$.
$$x = p + q$$

**Kerentanan:**
Kita mengetahui dua persamaan dasar:

1.  $n = p \times q$
2.  $x = p + q$

Kita dapat mensubstitusi $q = x - p$ ke dalam persamaan pertama:
$$n = p(x - p)$$
$$n = px - p^2$$
$$p^2 - xp + n = 0$$

Ini adalah persamaan kuadrat. Kita dapat mencari nilai $p$ dan $q$ menggunakan rumus ABC:
$$p, q = \frac{x \pm \sqrt{x^2 - 4n}}{2}$$

**Penyelesaian:**

1.  Hitung diskriminan $D = x^2 - 4n$.
2.  Hitung $p$ dan $q$.
3.  Hitung $\phi(n) = (p-1)(q-1)$.
4.  Hitung $d = e^{-1} \pmod{\phi(n)}$.
5.  Dekripsi ciphertext.

-----

## Full Solver Script

Berikut adalah script Python lengkap yang menggabungkan ketiga solusi di atas:

```python
import base64
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse

def integer_nth_root(y, n):
    if y == 0: return 0, True
    L = y.bit_length()
    x = 1 << (L // n + 1)
    while True:
        next_x = ((n - 1) * x + y // pow(x, n - 1)) // n
        if next_x >= x: return x, (x**n == y)
        x = next_x

def integer_sqrt(y):
    return integer_nth_root(y, 2)

def solve_part1():
    try:
        with open('part1_pubkey.pem', 'r') as f:
            key = RSA.importKey(f.read())
        with open('part1_ciphertext.enc', 'r') as f:
            c = bytes_to_long(base64.b64decode(f.read().strip()))
        m, exact = integer_nth_root(c, key.e)
        return long_to_bytes(m).decode()
    except: return "Error"

def solve_part2():
    def continued_fractions(n, d):
        while d:
            q = n // d; yield q; n, d = d, n % d
    def convergents(cf):
        n0, n1, d0, d1 = 0, 1, 1, 0
        for q in cf:
            n_k, d_k = q * n1 + n0, q * d1 + d0
            yield n_k, d_k
            n0, n1, d0, d1 = n1, n_k, d1, d_k
    
    # Load data from part2.txt manually or hardcode
    n = 104150539323944854218222518232816171826386239923685519274534329680325309132683974594098331104258403147344177189768073033564919038098442267302014694387412013822707091084490543236331842059391521420457366362728247711745105766612827412454300663568582320270027088610499841553840112523546156538174899290062988597593
    e = 78740579270309350500158260397098709642129833310142201531554618974616246780757900680733070610557494359287280468205012618493909046694049056934377160129901445553460919676068672752533789927521693126839943987273791616604585961061211346527756846169228011392373290381588435250066915289098198037239703070080127336841
    c = 51371233935381919214715766093051795293685486813760984634822046434208967959036571449791669863374846731640740420250521846513439634295335594720553696577405628109761645163489806223416921109016094962013954533469542377322319705207143710628659555947371929369211881462934907808753787920879367365175801522179112883963
    
    for k, d in convergents(continued_fractions(e, n)):
        if k == 0: continue
        if (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            b = n - phi + 1
            delta = b*b - 4*n
            if delta >= 0:
                sqrt_delta, exact = integer_sqrt(delta)
                if exact and (b + sqrt_delta) % 2 == 0:
                    return long_to_bytes(pow(c, d, n)).decode()
    return "Error"

def solve_part3():
    # Load data from part3.txt manually or hardcode
    n = 0x6b26d86d654e1bb88dbd6da05866e97eebc1169dce56bd3c52c65c49851ffe3bc5ae114cc22fa491f6d6675ba1fdb7a846d199f5e9e68af6322ab7ead2c481aa160c15f9132e0ee07e84423d3e0fa108857198250bb37f032c9499b205beb0f42aee43b533dc79f53a7e27737dd7679d4d44f0beed6a15e78179449a0c655603
    e = 65537
    c = 0x7bfe695dc3925f9743065a8b79ed9367abbaf8ca092b362e31c48453ecb96363c7fd3d5b40052bae7c6c8515e7da1488892018557f234b41a319a9f7f8672b0cd8c7e5a159628af2c1f13b57e164b2f3ce32b363ddd3ee4c84012a621a60b353d6e1a4b96961effb6de36835e0df9d1702d5988ebe1902789dfa7e70924ae39
    x = 0x14ddc18c5fe16ac1125fe2a7049c3c53f98d2c5ecf552013534ddbfc06a714fe094eb33226ad6273eeb9a30d9c01d752b4f7adae4e34c16532cd6b8e2d4e01bac

    delta = x*x - 4*n
    if delta >= 0:
        diff, exact = integer_sqrt(delta)
        if exact:
            p = (x + diff) // 2
            q = (x - diff) // 2
            phi = (p - 1) * (q - 1)
            d = inverse(e, phi)
            return long_to_bytes(pow(c, d, n)).decode()
    return "Error"

p1 = solve_part1()
p2 = solve_part2()
p3 = solve_part3()

print(f"Flag Part 1: {p1}")
print(f"Flag Part 2: {p2}")
print(f"Flag Part 3: {p3}")
print(f"\nFull Flag: {p1}{p2}{p3}")
```

## Output Terminal

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF CTF 2025/Crypto/Rsa Trilogy]
└─$ python3 solver.py
Flag Part 1: FGTE{small_e_works_wi
Flag Part 2: ener_strikes_back_su
Flag Part 3: m_of_primes_indeed!}

Full Flag: FGTE{small_e_works_wiener_strikes_back_sum_of_primes_indeed!}
```
