# WriteUp - modular arithmetic

## Overview
- **Judul Challenge:** modular arithmetic
- **Kategori:** Cryptography
- **Poin:** 150
- **Author:** leastinformednerd
- **Release:** Site Release
- **Solves:** 26
- **First Blood:** whiterabbit240
- **Deskripsi:** I've encrypted the flag with RSA. I'm not sure why everyone tells me I need to know about modular arithmetic for it, though...

## Informasi Attachment & Struktur Direktori
Terdapat dua file yang diberikan, yaitu *source code* enkripsi Python dan file output yang berisi parameter publik RSA serta *ciphertext*. Berikut adalah struktur direktori dan isi file yang diinspeksi melalui terminal:

```bash
…WanZKey  ～  ~../Cryptography/modular arithmetic 󱎫 0s 󱑎 23.58
 󰋑  ▶  tree
.
├── output.txt
└── source.py

1 directory, 2 files

…WanZKey  ～  ~../Cryptography/modular arithmetic 󱎫 0s 󱑎 23.58
 󰋑  ▶  cat source.py
from os import getenv
from Crypto.Util.number import getPrime, bytes_to_long

p = getPrime(2048)
q = getPrime(2048)
n = p * q
e = 3
flag = bytes(getenv("FLAG"), "utf8") # VuwCTF{XXXXXXXX}
c = pow(bytes_to_long(flag), e, n)
print(f"{n=}, {e=}")
print(f"{c=}")

…WanZKey  ～  ~../Cryptography/modular arithmetic 󱎫 0s 󱑎 23.58
 󰋑  ▶  cat output.txt
n=641152162111255832806849940157292731048581855522342564071531816735693687129787191950218183203694724129216354459801337832552046585199636015507864039723932428215532179887900934308353586911651743274618686355944536613825592833889819874167021053173121866013111893531497804536262294550091237734728531456968006074978120928374991709662394647156494417492645486064379100142031756344923312060004086165732775158384625930796438533325654733431684996067202143555183451176924875076684727233205990251987246839380837521161418477244424738454184872046608019044884711971636440274229608057169460673484751893973455958889109468466295539617668578625836395968402375902803448153349129286466982417505629404420077784612270326326450205365220886391394861190616638338138798470575451427426407717125979627720898315614874253066432299806566640625221695956668109324258727461928896832613358825498534129481603069995804586061040044882805389787420832352466850799521771200628440017733908396871077996355871144459247199086765174553916232317919963253161433231876471089103606394310324843734331485704336643408924387935801816981988591739856745131167381761673944449313912181218114074727972035293904192142112756597194627050266903704367824138211205033200971339594738214933501446712937, e=3
c=79495882249845499496439141769531781176938627967717860175663659522125283197603391100966365269809320498266183369482098747024236712365629183552771069965050658339978975866026197759700574508615530914521594519099639278075848446610365268360010083259393717875709065451687013
```

## Proses Penyelesaian
1. Melakukan analisis pada file `source.py`. Terlihat bahwa *flag* dienkripsi menggunakan algoritma RSA standar dengan rumus $c \equiv m^e \pmod n$.
2. Mengidentifikasi kerentanan pada parameter yang digunakan. Nilai modulus $n$ sangat besar (4096-bit, hasil perkalian dua bilangan prima 2048-bit), namun nilai eksponen publik $e$ sangat kecil, yaitu $3$.
3. Mengingat ukuran pesan $m$ (*flag* dalam bentuk integer) relatif kecil dibandingkan $n$, maka saat $m$ dipangkatkan dengan $e$ ($m^3$), hasilnya tidak melebihi nilai $n$. 
4. Karena $m^3 < n$, operasi modulus tidak pernah membungkus (*wrap-around*) nilai tersebut. Dengan kata lain, $c = m^3$ murni tanpa efek modulus. Situasi ini memungkinkan dilakukannya **Low Public Exponent Attack** (spesifiknya **Cube Root Attack**).
5. Untuk mendekripsi pesan, tidak perlu memfaktorkan $n$ atau mencari *private key* $d$. Nilai asli $m$ dapat diperoleh cukup dengan menghitung akar pangkat tiga (*cube root*) murni dari *ciphertext* $c$.
6. Membuat *script solver* dengan algoritma pencarian biner (*binary search*) untuk mengekstraksi nilai integer secara akurat tanpa kendala presisi *floating-point*, sekaligus membaca file menggunakan mode `rb` agar pembacaan bersih dari masalah *encoding*.

## Script Solver
**solver.py**
```python
import re
from Crypto.Util.number import long_to_bytes

def integer_cube_root(n):
    low = 0
    high = n
    while low < high:
        mid = (low + high) // 2
        if mid**3 < n:
            low = mid + 1
        else:
            high = mid
    return low

def solve():
    try:
        with open("output.txt", "rb") as f:
            content = f.read().decode('utf-8')
        
        c_match = re.search(r'c=(\d+)', content)
        
        if c_match:
            c = int(c_match.group(1))
            print("[*] Berhasil mengekstrak nilai c dari output.txt.")
            print("[*] Melakukan eksekusi Cube Root Attack...")
            
            m = integer_cube_root(c)
            
            if m**3 == c:
                flag = long_to_bytes(m).decode('utf-8')
                print("[*] Dekripsi berhasil!")
                print(f"[*] Flag : {flag}")
            else:
                print("[!] Dekripsi gagal. c bukan perfect cube.")
        else:
            print("[!] Gagal menemukan nilai c di dalam file output.txt.")
            
    except FileNotFoundError:
        print("[!] File output.txt tidak ditemukan. Pastikan ada di direktori yang sama.")
    except Exception as e:
        print(f"[!] Terjadi error: {e}")

if __name__ == '__main__':
    solve()
```

**Output Terminal**
```bash
 󰋑  ▶  ./solver.py
[*] Berhasil mengekstrak nilai c dari output.txt.
[*] Melakukan eksekusi Cube Root Attack...
[*] Dekripsi berhasil!
[*] Flag : VuwCTF{big_n_leads_to_bigger_problem}
```

## Flag

```
VuwCTF{big_n_leads_to_bigger_problem}
```
