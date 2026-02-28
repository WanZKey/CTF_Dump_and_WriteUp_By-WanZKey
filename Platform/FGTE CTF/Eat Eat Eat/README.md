# WriteUp - Eat Eat Eat

## Overview

* **Judul:** Eat Eat Eat
* **Kategori:** Reverse Engineering
* **Poin:** 50
* **Deskripsi:** The author was very hungry while writing this program. Variable names make no sense, logic flows in strange ways, and yet… the program works perfectly. Your task is simple: Find the input that satisfies the program and gets absolutely EATEN.
* **Author:** aria

## Attachment

* **Direktori:** `~../Reverse/Eat Eat Eat`
* **File:** `eat.py`

## Proses Penyelesaian

### 1. Reconnaissance & Code Analysis

Langkah pertama adalah menganalisis file `eat.py`. Kode sumber penuh dengan variabel yang disamarkan (obfuscated) menggunakan kata "EAT" dalam berbagai variasi huruf besar dan kecil, membuat logika sulit dibaca secara langsung.

**Output Terminal (Recon):**

```bash
WanZKey  ～  ~../Reverse/Eat Eat Eat 󱎫 0s 󱑎 16.42
 󰋑  ▶  file eat.py
eat.py: Python script, ASCII text executable

WanZKey  ～  ~../Reverse/Eat Eat Eat 󱎫 0s 󱑎 16.42
 󰋑  ▶  cat eat.py
# I wrote and debugged this code with all the convoluted "EAT" variable names.
# Was it confusing? Yes.
# Was debugging hard? Yes.
# Did I spend more time than I should have on this problem? Yes

EAT = int
eAT = len
EaT = print
ATE = str
EATEATEATEATEATEAT = ATE.isdigit

def Eating(eat):
    return ATE(EAT(eat) * EATEATEAT)

def EAt(eat, eats):
    eat1 = 0
    eat2 = 0
    eateat = 0
    eAt = ""
    while eat1 < eAT(eat) and eat2 < eAT(eats):
        if eateat % EATEATEAT == EATEATEATEATEAT // EATEATEATEAT:
            eAt += eats[eat2]
            eat2 += 1
        else:
            eAt += eat[eat1]
            eat1 += 1
        eateat += 1
    return eAt

def aten(eat):
    return eat[::EATEATEAT - EATEATEATEAT]

def eaT(eat):
    return Eating(eat[:EATEATEAT]) + aten(eat)

def aTE(eat):
    return eat

def Ate(eat):
    return "Eat" + ATE(eAT(eat)) + eat[:EATEATEAT]

def Eat(eat):
    if eAT(eat) == 9:
        if EATEATEATEATEATEAT(eat[:EATEATEAT]) and \
           EATEATEATEATEATEAT(eat[eAT(eat) - EATEATEAT + 1:]):

             eateat = EAt(eaT(eat), Ate(aTE(aten(eat))))

             if eateat == "E10a23t9090t9ae0140":
                 flag = "FGTE{eat_python_" + eat + "}"
                 EaT("absolutely EATEN!!!")
                 EaT(flag)
             else:
                 EaT("wrong answer, but nicely formatted")
        else:
            EaT("bad format (example: 123abc456)")
    else:
        EaT("bad length")

EaT("what's the answer")
eat = input()

EATEATEAT = eAT(eat) // 3
EATEATEATEAT = EATEATEAT + 1
EATEATEATEATEAT = EATEATEAT - 1

Eat(eat)

```

### 2. Deobfuscation (Analisis Logika)

Kita perlu menerjemahkan variabel "EAT" ke dalam bentuk yang dapat dimengerti. Berdasarkan definisi di awal script dan operasi matematika sederhana:

* `EAT` = `int`
* `eAT` = `len`
* `ATE` = `str`
* `EATEATEAT` (3 EATs) = `len(eat) // 3`. Karena validasi mengharuskan panjang string 9, maka nilai ini adalah **3**.
* `EATEATEATEAT` (4 EATs) = **4**.
* `EATEATEATEATEAT` (5 EATs) = **3**.

**Fungsi Utama (`Eat`):**

1. Validasi panjang input harus **9** karakter.
2. 3 karakter awal (`eat[:3]`) harus digit.
3. 2 karakter akhir harus digit.
4. Jika valid, input diproses menjadi dua bagian string (`eaT` dan `Ate`), lalu digabung (`EAt`) untuk dicocokkan dengan target `"E10a23t9090t9ae0140"`.

**Bedah Fungsi Proses:**

1. **`Eating(eat)`:** Mengembalikan string hasil perkalian integer input dengan 3 (`str(int(eat) * 3)`).
2. **`aten(eat)`:** Mengembalikan string yang dibalik (`reverse`).
3. **`eaT(eat)` / String 1:** `Eating(eat[:3]) + aten(eat)`.
* Rumus: `(3 Digit Awal * 3) + Reverse(Full Input)`.


4. **`Ate(eat)` / String 2:** `"Eat" + str(len(eat)) + eat[:3]`.
* Rumus: `"Eat9" + Reverse(Full Input)[:3]`.


5. **`EAt(String1, String2)` / Interleaver:**
* Menggabungkan kedua string. Jika index counter `% 3 == 0`, ambil karakter dari **String 2**, selain itu ambil dari **String 1**.



### 3. Solving Strategy

Kita bisa membalikkan proses penggabungan (interleaving) untuk mendapatkan kembali String 1 dan String 2 dari target `"E10a23t9090t9ae0140"`.

**Langkah Reverse:**

1. **Ekstrak String 2 (Posisi index 0, 3, 6, ...):**
* Target: `E`..`a`..`t`..`9`..`9`..`0`..`0` -> **`Eat9900`**
* Analisis: `Eat9900` = `"Eat9"` + `Reverse(Input)[:3]`.
* Kesimpulan: 3 huruf awal dari reversed input adalah **`900`**. Ini berarti input asli berakhiran **`009`**.


2. **Ekstrak String 1 (Posisi index sisa):**
* Target: .`10`..`23`..`90`..`0t`..`ae`..`14` -> **`1023900tae14`**
* Analisis: `1023900tae14` = `(3 Digit Awal * 3)` + `Reverse(Full Input)`.
* Kita tahu `Reverse(Full Input)` diawali dengan `900`.
* Maka, string ini dipisah menjadi: `1023` (Hasil Kali) dan `900tae14` (Sisa Reverse).


3. **Rekonstruksi Input:**
* **Prefix:** `3 Digit Awal * 3 = 1023` -> `3 Digit Awal = 1023 / 3 = 341`.
* **Reverse Lengkap:** Kita punya potongan reverse `900tae14` (8 karakter). Input harus 9 karakter. Karakter yang hilang di akhir reverse string adalah karakter pertama dari input asli (`3`).
* Reverse Lengkap = `900tae14` + `3` -> **`900tae143`**.
* **Final Input:** Balikkan `900tae143` menjadi **`341eat009`**.



### 4. Solver Script & Output

Berikut adalah script solver yang mengimplementasikan logika di atas.

```python
def solve():
    # Target string output
    target = "E10a23t9090t9ae0140"
    
    print("[*] Target:", target)
    
    # Step 1: Extract 'String 2' (indices 0, 3, 6...)
    # Logic: if eateat % 3 == 0: take from String 2
    s2_indices = [i for i in range(len(target)) if i % 3 == 0]
    string2 = "".join([target[i] for i in s2_indices])
    print(f"[*] Extracted String 2 (Ate): {string2}")
    
    # Step 2: Extract 'String 1' (remaining indices)
    s1_indices = [i for i in range(len(target)) if i % 3 != 0]
    string1 = "".join([target[i] for i in s1_indices])
    print(f"[*] Extracted String 1 (eaT): {string1}")
    
    # String 1 breakdown: "1023" (Product) + "900tae14" (Partial Rev)
    product_str = "1023"
    partial_rev = "900tae14"
    
    # Step 3: Recover first 3 digits
    # Product = int(input[:3]) * 3
    first_three = str(int(product_str) // 3)
    print(f"[*] Input first 3 chars: {first_three}")
    
    # Step 4: Recover full reversed string
    # The last char of rev_input MUST be the first char of input.
    last_char_rev = first_three[0] # '3'
    full_rev = partial_rev + last_char_rev
    print(f"[*] Full Reversed Input: {full_rev}")
    
    # Step 5: Final Input
    final_input = full_rev[::-1]
    print(f"\n[+] FOUND INPUT: {final_input}")
    print(f"[+] Flag: FGTE{{eat_python_{final_input}}}")

if __name__ == "__main__":
    solve()

```

**Output Terminal:**

```bash
 󰋑  ▶  ./solver.py
[*] Target: E10a23t9090t9ae0140
[*] Extracted String 2 (Ate): Eat9900
[*] Extracted String 1 (eaT): 1023900tae14
[*] Input first 3 chars: 341
[*] Full Reversed Input: 900tae143

[+] FOUND INPUT: 341eat009
[+] Flag: FGTE{eat_python_341eat009}

```

## Flag

```
FGTE{eat_python_341eat009}

```
