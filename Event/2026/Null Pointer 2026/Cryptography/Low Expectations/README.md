# WriteUp - Low Expectations

## Overview

* **Judul:** Low Expectations
* **Kategori:** Cryptography
* **Poin:** 200
* **Author:** Unknown
* **Deskripsi:** A high-security vault uses RSA, but they wanted the encryption to be "extra fast."
* **Public Key:** - `N = 26240732739797710318477280648827162473999619241835641060411810907669006036416906327186927503360680349518443458346196930521065539895056608374570962879387937304563063851863277053041565359436446611186437031619549156857986800713566069168317544707860032698279284661720521456543459316823282807275474930618080577985284867794560554048936357223033388337111849134097523646894081106245134933427497706571336934361273679124207332246613959080223802096116923549430879913574815815393702806791610867943661113274547752353977501668842731446991606609310163653949431859867741808652188730858595130329659297009250032996901671309833100857577`
* `e = 3`


* **Intercepted Ciphertext:** - `C = 2804334233556134023789914920080760625298971538583084583014507904151266268217865184683978548558602263322628392056339001518677061679977071618432489191660135079841091132148390248894784697236814938249255809978452570202476340414946833954348105514856611842710310602139410999092987887846523458973467398825722769875814197503273741291528282383501248057784462692345888002584212320607904293989`



## Proses Penyelesaian

1. Menganalisa deskripsi dan parameter soal. Diberikan parameter RSA yaitu modulus $N$, ciphertext $C$, dan public exponent $e = 3$.
2. Memperhatikan nilai $e = 3$ yang sangat kecil beserta petunjuk judul "Low Expectations" dan deskripsi "extra fast". Hal ini mengindikasikan kerentanan *Small Public Exponent Attack* (sering disebut *Cube Root Attack*).
3. Dalam RSA standar, enkripsi dilakukan dengan formula $C = M^e \pmod N$. Karena $e = 3$ dan pesan $M$ cukup kecil (serta tidak menggunakan skema padding yang aman seperti OAEP), maka $M^3 < N$. Akibatnya, operasi modulo tidak terjadi (tidak wrap around) dan persamaan enkripsi hanya menjadi $C = M^3$.
4. Menyusun script solver menggunakan algoritma pencarian biner (*binary search*) untuk mencari akar pangkat tiga (*integer cube root*) dari ciphertext $C$ secara presisi dan efisien.
5. Mengonversi nilai integer pesan $M$ yang didapatkan kembali ke dalam bentuk hexadecimal, lalu melakukan proses decode ke format string UTF-8.
6. Mengeksekusi script solver di terminal dan berhasil mengekstrak plaintext asli. We got this bro!

## Script Solver

```python
import binascii

def integer_nth_root(x, n):
    high = 1
    while high ** n <= x:
        high *= 2
    low = high // 2
    while low < high:
        mid = (low + high) // 2
        if low < mid and mid**n < x:
            low = mid
        elif high > mid and mid**n > x:
            high = mid
        else:
            return mid
    return mid + 1

def solve():
    N = 26240732739797710318477280648827162473999619241835641060411810907669006036416906327186927503360680349518443458346196930521065539895056608374570962879387937304563063851863277053041565359436446611186437031619549156857986800713566069168317544707860032698279284661720521456543459316823282807275474930618080577985284867794560554048936357223033388337111849134097523646894081106245134933427497706571336934361273679124207332246613959080223802096116923549430879913574815815393702806791610867943661113274547752353977501668842731446991606609310163653949431859867741808652188730858595130329659297009250032996901671309833100857577
    e = 3
    C = 2804334233556134023789914920080760625298971538583084583014507904151266268217865184683978548558602263322628392056339001518677061679977071618432489191660135079841091132148390248894784697236814938249255809978452570202476340414946833954348105514856611842710310602139410999092987887846523458973467398825722769875814197503273741291528282383501248057784462692345888002584212320607904293989
    
    print("[*] Hustling the small exponent attack (cube root)...")
    m = integer_nth_root(C, e)
    
    if m**e == C:
        print("[+] We got a perfect cube bro!")
        hex_m = hex(m)[2:]
        if len(hex_m) % 2 != 0:
            hex_m = '0' + hex_m
        
        try:
            flag = binascii.unhexlify(hex_m).decode('utf-8')
            print(f"Result: {flag}")
        except Exception as err:
            print(f"Decode failed: {err}")
    else:
        print("[-] Not a perfect cube. The message might be padded or wrapped around N.")

if __name__ == "__main__":
    solve()

```

## Terminal Output

```text
  ▶  ./solver.py
[*] Hustling the small exponent attack (cube root)...
[+] We got a perfect cube bro!
Result: STURSEC{r34l_m4th_h45_curv35_bu7_th15_j35t_h45_r00t5}

```

## Flag

```text
STURSEC{r34l_m4th_h45_curv35_bu7_th15_j35t_h45_r00t5}

```

