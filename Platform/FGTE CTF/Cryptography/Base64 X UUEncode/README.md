# WriteUp - Base64 X UUEncode

## Overview

* **Judul:** Base64 X UUEncode
* **Kategori:** Crypto
* **Poin:** 50
* **Author:** aria
* **Deskripsi:**
base64 dengan tambahan lapisan UUEncode.

## Informasi Attachment

Challenge ini memberikan ciphertext dalam format string.

**Ciphertext:**

```text
TTFEPTQxN00iODctRS1DMT82JV01NTQ1TjhWXUQ5NV0zPTYtQzk3LVM5RzVMOydFPzEmNUM7VjFFOSIlXQ==

```

## Proses Penyelesaian

1. **Analisa Layer 1 (Base64):**
String yang diberikan memiliki format standar Base64 (alphanumeric dengan padding `=` di akhir).
Langkah pertama adalah melakukan decode Base64 terhadap string tersebut.
* **Input:** `TTFEPTQx...`
* **Output:** `M1D=417M"87-E-C1?6%]5545N8V]D95]3=6-C97-S9G5L;'E?1&5C;V1E9"%]`


2. **Analisa Layer 2 (UUEncode):**
Hasil decode Layer 1 diawali dengan karakter `M`. Dalam skema **UUEncode**, karakter pertama merepresentasikan panjang data dalam baris tersebut (Length Byte). Format string ini cocok dengan *raw UUEncoded line*.
Langkah selanjutnya adalah melakukan decode UUEncode untuk mendapatkan plaintext asli.

## Script Solver

Berikut adalah script Python (`solve.py`) untuk menyelesaikan challenge ini:

```python
import base64
import binascii

def solve():
    print("[*] Solver Base64 X UUEncode")
    
    # 1. Input ciphertext
    ct = "TTFEPTQxN00iODctRS1DMT82JV01NTQ1TjhWXUQ5NV0zPTYtQzk3LVM5RzVMOydFPzEmNUM7VjFFOSIlXQ=="
    
    try:
        # 2. Decode Base64
        print("[*] Decoding Base64...")
        step1 = base64.b64decode(ct).decode('utf-8')
        print(f"    [>] Result: {step1}")
        
        # 3. Decode UUEncode
        print("[*] Decoding UUEncode...")
        # binascii.a2b_uu digunakan untuk decode single line UUEncode
        flag_bytes = binascii.a2b_uu(step1)
        flag = flag_bytes.decode('utf-8')
        
        print("\n" + "="*40)
        print(f"SOLVED FLAG: {flag}")
        print("="*40 + "\n")
        
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()

```

## Output Terminal

```bash
 󰋑  ▶  ./solver.py
[*] Solver Base64 X UUEncode
[*] Decoding Base64...
    [>] Result: M1D=417M"87-E-C1?6%]5545N8V]D95]3=6-C97-S9G5L;'E?1&5C;V1E9"%]
[*] Decoding UUEncode...

========================================
SOLVED FLAG: FGTE{Base64_X_UUEncode_Successfully_Decoded!}
========================================

```

## Flag

```
FGTE{Base64_X_UUEncode_Successfully_Decoded!}

```
