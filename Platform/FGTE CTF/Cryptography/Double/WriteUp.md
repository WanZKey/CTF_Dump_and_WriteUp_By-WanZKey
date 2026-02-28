https://g.co/gemini/share/e05c7eab369e
```markdown
# CTF WriteUp: Double (Crypto)

-   **Challenge Name:** double
-   **Category:** Crypto
-   **Points:** 100
-   **Author:** aria
-   **Description:** Awalnya tampak seperti angka & huruf heksadesimal, tapi jangan berhenti di situ. Setelah dibuka, masih ada lapisan klasik dengan pergeseran +7.

## 1. Problem Statement

We are given an encoded string and two hints about its decoding process.

```

526i645552587444556j6j515645396653564l66526j564m58304h565646394451553566516i566656464h4h5130745h587h49774k6h55774m54493166513k3k0h

````

**Hints:**
1.  "Awalnya tampak seperti angka & huruf heksadesimal, tapi jangan berhenti di situ." (Initially looks like hexadecimal numbers & letters, but don't stop there.)
2.  "Setelah dibuka, masih ada lapisan klasik dengan pergeseran +7." (After opening it, there's still a classic layer with a +7 shift.)

## 2. Initial Analysis

The first hint immediately points out that the given string is *not* standard hexadecimal, despite its appearance. Standard hex uses `0-9` and `a-f`. The string contains characters like `h, i, j, k, l, m`.

The second hint about a "classic layer with a +7 shift" is crucial. This hints at a Caesar cipher, or at least a character shift mechanism. It's likely that the non-hex characters (`h` through `m`) are the result of this +7 shift applied to the standard hex characters (`a` through `f`).

Let's test this hypothesis:
-   `a` + 7 = `h`
-   `b` + 7 = `i`
-   `c` + 7 = `j`
-   `d` + 7 = `k`
-   `e` + 7 = `l`
-   `f` + 7 = `m`

This confirms our hypothesis for the first layer. The first step will be to reverse this shift.

## 3. Solution Steps

### Step 1: Decode the Custom Hex Layer

We need to replace `h` with `a`, `i` with `b`, `j` with `c`, `k` with `d`, `l` with `e`, and `m` with `f` in the given string. This will convert the custom hex into a valid standard hexadecimal string.

Original string:
`526i645552587444556j6j515645396653564l66526j564m58304h565646394451553566516i566656464h4h5130745h587h49774k6h55774m54493166513k3k0h`

Applying the reverse shift (`-7`):
-   `i` -> `b`
-   `j` -> `c`
-   `l` -> `e`
-   `m` -> `f`
-   `h` -> `a`
-   `k` -> `d`

Resulting standard hex string:
`526b645552587444556c6c515645396653564e66526c564f58304a565646394451553566516b566656464a4a5130745a587a49774d6a55774f54493166513d3d0a`

### Step 2: Convert Hex to ASCII

Now that we have a valid hexadecimal string, we can convert it to its ASCII representation.

Using `xxd -r -p` (as suggested by the initial `echo` command in the prompt):

```bash
echo "526b645552587444556c6c515645396653564e66526c564f58304a565646394451553566516b566656464a4a5130745a587a49774d6a55774f54493166513d3d0a" | xxd -r -p
````

This yields:
`RkdURXtDUllQVE9fSVNfRlVOX0JVVF9DQU5fQkVfVFJJQ0tZXzIwMjUwOTI1fQ==`

### Step 3: Decode the Base64 Layer

The output from Step 2, `RkdURXtDUllQVE9fSVNfRlVOX0JVVF9DQU5fQkVfVFJJQ0tZXzIwMjUwOTI1fQ==`, is clearly a Base64 encoded string due to the trailing `==`. This is the "classic layer" mentioned in the hint.

Let's decode it:

```bash
echo "RkdURXtDUllQVE9fSVNfRlVOX0JVVF9DQU5fQkVfVFJJQ0tZXzIwMjUwOTI1fQ==" | base64 -d
```

This reveals the final message:
`FGTE{CRYPTO_IS_FUN_BUT_CAN_BE_TRICKY_20250925}`

It's important to note that the "pergeseran +7" (shift +7) mentioned in the hint applied to the *first* layer (the custom hex characters) and not necessarily to the final plaintext. The final message `FGTE{...}` is indeed the flag.

## 4\. Script Solver

A Python script was created to automate these steps:

```python
import base64

def solve_double_challenge(encoded_string):
    """
    Memecahkan tantangan "double" CTF.
    Melakukan dekripsi hex kustom, konversi hex ke ASCII, dan dekode Base64.
    """

    print(f"Original encoded string: {encoded_string}\n")

    # --- Langkah 1: Dekode Hex Kustom (Pergeseran -7 untuk non-hex chars) ---
    hex_custom_map = {
        'h': 'a', 'i': 'b', 'j': 'c', 'k': 'd', 'l': 'e', 'm': 'f'
    }

    decoded_hex_string = ""
    for char in encoded_string:
        decoded_hex_string += hex_custom_map.get(char, char)

    print(f"Step 1: Decoded custom hex string: {decoded_hex_string}\n")

    # --- Langkah 2: Konversi Hex ke ASCII ---
    try:
        ascii_bytes = bytes.fromhex(decoded_hex_string)
        decoded_ascii_string = ascii_bytes.decode('utf-8')
        print(f"Step 2: Decoded hex to ASCII string: {decoded_ascii_string}\n")
    except ValueError as e:
        print(f"Error converting hex to ASCII: {e}")
        return "Failed at Step 2"

    # --- Langkah 3: Dekode Base64 ---
    try:
        base64_bytes = decoded_ascii_string.encode('ascii')
        decoded_base64_bytes = base64.b64decode(base64_bytes)
        final_message = decoded_base64_bytes.decode('utf-8')
        print(f"Step 3: Decoded Base64 message: {final_message}\n")
    except base64.binascii.Error as e:
        print(f"Error decoding Base64: {e}")
        return "Failed at Step 3"
    except UnicodeDecodeError as e:
        print(f"Error decoding Base64 result to UTF-8: {e}")
        return "Failed at Step 3 (Unicode)"

    return final_message

# --- Data Challenge ---
challenge_string = "526i645552587444556j6j515645396653564l66526j564m58304h565646394451553566516i566656464h4h5130745h587h49774k6h55774m54493166513k3k0h"

# Jalankan solver
final_decoded_message = solve_double_challenge(challenge_string)

print("\n-------------------------------------------------")
print("SUMMARY:")
print(f"The message after all layers (Hex Kustom -> ASCII -> Base64) is:\n{final_decoded_message}")
```

## 5\. Execution and Flag

Running the provided Python script `solver.py` with the challenge string yields the following output:

```
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/ARIAF-CTF-2025/Crypto/Double]
└─$ python3 solver.py
Original encoded string: 526i645552587444556j6j515645396653564l66526j564m58304h565646394451553566516i566656464h4h5130745h587h49774k6h55774m54493166513k3k0h

Step 1: Decoded custom hex string: 526b645552587444556c6c515645396653564e66526c564f58304a565646394451553566516b566656464a4a5130745a587a49774d6a55774f54493166513d3d0a

Step 2: Decoded hex to ASCII string: RkdURXtDUllQVE9fSVNfRlVOX0JVVF9DQU5fQkVfVFJJQ0tZXzIwMjUwOTI1fQ==


Step 3: Decoded Base64 message: FGTE{CRYPTO_IS_FUN_BUT_CAN_BE_TRICKY_20250925}


-------------------------------------------------
SUMMARY:
The message after all layers (Hex Kustom -> ASCII -> Base64) is:
FGTE{CRYPTO_IS_FUN_BUT_CAN_BE_TRICKY_20250925}
```

The flag is clearly revealed after the final Base64 decoding.

## 6\. Flag

`FGTE{CRYPTO_IS_FUN_BUT_CAN_BE_TRICKY_20250925}`

```
```
