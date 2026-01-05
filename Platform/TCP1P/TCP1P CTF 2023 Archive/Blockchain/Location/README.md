# WriteUp : Location

## Overview

* **Judul**: Location
* **Kategori**: Blockchain
* **Poin**: 1000 pts
* **Author**: Kiinzu
* **URL**: [https://gzcli.1pc.tf/tcp1p-ctf-2023-archive-blockchain-location](https://gzcli.1pc.tf/tcp1p-ctf-2023-archive-blockchain-location)
* **Deskripsi**: Kita diminta mencari "lokasi pesta" dengan cara menjawab teka-teki mengenai posisi *Storage Slot* variabel `password` pada smart contract Solidity.

## Langkah Penyelesaian

### 1. Analisis Challenge

Saat terhubung ke layanan `nc gzcli.1pc.tf 52206`, server memberikan serangkaian pertanyaan (total 10 acak + 1 final). Setiap pertanyaan menampilkan kode Solidity dan meminta kita menentukan di **Slot** nomor berapa variabel `password` disimpan.

Aturan penyimpanan (*Storage Layout*) EVM yang perlu dipahami:

* Setiap slot berukuran **32 bytes**.
* Variabel state disimpan secara berurutan mulai dari **Slot 0**.
* **Packing**: Variabel yang ukurannya kurang dari 32 bytes (misal `uint64`, `address`, `bool`) akan digabung ke dalam satu slot jika muat.
* **Array Statis** (`address[2]`): Selalu memulai slot baru. Elemen array disusun berurutan.
* **Immutable**: Variabel dengan keyword `immutable` **TIDAK** disimpan di storage slot, melainkan di bytecode. Jawabannya selalu `0` (atau tidak dihitung).

### 2. Identifikasi Jawaban

Berdasarkan analisis layout dan perilaku server, berikut adalah kunci jawaban untuk setiap kontrak:

| Contract | Variabel Sebelum Password | Posisi Password | Jawaban Slot |
| --- | --- | --- | --- |
| **StorageChallenge1** | `bytes32`, `address[2]` | `uint64` (Packed) | **3** |
| **StorageChallenge2** | `address[2]` | `uint64` (Packed) | **2** |
| **StorageChallenge3** | `address`, `uint64` | `uint64` (Packed) | **0** |
| **StorageChallenge4** | (None) | `uint64` (First var) | **0** |
| **StorageChallenge5** | `address[2]`, `bytes32`, `address` | `uint64` (Packed) | **3** |
| **StorageChallenge6** | `immutable` (Skip) | `uint64` (First valid) | **0** |
| **StorageChallenge7** | `immutable` | `immutable` | **0** |
| **StorageChallenge8** | `bytes32`, `bytes4/16`, `address`, `uint256`... | `bytes32` | **6** |
| **StorageChallenge9** | `bytes32`, `bytes32`, `address`, `address[20]`... | `bytes32` | **24** |
| **StorageChallenge10** | 3x `bool`, `bytes32` | `bytes32` | **2** |
| **Hell_0** | (Kompleks Struct) | `bytes32` | **28** |

### 3. Otomatisasi Solver

Ditemukan *bug* pada string matching sederhana: `StorageChallenge1` adalah substring dari `StorageChallenge10`. Jika script mengecek `Challenge1` duluan, maka jawaban untuk `Challenge10` akan salah.

Solusinya adalah mengurutkan pengecekan nama kontrak berdasarkan panjang string (descending) dan menangani `Hell_0` sebagai akhir koneksi.

## Script Solver (`solver.py`)

```python
from pwn import *

# Konfigurasi Koneksi
HOST = 'gzcli.1pc.tf'
PORT = 52206

answers = {
    "StorageChallenge1": 3,
    "StorageChallenge2": 2,
    "StorageChallenge3": 0,
    "StorageChallenge4": 0,
    "StorageChallenge5": 3,
    "StorageChallenge6": 0,
    "StorageChallenge7": 0,
    "StorageChallenge8": 6,
    "StorageChallenge9": 24,
    "StorageChallenge10": 2,
    "Hell_0": 28
}

def start():
    # Setup koneksi
    r = remote(HOST, PORT)

    # Urutkan kunci berdasarkan panjang string (Descending)
    # Agar StorageChallenge10 dideteksi sebelum StorageChallenge1
    sorted_contracts = sorted(answers.keys(), key=len, reverse=True)

    try:
        while True:
            # Terima data dengan timeout untuk menghindari hang
            output = r.recvuntil(b'Answer:', drop=False).decode()
            print(output)

            current_contract = None
            
            # Deteksi kontrak yang sedang aktif
            for contract_name in sorted_contracts:
                if f"contract {contract_name}" in output:
                    current_contract = contract_name
                    break
            
            if current_contract:
                ans = answers[current_contract]
                print(f"[+] Detected: {current_contract} -> Sending Answer: {ans}")
                r.sendline(str(ans).encode())

                # Penanganan Khusus Final Boss (Hell_0)
                # Setelah jawab Hell_0, langsung baca sisa buffer (Flag)
                if current_contract == "Hell_0":
                    print("[*] Final answer sent! Receiving Flag...")
                    final_output = r.recvall().decode()
                    print(final_output)
                    break 
            else:
                pass

    except EOFError:
        print("[-] Connection Closed by Server.")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        r.close()

if __name__ == "__main__":
    start()

```

## Output Terminal

```bash
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/TCP1P/TCP1P CTF 2023 Archive/Blockchain/Location]
└─$ python3 solver.py
[+] Opening connection to gzcli.1pc.tf on port 52206: Done
====Going to The Party====

To Find the party location
You need to solve a simple riddle regarding a SLOT
Answer everything correctly, and find the exact location!
...
(Output pertanyaan dipotong untuk mempersingkat)
...
Question:

contract Hell_0 {
    uint256 private avail_money;
    uint256 private saved_money;
    bool private not_minus;
    address private owner;
    uint256[2] private geo_loc;
    bool private is_there;
    bool private there;
    address private wallet;
    address private receiver;
    address[20] private transaction_list;
    bytes32 private user_creds;
    uint256 private immutable user_in_uint;
    bytes32 private password;
    uint256 private password_uint;
    bool private correct_password;
    bool private is_user;
}

Answer:
[+] Detected: Hell_0 -> Sending Answer: 28
[*] Final answer sent! Receiving Flag...
[+] Receiving all data: Done (68B)
[*] Closed connection to gzcli.1pc.tf port 52206
 Go to Camelleion Street 78
TCP1P{c279f9799280442b8c50dd380ae9ef52}

```

**Flag:** `TCP1P{c279f9799280442b8c50dd380ae9ef52}`
