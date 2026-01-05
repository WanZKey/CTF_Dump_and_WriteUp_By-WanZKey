# WriteUp : Venue

## Overview

* **Judul**: Venue
* **Kategori**: Blockchain / Smart Contract
* **Poin**: 1000 pts
* **Author**: Kiinzu
* **Deskripsi**: Kita diajak masuk ke "Venue Pesta". Diberikan alamat kontrak di Sepolia Testnet dan diminta untuk berinteraksi dengannya untuk mendapatkan flag.

## Informasi Attachment

1. **`Venue.sol`**: Source code dari Smart Contract.
2. **`101.txt`**: Petunjuk singkat untuk menggunakan library Web3.
3. **Target Address**: `0x1AC90AFd478F30f2D617b3Cb76ee00Dd73A9E4d3` (Sepolia Network).
4. **RPC Provider**: URL Alchemy yang diberikan di soal sudah **tidak aktif/expired**.

## Analisis Mendalam

### 1. Bedah Smart Contract (`Venue.sol`)

Mari kita lihat kode Solidity yang diberikan:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract Venue{
    string private flag;      // Variabel state bersifat Private
    string private message;

    constructor(string memory initialFlag, string memory initialMessage){
        flag = initialFlag;
        message = initialMessage;
    }

    // Fungsi Public yang mengembalikan nilai flag
    function enterVenue() public view returns(string memory){
        return flag;
    }

    function goBack() public view returns(string memory){
        return message;
    }
}

```

**Analisis Kerentanan/Fitur:**

* Variabel `flag` dideklarasikan sebagai `private`. Dalam Solidity, `private` berarti variabel ini tidak bisa diakses oleh kontrak lain (*external contracts*).
* **NAMUN**, data di blockchain itu transparan. Semua variabel `private` sebenarnya bisa dibaca dengan cara mengakses *Storage Slot* secara langsung.
* **LEBIH MUDAHNYA LAGI**: Developer kontrak ini menyediakan fungsi **`enterVenue()`** yang bersifat `public`. Fungsi ini secara eksplisit me-return isi variabel `flag`.
* Fungsi ini bertipe **`view`**. Artinya, fungsi ini hanya **membaca** state blockchain, tidak mengubah data. Oleh karena itu, kita **tidak perlu membayar Gas Fee (ETH)** dan **tidak perlu Private Key** untuk memanggilnya. Kita hanya melakukan "Call", bukan "Transaction".

### 2. Masalah Infrastruktur (RPC Dead)

Tantangan teknis di soal ini adalah URL RPC Alchemy yang diberikan (`https://eth-sepolia.g.alchemy.com/v2/...`) sudah mati karena API Key-nya dinonaktifkan.

**Solusi:** Kita harus menggantinya dengan **Public RPC Node** yang tersedia gratis untuk jaringan Sepolia, misalnya `https://ethereum-sepolia-rpc.publicnode.com`.

## Strategi Penyelesaian

Kita akan menggunakan Python dengan library `web3.py`. Langkah-langkahnya:

1. Inisialisasi koneksi ke Sepolia Testnet menggunakan Public RPC.
2. Definisikan alamat kontrak target.
3. Definisikan **ABI (Application Binary Interface)** minimal. Kita hanya butuh definisi fungsi `enterVenue` agar script tahu cara memanggilnya.
4. Panggil fungsi tersebut menggunakan metode `.call()`.

### Script Solver (`solve.py`)

Berikut adalah script yang digunakan untuk menyelesaikan challenge:

```python
from web3 import Web3

# 1. Konfigurasi Koneksi (Gunakan Public RPC yang aktif)
rpc_url = "https://ethereum-sepolia-rpc.publicnode.com"
print(f"[*] Connecting to {rpc_url}...")

w3 = Web3(Web3.HTTPProvider(rpc_url))

if not w3.is_connected():
    print("[-] Gagal konek ke Public RPC. Cek internet.")
    exit()

print("[+] Connected successfully!")

# 2. Target Contract
target_address = "0x1AC90AFd478F30f2D617b3Cb76ee00Dd73A9E4d3"
target_address = w3.to_checksum_address(target_address)

# 3. ABI Minimal (Hanya fungsi enterVenue)
contract_abi = [
    {
        "inputs": [],
        "name": "enterVenue",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]

# 4. Load Contract
contract = w3.eth.contract(address=target_address, abi=contract_abi)

# 5. Eksekusi Call
print("[*] Calling enterVenue()...")
try:
    # Menggunakan .call() karena ini fungsi view (Read-only)
    flag = contract.functions.enterVenue().call()
    print(f"\n[+] FLAG FOUND: {flag}")
except Exception as e:
    print(f"[-] Error: {e}")

```

## Hasil Eksekusi

Menjalankan script di atas menghasilkan output berikut:

```text
┌──(wanz)─(wanzkey㉿Hengker-Bwang)-[~/TCP1P/TCP1P CTF 2023 Archive/Blockchain/Venue]
└─$ python3 solver.py
[*] Connecting to https://ethereum-sepolia-rpc.publicnode.com...
[+] Connected successfully!
[*] Calling enterVenue()...

[+] FLAG FOUND: TCP1P{d0_3nj0y_th3_p4rty_bu7_4r3_y0u_4_VIP?}

```

## Kesimpulan

Challenge ini mengajarkan dasar interaksi dengan Smart Contract:

1. Pentingnya memahami visibilitas fungsi (`public`, `private`, `view`).
2. Cara menggunakan **RPC Provider** untuk terhubung ke jaringan blockchain.
3. Cara memanggil fungsi kontrak tanpa melakukan transaksi (gratis gas fee) menggunakan Web3 library.

**Flag:** `TCP1P{d0_3nj0y_th3_p4rty_bu7_4r3_y0u_4_VIP?}`
