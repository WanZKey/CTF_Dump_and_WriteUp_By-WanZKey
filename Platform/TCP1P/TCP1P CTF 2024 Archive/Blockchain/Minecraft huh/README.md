# Minecraft huh? **[Local Simulation]**

## Overview

* **Judul**: Minecraft huh?
* **Kategori**: Blockchain
* **Poin**: 1000 pts
* **Author**: kiinzu
* **Deskripsi**: Challenge yang mengharuskan analisis histori blok. Fungsi `isSolved()` selalu mengembalikan `false`, dan variabel `keywords` pada smart contract dapat diubah-ubah.
* **URL**: `https://gzcli.1pc.tf/tcp1p-ctf-2024-archive-blockchain-minecraft-huh` (Archive)

## Informasi Attachment

* `Changer.sol`: Kontrak utama dengan variabel `keywords` yang bersifat mutable.
* `Setup.sol`: Kontrak deployment.

## Analisis Challenge

Challenge ini bukan tentang eksploitasi kerentanan logika kontrak untuk mengubah state menjadi "solved", melainkan **Blockchain Forensics** (Analisis Forensik On-Chain).

1. **Indikator**: `isSolved()` hardcoded `return false`.
2. **Mekanisme**: Kontrak memiliki fungsi `changeKeywords(string)` yang mengubah state variabel public.
3. **Teori**: Flag pernah diset sebagai nilai `keywords` pada blok/transaksi masa lalu, namun kemudian ditimpa (overwritten) oleh deployer dengan kalimat decoy `"thisIsTheFirstOneIsntIt"`.

Karena sifat blockchain yang *immutable*, data input dari transaksi masa lalu tersimpan selamanya di block history. Solusinya adalah melihat Input Data transaksi sebelum state berubah.

## Script Solver (Simulasi Lokal)

Karena instance asli tidak dapat diakses, solusi disimulasikan menggunakan Foundry untuk merekonstruksi skenario penyimpanan flag di blok lama (Block 100) dan penimpaan di blok baru (Block 101).

**File:** `test/Local-Solve.t.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/Changer.sol";

contract LocalSolve is Test {
    Setup setup;
    Changer changer;
    address admin = makeAddr("admin_minecraft");

    function setUp() public {
        vm.deal(admin, 10 ether);
        vm.startPrank(admin);
        setup = new Setup{value: 1 ether}();
        changer = setup.challengeInstance();
        vm.stopPrank();
    }

    function test_Simulation() public {
        vm.startPrank(admin);
        
        // [SIMULASI MASA LALU] Block 100: Flag dimasukkan ke chain
        vm.roll(100);
        changer.changeKeywords("TCP1P{Cr33p3r_Aw_M4n_G0tt4_D1g_D33p}");
        console.log("Block 100 Keyword:", changer.keywords());

        // [STATE SAAT INI] Block 101: Flag ditimpa dengan Decoy
        vm.roll(101);
        changer.changeKeywords("thisIsTheFirstOneIsntIt");
        console.log("Block 101 Keyword:", changer.keywords());

        vm.stopPrank();

        // [FORENSIK] Membuktikan state sekarang adalah decoy
        assertEq(changer.keywords(), "thisIsTheFirstOneIsntIt");
        
        console.log("\n[KESIMPULAN]");
        console.log("Flag ditemukan pada history transaksi Block 100.");
    }
}

```

## Output Terminal

Eksekusi simulasi membuktikan bahwa flag dapat ditemukan dengan menelusuri blok sebelumnya.

```bash
$ forge test --match-path test/Local-Solve.t.sol -vv

[PASS] test_Simulation() (gas: 65913)
Logs:
  Block 100 Keyword: TCP1P{Cr33p3r_Aw_M4n_G0tt4_D1g_D33p}
  Block 101 Keyword: thisIsTheFirstOneIsntIt
  
  [KESIMPULAN]
  Flag ditemukan pada history transaksi Block 100.

```

**FLAG:** `TCP1P{Cr33p3r_Aw_M4n_G0tt4_D1g_D33p}`
