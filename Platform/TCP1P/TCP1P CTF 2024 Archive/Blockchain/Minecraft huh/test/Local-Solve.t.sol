// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/Changer.sol";

contract LocalSolve is Test {
    Setup setup;
    Changer changer;
    address admin = makeAddr("admin_minecraft");
    address player = makeAddr("steve");

    function setUp() public {
        // Deploy Setup
        vm.deal(admin, 10 ether);
        vm.startPrank(admin);
        setup = new Setup{value: 1 ether}();
        changer = setup.challengeInstance();
        vm.stopPrank();
    }

    function test_Simulation() public {
        // === SIMULASI HISTORY (Apa yang terjadi di Chain Asli) ===
        
        vm.startPrank(admin);
        
        // Block 100: Admin menaruh Flag rahasia
        // Di chain asli, ini akan tercatat di Input Data transaksi
        vm.roll(100);
        changer.changeKeywords("TCP1P{Cr33p3r_Aw_M4n_G0tt4_D1g_D33p}");
        console.log("Block 100 Keyword:", changer.keywords());

        // Block 101: Admin menimpa Flag (Overwrite)
        // Ini yang kita lihat saat buka challenge pertama kali
        vm.roll(101);
        changer.changeKeywords("thisIsTheFirstOneIsntIt");
        console.log("Block 101 Keyword:", changer.keywords());

        vm.stopPrank();

        // === SIMULASI SOLVER (Cara kita menemukannya) ===
        // Di dunia nyata, kita akan buka Block Explorer dan liat Tx History.
        // Di Foundry, kita bisa buktikan bahwa string ini tersimpan di Storage Slot 0.
        
        console.log("\n=== FORENSIC ANALISIS ===");
        
        // String pendek (<32 bytes) disimpan langsung di slot.
        // "thisIsTheFirstOneIsntIt" panjangnya 23 char, jadi masuk slot 0.
        
        // Baca raw storage slot 0
        bytes32 slot0 = vm.load(address(changer), bytes32(uint256(0)));
        console.log("Current Storage Slot 0 (Raw):");
        console.logBytes32(slot0);

        // Dekode string dari slot (Logic Solidity Storage)
        // Byte terakhir (LSB) * 2 = Panjang string
        // Sisanya adalah stringnya.
        // Tapi biar gampang, kita assert aja logic contractnya jalan.
        
        assertEq(changer.keywords(), "thisIsTheFirstOneIsntIt");
        console.log("Verified: Keyword saat ini adalah decoy.");
        
        console.log("\n[KESIMPULAN]");
        console.log("Challenge ini mengharuskan kita melihat 'Transaction History'");
        console.log("pada block sebelum current block untuk menemukan Flag.");
    }
}
