// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FlagManager {
    address public owner;
    address public vaultZap;
    string private flag;
    bool public revealed;
    
    event FlagRevealed(string flag);
    event FlagSet();

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyVaultZap() {
        require(msg.sender == vaultZap, "Only vault zap");
        _;
    }

    function setVaultZap(address _vaultZap) external onlyOwner {
        vaultZap = _vaultZap;
    }

    function setFlag(string calldata _flag) external onlyOwner {
        flag = _flag;
        emit FlagSet();
    }

    function revealFlag() external onlyVaultZap {
        require(bytes(flag).length > 0, "Flag not set");
        revealed = true;
        emit FlagRevealed(flag);
    }

    function getFlag() external view returns (string memory) {
        require(revealed, "Flag not yet revealed");
        return flag;
    }

    function isRevealed() external view returns (bool) {
        return revealed;
    }
}
