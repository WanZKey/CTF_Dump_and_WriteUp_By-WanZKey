// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract BadgerVaultZap is ReentrancyGuard {
    using SafeERC20 for IERC20;

    // Role addresses
    address public governance;
    address public guardian;
    address public pendingGovernance;

    // Governance Logic
    uint256 public proposalTimestamp;
    uint256 public constant DELAY = 1 days;

    // Supported tokens
    mapping(address => bool) public approvedTokens;

    // User balances
    mapping(address => mapping(address => uint256)) public userBalances;

    // Flag manager contract
    address public flagManager;
    bool public flagRevealed;

    // Events
    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount);
    event GovernanceProposed(
        address indexed pendingGovernance,
        uint256 executableAt
    );
    event GovernanceChanged(
        address indexed oldGovernance,
        address indexed newGovernance
    );
    event GuardianChanged(
        address indexed oldGuardian,
        address indexed newGuardian
    );
    event EmergencyWithdrawal(address indexed token, uint256 amount);

    // Modifiers
    modifier onlyGovernance() {
        require(msg.sender == governance, "Only governance");
        _;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "Only guardian");
        _;
    }

    modifier onlyGovernanceOrGuardian() {
        require(
            msg.sender == governance || msg.sender == guardian,
            "Only governance or guardian"
        );
        _;
    }

    constructor(
        address _governance,
        address _guardian,
        address _flagManager,
        address[] memory _approvedTokens
    ) {
        require(_governance != address(0), "Invalid governance");
        require(_guardian != address(0), "Invalid guardian");
        governance = _governance;
        guardian = _guardian;
        flagManager = _flagManager;

        for (uint256 i = 0; i < _approvedTokens.length; i++) {
            approvedTokens[_approvedTokens[i]] = true;
        }
    }

    function addApprovedToken(address _token) external onlyGovernance {
        approvedTokens[_token] = true;
    }

    function deposit(address _token, uint256 _amount) external nonReentrant {
        require(approvedTokens[_token], "Token not approved");
        require(_amount > 0, "Amount must be > 0");

        IERC20(_token).safeTransferFrom(msg.sender, address(this), _amount);
        userBalances[msg.sender][_token] += _amount;

        emit Deposit(msg.sender, _token, _amount);
    }

    function withdraw(address _token, uint256 _amount) external nonReentrant {
        require(
            userBalances[msg.sender][_token] >= _amount,
            "Insufficient balance"
        );

        userBalances[msg.sender][_token] -= _amount;
        IERC20(_token).safeTransfer(msg.sender, _amount);

        emit Withdraw(msg.sender, _token, _amount);
    }

    function proposeGovernance(address _newGovernance) external {
        pendingGovernance = _newGovernance;
        proposalTimestamp = block.timestamp;
        emit GovernanceProposed(_newGovernance, block.timestamp + DELAY);
    }

    function acceptGovernance() external {
        require(msg.sender == pendingGovernance, "Only pending governance");

        address oldGovernance = governance;
        governance = msg.sender;
        pendingGovernance = address(0);

        emit GovernanceChanged(oldGovernance, msg.sender);
    }

    function setGuardian(address _guardian) external onlyGovernance {
        governance = _guardian;
        emit GuardianChanged(guardian, _guardian);
    }

    function emergencyWithdraw(
        address _token
    ) external onlyGovernanceOrGuardian {
        uint256 balance = IERC20(_token).balanceOf(address(this));
        require(balance > 0, "No balance to withdraw");

        IERC20(_token).safeTransfer(msg.sender, balance);
        emit EmergencyWithdrawal(_token, balance);
    }

    function extractFunds(address[] calldata _tokens) external onlyGovernance {
        require(!flagRevealed, "Flag already revealed");

        for (uint256 i = 0; i < _tokens.length; i++) {
            uint256 balance = IERC20(_tokens[i]).balanceOf(address(this));
            if (balance > 0) {
                IERC20(_tokens[i]).safeTransfer(governance, balance);
            }
        }

        flagRevealed = true;
        IFlagManager(flagManager).revealFlag();
    }

    function getContractBalance(
        address _token
    ) external view returns (uint256) {
        return IERC20(_token).balanceOf(address(this));
    }
}

interface IFlagManager {
    function revealFlag() external;
}
