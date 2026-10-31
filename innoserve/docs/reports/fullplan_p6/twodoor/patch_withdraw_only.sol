// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// P6 acceptance contract (written for this test, deliberately vulnerable): two ways out,
/// both pay before they update the books. Fixing one door leaves the other open.
contract TwoDoorVault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposits;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);

    constructor() payable {
        balanceOf[msg.sender] = msg.value;
        totalDeposits = msg.value;
    }

    function deposit() external payable {
        require(msg.value > 0, "amount is zero");
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdrawAll() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
        balanceOf[msg.sender] = 0;
        totalDeposits -= amount;
        emit Withdrawn(msg.sender, amount);
    }

    function withdraw(uint256 amount) external {
        uint256 have = balanceOf[msg.sender];
        require(amount > 0 && amount <= have, "bad amount");
        uint256 remaining = have - amount;
        balanceOf[msg.sender] = remaining;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
        emit Withdrawn(msg.sender, amount);
    }
}
