// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PrimeYieldVault {
    mapping(address => uint256) public shareOf;
    mapping(address => uint256) public pendingDeposit;
    uint256 public totalShares;
    uint256 public pendingAssets;

    event DepositRequested(address indexed owner, uint256 assets);
    event DepositSettled(address indexed owner, uint256 assets, uint256 shares);
    event Redeemed(address indexed owner, uint256 shares, uint256 assets);

    receive() external payable {}

    function totalAssets() public view returns (uint256) {
        return address(this).balance - pendingAssets;
    }

    function requestDeposit() external payable {
        require(msg.value > 0, "zero assets");
        pendingDeposit[msg.sender] += msg.value;
        pendingAssets += msg.value;
        emit DepositRequested(msg.sender, msg.value);
    }

    function settleDeposit(address owner) external {
        uint256 assets = pendingDeposit[owner];
        require(assets > 0, "nothing pending");
        uint256 supply = totalShares;
        uint256 base = totalAssets();
        uint256 shares = (assets * (supply + 1)) / (base + 1);
        pendingDeposit[owner] = 0;
        pendingAssets -= assets;
        shareOf[owner] += shares;
        totalShares = supply + shares;
        emit DepositSettled(owner, assets, shares);
    }

    function redeem(uint256 shares) external {
        require(shares > 0, "zero shares");
        require(shareOf[msg.sender] >= shares, "insufficient shares");
        uint256 assets = (shares * (totalAssets() + 1)) / (totalShares + 1);
        shareOf[msg.sender] -= shares;
        totalShares -= shares;
        (bool ok, ) = msg.sender.call{value: assets}("");
        require(ok, "eth transfer failed");
        emit Redeemed(msg.sender, shares, assets);
    }
}
