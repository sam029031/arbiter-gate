#!/usr/bin/env python3
"""Can setup, or the victim's own steps, name the accounts the harness draws?

The identity draw (workspace.draw_identity) exists so that setup cannot hand the attacker
a role: the attacker's address is chosen after setup is written. But in victim_loss the
drawn addresses live in contract-level constants of the test contract -- arbEoa,
arbAtkEoa, arbVictim -- and setup runs inside that contract, so it could simply name
them. Reproduced with forge before the fix, against a correctly guarded vault:

    mode='eoa', deploy_code "Vault target = new Vault(); target.setOwner(arbEoa);"
    attack_body "target.sweep(arbEoa);"                      -> [PASS] victim_loss

The depositor really lost, and the "attacker" was the owner setup had appointed. The
negation check did not see it either, because neuter() only knew the profit template's
`vm.startPrank(eoa, eoa)` block, so every EOA-mode victim_loss proof went un-neutered.

Cases:
  1. the reproduced exploit is refused at composition, and (with the name check switched
     off for this one case only) it really does pass forge -- the check is load-bearing;
  2-7. the other routes to the same theft are refused: arbAtkEoa, its keccak preimage,
     setup pranking the victim into an approval, setup reading arbiterVictim(), the
     victim approving the attacker, setup computing the attacker's CREATE address;
  8-10. controls: victim_probe's reentrancy DRAIN still composes and passes; a legitimate
     EOA-mode theft (an unguarded sweep) composes and passes, and fails on the guarded
     twin; identifiers that merely resemble harness names still compose;
  11. negation now covers EOA victim mode: neuter() finds the attack, and the neutered
     proof fails; the profit template's EOA block is still found.

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))
sys.path.insert(0, str(RIG / "scripts"))

import arbiter.workspace as wsmod  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

import victim_probe as vp  # noqa: E402

WS = Path("/tmp/eoa-identity-probe")

# Correctly guarded: only the owner may sweep or appoint, depositors can always withdraw.
GUARDED = """// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

contract Vault {
    address public owner;
    mapping(address => uint256) public deposits;
    constructor() payable { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw(uint256 a) external {
        require(deposits[msg.sender] >= a, "insufficient");
        deposits[msg.sender] -= a;
        payable(msg.sender).transfer(a);
    }
    function setOwner(address to) external onlyOwner { owner = to; }
    function sweep(address to) external onlyOwner { payable(to).transfer(address(this).balance); }
}
"""
# The same vault with the guard missing from sweep: a real theft any account can commit.
UNGUARDED = GUARDED.replace(
    "function sweep(address to) external onlyOwner", "function sweep(address to) external")

VICTIM = dict(victim_enter="target.deposit{value: 4 ether}();",
              victim_exit="target.withdraw(4 ether);")
NOOP_ATTACKER = "contract Attacker { constructor(address) {} function attack() external {} }"
SWEEP_ATTACKER = """
contract Attacker {
    Vault v;
    constructor(address t) { v = Vault(payable(t)); }
    function attack() external { v.sweep(address(this)); }
    receive() external payable {}
}
"""

REPRODUCED = dict(VICTIM, mode="eoa",
                  deploy_code="Vault target = new Vault(); target.setOwner(arbEoa);",
                  attack_body="target.sweep(arbEoa);")

REFUSED = [
    ("setup appoints arbEoa (the reproduced exploit)", REPRODUCED, "arbEoa"),
    ("setup appoints arbAtkEoa (contract mode)",
     dict(VICTIM, mode="contract", attacker_code=SWEEP_ATTACKER,
          deploy_code="Vault target = new Vault(); target.setOwner(arbAtkEoa);"),
     "arbAtkEoa"),
    ("setup derives arbAtkEoa from its preimage",
     dict(VICTIM, mode="contract", attacker_code=SWEEP_ATTACKER,
          deploy_code=("Vault target = new Vault();\n"
                       "target.setOwner(address(uint160(uint256("
                       "keccak256(\"arbiter.attacker\")))));")),
     "arbiter.attacker"),
    ("setup pranks the victim into an approval",
     dict(VICTIM, mode="eoa", attack_body="target.deposit{value: 1}();",
          deploy_code=("Vault target = new Vault();\n"
                       "vm.prank(arbVictim); target.setOwner(address(0xBEEF));")),
     "arbVictim"),
    ("setup looks the victim up",
     dict(VICTIM, mode="eoa", attack_body="target.deposit{value: 1}();",
          deploy_code=("Vault target = new Vault();\n"
                       "address who = this.arbiterVictim();")),
     "arbiterVictim"),
    ("victim_enter approves the attacker",
     dict(mode="eoa", attack_body="target.sweep(arbEoa);",
          deploy_code="Vault target = new Vault();",
          victim_enter="target.deposit{value: 4 ether}(); target.setOwner(arbEoa);",
          victim_exit="target.withdraw(4 ether);"),
     "arbEoa"),
    ("setup computes the attacker's CREATE address",
     dict(VICTIM, mode="contract", attacker_code=SWEEP_ATTACKER,
          deploy_code=("Vault target = new Vault();\n"
                       "target.setOwner(vm.computeCreateAddress(address(this), "
                       "vm.getNonce(address(this))));")),
     "computeCreateAddress"),
]


def _run(source: str, spec: dict, label: str) -> tuple[bool, str, str]:
    """(passed, short detail, composed solidity)."""
    ws = Workspace(WS, re.sub(r"\W+", "_", label)[:48], source)
    try:
        solidity = ws.compose_victim_loss(**spec)
        ws.write_poc("Ident", solidity)
        build = ws.build()
        if not build.ok:
            errs = [ln.strip()[:90] for ln in build.combined.splitlines() if "Error" in ln][:1]
            return False, f"no build {errs}", solidity
        run = ws.run_poc("IdentPoc")
        passed = any(ln.strip().startswith("[PASS]") for ln in run.combined.splitlines())
        hit = re.search(r"(ArbiterNoHarm\([^)]*\)|ARBITER: [^\"']{0,40})", run.combined)
        return passed, (hit.group(1)[:60] if hit else ""), solidity
    finally:
        ws.cleanup()


def _refused(source: str, spec: dict, label: str) -> str | None:
    ws = Workspace(WS, re.sub(r"\W+", "_", label)[:48], source)
    try:
        ws.compose_victim_loss(**spec)
        return None
    except ValueError as exc:
        return str(exc)
    finally:
        ws.cleanup()


def main() -> int:
    print("setup and the victim's steps are written before the accounts are drawn, so")
    print("they may not name them.\n")
    results: list[bool] = []

    def report(ok: bool, label: str, detail: str) -> None:
        results.append(ok)
        print(f"  [{'OK  ' if ok else 'HOLE'}] {label:50s} {detail}")

    # 1-7: refused at composition, and the refusal names the identifier.
    for label, spec, name in REFUSED:
        why = _refused(GUARDED, spec, label)
        ok = why is not None and repr(name) in why and "belongs to the harness" in why
        report(ok, label, "REFUSED" if why else "ACCEPTED at composition")

    # 1b: the reproduced exploit is a real pass when the name check is switched off --
    # without this the refusal above could be guarding something harmless.
    saved = wsmod._reject_harness_names
    wsmod._reject_harness_names = lambda *a, **k: None
    try:
        passed, detail, _ = _run(GUARDED, REPRODUCED, "reproduced_without_check")
    finally:
        wsmod._reject_harness_names = saved
    report(passed, "  ... and with the check off it PASSES forge", detail or
           ("[PASS]" if passed else "did not pass"))

    # 8: victim_probe's reentrancy drain, contract mode.
    passed, detail, _ = _run(vp.load("V_reentrancy_unstake"), vp.DRAIN, "control_drain")
    report(passed, "control: reentrancy DRAIN still passes", detail or "[PASS]")

    # 9: a legitimate EOA-mode theft, and its guarded twin.
    # The attack may name its own account; only setup and the victim's steps may not.
    eoa_theft = dict(VICTIM, mode="eoa",
                     deploy_code="Vault target = new Vault{value: 10 ether}();",
                     attack_body="target.sweep(arbEoa);")
    passed, detail, solidity = _run(UNGUARDED, eoa_theft, "control_eoa_theft")
    report(passed, "control: EOA theft (unguarded sweep) passes", detail or "[PASS]")
    passed_twin, detail, _ = _run(GUARDED, eoa_theft, "control_eoa_guarded")
    report(not passed_twin, "control: same EOA attack on the guarded twin fails",
           detail or ("[PASS]" if passed_twin else "refused"))

    # 10: names that only resemble the harness's still compose.
    lookalikes = [
        ("contract", dict(VICTIM, mode="contract", attacker_code=SWEEP_ATTACKER,
                          deploy_code=("Vault target = new Vault();\n"
                                       "uint256 atkBudget = 1; address arbiterFee = address(1);"))),
        ("eoa", dict(VICTIM, mode="eoa", attack_body="target.sweep(arbEoa);",
                     deploy_code="Vault target = new Vault();\naddress atk = address(7);")),
    ]
    for mode, spec in lookalikes:
        why = _refused(UNGUARDED, spec, f"lookalike_{mode}")
        report(why is None, f"control: look-alike names compose ({mode} mode)",
               "composed" if why is None else why[:60])

    # 11: negation reaches EOA victim mode.
    neutered, found = Workspace.neuter(solidity)
    gone = found and "target.sweep(arbEoa)" not in neutered.split("function arbAttack()")[1].split(
        "function arbTrial")[0]
    report(gone, "neuter() finds the attack in EOA victim mode",
           "found" if found else "NOT FOUND")
    ws = Workspace(WS, "neutered_eoa", UNGUARDED)
    try:
        ws.write_poc("Neg", neutered)
        ok_build = ws.build().ok
        run = ws.run_poc("NegPoc") if ok_build else None
        neg_passed = bool(run) and any(ln.strip().startswith("[PASS]")
                                       for ln in run.combined.splitlines())
        prof = ws.compose_exploit(
            deploy_code="Vault target = new Vault{value: 10 ether}();",
            predicate="eth_profit", mode="eoa",
            attack_body="target.sweep(eoa);",
            honest_body="target.deposit{value: 1 ether}(); target.withdraw(1 ether);")
    finally:
        ws.cleanup()
    report(ok_build and not neg_passed, "the neutered EOA proof fails",
           "fails" if ok_build and not neg_passed else
           ("no build" if not ok_build else "STILL PASSES"))
    report(Workspace.neuter(prof)[1], "neuter() still finds the profit template's block", "")

    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
