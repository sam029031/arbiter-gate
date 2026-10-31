#!/usr/bin/env python3
"""Check 5's rounds (attack, defend, attack, defend, attack), offline: no LLM request.

The model's two roles are scripted -- the patch proposals are fixed diffs, the re-attack
returns a fixed result -- and everything else is the real repair loop and patch gate,
with forge. The contract has two doors (withdrawAll and withdraw, both pay before they
update the books); E_ALL attacks the first, E_ONE the second, both composed by the
harness exactly as an agent's run_exploit would be.

  two_rounds   P_ALL (closes withdrawAll only) passes 0-4; the re-attack proves E_ONE;
               P_BOTH passes, and check 1 re-runs E_ONE against it; the next re-attack
               finds nothing -> accepted, timeline attack/defend/attack/defend/attack,
               the second re-attack told both hypotheses
  extra_blocks after E_ONE, the model proposes P_ALL again: check 1 refuses it because
               E_ONE still succeeds (that is what makes the new attack evidence); then
               P_BOTH -> accepted
  capped       both re-attacks prove an attack -> stops after two defences:
               rejected_reattack, "修補未通過再攻擊"
  not_run      the re-attack does not complete -> the patch stands on 0-4, check 5 is
               "skipped", never a pass

    python3 scripts/reattack_probe.py
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter import patch as patch_mod  # noqa: E402
from arbiter.patch import make_diff, verify_fix  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

V = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TwoDoorVault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposits;

    constructor() payable {
        balanceOf[msg.sender] = msg.value;
        totalDeposits = msg.value;
    }

    function deposit() external payable {
        require(msg.value > 0, "amount is zero");
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdrawAll() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
        balanceOf[msg.sender] = 0;
        totalDeposits -= amount;
    }

    function withdraw(uint256 amount) external {
        uint256 have = balanceOf[msg.sender];
        require(amount > 0 && amount <= have, "bad amount");
        uint256 remaining = have - amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
        balanceOf[msg.sender] = remaining;
        totalDeposits -= amount;
    }
}
"""

_ALL_OLD = """        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
        balanceOf[msg.sender] = 0;
        totalDeposits -= amount;
"""
_ALL_NEW = """        balanceOf[msg.sender] = 0;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
"""
_ONE_OLD = """        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
        balanceOf[msg.sender] = remaining;
        totalDeposits -= amount;
"""
_ONE_NEW = """        balanceOf[msg.sender] = remaining;
        totalDeposits -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "eth transfer failed");
"""
P_ALL = V.replace(_ALL_OLD, _ALL_NEW, 1)
P_BOTH = P_ALL.replace(_ONE_OLD, _ONE_NEW, 1)
assert P_ALL != V and P_BOTH != P_ALL

_COMMON = dict(deploy_code="TwoDoorVault target = new TwoDoorVault{value: 5 ether}();",
               mode="contract", victim_enter="target.deposit{value: 2 ether}();",
               victim_exit="target.withdrawAll();")
E_ALL_SPEC = dict(_COMMON, attacker_code="""
contract Attacker {
    TwoDoorVault public v;
    uint256 public hits;
    constructor(address _v) payable { v = TwoDoorVault(payable(_v)); }
    function attack() external { v.deposit{value: 1 ether}(); v.withdrawAll(); }
    receive() external payable {
        if (hits < 8 && address(v).balance >= 1 ether) { hits++; v.withdrawAll(); }
    }
}
""")
E_ONE_SPEC = dict(_COMMON, attacker_code="""
contract Attacker {
    TwoDoorVault public v;
    uint256 public hits;
    constructor(address _v) payable { v = TwoDoorVault(payable(_v)); }
    function attack() external { v.deposit{value: 1 ether}(); v.withdraw(1 ether); }
    receive() external payable {
        if (hits < 8 && address(v).balance >= 1 ether) { hits++; v.withdraw(1 ether); }
    }
}
""")


class FakeUsage:
    requests = 0


class FakeGateway:
    """Hands out scripted propose_patch calls; records what the loop told the model."""

    model = "scripted"

    def __init__(self, patches: list[str]) -> None:
        self.usage = FakeUsage()
        self.diffs = [make_diff(V, p) for p in patches]
        self.seen: list[list[dict[str, Any]]] = []

    def chat(self, messages: list[dict[str, Any]], **_: Any) -> dict[str, Any]:
        self.seen.append([dict(m) for m in messages])
        self.usage.requests += 1
        diff = self.diffs.pop(0)
        return {"content": "", "tool_calls": [{"id": f"c{self.usage.requests}", "function": {
            "name": "propose_patch", "arguments": json.dumps({"diff": diff, "rationale": "scripted"})}}]}


def fake_reattack(script: list[dict[str, Any]], calls: list[dict[str, Any]]):
    def run(gateway: Any, exploit: dict, patched: str, *, root: Path, ruled_out: list[str],
            n: int = 1, **_: Any) -> dict[str, Any]:
        calls.append({"n": n, "ruled_out": list(ruled_out), "patched_is": (
            "P_ALL" if patched == P_ALL else "P_BOTH" if patched == P_BOTH else "other")})
        r = dict(script.pop(0))
        r.update(n=n, ruled_out=list(ruled_out), elapsed_s=0.0, requests=0)
        return r
    return run


results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'WRONG'}] {name:12s} {detail}")


def tl(rec: dict) -> str:
    return " -> ".join(f"{e['side'][0].upper()}{e['round']}:{e['result']}" for e in rec["timeline"])


def main() -> int:
    root = Path(tempfile.mkdtemp(prefix="reattack-probe-"))
    real = patch_mod.reattack
    try:
        e_all = Workspace(root, "c1", V).compose_victim_loss(**E_ALL_SPEC)
        e_one = Workspace(root, "c2", V).compose_victim_loss(**E_ONE_SPEC)
        # sanity: E_ALL is stopped by P_ALL, E_ONE is not; P_BOTH stops both
        g1 = verify_fix(V, e_all, patched=P_ALL, root=root, sample_id="s1")
        g2 = verify_fix(V, e_one, patched=P_ALL, root=root, sample_id="s2")
        g3 = verify_fix(V, e_one, patched=P_BOTH, root=root, sample_id="s3")
        check("doors", g1["accepted"] and g2["first_failure"] == "1" and g3["accepted"],
              f"P_ALL vs E_ALL accepted={g1['accepted']}; P_ALL vs E_ONE first failure="
              f"{g2['first_failure']}; P_BOTH vs E_ONE accepted={g3['accepted']}")
        exploit = {"source": V, "solidity": e_all, "poc_name": "AllDoorPoc",
                   "finding": {"vulnerable_function": "withdrawAll", "title": "withdrawAll reentrancy"},
                   "sample_id": "twodoor", "hypothesis": "re-enter withdrawAll before the balance is cleared",
                   "repo": None, "layout": None}
        new_attack = {"status": "proven", "turns": 3, "tried": [], "exploit": {
            "poc_name": "OneDoorPoc", "predicate": "victim_loss",
            "hypothesis": "re-enter withdraw(amount) before the balance is written",
            "finding": {"vulnerable_function": "withdraw", "attack_path": "deposit, withdraw, re-enter"},
            "solidity": e_one, "repo_solidity": e_one}}
        quiet = {"status": "not_proven", "turns": 5, "tried": ["something else"]}

        cases = [
            ("two_rounds", [P_ALL, P_BOTH], [new_attack, quiet], "accepted",
             "A1:proven -> D1:accepted -> A2:proven -> D2:accepted -> A3:not_proven"),
            ("extra_blocks", [P_ALL, P_ALL, P_BOTH], [new_attack, quiet], "accepted",
             "A1:proven -> D1:accepted -> A2:proven -> D2:accepted -> A3:not_proven"),
            ("capped", [P_ALL, P_BOTH], [new_attack, dict(new_attack)], "rejected_reattack",
             "A1:proven -> D1:accepted -> A2:proven -> D2:accepted -> A3:proven"),
            ("not_run", [P_ALL], [{"status": "not_executed", "reason": "scripted"}], "accepted",
             "A1:proven -> D1:accepted -> A2:not_executed"),
        ]
        for name, patches, script, want, want_tl in cases:
            calls: list[dict[str, Any]] = []
            patch_mod.reattack = fake_reattack(list(script), calls)
            gw = FakeGateway(patches)
            rec = patch_mod.repair(gw, exploit, root=root / name, rounds=3, reattack_turns=16)
            c5 = rec["checks"].get("5", {}).get("status")
            fed = any("PATCH REJECTED: 5" in str(m.get("content")) for m in gw.seen[-1]) \
                if len(gw.seen) > 1 else None
            ok = rec["status"] == want and tl(rec) == want_tl
            detail = f"status={rec['status']} check5={c5} timeline: {tl(rec)}"
            if name == "two_rounds":
                ok = ok and fed and calls[1]["ruled_out"] == [exploit["hypothesis"],
                                                              new_attack["exploit"]["hypothesis"]] \
                    and calls[1]["patched_is"] == "P_BOTH" and c5 == "pass" \
                    and rec["checks"]["1"].get("extra", [{}])[0].get("status") == "pass"
                detail += f"; 2nd re-attack ruled out {len(calls[1]['ruled_out'])} hypotheses"
            if name == "extra_blocks":
                r = rec["rounds"]
                ok = ok and len(r) == 3 and r[1]["first_failure"] == "1" \
                    and "the re-audit found" in r[1]["message"]
                detail += f"; proposal 2: {r[1]['first_failure']} '{r[1]['message'][:60]}...'"
            if name == "capped":
                ok = ok and c5 == "fail" and len(gw.seen) == 2
            if name == "not_run":
                ok = ok and c5 == "skipped"
            check(name, ok, detail)
    finally:
        patch_mod.reattack = real
        shutil.rmtree(root, ignore_errors=True)
    good = sum(ok for _, ok, _ in results)
    print(f"\n{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
