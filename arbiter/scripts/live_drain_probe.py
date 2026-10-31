#!/usr/bin/env python3
"""Rung 3's drain invariant, both directions, on local anvil chains. No LLM request.

User decision D20 (10/30): the live victim_loss replay measures what left the contract
under audit across the ATTACK on the attacked chain (before the attack, after it, before
the victim exits) -- the synthetic harness's tgtPre / tgtPost -- instead of subtracting the
two chains' outflow to the end, which counted the victim's own withdrawal on the clean
chain and cancelled a real drain. The requirement itself stays: value has to come out of
the contract being audited.

  (a) drained       P8 main runs 3 and 6 (StakingVault, victim_loss): the attack empties
                    the vault, the victim's exit() reverts            -> proven
  (b) scenery       the case ec5ad6a was written for, rebuilt: the victim's money sits in
                    a contract the setup built, the attacker takes it; shortfall and
                    attacker_gain are real, the contract under audit loses nothing
                                                                       -> not proven
  (c) reverted      P8 main runs 4 and 8: the attack transaction reverts on a chain
                                                                       -> not proven
  (d) untranslatable P8 main runs 5 and 9 (eth_profit): all three translations refuse
                                                                       -> no replay

The P8 dumps are only read (copied to a temporary directory first). Without them (a), (c)
and (d) are reported as missing material; (b) needs nothing but forge and anvil.

    python3 scripts/live_drain_probe.py
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.live_replay import (  # noqa: E402
    Replay,
    Untranslatable,
    parse_poc,
    parse_poc_exploit,
    parse_poc_other,
    replay,
)
from arbiter.prove import prove_dump  # noqa: E402

RUNS = Path(__file__).resolve().parent.parent / "runs" / "gate"
P8 = {3: "20261030-212309-109f0d", 4: "20261030-212742-8b1ef4", 5: "20261030-213246-8943a0",
      6: "20261030-213656-54de09", 8: "20261030-214513-0304e8", 9: "20261030-214910-cd53dd"}
ETH = 10**18

results: list[tuple[str, bool | None, str]] = []


def check(name: str, ok: bool | None, detail: str) -> None:
    results.append((name, ok, detail))
    tag = {True: "OK  ", False: "WRONG", None: "SKIP"}[ok]
    print(f"  [{tag}] {name:16s} {detail}")


def eth(v: int | None) -> str:
    return "-" if v is None else f"{v / ETH:g}"


def p8_dump(n: int, tmp: Path) -> Path | None:
    src = RUNS / f"web-{P8[n]}" / "dump"
    if not (src / "manifest.json").is_file():
        return None
    dst = tmp / f"main{n}"
    shutil.copytree(src, dst)
    return dst


def live_of(n: int, tmp: Path, port: int) -> dict | None:
    d = p8_dump(n, tmp)
    if d is None:
        return None
    return prove_dump(d, port=port)["findings"][0]


# (b): the contract under audit is a plain vault nobody touches; the victim's position is
# in Scenery, built by the setup, and that is what the attacker empties.
SCENERY_TARGET = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract PlainVault {
    mapping(address => uint256) public balanceOf;
    function deposit() external payable { balanceOf[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 a = balanceOf[msg.sender];
        balanceOf[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "send");
    }
}
"""
SCENERY_ATTACKER = """contract Scenery {
    mapping(address => uint256) public balanceOf;
    function deposit() external payable { balanceOf[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 a = balanceOf[msg.sender];
        balanceOf[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok, "scenery empty");
    }
    function take(address to) external {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "take");
    }
}
interface _World { function scenery() external view returns (Scenery); }
contract Attacker {
    address public owner;
    constructor(address) payable { owner = msg.sender; }
    function attack() external {
        address world = _ArbiterHarness(owner).arbiterVictim();
        _World(world).scenery().take(address(this));
    }
    receive() external payable {}
}"""


def scenery_replay() -> Replay:
    return Replay(
        sample_id="scenery", pragma="^0.8.20", target_source=SCENERY_TARGET,
        attacker_contract=SCENERY_ATTACKER,
        state_decls="    PlainVault public target;\n    Scenery public scenery;",
        setup_body=("        target = new PlainVault();\n        scenery = new Scenery();\n"
                    "        target.deposit{value: 1 ether}();"),
        enter_body="        scenery.deposit{value: 5 ether}();",
        exit_body="        scenery.withdraw();",
        target_type="PlainVault", ctor_payable=True)


def main() -> int:
    if not shutil.which("anvil") or not shutil.which("forge"):
        print("forge and anvil are needed (local chains); refusing to report without them")
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="live-drain-probe-"))
    try:
        print("rung 3 drain invariant (D20): measured across the attack on the attacked chain\n")
        for n, port in ((3, 9600), (6, 9620)):
            f = live_of(n, tmp, port)
            if f is None:
                check(f"(a) main {n}", None, "P8 dump missing (runs/ is not in git)")
                continue
            d = f.get("live_detail") or {}
            ok = (f["live"] is True and d.get("shortfall", 0) > 0
                  and d.get("extracted_from_contract", 0) > 0)
            check(f"(a) main {n}", ok,
                  f"{'PROVEN' if f['live'] else 'not proven'}  shortfall {eth(d.get('shortfall'))}, "
                  f"attacker_gain {eth(d.get('attacker_gain'))}, extracted by the attack "
                  f"{eth(d.get('extracted_from_contract'))}, old cross-chain measure "
                  f"{eth(d.get('drained_vs_clean'))}")

        d = replay(scenery_replay(), tmp / "scenery", 9640)
        ok = ("error" not in d and d.get("shortfall", 0) > 0
              and d.get("attacker_gain", 0) >= d.get("shortfall", 0)
              and d.get("extracted_from_contract") == 0 and d.get("proven") is False)
        check("(b) scenery", ok,
              f"{'PROVEN' if d.get('proven') else 'not proven'}  shortfall {eth(d.get('shortfall'))}, "
              f"attacker_gain {eth(d.get('attacker_gain'))}, extracted "
              f"{eth(d.get('extracted_from_contract'))}"
              + (f"  error: {d['error']}" if "error" in d else ""))

        for n, port in ((4, 9660), (8, 9680)):
            f = live_of(n, tmp, port)
            if f is None:
                check(f"(c) main {n}", None, "P8 dump missing")
                continue
            d = f.get("live_detail") or {}
            atk = next((w for w in d.get("worlds") or [] if w.get("with_attack")), {})
            failed = [s["what"] for s in atk.get("steps") or [] if not s.get("ok")]
            ok = f["live"] is False and bool(d) and "run()" in failed
            check(f"(c) main {n}", ok,
                  f"{'PROVEN' if f['live'] else 'not proven'}  failed on chain: {failed}, "
                  f"shortfall {eth(d.get('shortfall'))}, attacker_gain {eth(d.get('attacker_gain'))}")

        for n, port in ((5, 9700), (9, 9720)):
            dump = p8_dump(n, tmp / "u")
            if dump is None:
                check(f"(d) main {n}", None, "P8 dump missing")
                continue
            proj = next(p for p in dump.iterdir() if (p / "foundry.toml").is_file())
            poc = next((proj / "test").glob("*.t.sol"))
            refused = []
            for parse in (parse_poc, parse_poc_exploit, parse_poc_other):
                try:
                    parse(poc, proj / "src" / "Target.sol", proj.name)
                except Untranslatable:
                    refused.append(parse.__name__)
            f = prove_dump(dump, port=port)["findings"][0]
            ok = len(refused) == 3 and f["live"] is False and not f.get("live_detail")
            check(f"(d) main {n}", ok,
                  f"Untranslatable from {len(refused)}/3 translations; replay ran: "
                  f"{bool(f.get('live_detail'))}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ran = [r for r in results if r[1] is not None]
    good = sum(1 for r in ran if r[1])
    skipped = len(results) - len(ran)
    print(f"\n{good}/{len(ran)} as expected" + (f", {skipped} skipped (material missing)" if skipped else ""))
    return 0 if good == len(ran) and not skipped else 1


if __name__ == "__main__":
    raise SystemExit(main())
