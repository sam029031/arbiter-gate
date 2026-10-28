#!/usr/bin/env python3
"""Does the patch gate accept real fixes and refuse fake ones -- for the right reason?

One proven exploit (victim_probe's DRAIN on V_reentrancy_unstake), composed ONCE and
never recomposed, against five fixed patches. Every check runs on every case (run_all),
so a check that would have caught something an earlier one already caught is still
exercised. Each case asserts which checks must fail and which must pass:

  1. human fix (S_reentrancy_unstake: transfer after the state update)  -> accepted
  2. private reentrancy lock + modifier                                 -> accepted
  3. unstake() reverts on its first line                                -> check 2 (and L)
     -- check 1 alone would ACCEPT it: its failure message is the real fix's
  4. unstake() deleted                                                  -> check 3 and 1
  5. only accounts with code.length == 0 may call                       -> L, and only L

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))
sys.path.insert(0, str(RIG / "scripts"))

import victim_probe as vp  # noqa: E402
from arbiter.patch import GATE_ORDER, reproduce, verify_fix  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402


def mutate(src: str, old: str, new: str) -> str:
    assert old in src, old
    return src.replace(old, new, 1)


V = vp.load("V_reentrancy_unstake")
S = vp.load("S_reentrancy_unstake")
_HEAD = "    function unstake() external {\n"
_START = V.index(_HEAD)
CASES = [
    ("human_fix", S, "accept", {}),
    ("reentrancy_lock", mutate(V, _HEAD, (
        "    bool private _locked;\n"
        "    modifier nonReentrant() { require(!_locked, \"reentrant\"); _locked = true; _; _locked = false; }\n"
        "    function unstake() external nonReentrant {\n")), "accept", {}),
    ("always_revert", mutate(V, _HEAD, _HEAD + "        revert(\"paused\");\n"),
     "reject", {"2": "fail", "L": "fail", "1": "pass", "3": "pass"}),
    ("deleted", V[:_START] + V[V.index("    function coverageRatio()"):],
     "reject", {"3": "fail", "1": "fail"}),
    ("eoa_only", mutate(V, _HEAD, _HEAD + "        require(msg.sender.code.length == 0, \"eoa only\");\n"),
     "reject", {"L": "fail", "1": "pass", "2": "pass", "3": "pass"}),
]


def _abg(rows: list[dict]) -> str:
    def eth(v):
        return "?" if v is None else f"{v / 1e18:g}"
    return " ".join(f"{eth(r['A'])}/{eth(r['B'])}/{eth(r['G'])}" for r in rows)


def main() -> int:
    print("a fix is accepted on forge's evidence: the same exploit fails in four")
    print("environments, the honest path still pays, and the interface is unchanged.\n")
    root = Path(tempfile.mkdtemp(prefix="patch-probe-"))
    try:
        solidity = Workspace(root, "compose", V).compose_victim_loss(**vp.DRAIN)
        base = reproduce(V, solidity, root, "base")
        if base["status"] != "pass":
            print(f"  check 0 failed on V: {base}")
            return 1
        print(f"  check 0  V reproduces; A/B/G (ETH) per env: {_abg(base['abg'])}\n")
        results = []
        for label, patched, expect, must in CASES:
            t0 = time.monotonic()
            r = verify_fix(V, solidity, patched=patched, root=root, sample_id=label,
                           baseline=base, run_all=True)
            got = {n: r["checks"][n]["status"] for n in GATE_ORDER}
            ok = (r["accepted"] == (expect == "accept")
                  and all(got[n] == s for n, s in must.items()))
            if expect == "accept":
                ok = ok and all(s == "pass" for s in got.values())
            marks = " ".join(f"{n}:{got[n]}" for n in GATE_ORDER)
            print(f"  [{'OK  ' if ok else 'WRONG'}] {label:16s} "
                  f"{'ACCEPTED' if r['accepted'] else 'REJECTED'}  {marks}  "
                  f"({r['changed_lines']} lines, {time.monotonic() - t0:.1f}s)")
            c = r["checks"]
            if label == "always_revert" and c["1"]["status"] == "pass":
                print("         check 1 alone would have ACCEPTED this; check 2 refused it: "
                      f"honest A after = {_abg(c['1']['abg'])}")
            if c["3"].get("abi_diff", {}).get("removed"):
                print(f"         removed: {c['3']['abi_diff']['removed']}")
            for h in c["L"].get("lint", []):
                print(f"         lint [{h['rule']}] {h['text']}")
            results.append(ok)
        print(f"\n{sum(results)}/{len(results)} as expected")
        return 0 if all(results) else 1
    finally:
        import shutil
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
