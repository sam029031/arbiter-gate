#!/usr/bin/env python3
"""Check 5 against a patch that only closes the door the first attack used (uses LLM).

    python3 scripts/reattack_trial.py --results runs/gate/<id>/<id>.results.jsonl \
        --patch withdrawAll=PATCH_A.sol --patch withdraw=PATCH_B.sol [--out trial.json]

The results row is a proven audit of a contract with more than one way to attack it.
The hand-written patch chosen is the one keyed by the proven finding's vulnerable
function: it stops THAT exploit (checks 0, L, 3, 1, 2 must pass -- otherwise the trial
says so and stops), and leaves the other door open. Then one re-attack (patch.reattack,
the same call --reattack makes) with the original hypothesis ruled out. Whether it finds
the other door is the measurement; nothing here is tuned to make it.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.gateway import Gateway  # noqa: E402
from arbiter.patch import exploit_from_row, reattack, verify_fix  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--patch", action="append", default=[], help="FUNCTION=patched.sol")
    ap.add_argument("--model", default=None)
    ap.add_argument("--max-turns", type=int, default=16)
    ap.add_argument("--out", default=None)
    ap.add_argument("--door", default=None,
                    help="which --patch to use, when the finding names several functions "
                         "(read it off the exploit: the function its attacker calls)")
    a = ap.parse_args()
    import os
    model = a.model or os.environ.get("ARBITER_MODEL") or os.environ.get("AIS3_MODEL")
    row = json.loads(Path(a.results).read_text(encoding="utf-8").splitlines()[0])
    if not row["outcome"].get("proven"):
        print("the audit did not prove an attack; nothing to patch")
        return 2
    ex = exploit_from_row(row)
    fn = str((ex["finding"] or {}).get("vulnerable_function") or "")
    patches = dict(p.split("=", 1) for p in a.patch)
    key = a.door if a.door in patches else next(
        (k for k in sorted(patches, key=len, reverse=True)
         if f"{k}(" in fn or fn.endswith(k) or fn == k), None)
    out: dict = {"proven_function": fn, "hypothesis": ex.get("hypothesis"),
                 "poc_name": ex["poc_name"], "patch_used": key}
    print(f"original finding: {fn}  hypothesis: {ex.get('hypothesis')}")
    if key is None:
        print(f"no hand-written patch for {fn!r}; keys: {sorted(patches)}")
        out["result"] = "no_patch_for_function"
    else:
        patched = Path(patches[key]).read_text(encoding="utf-8")
        root = Path(tempfile.mkdtemp(prefix="reattack-trial-"))
        gate = verify_fix(ex["source"], ex["solidity"], patched=patched, root=root,
                          sample_id="trial")
        out["gate"] = {n: c["status"] for n, c in gate["checks"].items()}
        print(f"patch for {key}: gate {out['gate']}  accepted={gate['accepted']}")
        if not gate["accepted"]:
            out["result"] = "patch_not_accepted"
        else:
            gw = Gateway(model=model, ledger_path=root / "trial.ledger.jsonl")
            t0 = time.monotonic()
            ra = reattack(gw, ex, patched, root=root,
                          ruled_out=[ex["hypothesis"]] if ex.get("hypothesis") else [],
                          max_turns=a.max_turns)
            ra.pop("exploit", None) if ra.get("status") != "proven" else None
            out["reattack"] = {k: v for k, v in ra.items() if k != "exploit"}
            if ra.get("exploit"):
                x = ra["exploit"]
                out["reattack"]["new_attack"] = {k: x.get(k) for k in
                                                 ("poc_name", "predicate", "hypothesis", "finding")}
            out["reattack"]["wall_s"] = round(time.monotonic() - t0, 2)
            out["result"] = ra["status"]
            print(f"re-attack: {ra['status']}  turns={ra.get('turns')}  "
                  f"requests={ra.get('requests')}  {ra.get('elapsed_s')} s")
            if ra.get("exploit"):
                f = ra["exploit"].get("finding") or {}
                print(f"  new attack: {f.get('vulnerable_function')}  "
                      f"[{ra['exploit'].get('predicate')}]  {ra['exploit'].get('hypothesis')}")
            for h in ra.get("tried") or []:
                print(f"  tried: {h}")
    if a.out:
        Path(a.out).write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
