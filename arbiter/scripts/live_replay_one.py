#!/usr/bin/env python3
"""Replay ONE recorded proof on two local anvil chains, original or patched target.

    python3 scripts/live_replay_one.py --results runs/<id>.results.jsonl \
        --target examples/StakingVault.sol [--patches runs/<id>.patches.jsonl] \
        [--port 8800] [--json out.json]

The proof is the first passed-and-adjudicated PoC in the results file. Parsing tries the
three templates in the same order as scripts/live_sweep.py (victim, exploit, other) and
calls arbiter.live_replay unchanged. With --patches, the target is the original with the
accepted diff applied (arbiter.patch.apply_diff), so the SAME exploit is replayed against
the fix. No LLM request is made.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.live_replay import (  # noqa: E402
    Untranslatable,
    parse_poc,
    parse_poc_exploit,
    parse_poc_other,
    replay,
    replay_exploit,
    replay_other,
)
from arbiter.patch import apply_diff  # noqa: E402

ETHER = 10**18


def _eth(wei: int | None) -> str:
    return "?" if wei is None else f"{wei / ETHER:g} ETH"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", type=Path, required=True)
    ap.add_argument("--target", type=Path, required=True)
    ap.add_argument("--patches", type=Path, default=None,
                    help="replay against the accepted patch in this file")
    ap.add_argument("--port", type=int, default=8800)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    row = json.loads(next(l for l in args.results.read_text(encoding="utf-8").splitlines()
                          if l.strip()))
    poc = next(p for p in row["outcome"]["pocs"] if p["passed"] and p["adjudicated"])
    source = args.target.read_text(encoding="utf-8")
    label = "original"
    if args.patches:
        rec = next(json.loads(l) for l in args.patches.read_text(encoding="utf-8").splitlines()
                   if l.strip() and json.loads(l).get("status") == "accepted")
        patched, err = apply_diff(source, rec["diff"])
        if patched is None:
            print(f"patch does not apply: {err}")
            return 2
        source, label = patched, "patched"

    out: dict = {"results": str(args.results), "poc": poc["name"],
                 "predicate": poc["predicate"], "target": label}
    with tempfile.TemporaryDirectory(prefix="live-one-") as tmp:
        tmpd = Path(tmp)
        (tmpd / "Target.sol").write_text(source, encoding="utf-8")
        (tmpd / "Poc.t.sol").write_text(poc["solidity"], encoding="utf-8")
        tried = []
        for name, parse, run in (("victim", parse_poc, replay),
                                 ("exploit", parse_poc_exploit, replay_exploit),
                                 ("other", parse_poc_other, replay_other)):
            try:
                rep = parse(tmpd / "Poc.t.sol", tmpd / "Target.sol", row["sample_id"])
            except Untranslatable as exc:
                tried.append({"template": name, "untranslatable": str(exc)})
                continue
            out["template"] = name
            out["record"] = run(rep, tmpd / "build", args.port)
            break
        out["tried"] = tried

    rec = out.get("record")
    print(f"exploit {out['poc']} ({out['predicate']}) against the {label} target")
    for t in out["tried"]:
        print(f"  template {t['template']}: Untranslatable: {t['untranslatable']}")
    if rec is None:
        print("  no template could translate this proof")
    elif rec.get("error"):
        print(f"  template {out['template']}: error: {rec['error']}")
    else:
        print(f"  template {out['template']}")
        for w in rec["worlds"]:
            print(f"  world {'with attack' if w['with_attack'] else 'no attack  '}: "
                  f"victim recovered {_eth(w['recovered'])}, attacker gain "
                  f"{_eth(w['attacker_gain'])}, target {_eth(w['target_held_mid'])} -> "
                  f"{_eth(w['target_held_end'])}, exit_ok={w['exit_ok']}")
            for s in w["steps"]:
                print(f"      {'ok ' if s.get('ok', True) else 'REV'} {s['what']:<28} "
                      f"tx={s.get('tx')}  gas={s.get('gas_used')}"
                      + (f"  note={s['note']}" if s.get("note") else ""))
        print(f"  shortfall {_eth(rec['shortfall'])}  attacker_gain "
              f"{_eth(rec['attacker_gain'])}  extracted_from_contract "
              f"{_eth(rec['extracted_from_contract'])}")
        print(f"  live verdict: {'PROVEN' if rec['proven'] else 'NOT PROVEN'}")
    if args.json:
        args.json.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
