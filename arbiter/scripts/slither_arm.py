#!/usr/bin/env python3
"""Slither as a second control arm, on the same forty samples.

The evaluation has had one baseline, and it is an LLM one. That leaves the obvious
objection open: perhaps the paired set is simply hard, and any tool would saturate on it.
Slither is the standard static analyser practitioners actually run, it is not an LLM, and
it costs no gateway requests -- so it answers that objection for free.

It is given every advantage the ARBITER arm was not. Slither is run once per contract and
every finding is kept; the operating point is then chosen OFFLINE by sweeping impact and
confidence thresholds and reporting the best MCC. That is deliberately generous -- the
threshold is picked with the answers in hand -- and it is the same courtesy already
extended to the other baseline, whose merge threshold was swept from k=1 to k=20.

The second number this produces has nothing to do with accuracy. Slither emits a
detector name, a severity and a source range. It does not emit a contract, a test, or a
transaction, so the count of its findings that carry a re-runnable execution record is
zero -- structurally, not because it does the job badly. That is the same zero the LLM
baseline produced, from a completely different architecture, which is what makes it a
property of the output format rather than of one tool.

    scripts/slither_arm.py --evalset evalsets/v3_authored.json --out runs/slither.json

Needs slither (on PATH, $ARBITER_SLITHER, or the tools venv beside the checkout) and a
forge-downloaded solc under ~/.svm. The analysis itself is arbiter.static_hints.run_slither,
which the gate also uses; `run_one` is that function with a working directory the caller
owns, and every finding keeps its source lines and enclosing function.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter.score import Confusion  # noqa: E402
from arbiter.static_hints import (CONFIDENCES, IMPACTS, find_slither,  # noqa: E402
                                  run_slither)


def run_one(code: str, slither: str, timeout: int, work_dir: Path,
            filename: str = "T.sol") -> tuple[list[dict], str]:
    """Every detector hit for one contract (check, impact, confidence, line, end_line,
    function, message), or the reason there are none. `work_dir` is the caller's."""
    run = run_slither(code, filename, work_dir, timeout=timeout, slither=slither)
    return run.findings, run.reason


def confusion(rows: list[dict], min_impact: int, min_conf: int) -> Confusion:
    """Flag a contract when it has any finding at or above both thresholds."""
    tp = tn = fp = fn = 0
    for r in rows:
        flagged = any(
            IMPACTS.index(f.get("impact", "Optimization")) <= min_impact
            and CONFIDENCES.index(f.get("confidence", "Low")) <= min_conf
            for f in r["findings"]
        )
        vuln = r["label"] == "vuln"
        if vuln and flagged:
            tp += 1
        elif vuln:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
    return Confusion(tp=tp, tn=tn, fp=fp, fn=fn)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evalset", type=Path,
                    default=Path("evalsets/v3_authored.json"))
    ap.add_argument("--out", type=Path, default=Path("runs/slither.json"))
    ap.add_argument("--timeout", type=int, default=180)
    args = ap.parse_args()

    slither = find_slither()
    if not slither:
        print("slither not found (PATH, $ARBITER_SLITHER, or ../venv-tools/bin/slither)")
        return 2

    items = json.loads(args.evalset.read_text(encoding="utf-8"))["items"]
    rows: list[dict] = []
    errs = 0
    tmp_root = Path(tempfile.mkdtemp(prefix="slither-arm-"))
    for i, it in enumerate(items, 1):
        findings, err = run_one(it["code"], slither, args.timeout, tmp_root / it["id"])
        if err:
            errs += 1
        rows.append({"id": it["id"], "label": it["label"],
                     "findings": findings,
                     "error": err})
        print(f"  {i:3d}/{len(items)}  {it['id'][:44]:<44} "
              f"{len(findings):3d} findings{'  ' + err if err else ''}")

    total = sum(len(r["findings"]) for r in rows)
    print(f"\n{total} findings over {len(rows)} contracts, {errs} failed to analyse")

    print("\noperating points, chosen with the answers in hand:")
    print(f"  {'impact >=':<16}{'conf >=':<10}{'TP':>4}{'TN':>4}{'FP':>4}{'FN':>4}"
          f"{'prec':>8}{'rec':>8}{'spec':>8}{'f1':>8}{'mcc':>8}")
    best = None
    for mi in range(len(IMPACTS)):
        for mc in range(len(CONFIDENCES)):
            c = confusion(rows, mi, mc)
            line = (f"  {IMPACTS[mi]:<16}{CONFIDENCES[mc]:<10}"
                    f"{c.tp:>4}{c.tn:>4}{c.fp:>4}{c.fn:>4}"
                    f"{c.precision:>8.3f}{c.recall:>8.3f}{c.specificity:>8.3f}"
                    f"{c.f1:>8.3f}{c.mcc:>8.3f}")
            print(line)
            if best is None or c.mcc > best[0].mcc:
                best = (c, IMPACTS[mi], CONFIDENCES[mc])

    c, bi, bc = best
    print(f"\nBEST BY MCC: impact >= {bi}, confidence >= {bc}")
    print(f"  TP {c.tp}  TN {c.tn}  FP {c.fp}  FN {c.fn}")
    print(f"  precision {c.precision:.3f}  recall {c.recall:.3f}  "
          f"specificity {c.specificity:.3f}  f1 {c.f1:.3f}  mcc {c.mcc:.3f}")
    print(f"\n  findings carrying a re-runnable execution record: 0 of {total}")
    print("  Slither reports a detector name, a severity and a source range. There is "
          "no contract,\n  no test and no transaction, so there is nothing for any "
          "adjudicator to run.")

    shutil.rmtree(tmp_root, ignore_errors=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({
        "arm": "slither",
        "evalset": str(args.evalset),
        "version": subprocess.run([slither, "--version"], capture_output=True,
                                  text=True).stdout.strip(),
        "rows": rows,
        "best": {"impact": bi, "confidence": bc, "tp": c.tp, "tn": c.tn,
                 "fp": c.fp, "fn": c.fn, "precision": c.precision,
                 "recall": c.recall, "specificity": c.specificity,
                 "f1": c.f1, "mcc": c.mcc},
        "findings_total": total,
        "findings_executable": 0,
    }, indent=1), encoding="utf-8")
    print(f"\n  {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
