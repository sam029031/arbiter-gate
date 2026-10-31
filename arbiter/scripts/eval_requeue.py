#!/usr/bin/env python3
"""Validity check and infrastructure-error requeue for a pre-registered run.

    python3 scripts/eval_requeue.py <run-id> --check   # report only, changes nothing
    python3 scripts/eval_requeue.py <run-id>           # move infra-error rows aside

`run.py` writes a row for every sample it finishes, including a sample whose every
gateway call failed, and on a rerun with the same run id it skips any sample that already
has a row. A dropped tunnel therefore leaves rows that look finished but measured nothing.
PREREGISTRATION_arbitergpt_v3.md fixes what happens to them, and this script is that rule:

* infrastructure error = some attempt stopped with
  ``error: GatewayError: gave up after ...`` (the gateway exhausted its retries on
  connection errors, timeouts, 429 or 5xx). Such rows are requeued whatever the outcome,
  so the rule cannot favour any label;
* ``error: ModelMismatch`` anywhere, or more than one ``model_served`` in the ledger,
  voids the whole run;
* any other ``error:``, ``context_unbuildable`` or ``toolchain_unavailable`` is not
  requeued; it is scored as the harness scores it (safe) and reported as not_executed;
* a sample is requeued at most twice; after that its last row stands as not_executed.

Requeued rows are appended to ``<run-id>.requeued.jsonl`` with a timestamp, the original
results file is copied to ``<run-id>.results.<stamp>.bak.jsonl`` first, and nothing is
deleted. Settings are never touched: resume with ``eval_launch.sh <run-id> --resume``.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

RUNS = Path(__file__).resolve().parent.parent / "runs"
INFRA_PREFIX = "error: GatewayError: gave up after"
MAX_REQUEUES = 2


def _reasons(row: dict) -> list[str]:
    reasons = [str(a.get("stop_reason") or "") for a in row.get("attempts") or []]
    reasons.append(str((row.get("outcome") or {}).get("stop_reason") or ""))
    return reasons


def classify(row: dict) -> str:
    reasons = _reasons(row)
    if any(r.startswith("error: ModelMismatch") for r in reasons) or str(
        row.get("error") or ""
    ).startswith("ModelMismatch"):
        return "model_mismatch"
    if any(r.startswith(INFRA_PREFIX) for r in reasons):
        return "infra"
    if any(r.startswith("error:") for r in reasons):
        return "other_error"
    last = reasons[-1]
    if last in ("context_unbuildable", "toolchain_unavailable"):
        return last
    return "ok"


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_id")
    ap.add_argument("--check", action="store_true", help="report only")
    args = ap.parse_args()

    results = RUNS / f"{args.run_id}.results.jsonl"
    ledger = RUNS / f"{args.run_id}.ledger.jsonl"
    requeued_path = RUNS / f"{args.run_id}.requeued.jsonl"
    rows = load(results)
    if not rows:
        print(f"{args.run_id}: no rows")
        return 1

    kinds = Counter(classify(r) for r in rows)
    served = Counter(e.get("model_served", "") for e in load(ledger))
    previous = Counter(r["sample_id"] for r in load(requeued_path))
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")

    print(f"[{stamp}] {args.run_id}: {len(rows)} rows  " + "  ".join(
        f"{k}={v}" for k, v in sorted(kinds.items())))
    print(f"  ledger: {sum(served.values())} requests, model_served={dict(served)}")
    void = kinds["model_mismatch"] > 0 or len([m for m in served if m]) > 1
    if void:
        print("  VOID: more than one served model or a ModelMismatch row; "
              "the pre-registration says this run is discarded and rerun")
    if previous:
        print(f"  previously requeued: {dict(previous)}")

    infra = [r for r in rows if classify(r) == "infra"]
    capped = [r for r in infra if previous[r["sample_id"]] >= MAX_REQUEUES]
    movable = [r for r in infra if previous[r["sample_id"]] < MAX_REQUEUES]
    for r in infra:
        flag = " (cap reached, stays as not_executed)" if r in capped else ""
        print(f"  infra  r{r['repeat']} {r['sample_id']}{flag}")
    if args.check or not movable:
        if not args.check:
            print("  nothing to requeue")
        return 2 if void else 0
    if void:
        print("  not requeueing a void run")
        return 2

    backup = RUNS / f"{args.run_id}.results.{time.strftime('%Y%m%d-%H%M%S')}.bak.jsonl"
    shutil.copy2(results, backup)
    moved_ids = {(r["repeat"], r["sample_id"]) for r in movable}
    with requeued_path.open("a", encoding="utf-8") as fh:
        for r in movable:
            fh.write(json.dumps({
                "requeued_at": stamp, "repeat": r["repeat"], "sample_id": r["sample_id"],
                "requeue_number": previous[r["sample_id"]] + 1,
                "stop_reasons": _reasons(r), "row": r,
            }, ensure_ascii=False) + "\n")
    kept = [r for r in rows if (r["repeat"], r["sample_id"]) not in moved_ids]
    tmp = results.with_suffix(".tmp")
    tmp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in kept),
                   encoding="utf-8")
    tmp.replace(results)
    print(f"  moved {len(movable)} rows to {requeued_path.name}; backup {backup.name}")
    print(f"  next: bash scripts/eval_launch.sh {args.run_id} --resume")
    return 0


if __name__ == "__main__":
    sys.exit(main())
