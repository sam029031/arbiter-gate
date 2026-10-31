#!/usr/bin/env python3
"""Patch statistics over a pre-registered run's proven rows (P7b): patch gate + check 5.

    python3 scripts/patch_stats.py --results R1.results.jsonl [--results R2...] \
        --out runs/patchstats/patchstats.jsonl [--stop-at 19:50] [--only V|S]

For every proven row: the stored exploit goes through the repair loop the gate uses
(patch.repair: up to 3 proposals through checks 0, L, 3, 1, 2, 4) and an accepted patch
is attacked again (check 5, at most two defences) -- the settings of the P6 acceptance:
per-row sandbox on, re-attack on, 16 turns, the model from ARBITER_MODEL / AIS3_MODEL.
The results files are only read (the evaluation's worktree is never written to).

One JSON line per row, appended and fsynced as each row finishes; a row already in the
output is skipped, so an interrupted run resumes where it stopped. A row is never
started after --stop-at, nor while a pre-registered evaluation (gptoss-v3-) is running.

Rows proven under a predicate the patch gate does not handle are recorded as skipped
with the reason (plan 6.2: only the strict predicates, victim_loss and liveness_broken,
are patched). S_ rows (the fixed half of a pair, proven anyway) are recorded like the
others and counted apart by whoever reads the file. Every proposal is kept (diff, the
model's rationale, the first check that refused it and the message fed back), so a
refusal can be explained afterwards. No summary numbers here: the P7b report draws them
after r3.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter import sandbox  # noqa: E402
from arbiter.gateway import Gateway  # noqa: E402
from arbiter.patch import exploit_from_row, repair  # noqa: E402

GATE_CHECKS = ("0", "L", "3", "1", "2", "4", "5")


def evaluation_running() -> bool:
    r = subprocess.run(["pgrep", "-f", r"cli\.py run .*--run-id gptoss-v3-"],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def past(stop_at: str | None) -> bool:
    if not stop_at:
        return False
    hh, mm = (int(x) for x in stop_at.split(":"))
    now = time.localtime()
    return (now.tm_hour, now.tm_min) >= (hh, mm)


def done_keys(out: Path) -> set[str]:
    if not out.exists():
        return set()
    keys = set()
    for line in out.read_text(encoding="utf-8").splitlines():
        try:
            keys.add(json.loads(line)["key"])
        except (json.JSONDecodeError, KeyError):
            continue
    return keys


def emit(out: Path, rec: dict) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def summarise(rec: dict, patch: dict) -> dict:
    """The per-row fields P7b asks for, from a PatchRecord."""
    checks = {n: (patch.get("checks") or {}).get(n, {}).get("status") for n in GATE_CHECKS}
    attacks = [e for e in patch.get("timeline") or [] if e.get("side") == "attack"
               and e.get("source") == "reattack"]
    broke = [e for e in attacks if e.get("result") == "proven"]
    rec.update(
        status=patch["status"], skip_reason=patch.get("skip_reason") or "",
        checks=checks, proposals=len(patch.get("rounds") or []),
        defences=sum(1 for e in patch.get("timeline") or [] if e.get("side") == "defend"),
        first_failures=[r.get("first_failure") for r in patch.get("rounds") or []],
        reattacks=[{"round": e["round"], "result": e["result"], "turns": e.get("turns"),
                    "elapsed_s": e.get("elapsed_s"), "requests": e.get("requests"),
                    "new_attack": ({"hypothesis": e.get("hypothesis"),
                                    "predicate": e.get("predicate"),
                                    "function": (e.get("finding") or {}).get("vulnerable_function")}
                                   if e.get("result") == "proven" else None),
                    "reason": e.get("reason") or ""} for e in attacks],
        broken_through=bool(broke),
        requests=patch.get("requests"), requests_reattack=patch.get("reattack_requests", 0),
        requests_proposals=(patch.get("requests") or 0) - (patch.get("reattack_requests") or 0),
        diff=patch.get("diff"), timeline=patch.get("timeline"),
        check2_note=patch.get("check2_note"),
        rounds=[{"round": r.get("round"), "defence": r.get("defence"),
                 "first_failure": r.get("first_failure"), "checks": r.get("checks"),
                 "message": str(r.get("message") or "")[:800],
                 "rationale": str(r.get("rationale") or "")[:400],
                 "diff": str(r.get("diff") or "")[:4000]} for r in patch.get("rounds") or []])
    return rec


def run_row(row: dict, run_id: str, root: Path, model: str, max_turns: int,
            rounds: int) -> dict:
    sid = row["sample_id"]
    o = row.get("outcome") or {}
    poc = next((p for p in o.get("pocs") or [] if p.get("passed") and p.get("adjudicated")), {})
    rec = {"key": f"{run_id}::{row.get('repeat', 0)}::{sid}", "run_id": run_id,
           "sample_id": sid, "half": sid[:1], "predicate": poc.get("predicate"),
           "model": model, "started_at": time.strftime("%Y-%m-%d %H:%M:%S")}
    t0 = time.monotonic()
    try:
        exploit = exploit_from_row(row)
    except ValueError as exc:
        reason = f"predicate_not_patched: {exc}"
        rec.update(status="skipped", skip_reason=reason, checks={}, requests=0,
                   elapsed_s=round(time.monotonic() - t0, 2))
        return rec
    job = root / re.sub(r"[^A-Za-z0-9_.-]", "_", f"{run_id}__{sid}")
    ok, why = sandbox.available()
    if not ok:
        rec.update(status="not_executed", skip_reason=f"sandbox unavailable: {why}",
                   checks={}, requests=0, elapsed_s=round(time.monotonic() - t0, 2))
        return rec
    box = sandbox.JobSandbox(job, f"ps-{run_id[-2:]}-{sid}"[:40], job_max_s=3600)
    env = box.__enter__()
    try:
        with sandbox.applied_env(env):
            gw = Gateway(model=model, ledger_path=job / "patch.ledger.jsonl")
            patch = repair(gw, {**exploit, "sample_id": sid}, root=job / "work",
                           rounds=rounds, reattack_turns=max_turns)
    except Exception as exc:  # noqa: BLE001
        rec.update(status="not_executed", skip_reason=f"{type(exc).__name__}: {exc}"[:300],
                   checks={}, requests=None, elapsed_s=round(time.monotonic() - t0, 2))
        return rec
    finally:
        box.__exit__(None, None, None)
    rec = summarise(rec, patch)
    rec.update(sandbox="on", elapsed_s=round(time.monotonic() - t0, 2),
               finished_at=time.strftime("%Y-%m-%d %H:%M:%S"))
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", action="append", required=True)
    ap.add_argument("--out", default="runs/patchstats/patchstats.jsonl")
    ap.add_argument("--stop-at", default=None, help="HH:MM: start no row at or after this")
    ap.add_argument("--only", choices=("V", "S"), default=None)
    ap.add_argument("--max-turns", type=int, default=16)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--model", default=None)
    a = ap.parse_args()
    model = a.model or os.environ.get("ARBITER_MODEL") or os.environ.get("AIS3_MODEL") or ""
    out = Path(a.out)
    root = out.parent / "jobs"
    done = done_keys(out)
    todo = []
    for path in a.results:
        run_id = Path(path).name.removesuffix(".results.jsonl")
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            if not (row.get("outcome") or {}).get("proven"):
                continue
            if a.only and not row["sample_id"].startswith(a.only + "_"):
                continue
            key = f"{run_id}::{row.get('repeat', 0)}::{row['sample_id']}"
            if key not in done:
                todo.append((run_id, row))
    print(f"{len(done)} row(s) already done, {len(todo)} to do", flush=True)
    for i, (run_id, row) in enumerate(todo, 1):
        if past(a.stop_at):
            print(f"stop: it is past {a.stop_at}; {len(todo) - i + 1} row(s) left", flush=True)
            return 3
        if evaluation_running():
            print("stop: a pre-registered evaluation is running; no model request", flush=True)
            return 3
        print(f"[{time.strftime('%H:%M:%S')}] {i}/{len(todo)} {run_id} {row['sample_id']}", flush=True)
        rec = run_row(row, run_id, root, model, a.max_turns, a.rounds)
        emit(out, rec)
        print(f"    -> {rec['status']} {rec.get('skip_reason', '')[:80]} checks={rec.get('checks')} "
              f"proposals={rec.get('proposals')} requests={rec.get('requests')} "
              f"{rec.get('elapsed_s')} s", flush=True)
    print("all rows done", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
