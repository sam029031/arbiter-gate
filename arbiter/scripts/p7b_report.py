#!/usr/bin/env python3
"""P7b: the numbers PREREGISTRATION_arbitergpt_v3.md sections 5, 8 and 9 promise, for the
three runs gptoss-v3-r1..r3. No LLM request.

    python3 scripts/p7b_report.py [--runs-dir DIR] [--out runs/p7b/metrics.json] [--slither]

Every metric comes from arbiter/score.py: score() for the matrices, summarise_runs() for
mean / min / max, bootstrap_delta(a=constant_no, b=run, metric="mcc") for the MCC interval
(section 5.2), and the same resampling -- same generator, same seed, same draws -- for the
other metrics, which this script computes with score.score() on each resample. The
winning predicate is report_arm.winning_predicate(); analyst time is analyst_cost.py's
functions with its defaults (15 / 2 minutes, false positives at full triage).

The run directory (the evaluation's worktree) is only read. --slither runs the section 9
Slither arm once per sample with arbiter.static_hints.run_slither (what slither_arm.py
calls) and scores it at the fixed impact >= Medium, confidence >= Medium; slither_arm.py's
`best` is not read.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from analyst_cost import analyst_minutes, recall_at_budget  # noqa: E402
from report_arm import winning_predicate  # noqa: E402

from arbiter import score as S  # noqa: E402
from arbiter.tools import STRICT_PREDICATES  # noqa: E402

RUN_IDS = ("gptoss-v3-r1", "gptoss-v3-r2", "gptoss-v3-r3")
METRICS = ("precision", "recall", "specificity", "f1", "accuracy", "mcc")
N_BOOT, SEED = 10000, 20260726
BUDGETS = (60, 120, 180, 240, 300, 420, 600)
INFRA_PREFIX = "error: GatewayError: gave up after"


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def stop_reasons(row: dict) -> list[str]:
    return [str(a.get("stop_reason") or "") for a in row.get("attempts") or []] + \
        [str((row.get("outcome") or {}).get("stop_reason") or "")]


def not_executed(row: dict) -> str:
    """Section 5.4: the reason a row counts as not_executed, or ''."""
    reasons = stop_reasons(row)
    err = next((r for r in reasons if r.startswith("error:")), "")
    if err:
        return err
    if reasons[-1] in ("context_unbuildable", "toolchain_unavailable"):
        return reasons[-1]
    return ""


def bootstrap(pred: dict, truth: dict) -> dict:
    """95% intervals for every metric, resampling sample ids exactly as
    score.bootstrap_delta does (same _Lcg, seed, draw count, percentile indices)."""
    ids = list(truth.keys())
    n = len(ids)
    rng = S._Lcg(SEED)
    vals: dict[str, list[float]] = {m: [] for m in METRICS}
    for _ in range(N_BOOT):
        picked = [ids[rng.below(n)] for _ in range(n)]
        sub_truth, sub_pred = {}, {}
        for j, sid in enumerate(picked):
            key = f"{sid}#{j}"
            sub_truth[key] = truth[sid]
            sub_pred[key] = pred.get(sid, "safe")
        c = S.score(sub_pred, sub_truth)
        for m in METRICS:
            vals[m].append(S._metric(c, m))
    out = {}
    for m, v in vals.items():
        v.sort()
        out[m] = [round(v[int(0.025 * len(v))], 4), round(v[min(int(0.975 * len(v)), len(v) - 1)], 4)]
    return out


def sessions_wall_clock(path: Path) -> tuple[float, list[str]]:
    starts, total, lines = None, 0.0, []
    for ln in path.read_text(encoding="utf-8").splitlines():
        lines.append(ln)
        stamp = datetime.strptime(ln[:19], "%Y-%m-%d %H:%M:%S")
        if " start " in ln:
            starts = stamp
        elif " end " in ln and starts:
            total += (stamp - starts).total_seconds()
            starts = None
    return total, lines


def slither_arm(evalset: dict, work: Path) -> dict:
    from slither_arm import confusion as sl_confusion
    from arbiter.static_hints import CONFIDENCES, IMPACTS, find_slither, run_slither

    slither = find_slither()
    if not slither:
        return {"status": "not_run", "reason": "slither not found"}
    rows, solcs, versions = [], Counter(), Counter()
    for it in evalset["items"]:
        run = run_slither(it["code"], "T.sol", work / it["id"], timeout=180, slither=slither)
        solcs[run.solc] += 1
        versions[run.version] += 1
        rows.append({"id": it["id"], "label": it["label"], "findings": run.findings,
                     "error": run.reason, "solc": run.solc})
    c = sl_confusion(rows, IMPACTS.index("Medium"), CONFIDENCES.index("Medium"))
    return {"status": "ran", "threshold": "impact >= Medium and confidence >= Medium (fixed)",
            "slither_versions": dict(versions), "solc": dict(solcs),
            "errors": sum(1 for r in rows if r["error"]),
            "findings_total": sum(len(r["findings"]) for r in rows),
            "confusion": c.as_dict(), "rows": rows}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs-dir", type=Path,
                    default=Path.home() / "innoserve" / "eval-worktree" / "arbiter" / "runs")
    ap.add_argument("--evalset", type=Path, default=HERE.parent / "evalsets" / "v3_authored.json")
    ap.add_argument("--out", type=Path, default=HERE.parent / "runs" / "p7b" / "metrics.json")
    ap.add_argument("--slither", action="store_true")
    a = ap.parse_args()

    assert set(STRICT_PREDICATES) == {"victim_loss", "liveness_broken"}, STRICT_PREDICATES
    evalset = json.loads(a.evalset.read_text(encoding="utf-8"))
    truth = {it["id"]: it["label"] for it in evalset["items"]}
    assert len(truth) == 40

    out: dict = {"runs": {}, "truth_n": len(truth), "n_boot": N_BOOT, "seed": SEED}
    reported_all, strict_all = [], []
    for rid in RUN_IDS:
        rows = load(a.runs_dir / f"{rid}.results.jsonl")
        summ = json.loads((a.runs_dir / f"{rid}.summary.json").read_text(encoding="utf-8"))
        ledger = load(a.runs_dir / f"{rid}.ledger.jsonl")
        requeued = load(a.runs_dir / f"{rid}.requeued.jsonl")
        assert len(rows) == 40 and {r["sample_id"] for r in rows} == set(truth)
        assert all(r["truth"] == truth[r["sample_id"]] for r in rows)
        by_id = {r["sample_id"]: r for r in rows}

        reported = summ["predictions_by_repeat"]["0"]
        assert reported == {r["sample_id"]: r["predicted"] for r in rows}, rid
        win = {sid: winning_predicate(r) for sid, r in by_id.items() if r["predicted"] == "vuln"}
        strict = {sid: ("vuln" if p == "vuln" and win.get(sid) in STRICT_PREDICATES else "safe")
                  for sid, p in reported.items()}
        reported_all.append(reported)
        strict_all.append(strict)

        loose = Counter()
        for sid, pred in win.items():
            if pred not in STRICT_PREDICATES:
                loose[(pred, sid[:1])] += 1

        c_rep, c_str = S.score(reported, truth), S.score(strict, truth)
        no = {k: "safe" for k in truth}
        bd = S.bootstrap_delta(a=no, b=reported, truth=truth, metric="mcc", n_boot=N_BOOT, seed=SEED)
        bd_s = S.bootstrap_delta(a=no, b=strict, truth=truth, metric="mcc", n_boot=N_BOOT, seed=SEED)
        ci_rep, ci_str = bootstrap(reported, truth), bootstrap(strict, truth)
        assert ci_rep["mcc"] == bd["ci95"] and ci_str["mcc"] == bd_s["ci95"], (rid, bd, ci_rep["mcc"])

        wall, sess = sessions_wall_clock(a.runs_dir / f"{rid}.sessions.log")
        finish = Counter(e.get("finish_reason") for e in ledger)
        ne = [{"sample_id": sid, "truth": r["truth"], "predicted": r["predicted"],
               "reason": not_executed(r), "attempts": [str(x.get("stop_reason")) for x in r["attempts"]]}
              for sid, r in by_id.items() if not_executed(r)]
        turns = [r["outcome"]["turns"] for r in rows]
        reqs = [sum(x["turns"] for x in r.get("attempts", [])) for r in rows]
        nv = sum(1 for r in rows if r["outcome"]["verdict"] == "no_verdict")
        out["runs"][rid] = {
            "as_reported": {**c_rep.as_dict(), "ci95": ci_rep, "mcc_bootstrap_delta": bd},
            "strict_only": {**c_str.as_dict(), "ci95": ci_str, "mcc_bootstrap_delta": bd_s},
            "positives": {sid: {"truth": truth[sid], "predicate": p} for sid, p in sorted(win.items())},
            "loose_positives": [{"predicate": p, "half": h, "n": n} for (p, h), n in sorted(loose.items())],
            "not_executed": ne,
            "requeued": [{"sample_id": q["sample_id"], "requeue_number": q["requeue_number"],
                          "requeued_at": q["requeued_at"],
                          "stop_reasons": [s[:120] for s in q["stop_reasons"]],
                          "final": {"predicted": by_id[q["sample_id"]]["predicted"],
                                    "stop_reasons": stop_reasons(by_id[q["sample_id"]])}}
                         for q in requeued],
            "analyst": {"minutes": analyst_minutes(c_rep.tp, c_rep.fp, True, 15.0, 2.0),
                        "recall_at_budget": {b: round(recall_at_budget(c_rep.tp, c_rep.fp, True, b, 15.0, 2.0), 2)
                                             for b in BUDGETS}},
            "analyst_strict": {"minutes": analyst_minutes(c_str.tp, c_str.fp, True, 15.0, 2.0)},
            "cost": {"ledger_requests": len(ledger),
                     "model_served": dict(Counter(e.get("model_served") for e in ledger)),
                     "summary_models_seen": summ["usage"].get("models_seen"),
                     "prompt_tokens": sum(e.get("prompt_tokens") or 0 for e in ledger),
                     "completion_tokens": sum(e.get("completion_tokens") or 0 for e in ledger),
                     "finish_reasons": dict(finish), "finish_length": finish.get("length", 0),
                     "wall_clock_s": wall, "sessions": sess,
                     "mean_turns": round(sum(turns) / len(turns), 2),
                     "mean_requests_per_sample": round(sum(reqs) / len(reqs), 2),
                     "no_verdict_rate": round(nv / len(rows), 4), "no_verdict_rows": nv,
                     "summary_mean_turns": summ["mean_turns"],
                     "summary_mean_requests_per_sample": summ["mean_requests_per_sample"],
                     "summary_no_verdict_rate": summ["no_verdict_rate"]},
        }
    out["summary"] = {"as_reported": S.summarise_runs(reported_all, truth),
                      "strict_only": S.summarise_runs(strict_all, truth)}
    out["f0"] = {"constant_yes": S.constant_yes_baseline(truth).as_dict(),
                 "constant_no": S.constant_no_baseline(truth).as_dict()}

    # section 8, applied as written: the AIS3 h2h-arbiter MCC, the v4 range and its width
    ref, lo, hi = 0.2669, 0.118, 0.303
    width = round(hi - lo, 3)
    rules = {}
    for kind in ("as_reported", "strict_only"):
        s = out["summary"][kind]
        mccs = [r["mcc"] for r in s["runs"]]
        mean = s["mcc"]["mean"]
        gap = round(abs(mean - ref), 4)
        rng = round(max(mccs) - min(mccs), 4)
        rules[kind] = {"mccs": mccs, "mean": mean, "gap_to_h2h_arbiter": gap,
                       "within_gap_rule": gap <= width, "inside_v4_range": lo <= mean <= hi,
                       "within_variation_range": gap <= width or lo <= mean <= hi,
                       "degraded": any(m <= 0 for m in mccs),
                       "range_of_runs": rng, "range_wider_than_gap": rng > gap}
    out["section8"] = {"ref_mcc": ref, "v4_range": [lo, hi], "width": width, **rules}

    if a.slither:
        work = Path(tempfile.mkdtemp(prefix="p7b-slither-"))
        try:
            out["slither"] = slither_arm(evalset, work)
        finally:
            shutil.rmtree(work, ignore_errors=True)
        stored = json.loads((HERE.parent / "runs" / "slither.json").read_text(encoding="utf-8"))
        out["slither_ais3_stored"] = {"version": stored.get("version"), "best": stored.get("best"),
                                      "findings_total": stored.get("findings_total")}

    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")

    for kind in ("as_reported", "strict_only"):
        print(f"\n== {kind} (arbiter-gpt, TUNE)")
        print(f"{'run':14s}{'TP':>4}{'TN':>4}{'FP':>4}{'FN':>4}" + "".join(f"{m:>13s}" for m in METRICS))
        for rid in RUN_IDS:
            r = out["runs"][rid][kind]
            print(f"{rid:14s}{r['TP']:>4}{r['TN']:>4}{r['FP']:>4}{r['FN']:>4}" +
                  "".join(f"{r[m]:>13.4f}" for m in METRICS))
            print(f"{'  95% CI':22s}" + "".join(f"{'[%.2f,%.2f]' % tuple(r['ci95'][m]):>13s}" for m in METRICS))
        s = out["summary"][kind]
        for agg in ("mean", "min", "max"):
            print(f"{agg:14s}" + "".join(f"{s[k][agg]:>6.4g}" for k in ("TP", "TN", "FP", "FN")) +
                  "".join(f"{s[m][agg]:>13.4f}" for m in METRICS))
    print("\nsection 8:", json.dumps(out["section8"], ensure_ascii=False))
    for rid in RUN_IDS:
        r = out["runs"][rid]
        print(f"\n{rid}: loose positives {r['loose_positives']}")
        print(f"  not_executed {[(x['sample_id'], x['reason'][:60]) for x in r['not_executed']]}")
        print(f"  requeued {[(x['sample_id'], x['requeue_number'], x['final']['predicted']) for x in r['requeued']]}")
        c = r["cost"]
        print(f"  cost: {c['ledger_requests']} req, {c['prompt_tokens']} prompt, {c['completion_tokens']} completion,"
              f" length {c['finish_length']}, wall {c['wall_clock_s']:.0f} s, turns {c['mean_turns']}"
              f" (summary {c['summary_mean_turns']}), req/sample {c['mean_requests_per_sample']}"
              f" (summary {c['summary_mean_requests_per_sample']}), no_verdict {c['no_verdict_rate']}")
        print(f"  analyst: {r['analyst']}")
    print(f"\nF0: {out['f0']}")
    if a.slither:
        sl = out["slither"]
        print(f"slither: {sl.get('confusion')} solc {sl.get('solc')} errors {sl.get('errors')} "
              f"findings {sl.get('findings_total')}; stored AIS3: {out['slither_ais3_stored']}")
    print(f"\nwritten: {a.out.relative_to(HERE.parent) if a.out.is_relative_to(HERE.parent) else a.out.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
