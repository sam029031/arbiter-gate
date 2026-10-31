#!/usr/bin/env python3
"""P7b: the patch statistics D13 asks for, from patch_stats.py's records. No LLM request.

    python3 scripts/patch_stats_report.py [--dir runs/patchstats] [--out runs/patchstats/summary.json]

Which record counts (user decision D16): for every row, the FIRST run that finished.
A run that did not finish (not_executed: HTTP 500, connection) never counts, and a row
recorded as skipped only because the gate did not yet handle its predicate (the r2
liveness_broken row before liveness patching existed) is not a run of the gate. Every
record of every row is listed anyway, counted or not. Both files are read
(patchstats.jsonl holds the latest record of a row, patchstats.superseded.jsonl the
ones it replaced); neither is changed.

Main numbers: V_ rows proven under a strict predicate (victim_loss, liveness_broken).
S_ rows (the fixed half, proven anyway) are counted apart; rows proven under a loose
predicate are listed as skipped with the reason, not as failed patches.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
STRICT = ("victim_loss", "liveness_broken")
CHECKS = ("0", "L", "3", "1", "2", "4", "5")


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def pre_implementation(rec: dict) -> bool:
    return rec.get("status") == "skipped" and "沒有實作" in (rec.get("skip_reason") or "")


def counted(records: list[dict]) -> dict | None:
    for rec in sorted(records, key=lambda r: r.get("started_at") or ""):
        if rec.get("status") == "not_executed" or pre_implementation(rec):
            continue
        return rec
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path, default=HERE.parent / "runs" / "patchstats")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--evalset", type=Path, default=HERE.parent / "evalsets" / "v3_authored.json")
    a = ap.parse_args()
    out_path = a.out or a.dir / "summary.json"
    tags = {i["id"]: i.get("true_tag") or "" for i in
            json.loads(a.evalset.read_text(encoding="utf-8"))["items"]}

    by_key: dict[str, list[dict]] = defaultdict(list)
    for rec in load(a.dir / "patchstats.superseded.jsonl") + load(a.dir / "patchstats.jsonl"):
        by_key[rec["key"]].append(rec)

    rows = []
    for key, recs in sorted(by_key.items()):
        c = counted(recs)
        first = recs[0]
        rows.append({"key": key, "run_id": first["run_id"], "sample_id": first["sample_id"],
                     "half": first["sample_id"][:1], "pair": first["sample_id"][2:],
                     "true_tag": tags.get("V_" + first["sample_id"][2:], ""),
                     "predicate": first.get("predicate"), "counted": c,
                     "all": [{"started_at": r.get("started_at"), "status": r.get("status"),
                              "first_failures": r.get("first_failures"),
                              "counted": r is c,
                              "why_not": ("" if r is c else "not_executed（沒跑完）"
                                          if r.get("status") == "not_executed" else
                                          "修補閘門當時還沒支援這個謂詞" if pre_implementation(r)
                                          else "不是第一次跑完的紀錄"),
                              "note": (r.get("skip_reason") or "")[:160]} for r in
                             sorted(recs, key=lambda x: x.get("started_at") or "")]})

    main_rows = [r for r in rows if r["half"] == "V" and r["predicate"] in STRICT]
    s_rows = [r for r in rows if r["half"] == "S"]
    skipped = [r for r in rows if r["half"] == "V" and r["predicate"] not in STRICT]

    blocked = Counter()
    reattacks = broken = 0
    new_attacks = []
    for r in main_rows:
        c = r["counted"] or {}
        if c.get("status") == "skipped" and "not_reproducible" in (c.get("skip_reason") or ""):
            blocked["0"] += 1
        for f in c.get("first_failures") or []:
            if f:
                blocked[str(f)] += 1
        for ra in c.get("reattacks") or []:
            reattacks += 1
            if ra.get("result") == "proven":
                broken += 1
                blocked["5"] += 1
                new_attacks.append({"key": r["key"], "round": ra.get("round"),
                                    "turns": ra.get("turns"), **(ra.get("new_attack") or {})})

    def view(r: dict) -> dict:
        c = r["counted"] or {}
        return {"key": r["key"], "pair": r["pair"], "true_tag": r["true_tag"],
                "predicate": r["predicate"], "status": c.get("status"),
                "proposals": c.get("proposals"), "defences": c.get("defences"),
                "first_failures": c.get("first_failures"),
                "reattacks": [(ra.get("result"), ra.get("turns"), ra.get("elapsed_s"))
                              for ra in c.get("reattacks") or []],
                "elapsed_s": c.get("elapsed_s"), "requests": c.get("requests"),
                "check2_note": bool(c.get("check2_note")), "records": len(r["all"])}

    by_type: dict[str, Counter] = defaultdict(Counter)
    for r in main_rows:
        by_type[r["pair"]][(r["counted"] or {}).get("status") or "none"] += 1
    summary = {
        "rule": "D16: first finished run per row; not_executed and pre-implementation skips do not count",
        "main": {"n": len(main_rows),
                 "accepted": sum(1 for r in main_rows if (r["counted"] or {}).get("status") == "accepted"),
                 "status": dict(Counter((r["counted"] or {}).get("status") for r in main_rows)),
                 "blocked_first_failure": {k: blocked.get(k, 0) for k in CHECKS},
                 "proposals": sum((r["counted"] or {}).get("proposals") or 0 for r in main_rows),
                 "reattacks": reattacks, "broken_through": broken, "new_attacks": new_attacks,
                 "by_type": {k: dict(v) for k, v in sorted(by_type.items())},
                 "rows": [view(r) for r in main_rows]},
        "s_rows": [view(r) for r in s_rows],
        "skipped": [{"key": r["key"], "predicate": r["predicate"],
                     "reason": ((r["counted"] or {}).get("skip_reason") or "")[:120]} for r in skipped],
        "all_records": [{"key": r["key"], "all": r["all"]} for r in rows if len(r["all"]) > 1],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")

    m = summary["main"]
    print(f"main (V_, strict predicates, arbiter-gpt): {m['n']} row(s), accepted {m['accepted']}; status {m['status']}")
    print(f"  first failing check per proposal: {m['blocked_first_failure']}  (proposals {m['proposals']})")
    print(f"  re-attacks {m['reattacks']}, broken through {m['broken_through']}")
    for x in m["new_attacks"]:
        print(f"    new attack: {x}")
    for v in m["rows"]:
        print(f"  {v['key']:58s} {v['predicate']:15s} {v['status']:18s} proposals={v['proposals']} "
              f"defences={v['defences']} ff={v['first_failures']} reattacks={v['reattacks']} "
              f"{v['elapsed_s']} s req={v['requests']} records={v['records']}")
    print(f"  by type: {m['by_type']}")
    print(f"S_ rows: {[(v['key'], v['predicate'], v['status']) for v in summary['s_rows']]}")
    print(f"skipped V_ rows: {Counter(s['predicate'] for s in summary['skipped'])}")
    for r in summary["all_records"]:
        print(f"  all records of {r['key']}:")
        for x in r["all"]:
            print(f"    {x['started_at']} {x['status']:12s} {x['first_failures']} counted={x['counted']} {x['why_not']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
