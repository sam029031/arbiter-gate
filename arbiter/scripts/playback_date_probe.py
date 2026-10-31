#!/usr/bin/env python3
"""The playback banner's date, with no LLM request and no network (user decision D28).

A recorded run's files carry no time of their own. runs/spark-test-2.recorded.json says
which day the run was made and where that day was taken from (the results file's mtime on
the machine that recorded it, and the first local backup's tar); jobs.recorded_timeline()
shows its recorded_on and, without the note, falls back to the results file's mtime as
before. The material is copied to a temporary directory: the files in runs/ are only read,
their mtimes are never touched.

  runs_note      runs/ as it is: the banner date is the note's recorded_on, 2026-10-28,
                 and the note says where the day came from
  mtime_moved    a copy whose results file's mtime is set to 2026-11-15 -> still 2026-10-28
  no_note        the same copy without the note -> 2026-11-15 (the mtime, as before)
  bad_note       a note without a valid recorded_on -> the mtime
  same_timeline  with and without the note, everything but recorded_on is identical
  other_run      a run with no note (spark-test-3) still shows its own mtime

    python3 scripts/playback_date_probe.py [--runs DIR]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter import jobs  # noqa: E402

RIG = Path(__file__).resolve().parent.parent
RUN = "spark-test-2"
RECORDED = "2026-10-28"
MOVED = time.mktime((2026, 11, 15, 12, 0, 0, 0, 0, -1))

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'WRONG'}] {name:14s} {detail}")


def day_of(path: Path) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(path.stat().st_mtime))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default=str(RIG / "runs"))
    runs = Path(ap.parse_args().runs)
    res = runs / f"{RUN}.results.jsonl"
    note = runs / f"{RUN}.recorded.json"
    if not (res.is_file() and note.is_file()):
        print(f"material missing: runs/{RUN}.results.jsonl and runs/{RUN}.recorded.json "
              "(copy innoserve/demo_runs/* into runs/)")
        return 2
    print(f"playback banner date: {RUN} (results mtime here {day_of(res)})\n")

    got = jobs.recorded_timeline(res)["recorded_on"]
    source = json.loads(note.read_text(encoding="utf-8")).get("source") or ""
    check("runs_note", got == RECORDED and bool(source),
          f"banner {got}; note's source given: {bool(source)}")

    with tempfile.TemporaryDirectory(prefix="playback-date-") as tmp:
        t = Path(tmp)
        for suffix in (".results.jsonl", ".ledger.jsonl", ".recorded.json"):
            shutil.copy2(runs / f"{RUN}{suffix}", t / f"{RUN}{suffix}")
        copy, copy_note = t / f"{RUN}.results.jsonl", t / f"{RUN}.recorded.json"
        os.utime(copy, (MOVED, MOVED))
        with_note = jobs.recorded_timeline(copy)
        check("mtime_moved", with_note["recorded_on"] == RECORDED,
              f"results mtime {day_of(copy)} -> banner {with_note['recorded_on']}")

        copy_note.unlink()
        without = jobs.recorded_timeline(copy)
        check("no_note", without["recorded_on"] == day_of(copy) == "2026-11-15",
              f"note removed -> banner {without['recorded_on']} (the mtime)")

        a, b = dict(with_note), dict(without)
        a.pop("recorded_on")
        b.pop("recorded_on")
        same = json.dumps(a, sort_keys=True, default=str) == json.dumps(b, sort_keys=True, default=str)
        check("same_timeline", same, f"{len(with_note['timeline'])} events, notes and row identical: {same}")

        bad = []
        for text in ('{"source": "no date"}', '{"recorded_on": "10/28"}', '["2026-10-28"]', "not json"):
            copy_note.write_text(text, encoding="utf-8")
            bad.append(jobs.recorded_timeline(copy)["recorded_on"])
        check("bad_note", all(d == "2026-11-15" for d in bad), f"4 malformed notes -> {sorted(set(bad))}")

    other = runs / "spark-test-3.results.jsonl"
    if other.is_file() and not (runs / "spark-test-3.recorded.json").exists():
        got3 = jobs.recorded_timeline(other)["recorded_on"]
        check("other_run", got3 == day_of(other), f"spark-test-3 (no note) -> banner {got3} (its mtime)")
    else:
        check("other_run", False, "spark-test-3 material missing or has a note")

    good = sum(ok for _, ok, _ in results)
    print(f"\n{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
