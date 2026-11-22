#!/usr/bin/env python3
"""gate.json's tool_commit says which ARBITER Gate code produced the report -- or that it
cannot. No forge, no LLM.

An ME record registers toolCommit from gate.json, so the commit a report names must be the
code that produced it, or the report must say it is not. Each case runs gate.py from a
throwaway git checkout of this arbiter/ package, in a fresh interpreter:

  clean    no tracked change       -> tool_commit = HEAD, tool_commit_dirty false,
                                      tool_commit_role "audit"
  dirty    a tracked file modified -> tool_commit_dirty true, and the source says HEAD is
                                      not the code that ran (the commit used to be written
                                      bare, its "-dirty" marker documented but never
                                      written: gate-logic-7)
  replay   gate.main --from-results on a recorded row -> tool_commit_role "replay": this
           code only re-measured and rendered a run some other code recorded
  env      ARBITER_TOOL_COMMIT set -> that commit, named as the operator's statement
  no_git   not a git checkout      -> nothing written

    python3 scripts/tool_commit_probe.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
PKG = RIG / "arbiter"
SNAPSHOT = "ab" * 20

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'WRONG'}] {name:7s} {detail}")


def env(**extra: str) -> dict[str, str]:
    e = {k: v for k, v in os.environ.items()
         if k not in ("ARBITER_TOOL_COMMIT", "ARBITER_API_KEY", "AIS3_API_KEY", "OPENAI_API_KEY",
                      "ARBITER_SANDBOX", "PYTHONPATH")}
    e.update(ARBITER_BASE_URL="http://127.0.0.1:9/v1", AIS3_BASE_URL="http://127.0.0.1:9/v1",
             **extra)
    return e


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=probe",
                           "-c", "user.email=probe@example.invalid", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def checkout(root: Path, with_git: bool = True) -> Path:
    shutil.copytree(PKG, root / "arbiter", ignore=shutil.ignore_patterns("__pycache__"))
    if with_git:
        git(root, "init", "-q")
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "snapshot")
    return root


def tool_commit(root: Path, replay: bool = False, **extra: str) -> dict:
    """gate._tool_commit() as that checkout's gate.py computes it ({"error": ...} if it
    cannot be called)."""
    call = "gate._tool_commit(replay=True)" if replay else "gate._tool_commit()"
    code = ("import json, sys; sys.path.insert(0, sys.argv[1]); from arbiter import gate; "
            f"print(json.dumps({call}))")
    p = subprocess.run([sys.executable, "-c", code, str(root)],
                       cwd=root, env=env(**extra), capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        return {"error": (p.stderr.strip().splitlines() or ["?"])[-1][:200]}
    return json.loads(p.stdout.strip().splitlines()[-1])


def main() -> int:
    if shutil.which("git") is None:
        print("git not on PATH")
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="tool-commit-probe-"))
    try:
        repo = checkout(tmp / "repo")
        head = git(repo, "rev-parse", "HEAD")

        got = tool_commit(repo)
        check("clean", got == {"tool_commit": head, "tool_commit_source": "git HEAD",
                               "tool_commit_dirty": False, "tool_commit_role": "audit"},
              json.dumps(got, ensure_ascii=False))

        with (repo / "arbiter" / "patch.py").open("a", encoding="utf-8") as fh:
            fh.write("\n# a local change the commit does not have\n")
        got = tool_commit(repo)
        check("dirty", got.get("tool_commit") == head and got.get("tool_commit_dirty") is True
              and "未提交" in got.get("tool_commit_source", "")
              and "不是實際執行的程式" in got.get("tool_commit_source", ""),
              json.dumps(got, ensure_ascii=False))
        git(repo, "checkout", "--", "arbiter/patch.py")

        # --from-results end to end: a recorded row that needs no forge (nothing proven)
        results_file = tmp / "rec.results.jsonl"
        results_file.write_text(json.dumps({
            "sample_id": "rec::C", "path": "", "source": "pragma solidity ^0.8.20;\ncontract C {}\n",
            "context": {"ok": True, "mode": "hermetic"}, "attempts": [{"turns": 2}],
            "outcome": {"verdict": "safe", "proven": False, "stop_reason": "conclude_safe",
                        "turns": 2, "findings": [], "pocs": []}}) + "\n", encoding="utf-8")
        out = tmp / "replay.gate.json"
        p = subprocess.run([sys.executable, "-m", "arbiter.gate", "--from-results", str(results_file),
                            "--out", str(out), "--slither", "off", "--evidence-ladder", "off",
                            "--sandbox", "off", "--workdir", str(tmp / "work")],
                           cwd=repo, env=env(), capture_output=True, text=True, timeout=300)
        rep = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        unit = tool_commit(repo, replay=True)
        check("replay", rep.get("tool_commit") == head and rep.get("tool_commit_role") == "replay"
              and rep.get("tool_commit_dirty") is False and unit.get("tool_commit_role") == "replay"
              and (rep.get("input") or {}).get("mode") == "from_results",
              f"gate.main --from-results rc {p.returncode}: tool_commit_role "
              f"{rep.get('tool_commit_role')!r}, dirty {rep.get('tool_commit_dirty')!r}"
              + ("" if rep else f"; stderr {p.stderr[-300:]!r}"))

        got = tool_commit(repo, ARBITER_TOOL_COMMIT=SNAPSHOT.upper())
        check("env", got == {"tool_commit": SNAPSHOT, "tool_commit_source": "ARBITER_TOOL_COMMIT",
                             "tool_commit_role": "audit"}, json.dumps(got, ensure_ascii=False))

        got = tool_commit(checkout(tmp / "plain", with_git=False))
        check("no_git", got == {}, json.dumps(got, ensure_ascii=False))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    good = sum(ok for _, ok, _ in results)
    print(f"\n{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
