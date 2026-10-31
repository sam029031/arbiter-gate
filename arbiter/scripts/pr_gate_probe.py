#!/usr/bin/env python3
"""gate.py PR mode end to end, with the audit replaced by a recorded row. No LLM request.

    python3 scripts/pr_gate_probe.py [--sandbox]

The model call (gate.run_arbiter_call) is swapped for one that writes a stored results
row -- runs/spark-test-2 (examples/StakingVault.sol, proven by arbiter-gpt through
unstake() re-entrancy) -- re-pointed at the PR's copy of the file. Everything after the
audit is the real code: diff scope, triage, Slither filtered to touched functions, A/B/G
by forge, the recorded arbiter-gpt patch re-verified, suggestions, the regression test,
SARIF, the PR comment, the exit code.

  vuln_in_pr     PR reintroduces the bug in unstake()     -> exit 1, finding in a
                 changed function, A/B/G measured, patch verified, suggestion blocks
                 that rebuild the patched file, SARIF error at src/StakingVault.sol
  vuln_not_in_pr PR edits stake() only; same proven row  -> exit 1 (D9), the comment
                 says the vulnerable function is not one this PR changed; Slither
                 hints kept for stake() only
  regr_pass      head = the patched contract + the TestArbiterRegression the first case
                 wrote, audit unproven                    -> exit 0, regression passed
  regr_fail      head = the vulnerable contract + that regression test, audit unproven
                                                          -> exit 1 from the regression
  not_executed   the audit raises (a dead gateway)        -> exit 2, "這不是發現漏洞"
  llm_blocked    --llm-blocked (the evaluation is running) -> exit 2, the audit is never
                 called, the touched functions are still listed
  fork           python3 -m arbiter.prgate refuse-fork    -> exit 2, no LLM, SARIF
                 executionSuccessful false

runs/ is not in git: without runs/spark-test-2.* the probe says so and exits 2.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))
os.environ["PATH"] = f"{Path.home() / '.foundry' / 'bin'}:{os.environ.get('PATH', '')}"
# Any request that slipped through would go nowhere: nothing listens on port 9.
os.environ["ARBITER_BASE_URL"] = "http://127.0.0.1:9/v1"

from arbiter import gate  # noqa: E402
from arbiter.patch import apply_diff  # noqa: E402

RESULTS = RIG / "runs" / "spark-test-2.results.jsonl"
PATCHES = RIG / "runs" / "spark-test-2.patches.jsonl"
VULN = (RIG / "examples" / "StakingVault.sol").read_text(encoding="utf-8")
FILE = "src/StakingVault.sol"
SID = f"pr::{FILE}"
VENV_PY = RIG.parent.parent / "venv-tools" / "bin" / "python"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=probe",
                           "-c", "user.email=probe@example.invalid", *args],
                          check=True, capture_output=True, text=True).stdout


def make_repo(root: Path, base_files: dict[str, str], head_files: dict[str, str]) -> Path:
    repo = root
    repo.mkdir(parents=True)
    (repo / "foundry.toml").write_text('[profile.default]\nsrc = "src"\nout = "out"\n')

    def put(files: dict[str, str]) -> None:
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text, encoding="utf-8")
    put(base_files)
    git(repo, "init", "-q", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "base")
    git(repo, "checkout", "-q", "-b", "pr")
    put(head_files)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "pr")
    return repo


def fake_audit(mode: str):
    row0 = json.loads(RESULTS.read_text(encoding="utf-8").splitlines()[0])

    def call(args, evalset: Path, run_id: str, job: Path, **_kw):
        items = json.loads(evalset.read_text(encoding="utf-8"))["items"]
        if mode == "raise":
            raise RuntimeError("GatewayError: gave up after 7 attempts (probe)")
        if mode == "forbidden":
            raise AssertionError("the audit must not be called")
        rows = []
        for it in items:
            r = copy.deepcopy(row0)
            r["sample_id"], r["path"], r["source"] = it["id"], it["path"], it["code"]
            r["context"]["plan"].update(target=it["path"], repo_root=it["repo_root"])
            if mode == "unproven":
                r["outcome"] = {"stop_reason": "conclude_safe", "proven": False, "findings": [],
                                "pocs": [], "verdict": "safe", "turns": 3}
                for a in r["attempts"]:
                    a["turns"] = 3
            rows.append(r)
        (job / f"{run_id}.results.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        return {"usage": {"requests": 0}}
    return call


def run_gate(tmp: Path, name: str, repo: Path, mode: str, *extra: str) -> tuple[int, dict, str, dict]:
    gate.run_arbiter_call = fake_audit(mode)
    out = tmp / f"{name}.gate.json"
    sarif = tmp / f"{name}.sarif"
    md = tmp / f"{name}.md"
    rc = gate.main(["--repo", str(repo), "--base", "main", "--head", "pr",
                    "--workdir", str(tmp / "work"), "--out", str(out), "--sarif", str(sarif),
                    "--pr-comment", str(md), "--evidence-ladder", "off", "--model", "probe-model",
                    *extra])
    return (rc, json.loads(out.read_text(encoding="utf-8")), md.read_text(encoding="utf-8"),
            json.loads(sarif.read_text(encoding="utf-8")))


def sarif_valid(sarif: Path, gate_json: Path) -> str:
    if not VENV_PY.exists():
        return "skipped (no venv-tools)"
    p = subprocess.run([str(VENV_PY), str(RIG / "scripts" / "sarif_validate.py"),
                        str(sarif), str(gate_json)], capture_output=True, text=True)
    return "valid" if p.returncode == 0 else f"INVALID: {(p.stdout + p.stderr)[-200:]}"


def wording_ok(md: str) -> bool:
    return "CLEAR" not in md and not re.search(r"(?<!不等於)安全", md)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sandbox", action="store_true", help="run forge/Slither in the sandbox")
    a = ap.parse_args()
    if not (RESULTS.exists() and PATCHES.exists()):
        print("runs/spark-test-2.{results,patches}.jsonl missing (runs/ is not in git); "
              "restore them from the backup to run this probe")
        return 2
    sbx = ["--sandbox", "on" if a.sandbox else "off"]
    tmp = Path(tempfile.mkdtemp(prefix="pr-gate-probe-"))
    patches = tmp / "patches.jsonl"
    recs = [json.loads(l) for l in PATCHES.read_text(encoding="utf-8").splitlines() if l.strip()]
    patches.write_text("".join(json.dumps({**r, "sample_id": SID}) + "\n" for r in recs))
    fixed = VULN.replace(
        '        (bool ok, ) = msg.sender.call{value: amount}("");\n'
        '        require(ok, "eth transfer failed");\n\n'
        '        totalStaked -= amount;\n        stakeOf[msg.sender] = 0;\n',
        '        totalStaked -= amount;\n        stakeOf[msg.sender] = 0;\n\n'
        '        (bool ok, ) = msg.sender.call{value: amount}("");\n'
        '        require(ok, "eth transfer failed");\n')
    assert fixed != VULN
    try:
        # 1. the PR reintroduces the re-entrancy in unstake()
        repo = make_repo(tmp / "r1", {FILE: fixed}, {FILE: VULN})
        rc, g, md, sar = run_gate(tmp, "vuln_in_pr", repo, "proven", *sbx,
                                  "--patches", str(patches), "--regression-out", str(tmp / "reg"))
        e = g["files"][0] if g["files"] else {}
        f = (e.get("findings") or [{}])[0]
        p = f.get("patch") or {}
        sug = p.get("suggestions") or []
        lines = VULN.splitlines()
        for s in sorted(sug, key=lambda s: -s["start_line"]):
            lines[s["start_line"] - 1:s["end_line"]] = s["body"].split("\n") if s["body"] else []
        want, _ = apply_diff(VULN, p.get("diff") or "")
        errors = [r for r in sar["runs"][0]["results"] if r["level"] == "error"]
        uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in errors}
        check("vuln_in_pr", rc == 1 and e.get("verdict") == "proven_exploitable"
              and e["artifact"]["uri"] == FILE and f.get("in_changed_function") is True
              and (f.get("abg") or {}).get("status") == "measured" and p.get("status") == "verified"
              and sug and "\n".join(lines) + "\n" == want and uris == {FILE}
              and "就是這次改到的函式" in md and "A 沒攻擊時取回" in md and wording_ok(md),
              f"rc={rc} touched={g['pr']['touched']} abg={(f.get('abg') or {}).get('status')} "
              f"patch={p.get('status')} suggestions={len(sug)} sarif_errors={len(errors)} "
              f"sarif={sarif_valid(tmp / 'vuln_in_pr.sarif', tmp / 'vuln_in_pr.gate.json')}")
        reg = sorted((tmp / "reg").glob("*/test/arbiter"))

        # 2. the PR only edits stake(); the proven bug is in unstake() (D9)
        stake_edit = VULN.replace('require(msg.value > 0, "amount is zero");',
                                  'require(msg.value > 0, "nothing to stake");')
        repo = make_repo(tmp / "r2", {FILE: VULN}, {FILE: stake_edit})
        rc, g, md, _ = run_gate(tmp, "vuln_not_in_pr", repo, "proven", *sbx)
        e = g["files"][0] if g["files"] else {}
        f = (e.get("findings") or [{}])[0]
        sa = e.get("static_analysis") or {}
        hint_fns = {h.get("function") for h in sa.get("hints") or []}
        check("vuln_not_in_pr", rc == 1 and f.get("in_changed_function") is False
              and "不是這次改到的函式" in md and hint_fns <= {"stake"}
              and (sa.get("status") != "ran" or sa.get("functions_filter") == ["stake"]),
              f"rc={rc} touched={g['pr']['touched']} slither={sa.get('status')} "
              f"filter={sa.get('functions_filter')} hint_functions={sorted(hint_fns)}")

        # 3./4. the repository carries the regression test from case 1
        if not reg:
            check("regr_pass", False, "case 1 wrote no regression project")
            check("regr_fail", False, "case 1 wrote no regression project")
        else:
            regfiles = {f"test/arbiter/{q.name}": q.read_text(encoding="utf-8")
                        for q in reg[0].iterdir()}
            patched, _ = apply_diff(VULN, recs[0]["diff"])
            repo = make_repo(tmp / "r3", {FILE: VULN}, {FILE: patched, **regfiles})
            rc, g, md, _ = run_gate(tmp, "regr_pass", repo, "unproven", *sbx, "--slither", "off")
            rr = g["pr"].get("regression_rerun") or {}
            check("regr_pass", rc == 0 and rr.get("status") == "passed" and "✅ 通過" in md,
                  f"rc={rc} rerun={rr.get('status')} tests={len(rr.get('tests') or [])}")
            stake_edit2 = VULN.replace("totalStaked += msg.value;", "totalStaked = totalStaked + msg.value;")
            repo = make_repo(tmp / "r4", {FILE: VULN}, {FILE: stake_edit2, **regfiles})
            rc, g, md, _ = run_gate(tmp, "regr_fail", repo, "unproven", *sbx, "--slither", "off")
            rr = g["pr"].get("regression_rerun") or {}
            check("regr_fail", rc == 1 and rr.get("status") == "failed"
                  and "testExploitBlocked()" in (rr.get("failed") or []) and "回歸測試失敗" in md,
                  f"rc={rc} rerun={rr.get('status')} failed={rr.get('failed')}")

        # 5. the audit itself does not finish
        repo = make_repo(tmp / "r5", {FILE: fixed}, {FILE: VULN})
        rc, g, md, sar = run_gate(tmp, "not_executed", repo, "raise", *sbx, "--slither", "off")
        inv = sar["runs"][0]["invocations"][0]
        check("not_executed", rc == 2 and g["files"][0]["verdict"] == "not_executed"
              and "這不是發現漏洞" in md and inv["executionSuccessful"] is False and wording_ok(md),
              f"rc={rc} verdict={g['files'][0]['verdict']}")

        # 5b. the model server is reserved: nothing is sent, nothing passes
        rc, g, md, _ = run_gate(tmp, "llm_blocked", repo, "forbidden", *sbx, "--slither", "off",
                                "--repair", "--llm-blocked", "evaluation running (probe)")
        check("llm_blocked", rc == 2 and g["files"][0]["verdict"] == "not_executed"
              and g["input"].get("llm_requests_this_invocation") == 0
              and g["pr"]["touched"] == {FILE: ["unstake"]} and "這不是發現漏洞" in md,
              f"rc={rc} requests={g['input'].get('llm_requests_this_invocation')} touched={g['pr']['touched']}")

        # 6. a fork PR is refused before anything runs
        cmd = [sys.executable, "-m", "arbiter.prgate", "refuse-fork", "--out", str(tmp / "fork.gate.json"),
               "--comment", str(tmp / "fork.md"), "--sarif", str(tmp / "fork.sarif")]
        p6 = subprocess.run(cmd, cwd=RIG, capture_output=True, text=True)
        md = (tmp / "fork.md").read_text(encoding="utf-8")
        sar = json.loads((tmp / "fork.sarif").read_text(encoding="utf-8"))
        check("fork", p6.returncode == 2 and "fork" in md and "這不是發現漏洞" in md
              and sar["runs"][0]["invocations"][0]["executionSuccessful"] is False,
              f"rc={p6.returncode} sarif={sarif_valid(tmp / 'fork.sarif', tmp / 'fork.gate.json')}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    good = sum(ok for _, ok, _ in results)
    print(f"{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
