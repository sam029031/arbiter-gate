#!/usr/bin/env python3
"""Fork PRs through the ARBITER Gate action, without a fork.

A live fork PR needs a second GitHub account, so the parts of the action a fork PR goes
through are exercised here, offline (no network, no model request):

  who           the "Same-repository PRs only" step's own shell, taken verbatim from
                .github/actions/arbiter-gate/action.yml, under five event payloads
  conditions    checkout and the SARIF upload run only in audit mode; the gate step
                runs for fork mode too (it writes the refusal)
  workflow      .github/workflows/arbiter-gate.yml triggers on pull_request only (never
                pull_request_target) and loads the action from main, not the PR checkout
  gate          scripts/gate_pr.sh fork  -> exit 2, "無法判定", no model request, no host
                path printed
  publish       scripts/gate_pr_publish.py against a fake API that answers 403 (a fork
                PR's read-only token) -> reported, exit 0, token never printed
  result        the "Result" step's shell: rc 2 or no rc -> the job fails with exit 2

    python3 scripts/action_fork_probe.py
"""

from __future__ import annotations

import http.server
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ARB = Path(__file__).resolve().parent.parent
ROOT = ARB.parent
ACTION = ROOT / ".github/actions/arbiter-gate/action.yml"
WORKFLOW = ROOT / ".github/workflows/arbiter-gate.yml"
results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}  {detail}")


def steps(text: str) -> list[dict]:
    """The composite action's steps: name, id, if, and the literal `run: |` block."""
    out, cur, run_ind = [], None, None
    for ln in text.splitlines():
        m = re.match(r"^    - name: (.*)$", ln)
        if m:
            cur = {"name": m.group(1).strip(), "run": []}
            out.append(cur)
            run_ind = None
            continue
        if cur is None:
            continue
        if run_ind is not None:
            if ln.strip() == "" or ln.startswith(" " * run_ind):
                cur["run"].append(ln[run_ind:])
                continue
            run_ind = None
        m = re.match(r"^      (id|if): (.*)$", ln)
        if m:
            cur[m.group(1)] = m.group(2).strip()
        if re.match(r"^      run: \|\s*$", ln):
            run_ind = 8
    for s in out:
        s["run"] = "\n".join(s["run"]).rstrip() + "\n"
    return out


def run_step(script: str, env: dict) -> tuple[int, str, dict]:
    with tempfile.NamedTemporaryFile("r", suffix=".out", delete=False) as fh:
        outfile = fh.name
    e = {"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", ""), "GITHUB_OUTPUT": outfile}
    e.update(env)
    p = subprocess.run(["bash", "-e", "-c", script], env=e, capture_output=True, text=True)
    outputs = dict(ln.split("=", 1) for ln in Path(outfile).read_text().splitlines() if "=" in ln)
    os.unlink(outfile)
    return p.returncode, p.stdout + p.stderr, outputs


class Deny(http.server.BaseHTTPRequestHandler):
    seen: list[str] = []

    def _deny(self) -> None:
        Deny.seen.append(f"{self.command} {self.path} auth={'Authorization' in self.headers}")
        body = json.dumps({"message": "Resource not accessible by integration"}).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PATCH = _deny

    def log_message(self, *a) -> None:  # quiet
        pass


def main() -> int:
    text = ACTION.read_text(encoding="utf-8")
    st = {s.get("id") or s["name"]: s for s in steps(text)}
    who = st["who"]

    # 1. the event / repository decision
    cases = [
        ("same-repo PR", {"EVENT": "pull_request", "HEAD_REPO": "o/demo", "BASE_REPO": "o/demo"}, "audit"),
        ("fork PR", {"EVENT": "pull_request", "HEAD_REPO": "someone/demo", "BASE_REPO": "o/demo"}, "fork"),
        ("fork deleted (head repo null)", {"EVENT": "pull_request", "HEAD_REPO": "", "BASE_REPO": "o/demo"}, "fork"),
        ("pull_request_target", {"EVENT": "pull_request_target", "HEAD_REPO": "o/demo", "BASE_REPO": "o/demo"}, "refuse-event"),
        ("push", {"EVENT": "push", "HEAD_REPO": "", "BASE_REPO": "o/demo"}, "refuse-event"),
    ]
    for name, env, want in cases:
        rc, log, out = run_step(who["run"], env)
        check(f"who: {name}", rc == 0 and out.get("mode") == want, f"mode={out.get('mode')} want={want}")

    # 2. which steps a fork PR reaches
    checkout = st["Check out the PR head"]
    sarif = st["Upload SARIF to code scanning"]
    gate = st["gate"]
    check("checkout only in audit mode", checkout.get("if") == "steps.who.outputs.mode == 'audit'", checkout.get("if", ""))
    check("SARIF upload only in audit mode", sarif.get("if", "").startswith("steps.who.outputs.mode == 'audit'"), sarif.get("if", ""))
    check("gate step runs for fork mode", "steps.who.outputs.mode == 'fork'" in gate.get("if", ""), gate.get("if", ""))
    check("no secrets referenced by the action", "secrets." not in text, "")

    # 3. the workflow
    wf = WORKFLOW.read_text(encoding="utf-8")
    on = re.search(r"^on:\n((?:[ \t].*\n|\n)*)", wf, re.M)
    on_block = on.group(1) if on else ""
    check("workflow: pull_request, not pull_request_target",
          re.search(r"^\s+pull_request:\s*$", on_block, re.M) is not None
          and "pull_request_target" not in on_block, on_block.strip().replace("\n", " "))
    uses = re.findall(r"uses: (\S+)", wf)
    check("workflow: action loaded from main of the demo repo, not the PR checkout",
          uses == ["sam029031/arbiter-gate-demo/.github/actions/arbiter-gate@main"], str(uses))
    check("workflow: no secrets", "secrets." not in wf, "")

    # 4. gate_pr.sh fork
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out"
        summ = Path(td) / "summary.md"
        p = subprocess.run(["bash", str(ARB / "scripts/gate_pr.sh"), "fork", "-", "a" * 40, "b" * 40, str(out),
                            "https://github.com/o/demo/actions/runs/1"],
                           env={"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", ""),
                                "GITHUB_STEP_SUMMARY": str(summ)},
                           capture_output=True, text=True, timeout=120)
        printed = p.stdout + p.stderr
        g = json.loads((out / "gate.json").read_text(encoding="utf-8"))
        md = (out / "comment.md").read_text(encoding="utf-8")
        sar = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
        inv = sar["runs"][0]["invocations"][0]
        check("gate_pr.sh fork: exit 2, refused fork_pr, 0 requests",
              p.returncode == 2 and g["exit_code"] == 2 and g["pr"]["refused"]["code"] == "fork_pr"
              and g["input"]["llm_requests_this_invocation"] == 0, f"rc={p.returncode}")
        check("fork comment: 無法判定, no endpoint, not a pass, not a finding",
              all(w in md for w in ("無法判定", "fork", "拿不到模型端點", "不算通過", "這不是發現漏洞")), "")
        check("fork SARIF: executionSuccessful false, no results",
              inv["executionSuccessful"] is False and not sar["runs"][0].get("results"), "")
        check("fork: step summary written", summ.exists() and "無法判定" in summ.read_text(encoding="utf-8"), "")
        check("fork: printed log has no host path",
              not re.search(r"/home/|/mnt/|/opt/", printed), printed.strip().splitlines()[-1] if printed.strip() else "")

        # 5. publishing with a read-only token
        srv = http.server.HTTPServer(("127.0.0.1", 0), Deny)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        token = "PLACEHOLDER_FORK_TOKEN"
        pp = subprocess.run([sys.executable, str(ARB / "scripts/gate_pr_publish.py"), "--out-dir", str(out),
                             "--repo", "o/demo", "--pr", "7", "--head", "b" * 40],
                            env={"PATH": os.environ["PATH"], "GITHUB_TOKEN": token,
                                 "GITHUB_API_URL": f"http://127.0.0.1:{srv.server_port}"},
                            capture_output=True, text=True, timeout=60)
        srv.shutdown()
        pout = pp.stdout + pp.stderr
        check("publish with a read-only token: reported, exit 0, token not printed",
              pp.returncode == 0 and "403" in pout and token not in pout and Deny.seen
              and all("auth=True" in s for s in Deny.seen), pout.strip())

    # 6. the job's final status
    result = st["Result"]["run"]
    for rc_in, want in (("2", 2), ("", 2), ("1", 1), ("0", 0)):
        with tempfile.TemporaryDirectory() as td:
            p = subprocess.run(["bash", "-c", result], cwd=td, env={"PATH": os.environ["PATH"], "RC": rc_in, "MODE": "fork"},
                               capture_output=True, text=True)
        check(f"result step: rc={rc_in or '(none)'} -> job exit {want}", p.returncode == want, p.stdout.strip()[:60])

    bad = [r for r in results if not r[1]]
    print(f"{len(results) - len(bad)}/{len(results)} as expected")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
