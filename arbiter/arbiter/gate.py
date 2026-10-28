"""ARBITER Gate, command-line edition: one contract (or one recorded run) in, gate.json out.

    python3 -m arbiter.gate --file Contract.sol [--repair] --out gate.json
    python3 -m arbiter.gate --from-results runs/<id>.results.jsonl \
        [--patches runs/<id>.patches.jsonl] --out gate.json

`--file` audits live: a fresh run_id and workspace per job, never filtered by triage.
A file with no imports is presented to the agent either hermetically (`--mode hermetic`,
src/Target.sol) or as a one-file repository (`--mode repo`, the same user message
`cli.py audit <file>` sends); A/B/G and patches run hermetically either way. `--from-results` replays a recorded run and sends
no LLM request at all; it is the finals demo's main path, and both write the same JSON.

Verdicts come from arbiter/verdict.py and nowhere else, as does the exit code
(worst_exit: 1 proven, 2 not executed, 0 otherwise). For each proven victim_loss finding
the stored exploit is re-run (patch.reproduce) to give A/B/G in four environments --
honest recovery, recovery under attack, attacker gain -- and a patch is shown only if
it passes the patch gate now: one read from --patches is re-verified against the
exploit (forge only, no LLM), and --repair generates one with the model. Neither given,
the finding says no patch was generated. A failed reproduction is labelled as such and
leaves the verdict untouched; the verdict is the audit's, not the replay's.

Not in this edition: repo mode, diff input, SARIF, the web page, regression downloads.
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import json
import re
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .patch import exploit_from_row, repair, reproduce, verify_fix
from .tools import STRICT_PREDICATES
from .verdict import LABELS, PROVEN, classify, worst_exit
from .workspace import VICTIM_ENVIRONMENTS, Workspace

SCHEMA = "arbiter-gate/0.1"
PATCH_VERIFIED = "修補已通過驗證（針對此攻擊）"
PATCH_NONE = "未產生修補"
PATCH_FAILED = "未能產生通過驗證的修補"
ABG_LABELS = {
    "measured": "已重現（合成層）",
    "reproduction_failed": "重現失敗",
    "not_supported": "此謂詞或模式尚不支援 A/B/G",
    "toolchain_unavailable": "無法重現（找不到 forge）",
}

# Agent stop reasons are internal vocabulary, and one of them names the opposite of what
# a person should read into an unproven result. The JSON carries a neutral code instead.
_STOP_CODES = {
    "conclude_safe": "agent_concluded_no_attack",
    "turn_budget_exhausted": "turn_budget_exhausted",
    "submit_finding": "finding_submitted",
}


def _reason_code(reason: str) -> str:
    return _STOP_CODES.get(reason, reason)


def ignore_whitespace_diff(original: str, patched: str, context: int = 3) -> str:
    """For display only: hunks where lines differ in more than whitespace.

    A model sometimes re-indents a whole function around a two-line fix; the canonical
    diff is kept verbatim for applying, and this view shows what actually changed. It is
    not meant to be applied.
    """
    a, b = original.splitlines(), patched.splitlines()
    ka = [" ".join(x.split()) for x in a]
    kb = [" ".join(x.split()) for x in b]
    out = ["--- a/src/Target.sol (whitespace ignored, display only)",
           "+++ b/src/Target.sol (whitespace ignored, display only)"]
    for group in difflib.SequenceMatcher(None, ka, kb, autojunk=False).get_grouped_opcodes(context):
        i1, i2, j1, j2 = group[0][1], group[-1][2], group[0][3], group[-1][4]
        out.append(f"@@ -{i1 + 1},{i2 - i1} +{j1 + 1},{j2 - j1} @@")
        for tag, x1, x2, y1, y2 in group:
            if tag == "equal":
                out += [" " + line for line in b[y1:y2]]
                continue
            out += ["-" + line for line in a[x1:x2]]
            out += ["+" + line for line in b[y1:y2]]
    return "\n".join(out) + "\n" if len(out) > 2 else ""


def _environments(abg: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows = []
    for i, (endow, warp, rounds) in enumerate(VICTIM_ENVIRONMENTS):
        m = next((r for r in abg or [] if r["env"] == i), {})
        rows.append({"env": i, "endow_wei": endow, "warp_s": warp, "rounds": rounds,
                     "A": m.get("A"), "B": m.get("B"), "G": m.get("G")})
    return rows


def _load_patches(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def _patch_entry(rec: dict[str, Any], exploit: dict[str, Any], diff: str, patched: str,
                 origin: str, check: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "verified", "label": PATCH_VERIFIED, "origin": origin,
        "model": rec.get("model"), "rationale": rec.get("rationale"),
        "diff": diff,
        "diff_ignore_whitespace": ignore_whitespace_diff(exploit["source"], patched),
        "changed_lines": check["changed_lines"],
        "gate_checks": {n: c["status"] for n, c in check["checks"].items()},
        "after": _environments(check["checks"]["1"].get("abg")),
    }


def _finding_evidence(row: dict[str, Any], finding: dict[str, Any], *, work: Path,
                      patches: list[dict[str, Any]], do_repair: bool,
                      gateway: Any, rounds: int, log: Any) -> dict[str, Any]:
    out = {k: finding.get(k) for k in ("title", "vulnerable_function", "severity",
                                       "vuln_class", "poc_name", "offending_expression",
                                       "attack_path")}
    poc = next((p for p in row["outcome"].get("pocs", [])
                if p.get("name") == finding.get("poc_name") and p.get("passed")
                and p.get("adjudicated")), None)
    out["predicate"] = poc.get("predicate") if poc else None
    # Decided 10/28: a proof under a loose predicate stays proven_exploitable (the
    # verdict rules are not the gate's to change) but says so in plain words.
    out["predicate_strict"] = out["predicate"] in STRICT_PREDICATES
    out["predicate_note"] = (
        "" if out["predicate_strict"] else
        f"以寬鬆謂詞 {out['predicate']} 證實；A/B/G 與修補目前只支援 victim_loss")
    abg: dict[str, Any] = {"status": "not_supported", "environments": _environments(None)}
    patch: dict[str, Any] = {"status": "not_generated", "label": PATCH_NONE}
    out["abg"], out["patch"] = abg, patch
    if out["predicate"] == "liveness_broken":
        abg["note"] = "liveness_broken 沒有取回金額；證據是可用性被破壞"
    try:
        exploit = exploit_from_row(row)
    except ValueError as exc:
        abg["note"] = abg.get("note") or str(exc)
        abg["label"] = ABG_LABELS[abg["status"]]
        return out
    if shutil.which("forge") is None:
        abg.update(status="toolchain_unavailable", label=ABG_LABELS["toolchain_unavailable"])
        return out

    sid = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{row['sample_id']}_{uuid.uuid4().hex[:6]}")
    base = reproduce(exploit["source"], exploit["solidity"], work, sid)
    if base["status"] != "pass":
        abg.update(status="reproduction_failed", label=ABG_LABELS["reproduction_failed"],
                   note=base.get("reason") or base.get("fail") or base.get("error"),
                   environments=_environments(base.get("abg")))
        return out
    abg.update(status="measured", label=ABG_LABELS["measured"],
               environments=_environments(base["abg"]))

    # A recorded patch is shown only if it still passes the gate against this exploit.
    for rec in patches:
        if (rec.get("sample_id") != row["sample_id"] or rec.get("status") != "accepted"
                or rec.get("poc_name") not in (None, exploit["poc_name"]) or not rec.get("diff")):
            continue
        check = verify_fix(exploit["source"], exploit["solidity"], diff=rec["diff"],
                           root=work, sample_id=sid + "_rec", baseline=base)
        if check["accepted"]:
            out["patch"] = _patch_entry(rec, exploit, rec["diff"], check["patched"],
                                        "patches_file", check)
            return out
        patch.update(status="rejected", label=PATCH_FAILED,
                     note=f"recorded patch no longer passes the gate (first failure: "
                          f"check {check['first_failure']})")
    if do_repair and gateway is not None:
        log(f"  repair {row['sample_id']}: up to {rounds} round(s)")
        rec = repair(gateway, {**exploit, "sample_id": sid}, root=work, rounds=rounds)
        out["repair_usage"] = {"requests": rec["requests"], "elapsed_s": rec["elapsed_s"],
                               "rounds": len(rec["rounds"])}
        if rec["status"] == "accepted":
            check = verify_fix(exploit["source"], exploit["solidity"], diff=rec["diff"],
                               root=work, sample_id=sid + "_rep", baseline=base)
            if check["accepted"]:
                out["patch"] = _patch_entry(rec, exploit, rec["diff"], check["patched"],
                                            "repair", check)
                return out
        patch.update(status="rejected", label=PATCH_FAILED,
                     note=f"{len(rec['rounds'])} round(s), refusals {rec['refusals']}")
    return out


def _file_entry(row: dict[str, Any], **kw: Any) -> dict[str, Any]:
    verdict, reason = classify(row)
    entry = {
        "id": row["sample_id"],
        "path": row.get("path") or None,
        "verdict": verdict,
        "label": LABELS[verdict],
        "reason": _reason_code(str(reason)),
        "detail": (row.get("error") or (row.get("context") or {}).get("error") or "")
        if verdict != PROVEN else "",
        "turns": sum(int(a.get("turns") or 0) for a in row.get("attempts") or []),
        "elapsed_s": row.get("elapsed_s"),
        "findings": [],
    }
    if verdict == PROVEN:
        entry["findings"] = [_finding_evidence(row, f, **kw)
                             for f in row["outcome"].get("findings", [])]
    return entry


def _models_from_ledger(results: Path) -> list[str]:
    ledger = results.with_name(results.name.replace(".results.jsonl", ".ledger.jsonl"))
    if not ledger.exists():
        return []
    seen = []
    for line in ledger.read_text(encoding="utf-8").splitlines():
        try:
            m = json.loads(line).get("model_served")
        except json.JSONDecodeError:
            continue
        if m and m not in seen:
            seen.append(m)
    return seen


def _unrun_row(item_id: str, path: str, stop: str, error: str) -> dict[str, Any]:
    return {"sample_id": item_id, "path": path, "context": {"ok": True},
            "outcome": {"stop_reason": stop, "proven": False}, "attempts": [],
            "error": error}


def _hermetic_compile_error(code: str, job: Path) -> str | None:
    """None if the contract compiles on its own, else the compiler's first error."""
    ws = Workspace(job / "ctx", "context", code)
    try:
        result = ws.context_ok()
    finally:
        ws.cleanup()
    if result.ok:
        return None
    lines = [ln.strip() for ln in result.combined.splitlines() if ln.strip()]
    # solc's own diagnostic ("Error (6933): Expected primary expression.") and where it
    # points; forge's "Error: Compiler run failed:" wrapper says nothing by itself.
    at = next((i for i, ln in enumerate(lines)
               if re.match(r"(\w*Error \(\d+\)|Error\[|\w+Error:)", ln)
               and "Compiler run failed" not in ln), None)
    if at is None:
        first = next((ln for ln in lines if "Error" in ln), lines[-1] if lines else "")
    else:
        loc = lines[at + 1] if at + 1 < len(lines) and lines[at + 1].startswith("-->") else ""
        first = f"{lines[at]} {loc}".strip()
    return f"context_unbuildable: {first[:300]}"


def run_gate(args: argparse.Namespace, log: Any = print) -> dict[str, Any]:
    t0 = time.monotonic()
    work_base = Path(args.workdir)
    rows: list[dict[str, Any]]
    gateway = None
    input_desc: dict[str, Any]

    if args.from_results:
        results = Path(args.from_results)
        rows = [json.loads(l) for l in results.read_text(encoding="utf-8").splitlines()
                if l.strip()]
        run_id = results.name.removesuffix(".results.jsonl")
        models = _models_from_ledger(results)
        input_desc = {"mode": "from_results", "results": str(results), "run_id": run_id,
                      "llm_requests_this_invocation": 0}
        job = work_base / f"replay-{run_id}-{uuid.uuid4().hex[:8]}"
    else:
        f = Path(args.file).resolve()
        code = f.read_text(encoding="utf-8", errors="ignore")
        run_id = args.run_id or f"gate-{f.stem}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        job = work_base / run_id
        models = [args.model]
        self_contained = not re.search(r"^\s*import\b", code, re.MULTILINE)
        item: dict[str, Any] = {"id": f"file::{f.stem}", "label": "unknown", "code": code}
        job.mkdir(parents=True, exist_ok=True)
        if not self_contained:
            # Imports need the repository to compile; the gate does not do repo mode yet,
            # but run_arbiter does, so the audit itself still runs where the file lives.
            item.update(path=str(f), repo_root=str(f.parent))
            workspace_mode = "in_repo"
        elif args.mode == "repo":
            # A one-file repository inside the job, named after the file's own directory,
            # so the agent gets exactly what `cli.py audit <file>` gives it (location and
            # REPO_BRIEF). In hermetic mode it consistently picked eth_profit (5/5); with
            # this user message it picked victim_loss (8/8). See CLAUDE.md section 7.
            repo = job / (f.parent.name or "contracts")
            repo.mkdir(parents=True, exist_ok=True)
            (repo / f.name).write_text(code, encoding="utf-8")
            item.update(path=str(repo / f.name), repo_root=str(repo))
            workspace_mode = "repo"
        else:
            workspace_mode = "hermetic"
        input_desc = {"mode": "file", "file": str(f), "run_id": run_id,
                      "workspace_mode": workspace_mode}
        if shutil.which("forge") is None:
            # Refuse before spending a request: without a compiler nothing can be proven,
            # and an empty result must not read as a clean one.
            rows = [_unrun_row(item["id"], item.get("path", ""), "toolchain_unavailable",
                               "toolchain_unavailable: forge not found on PATH")]
            input_desc["llm_requests_this_invocation"] = 0
        elif self_contained and (compile_err := _hermetic_compile_error(code, job)) is not None:
            # run.py only checks the build in repo mode; a hermetic contract that does
            # not compile would go straight into the agent loop and come back as "no
            # provable attack". No compilable context is no measurement (plan 7.6).
            # Checked in --mode repo too, so both modes refuse an unbuildable file the
            # same way before any request.
            rows = [_unrun_row(item["id"], "", "context_unbuildable", compile_err)]
            rows[0]["context"] = {"ok": False, "mode": "hermetic", "error": compile_err}
            input_desc["llm_requests_this_invocation"] = 0
        else:
            evalset = job / f"{run_id}.input.json"
            evalset.write_text(json.dumps({"meta": {"source": "gate", "n": 1},
                                           "items": [item]}, ensure_ascii=False),
                               encoding="utf-8")
            run_log = job / "run.log"
            try:
                with run_log.open("w", encoding="utf-8") as fh, contextlib.redirect_stdout(fh):
                    summary = run_arbiter_call(args, evalset, run_id, job)
                input_desc["llm_requests_this_invocation"] = summary["usage"].get("requests", 0)
                input_desc["usage"] = summary["usage"]
                rows = [json.loads(l) for l in
                        (job / f"{run_id}.results.jsonl").read_text(encoding="utf-8").splitlines()
                        if l.strip()]
            except Exception as exc:  # noqa: BLE001
                rows = [_unrun_row(item["id"], item.get("path", ""),
                                   f"error: {type(exc).__name__}",
                                   f"{type(exc).__name__}: {exc}"[:300])]
                input_desc["llm_requests_this_invocation"] = None
            input_desc["results"] = str(job / f"{run_id}.results.jsonl")

    if args.repair:
        from .gateway import Gateway
        try:
            gateway = Gateway(model=args.model,
                              ledger_path=job / f"{run_id}.repair.ledger.jsonl")
        except Exception as exc:  # noqa: BLE001
            log(f"  repair disabled: {type(exc).__name__}: {exc}")
    patches = _load_patches(Path(args.patches) if args.patches else None)
    work = job / "evidence"
    files = [_file_entry(r, work=work, patches=patches, do_repair=args.repair,
                         gateway=gateway, rounds=args.rounds, log=log) for r in rows]
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    # The headline count is every request this invocation sent: the audit's plus any
    # --repair proposals. It used to be the audit's alone, which understated a repair run.
    repair_reqs = sum((f.get("repair_usage") or {}).get("requests", 0)
                      for e in files for f in e["findings"])
    audit_reqs = input_desc.get("llm_requests_this_invocation")
    input_desc["llm_requests_audit"] = audit_reqs
    input_desc["llm_requests_repair"] = repair_reqs
    if audit_reqs is not None:
        input_desc["llm_requests_this_invocation"] = audit_reqs + repair_reqs
    code = worst_exit([e["verdict"] for e in files])
    return {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "input": input_desc,
        "models": models,
        "patches_file": args.patches,
        "repair": bool(args.repair),
        "exit_code": code,
        "files": files,
        "elapsed_s": round(time.monotonic() - t0, 2),
        "note": "已證實可攻擊的判定附可重跑的攻擊證據；其他判定都不代表合約沒有漏洞。",
    }


def run_arbiter_call(args: argparse.Namespace, evalset: Path, run_id: str,
                     job: Path) -> dict[str, Any]:
    from .run import run_arbiter
    return run_arbiter(evalset=evalset, model=args.model, run_id=run_id, out_dir=job,
                       attempts=args.attempts, concurrency=1, max_turns=args.max_turns,
                       rpm=args.rpm, workspace_root=job / "ws")


def _eth(v: int | None) -> str:
    return "?" if v is None else f"{v / 1e18:g}"


def print_report(report: dict[str, Any], log: Any = print) -> None:
    inp = report["input"]
    log(f"ARBITER Gate  [{inp['mode']}]  run_id={inp['run_id']}  "
        f"models={','.join(report['models']) or '?'}  "
        f"LLM requests this invocation={inp.get('llm_requests_this_invocation')} "
        f"(audit {inp.get('llm_requests_audit')}, repair {inp.get('llm_requests_repair')})"
        + (f"  workspace={inp['workspace_mode']}" if inp.get("workspace_mode") else ""))
    for e in report["files"]:
        log(f"\n  {e['label']}  [{e['verdict']}]  {e['id']}")
        if e["verdict"] != PROVEN:
            log(f"    reason: {e['reason']}")
            if e["detail"] and e["detail"] != e["reason"]:
                log(f"    detail: {e['detail'][:300]}")
        for f in e["findings"]:
            log(f"    {f['title']}")
            log(f"    function: {f['vulnerable_function']}  severity: {f['severity']}  "
                f"predicate: {f['predicate']} (strict={f['predicate_strict']})  "
                f"proof: {f['poc_name']}")
            if f["predicate_note"]:
                log(f"    {f['predicate_note']}")
            a = f["abg"]
            log(f"    A/B/G: {a.get('label')}" + (f" -- {a['note']}" if a.get("note") else ""))
            if a["status"] in ("measured", "reproduction_failed"):
                log("      env  endow     warp     rounds   A(ETH)  B(ETH)  G(ETH)")
                for r in a["environments"]:
                    log(f"      {r['env']:<4} {r['endow_wei'] / 1e18:<9g} {r['warp_s']:<8} "
                        f"{r['rounds']:<8} {_eth(r['A']):<7} {_eth(r['B']):<7} {_eth(r['G'])}")
            p = f["patch"]
            log(f"    patch: {p['label']}" + (f" ({p['origin']}, {p['changed_lines']} lines)"
                                              if p["status"] == "verified" else "")
                + (f" -- {p['note']}" if p.get("note") else ""))
            if p["status"] == "verified":
                for line in p["diff_ignore_whitespace"].splitlines()[2:]:
                    log(f"      {line}")
    log(f"\nexit code {report['exit_code']}")


def main(argv: list[str] | None = None) -> int:
    import os

    ap = argparse.ArgumentParser(prog="python3 -m arbiter.gate")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="one Solidity file, audited live")
    src.add_argument("--from-results", help="runs/<id>.results.jsonl, replayed with no LLM")
    ap.add_argument("--patches", help="runs/<id>.patches.jsonl (re-verified, no LLM)")
    ap.add_argument("--repair", action="store_true",
                    help="generate a patch with the model for proven findings (uses LLM)")
    # Default switched to repo on 10/28 by a criterion fixed before the trial (first
    # predicate victim_loss in 5/5 runs, none unexecuted): reports/mode_repo_trial_*.md.
    ap.add_argument("--mode", choices=("hermetic", "repo"), default="repo",
                    help="--file only: how a self-contained file is presented to the agent")
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--model", default=(os.environ.get("ARBITER_MODEL")
                                        or os.environ.get("AIS3_MODEL")
                                        or "ais3/nemotron-3-ultra-550b"))
    ap.add_argument("--run-id", default=None, help="default: unique per invocation")
    ap.add_argument("--attempts", type=int, default=1)
    ap.add_argument("--max-turns", type=int, default=16)
    ap.add_argument("--rpm", type=int, default=45)
    ap.add_argument("--workdir", default="runs/gate", help="per-job directories go here")
    ap.add_argument("--out", default="gate.json")
    ap.add_argument("--keep", action="store_true", help="keep evidence workspaces")
    args = ap.parse_args(argv)
    if args.file and args.run_id:
        done = Path(args.workdir) / args.run_id / f"{args.run_id}.results.jsonl"
        if done.exists():
            print(f"run-id {args.run_id!r} already has results; a gate run always audits "
                  "afresh -- pick a new --run-id or omit it", file=sys.stderr)
            return 2

    report = run_gate(args)
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n",
                              encoding="utf-8")
    print_report(report)
    print(f"gate.json: {args.out}")
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
