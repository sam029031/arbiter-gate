"""ARBITER Gate, command-line edition: one contract (or one recorded run) in, gate.json out.

    python3 -m arbiter.gate --file Contract.sol [--repair] --out gate.json
    python3 -m arbiter.gate --from-results runs/<id>.results.jsonl \
        [--patches runs/<id>.patches.jsonl] --out gate.json
    python3 -m arbiter.gate --repo DIR --base SHA --head SHA [--repair] \
        --out gate.json --sarif report.sarif --pr-comment comment.md
    ... [--sarif report.sarif] [--regression-out DIR]

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

`--sarif` writes SARIF 2.1.0 (arbiter/sarif.py) from the same report. `--regression-out`
writes one standalone Foundry project per proven victim_loss finding with A/B/G measured
(dump.write_regression: TestArbiterRegression, a plain-language README); a finding proven
under any other predicate gets none, and gate.json says why in plain words.

Slither (arbiter/static_hints.py, on unless `--slither off`) runs on every audited file.
When nothing was proven, a hint at impact >= Medium and confidence >= Medium makes the
file static_hint_unproven -- exit code 0, a hint and never evidence. Next to a proven
exploit the hints are reference only. Slither missing, failing or timing out leaves the
verdict alone and says 靜態分析未執行.

`--sandbox on` (or ARBITER_SANDBOX=1; arbiter/sandbox.py) runs every forge / anvil /
cast / Slither call of the job inside one throwaway container with no network and an
environment of PATH only; the model is still called from here. If the sandbox was asked
for and cannot be had, a live audit is "not executed" and a replay re-runs nothing --
never a silent fallback to the host.

Every path written out is relative (public_report): gate.json, the SARIF and the
regression projects leave this machine as downloads and PR artefacts.

`--repo/--base/--head` is PR mode (arbiter/prgate.py): only the .sol files in which the
diff touched a function are audited (whole, in repo mode), after triage drops interfaces,
libraries, mocks and tests; Slither hints are kept only for the touched functions; the
four unscanned_reasons of diffscan are reported as 未涵蓋, apart from every verdict. A
proven finding blocks whether or not its vulnerable function is one the PR changed
(decision D9); the finding says which. `--pr-comment` writes the PR comment (Markdown);
a TestArbiterRegression in the repository is re-run, and a failing one exits 1.

`--project DIR [--target REL]` audits one contract inside a project (a Foundry project
uploaded as a zip, for one): the project is copied into the job directory (symlinks and
build output dropped), the target is the one named or the one triage ranks first, and
the audit, A/B/G and the patch gate all run in repo mode against copies of it. PR mode
patches the same way.

A patch from --repair goes through checks 0, L, 3, 1, 2 and -- in a project -- 4 (the
project's own `forge test`, nothing that passed may fail). Then check 5 (`--reattack
on`, the default): the patched contract is audited again with the hypotheses already
used ruled out; a new proven attack rejects the patch and feeds the next round, at most
two defences. gate.json carries every round in `patch.timeline`.
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import json
import re
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .dump import regression_unavailable_reason, write_regression
from .repo import SKIP_DIRS
from .patch import MAX_DEFENSES, TARGET_PATH, exploit_from_row, repair, reproduce, verify_fix
from .tools import STRICT_PREDICATES
from . import progress, sandbox
from .progress import EV_PROXY as EV
from .static_hints import HINT_NOTE, NOT_RUN_LABEL, run_slither
from .verdict import LABELS, NOT_EXECUTED, PROVEN, STATIC_HINT, classify, with_static_hints, worst_exit
from .workspace import VICTIM_ENVIRONMENTS, Workspace

SCHEMA = "arbiter-gate/0.1"
PATCH_VERIFIED = "修補已通過驗證（針對此攻擊）"
PATCH_NONE = "未產生修補"
PATCH_FAILED = "未能產生通過驗證的修補"
PATCH_REATTACK_FAILED = "修補未通過再攻擊"
ABG_LABELS = {
    "measured": "已重現（合成層）",
    "reproduction_failed": "重現失敗",
    "not_supported": "此謂詞或模式尚不支援 A/B/G",
    "toolchain_unavailable": "無法重現（找不到 forge）",
    "sandbox_unavailable": "無法重現（沙箱無法使用，沒有在主機上改跑）",
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


RIG = Path(__file__).resolve().parent.parent          # the arbiter/ directory
_HOST_PATH_RE = re.compile(r"(?:/home|/root|/Users|/mnt|/tmp|/private|/var)/[^\s'\"`,;)\]}]*")


def _public_str(s: str) -> str:
    for base in sorted({str(RIG), str(Path.cwd())}, key=len, reverse=True):
        s = s.replace(base + "/", "")
    return _HOST_PATH_RE.sub(lambda m: Path(m.group(0)).name or "<path>", s)


def public_report(obj: Any) -> Any:
    """The same report with no host path left in it: under arbiter/ (or the working
    directory) a path becomes relative, anywhere else just its file name."""
    if isinstance(obj, dict):
        return {k: public_report(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [public_report(v) for v in obj]
    return _public_str(obj) if isinstance(obj, str) else obj


def contract_file_for(row: dict[str, Any], default: str = "Target.sol") -> str:
    """The audited contract's own file name, never its directory."""
    for cand in (((row.get("context") or {}).get("plan") or {}).get("target"), row.get("path")):
        if cand and str(cand).endswith(".sol"):
            return Path(cand).name
    return default


def _artifact(row: dict[str, Any], default_uri: str) -> dict[str, Any]:
    """Where the audited file is, relative to the root it was audited from."""
    plan = (row.get("context") or {}).get("plan") or {}
    uri = None
    if plan.get("target") and plan.get("repo_root"):
        try:
            uri = Path(plan["target"]).relative_to(plan["repo_root"]).as_posix()
        except ValueError:
            uri = None
    src = row.get("source") or ""
    return {"uri": uri or contract_file_for(row, default_uri),
            "sha256": hashlib.sha256(src.encode("utf-8")).hexdigest() if src else None}


def _function_name(raw: str | None) -> str:
    name = (raw or "").strip().split("(")[0].split(".")[-1].split("::")[-1].strip()
    return re.sub(r"^function\s+", "", name)


def locate_function(source: str, raw_name: str | None,
                    offending: str | None = None) -> dict[str, Any] | None:
    """Lines of the vulnerable function's definition (header to closing brace).

    Falls back to the offending expression, matched with whitespace collapsed the way
    workspace.contains_verbatim does, and says which basis was used.
    """
    name = _function_name(raw_name)
    lines = source.splitlines()
    if name:
        head = (r"\bconstructor\s*\(" if name == "constructor" else
                rf"\b{name}\s*\(" if name in ("receive", "fallback") else
                rf"\bfunction\s+{re.escape(name)}\s*\(")
        for m in re.finditer(head, source):
            body = source.find("{", m.end())
            semi = source.find(";", m.end())
            if body < 0 or (0 <= semi < body):
                continue  # a declaration without a body (interface, abstract)
            depth, i = 0, body
            while i < len(source):
                if source[i] == "{":
                    depth += 1
                elif source[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            return {"startLine": source.count("\n", 0, m.start()) + 1,
                    "endLine": source.count("\n", 0, i) + 1, "basis": "function_definition"}
    if offending:
        want = " ".join(offending.split())
        flat, owner = [], []
        for ln, text in enumerate(lines, 1):
            for tok in text.split():
                flat.append(tok)
                owner.append(ln)
        joined, starts, pos = "", [], 0
        for tok in flat:
            starts.append(pos)
            joined += tok + " "
            pos += len(tok) + 1
        at = joined.find(want)
        if want and at >= 0:
            first = max(i for i, st in enumerate(starts) if st <= at)
            last = max(i for i, st in enumerate(starts) if st <= at + len(want) - 1)
            return {"startLine": owner[first], "endLine": owner[last],
                    "basis": "offending_expression"}
    return None


def regression_material(row: dict[str, Any], poc_name: str | None) -> dict[str, Any]:
    """The exploit behind one finding, pointed at src/Target.sol, for write_regression."""
    o = row["outcome"]
    pocs = [p for p in o.get("pocs", []) if p.get("passed") and p.get("adjudicated")
            and (poc_name is None or p.get("name") == poc_name)]
    return exploit_from_row({**row, "outcome": {**o, "pocs": pocs[:1]}})


def build_regression(row: dict[str, Any], finding: dict[str, Any], proj: Path,
                     meta: dict[str, Any], default_file: str = "Target.sol") -> dict[str, Any]:
    """Write the regression project for one gate.json finding (no forge, no LLM)."""
    ex = regression_material(row, finding.get("poc_name"))
    return write_regression(
        proj, source=ex["source"], contract_file=contract_file_for(row, default_file),
        exploit_solidity=ex["solidity"],
        environments=(finding.get("abg") or {}).get("environments") or [],
        finding=finding, solc=(row.get("context") or {}).get("solc") or "", meta=meta)


def patch_for_download(diff: str, contract_file: str) -> str:
    """The verified diff with headers naming src/<contract file>, matching the regression
    project's layout so `patch -p1` applies it there."""
    return diff.replace(f"a/{TARGET_PATH}", f"a/src/{contract_file}").replace(
        f"b/{TARGET_PATH}", f"b/src/{contract_file}")


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
        "after": (_environments(check["checks"]["1"]["abg"])
                  if check["checks"]["1"].get("abg") else []),
    }


def _on_check(name: str, check: dict[str, Any]) -> None:
    EV.emit("check", name=name, status=check.get("status"))


def _on_propose(k: int) -> None:
    EV.stage("repair", f"AI 正在寫第 {k + 1} 輪修補，寫完後系統用修補閘門的檢查驗證")
    EV.emit("repair_round", round=k + 1, source="model")


def _on_attack(ev: dict[str, Any]) -> None:
    if ev.get("phase") == "start":
        EV.stage("repair", f"第 {ev['round']} 回合：修補通過檢查了，AI 換一種手法再攻擊修補後的合約"
                             "（不能用之前用過的攻擊假設）")
        EV.emit("reattack_start", round=ev["round"])
    else:
        EV.emit("reattack_done", round=ev["round"], status=ev.get("status"), turns=ev.get("turns"))
        EV.emit("check", name="5", status={"not_proven": "pass", "proven": "fail"}.get(
            ev.get("status"), "skipped"))


def _finding_evidence(row: dict[str, Any], finding: dict[str, Any], *, work: Path,
                      patches: list[dict[str, Any]], do_repair: bool,
                      gateway: Any, rounds: int, log: Any,
                      sandbox_unavailable: str = "", project: bool = False,
                      reattack_turns: int = 0) -> dict[str, Any]:
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
    out["region"] = locate_function(row.get("source") or "", finding.get("vulnerable_function"),
                                    finding.get("offending_expression"))
    out["regression"] = {"status": "unavailable",
                         "note": regression_unavailable_reason(out["predicate"], None)}
    if out["predicate"] == "liveness_broken":
        abg["note"] = "liveness_broken 沒有取回金額；證據是可用性被破壞"
    try:
        exploit = exploit_from_row(row, project=project)
    except ValueError as exc:
        abg["note"] = abg.get("note") or str(exc)
        abg["label"] = ABG_LABELS[abg["status"]]
        return out
    if sandbox_unavailable:
        abg.update(status="sandbox_unavailable", label=ABG_LABELS["sandbox_unavailable"],
                   note=sandbox_unavailable)
        out["regression"]["note"] = "沙箱無法使用，沒有重跑攻擊來量基準，所以這次沒有產生回歸測試。"
        return out
    if shutil.which("forge") is None:
        abg.update(status="toolchain_unavailable", label=ABG_LABELS["toolchain_unavailable"])
        out["regression"]["note"] = "找不到 forge，無法重跑攻擊來量基準，所以這次沒有產生回歸測試。"
        return out

    sid = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{row['sample_id']}_{uuid.uuid4().hex[:6]}")
    liveness = out["predicate"] == "liveness_broken"
    EV.stage("measure", "系統在原合約上重跑同一個攻擊，確認一般使用者的操作在攻擊後真的失敗"
             if liveness else "系統用同一個攻擊，在 4 種情境下各跑一次「有攻擊」和「沒攻擊」，"
                              "量受害者少拿回多少錢")
    repo = exploit.get("repo")
    base = reproduce(exploit["source"], exploit["solidity"], work, sid, repo=repo)
    EV.emit("abg", status=base["status"],
            environments=[{k: r.get(k) for k in ("env", "A", "B", "G")} for r in base.get("abg") or []])
    if base["status"] != "pass":
        abg.update(status="reproduction_failed", label=ABG_LABELS["reproduction_failed"],
                   note=base.get("reason") or base.get("fail") or base.get("error"),
                   environments=_environments(base.get("abg")))
        return out
    if liveness:
        # No amounts to show (abg stays not_supported with the note above); the exploit
        # did reproduce, which is check 0 of the patch gate below.
        abg.update(label=ABG_LABELS["not_supported"], reproduced=True)
    else:
        abg.update(status="measured", label=ABG_LABELS["measured"],
                   environments=_environments(base["abg"]))
    reason = regression_unavailable_reason(out["predicate"], None if liveness else "measured")
    if not reason and re.search(r"^\s*import\b", exploit["source"], re.MULTILINE):
        reason = "這份合約有 import；回歸測試下載目前只支援單一檔案的合約。"
    out["regression"] = ({"status": "available", "note": ""} if not reason else
                         {"status": "unavailable", "note": reason})
    if repo:
        rt = base.get("repo_tests") or {}
        out["repo_tests_before"] = {"status": rt.get("status"), "reason": rt.get("reason"),
                                    "passed": len(rt.get("passed") or []),
                                    "failed": len(rt.get("failed") or [])}

    # A recorded patch is shown only if it still passes the gate against this exploit.
    for rec in patches:
        if (rec.get("sample_id") != row["sample_id"] or rec.get("status") != "accepted"
                or rec.get("poc_name") not in (None, exploit["poc_name"]) or not rec.get("diff")):
            continue
        EV.stage("repair", "重新驗證錄製時由 AI 產生的修補（這一步不呼叫 AI）")
        EV.emit("repair_round", round=1, source="recorded")
        check = verify_fix(exploit["source"], exploit["solidity"], diff=rec["diff"],
                           root=work, sample_id=sid + "_rec", baseline=base,
                           on_check=_on_check, repo=repo,
                           extra_exploits=rec.get("extra_exploits") or None)
        EV.emit("repair_result", accepted=check["accepted"], source="recorded")
        if check["accepted"]:
            out["patch"] = _patch_entry(rec, exploit, rec["diff"], check["patched"],
                                        "patches_file", check)
            return out
        patch.update(status="rejected", label=PATCH_FAILED,
                     note=f"recorded patch no longer passes the gate (first failure: "
                          f"check {check['first_failure']})")
    if do_repair and gateway is not None:
        log(f"  repair {row['sample_id']}: up to {rounds} round(s)")
        rec = repair(gateway, {**exploit, "sample_id": sid}, root=work, rounds=rounds,
                     on_propose=_on_propose, on_check=_on_check,
                     on_round=lambda e: EV.emit("repair_round_done", round=e["round"] + 1,
                                                first_failure=e.get("first_failure")),
                     reattack_turns=reattack_turns, on_attack=_on_attack)
        out["repair_usage"] = {"requests": rec["requests"], "elapsed_s": rec["elapsed_s"],
                               "rounds": len(rec["rounds"]),
                               "reattack_requests": rec.get("reattack_requests", 0),
                               "reattack_s": rec.get("reattack_s", 0.0)}
        rounds_view = _timeline(rec, reattack_turns)
        if rec["status"] == "accepted":
            EV.emit("repair_round", round=len(rec["rounds"]), source="final_check")
            check = verify_fix(exploit["source"], exploit["solidity"], diff=rec["diff"],
                               root=work, sample_id=sid + "_rep", baseline=base,
                               on_check=_on_check, repo=repo,
                               extra_exploits=[{**x, "poc_name": x.get("poc_name")}
                                               for x in rec.get("extra_exploits") or []] or None)
            # The final re-verification resets the page's lights; check 5 ran before it.
            EV.emit("check", name="5", status=rounds_view["reattack"]["status"])
            EV.emit("repair_result", accepted=check["accepted"], source="model")
            if check["accepted"]:
                out["patch"] = _patch_entry(rec, exploit, rec["diff"], check["patched"],
                                            "repair", check)
                out["patch"].update(rounds_view)
                out["patch"]["gate_checks"]["5"] = rounds_view["reattack"]["status"]
                return out
        if rec.get("check2_note"):
            rounds_view["check2_note"] = rec["check2_note"]
        if rec["status"] == "rejected_reattack":
            patch.update(status="rejected_reattack", label=PATCH_REATTACK_FAILED,
                         note=f"攻防 {MAX_DEFENSES} 回合後，修補仍被新的攻擊打穿",
                         **rounds_view)
            return out
        patch.update(status="rejected", label=PATCH_FAILED,
                     note=f"{len(rec['rounds'])} round(s), refusals {rec['refusals']}",
                     **rounds_view)
    return out


def _timeline(rec: dict[str, Any], reattack_turns: int) -> dict[str, Any]:
    """The rounds for gate.json: every attack and defence in order, plus check 4 / 5."""
    tl = []
    for e in rec.get("timeline") or []:
        item = {k: v for k, v in e.items() if k not in ("finding",)}
        f = e.get("finding") or {}
        if f:
            item["finding"] = {k: f.get(k) for k in ("title", "vulnerable_function",
                                                     "attack_path") if f.get(k)}
        if e["side"] == "attack":
            item["label"] = _attack_label(e)
        else:
            item["label"] = ("修補通過檢查" if e["result"] == "accepted" else
                             f"修補沒有通過（{e.get('proposals')} 個提案）")
        tl.append(item)
    c5 = (rec.get("checks") or {}).get("5") or {}
    reattack = {"enabled": reattack_turns > 0, "max_turns": reattack_turns,
                "status": c5.get("status", "off" if reattack_turns <= 0 else "not_reached"),
                "requests": rec.get("reattack_requests", 0), "elapsed_s": rec.get("reattack_s", 0.0),
                "attacks": len(rec.get("reattacks") or [])}
    last = next((e for e in reversed(rec.get("timeline") or [])
                 if e["side"] == "attack" and e.get("source") == "reattack"), None)
    if c5.get("status") == "pass" and last:
        reattack["label"] = f"修補後再攻擊 1 次（{last.get('turns')} 回合）未成功"
    elif c5.get("status") == "skipped":
        reattack["label"] = "修補後再攻擊沒有完成（不算通過）"
    elif c5.get("status") == "fail":
        reattack["label"] = PATCH_REATTACK_FAILED
    out: dict[str, Any] = {"timeline": tl, "reattack": reattack}
    if rec.get("repo_tests"):
        out["repo_tests"] = rec["repo_tests"]
    return out


def _attack_label(e: dict[str, Any]) -> str:
    if e.get("source") == "audit":
        return "攻擊成功（已證實）"
    if e["result"] == "proven":
        return "換手法攻擊：成功（修補被打穿）"
    if e["result"] == "not_proven":
        return f"換手法攻擊：未成功（{e.get('turns')} 回合）"
    return "換手法攻擊：沒有完成（不算通過）"


def _static_analysis(row: dict[str, Any], verdict: str, default_uri: str, mode: str,
                     timeout: int, work: Path, sandbox_unavailable: str = "",
                     functions: set[str] | None = None) -> dict[str, Any]:
    if sandbox_unavailable:
        return {"status": "not_run", "label": NOT_RUN_LABEL,
                "reason": f"沙箱無法使用（{sandbox_unavailable}）", "hints": []}
    if mode == "off":
        return {"status": "not_run", "label": NOT_RUN_LABEL, "reason": "以 --slither off 關閉",
                "hints": []}
    if verdict == NOT_EXECUTED or not row.get("source"):
        return {"status": "not_run", "label": NOT_RUN_LABEL,
                "reason": "稽核沒有完成（合約無法編譯或工具缺少），沒有跑靜態分析", "hints": []}
    wd = work / "slither" / re.sub(r"[^A-Za-z0-9_.-]", "_", row["sample_id"])
    EV.emit("static_start", text="自動掃描工具（Slither）正在檢查程式")
    run = run_slither(row["source"], contract_file_for(row, default_uri), wd, timeout=timeout,
                      prefer_solc=(row.get("context") or {}).get("solc") or "")
    out = run.as_dict(functions)
    if functions is not None and run.status == "ran":
        out["functions_filter"] = sorted(functions)
    EV.emit("static", status=out["status"], hints=len(out["hints"]),
            checks=[h["check"] for h in out["hints"]], reason=out.get("reason"))
    return out


def _file_entry(row: dict[str, Any], default_uri: str = "Target.sol",
                slither: str = "auto", slither_timeout: int = 180,
                functions: set[str] | None = None, **kw: Any) -> dict[str, Any]:
    verdict, reason = classify(row)
    static = _static_analysis(row, verdict, default_uri, slither, slither_timeout, kw["work"],
                              kw.get("sandbox_unavailable", ""), functions)
    verdict = with_static_hints(verdict, static["hints"])
    entry = {
        "id": row["sample_id"],
        "path": row.get("path") or None,
        "artifact": _artifact(row, default_uri),
        "verdict": verdict,
        "label": LABELS[verdict],
        "reason": _reason_code(str(reason)),
        "detail": (row.get("error") or (row.get("context") or {}).get("error") or "")
        if verdict != PROVEN else "",
        "turns": sum(int(a.get("turns") or 0) for a in row.get("attempts") or []),
        "elapsed_s": row.get("elapsed_s"),
        "static_analysis": static,
        # Test material says so on its face (rows built for a display check, never audited).
        "fixture_note": row.get("fixture_note") or "",
        # Only a static_hint_unproven file carries hints as its result (SARIF warnings);
        # beside a proven exploit they stay in static_analysis as reference.
        "static_hints": static["hints"] if verdict == STATIC_HINT else [],
        "hint_note": HINT_NOTE if verdict == STATIC_HINT else "",
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


def _free_port() -> int:
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _evidence_ladder(results: Path, job: Path, out: dict[str, Any]) -> None:
    """Rungs 2 and 3 for every proven row of `results`, into out[sample_id]."""
    from .dump import dump_run
    from .prove import prove_dump
    EV.emit("ladder", rung=1, status="pass",
            text="第 1 階（合成層）：稽核時攻擊就已在 harness 裡成立")
    EV.emit("ladder_start", rung=2, text="正在把攻擊抽成獨立的 Foundry 專案重跑（第 2 階）")
    try:
        man = dump_run(results, job / "dump")
    except Exception as exc:  # noqa: BLE001
        EV.emit("ladder", rung=2, status="error", text=f"第 2 階沒有完成：{type(exc).__name__}")
        return
    names = {}
    for ex in man.get("exploits", []):
        rec = out.setdefault(ex["sample_id"], {})
        rec["rung2"] = {"status": "pass" if ex.get("reproduces") else "fail",
                        "build": ex.get("build")}
        names[Path(ex["path"]).name] = ex["sample_id"]
        EV.emit("ladder", rung=2, status=rec["rung2"]["status"], sample_id=ex["sample_id"],
                text="第 2 階（獨立專案）：" + ("在獨立專案裡也重現" if ex.get("reproduces")
                                             else "獨立專案沒有重現"))
    EV.emit("ladder_start", rung=3, text="正在本地真鏈（anvil）上用真的交易重播（第 3 階）")
    try:
        rep = prove_dump(job / "dump", port=_free_port())
    except Exception as exc:  # noqa: BLE001
        EV.emit("ladder", rung=3, status="error", text=f"第 3 階沒有完成：{type(exc).__name__}")
        return
    for f in rep.get("findings", []):
        sid = names.get(f["sample_id"])
        if sid is None:
            continue
        out.setdefault(sid, {})["rung3"] = {"live": bool(f.get("live")),
                                           "detail": f.get("live_detail") or {}}
        EV.emit("ladder", rung=3, status="pass" if f.get("live") else "fail", sample_id=sid,
                text="第 3 階（本地真鏈）：" + ("用真的交易重現了損失" if f.get("live")
                                            else "在真鏈上沒有成立（原因見結果頁）"))


def _rung3_reason(detail: dict[str, Any], finding: dict[str, Any]) -> str:
    """Why the local chain did not show harm, in plain words, from the data alone."""
    parts = []
    if not detail:
        parts.append("這個攻擊的寫法目前沒辦法自動轉成真鏈交易（三種轉譯方式都不支援），所以沒有重播。")
    elif detail.get("error"):
        parts.append(f"重播時發生錯誤：{str(detail['error'])[:160]}")
    else:
        for w in detail.get("worlds") or []:
            for st in w.get("steps") or []:
                if w.get("with_attack") and not st.get("ok") and st.get("what"):
                    parts.append(f"有攻擊的那條鏈上，「{st['what']}」這筆交易失敗（revert）。")
                    break
        rc, ra = detail.get("recovered_clean"), detail.get("recovered_attacked")
        if rc is not None and ra is not None:
            parts.append(f"受害者沒有攻擊時領回 {rc / 1e18:g} ETH、有攻擊時領回 {ra / 1e18:g} ETH，"
                         f"攻擊者獲利 {(detail.get('attacker_gain') or 0) / 1e18:g} ETH。")
    envs = (finding.get("abg") or {}).get("environments") or []
    harmed = [e for e in envs if e.get("A") is not None and e.get("B") is not None and e["B"] < e["A"]]
    if harmed and all(e.get("rounds", 1) > 1 for e in harmed):
        parts.append(f"合成層只有在攻擊重複 {harmed[0]['rounds']} 輪的環境才造成損失；"
                     "本地真鏈重播目前只跑一輪攻擊。")
    return "".join(parts)


def _ladder_entry(rec: dict[str, Any] | None, finding: dict[str, Any]) -> dict[str, Any]:
    if rec is None:
        return {"reached": 1, "rung2": {"status": "not_run"}, "rung3": {"status": "not_run"}}
    r2 = rec.get("rung2") or {"status": "not_run"}
    r3raw = rec.get("rung3")
    if r3raw is None:
        r3 = {"status": "not_run"}
    else:
        d = r3raw["detail"]
        worlds = [{"with_attack": w.get("with_attack"), "recovered": w.get("recovered"),
                   "attacker_gain": w.get("attacker_gain"), "target_drained": w.get("target_drained"),
                   "steps": [{k: (str(st.get(k))[:140] if k == "note" else st.get(k))
                              for k in ("what", "actor", "tx", "gas_used", "ok", "note")}
                             for st in w.get("steps") or []]}
                  for w in d.get("worlds") or []]
        r3 = {"status": "pass" if r3raw["live"] else "fail",
              "summary": {k: d.get(k) for k in ("recovered_clean", "recovered_attacked",
                                                "attacker_gain", "shortfall", "proven")},
              "worlds": worlds,
              "reason": "" if r3raw["live"] else _rung3_reason(d, finding)}
    reached = 3 if r3.get("status") == "pass" else 2 if r2.get("status") == "pass" else 1
    return {"reached": reached, "rung2": r2, "rung3": r3}


def _job_for(args: argparse.Namespace) -> tuple[str, Path]:
    """The run id and job directory, decided once (the sandbox mounts exactly this)."""
    work_base = Path(args.workdir).resolve()
    if getattr(args, "repo", None):
        run_id = args.run_id or f"gate-pr-{(args.head or 'head')[:12]}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        return run_id, work_base / run_id
    if getattr(args, "project", None):
        stem = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(args.target or args.project).stem)[:40]
        run_id = args.run_id or f"gate-proj-{stem}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
        return run_id, work_base / run_id
    if args.from_results:
        run_id = Path(args.from_results).name.removesuffix(".results.jsonl")
        return run_id, work_base / f"replay-{run_id}-{uuid.uuid4().hex[:8]}"
    stem = Path(args.file).stem
    run_id = args.run_id or f"gate-{stem}-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    return run_id, work_base / run_id


def run_gate(args: argparse.Namespace, log: Any = print) -> dict[str, Any]:
    """The gate, inside a per-job sandbox when one is asked for (--sandbox / ARBITER_SANDBOX)."""
    choice = getattr(args, "sandbox", None)
    use = (choice == "on") if choice in ("on", "off") else sandbox.enabled(default=False)
    args._run_id, args._job = _job_for(args)
    if not use:
        report = _run_gate(args, log)
        report["input"]["sandbox"] = {"status": "off"}
        return report
    ok, why = sandbox.available()
    if not ok:
        log(f"  sandbox unavailable: {why}")
        report = _run_gate(args, log, sandbox_unavailable=why)
        report["input"]["sandbox"] = {"status": "unavailable", "reason": why,
                                      "note": sandbox.UNAVAILABLE_NOTE}
        return report
    # An attack-defence cycle (check 5: up to three audits and two repairs) outlives the
    # default container lifetime; the limit is raised for it, never the work cut short.
    long_job = args.repair and getattr(args, "reattack", "on") == "on"
    box = sandbox.JobSandbox(args._job, args._run_id,
                             job_max_s=max(sandbox.JOB_MAX_S, 3600) if long_job else sandbox.JOB_MAX_S)
    try:
        env = box.__enter__()
    except RuntimeError as exc:
        why = str(exc)
        report = _run_gate(args, log, sandbox_unavailable=why)
        report["input"]["sandbox"] = {"status": "unavailable", "reason": why,
                                      "note": sandbox.UNAVAILABLE_NOTE}
        return report
    # The container sees only the job directory, and remappings are absolute paths, so the
    # vendored libraries a repo-mode build imports are copied in (repo.localize_dep_cache).
    deps: dict[str, Any] = {"ok": False, "reason": "not needed (recorded results)"}
    if not args.from_results:
        from .repo import localize_dep_cache
        deps = localize_dep_cache(args._job / "soldeps")
        if deps.get("ok"):
            env = {**env, "ARBITER_DEP_CACHE": str(args._job / "soldeps")}
    try:
        with sandbox.applied_env(env):
            report = _run_gate(args, log)
    finally:
        box.__exit__(None, None, None)
    report["input"]["sandbox"] = {"status": "on", "image": sandbox.IMAGE,
                                  "container_start_s": box.started_s,
                                  "memory_peak_bytes": box.memory_peak,
                                  "network": "none", "env": "PATH only",
                                  "dep_cache": {k: v for k, v in deps.items() if k != "packages"}}
    if not args.keep:
        shutil.rmtree(args._job / "soldeps", ignore_errors=True)
    return report


def _run_gate(args: argparse.Namespace, log: Any = print,
              sandbox_unavailable: str = "") -> dict[str, Any]:
    t0 = time.monotonic()
    work_base = Path(args.workdir)
    pr: dict[str, Any] | None = None
    rows: list[dict[str, Any]]
    gateway = None
    default_uri = "Target.sol"
    input_desc: dict[str, Any]

    if args.from_results:
        results = Path(args.from_results)
        rows = [json.loads(l) for l in results.read_text(encoding="utf-8").splitlines()
                if l.strip()]
        run_id = results.name.removesuffix(".results.jsonl")
        models = _models_from_ledger(results)
        input_desc = {"mode": "from_results", "results": str(results), "run_id": run_id,
                      "llm_requests_this_invocation": 0}
        job = args._job
    elif getattr(args, "repo", None):
        run_id, job = args._run_id, args._job
        models = [args.model]
        rows, input_desc, pr = _pr_rows(args, run_id, job, sandbox_unavailable)
    elif getattr(args, "project", None):
        run_id, job = args._run_id, args._job
        models = [args.model]
        rows, input_desc, default_uri = _project_rows(args, run_id, job, sandbox_unavailable)
    else:
        f = Path(args.file).resolve()
        code = f.read_text(encoding="utf-8", errors="ignore")
        default_uri = f.name
        run_id, job = args._run_id, args._job
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
        if sandbox_unavailable:
            # Asked to isolate the job and could not: nothing runs, not even unisolated.
            rows = [_unrun_row(item["id"], item.get("path", ""), "error: sandbox_unavailable",
                               f"sandbox_unavailable: {sandbox_unavailable}")]
            input_desc["llm_requests_this_invocation"] = 0
        elif shutil.which("forge") is None:
            # Refuse before spending a request: without a compiler nothing can be proven,
            # and an empty result must not read as a clean one.
            rows = [_unrun_row(item["id"], item.get("path", ""), "toolchain_unavailable",
                               "toolchain_unavailable: forge not found on PATH")]
            input_desc["llm_requests_this_invocation"] = 0
        elif self_contained and (EV.stage("compile", "正在檢查合約能不能編譯（這一步還沒用到 AI）")
                                 or (compile_err := _hermetic_compile_error(code, job)) is not None):
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
            extra: dict[str, Any] = {}
            if getattr(args, "slither_proposals", False):
                extra = _slither_proposals(code, f.name, item["id"], job, args.slither_timeout)
                input_desc["slither_proposals"] = extra.pop("_desc")
            EV.emit("compile_ok", text="合約可以編譯")
            EV.stage("ai", "AI 開始讀合約，想可能的攻擊方式",
                     attempts=args.attempts, max_turns=args.max_turns)
            hooks = progress.AuditHooks()
            extra.update(on_turn=hooks.on_turn, on_request=hooks.on_request,
                         on_row=hooks.on_row)
            try:
                with run_log.open("w", encoding="utf-8") as fh, contextlib.redirect_stdout(fh):
                    summary = run_arbiter_call(args, evalset, run_id, job, **extra)
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

    if args.repair and not sandbox_unavailable and not getattr(args, "llm_blocked", None):
        from .gateway import Gateway
        try:
            gateway = Gateway(model=args.model,
                              ledger_path=job / f"{run_id}.repair.ledger.jsonl")
        except Exception as exc:  # noqa: BLE001
            log(f"  repair disabled: {type(exc).__name__}: {exc}")
    patches = _load_patches(Path(args.patches) if args.patches else None)
    work = job / "evidence"
    # Evidence ladder rungs 2 and 3 (dump, then a local chain) run beside A/B/G and the
    # patch, as the finals timing needs (plan 12.4); joined before the report is built.
    ladder: dict[str, Any] = {}
    results_file = Path(input_desc["results"]) if input_desc.get("results") else None
    ladder_thread = None
    if (getattr(args, "evidence_ladder", "auto") != "off" and not sandbox_unavailable
            and results_file and results_file.exists()
            and any((r.get("outcome") or {}).get("proven") for r in rows)):
        import threading
        ladder_thread = threading.Thread(target=_evidence_ladder,
                                         args=(results_file, job, ladder), daemon=True)
        ladder_thread.start()
    files = [_file_entry(r, default_uri=default_uri, slither=args.slither,
                         slither_timeout=args.slither_timeout, work=work, patches=patches,
                         sandbox_unavailable=sandbox_unavailable,
                         do_repair=args.repair, gateway=gateway, rounds=args.rounds, log=log,
                         functions=_pr_functions(pr, r) if pr else None,
                         project=bool(pr is not None or getattr(args, "project", None)),
                         reattack_turns=(args.max_turns if getattr(args, "reattack", "on") == "on"
                                         else 0))
             for r in rows]
    if ladder_thread is not None:
        EV.emit("ladder_wait", text="等待證據等級（獨立專案、本地真鏈）的結果")
        ladder_thread.join(timeout=600)
    for e in files:
        for fd in e["findings"]:
            fd["evidence"] = _ladder_entry(ladder.get(e["id"]), fd)
    if not args.keep:
        shutil.rmtree(work, ignore_errors=True)
    reg_out = getattr(args, "regression_out", None)
    if reg_out:
        meta = {"models": models, "run_id": run_id,
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
        for e, r in zip(files, rows):
            for j, fd in enumerate(e["findings"]):
                if (fd.get("regression") or {}).get("status") != "available":
                    continue
                name = re.sub(r"[^A-Za-z0-9_.-]", "_", f"{e['id']}__{fd.get('poc_name') or j}")
                info = build_regression(r, fd, Path(reg_out) / name, meta, default_uri)
                fd["regression"]["project"] = info["project"]
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
    extra_out: dict[str, Any] = {}
    if pr is not None:
        code = _pr_finish(pr, files, rows, code, job, sandbox_unavailable)
        extra_out = {"pr": {k: v for k, v in pr.items() if not k.startswith("_")},
                     "unscanned_reasons": pr["unscanned"]}
        if not args.keep:
            shutil.rmtree(pr["_copy"], ignore_errors=True)
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
        **extra_out,
    }


def _pr_rows(args: argparse.Namespace, run_id: str, job: Path,
             sandbox_unavailable: str) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    """PR mode: scope the diff (prgate.prepare), then audit the kept files in one run."""
    from .prgate import PRInputError, prepare
    job.mkdir(parents=True, exist_ok=True)
    input_desc: dict[str, Any] = {"mode": "pr", "run_id": run_id, "workspace_mode": "repo",
                                  "llm_requests_this_invocation": 0}
    EV.stage("compile", "正在比對這個 PR 改到哪些函式（這一步還沒用到 AI）")
    try:
        pr = prepare(Path(args.repo), args.base, args.head, job)
    except PRInputError as exc:
        pr = {"base": args.base, "head": args.head, "granularity": "none", "touched": {},
              "audited": [], "skipped": [], "unscanned": [], "input_error": str(exc),
              "_copy": job / "repo"}
        rows = [_unrun_row("pr::input", "", "error: pr_input", f"pr_input: {exc}")]
        return rows, input_desc, pr
    copy = pr["_copy"]
    items = [{"id": f"pr::{rel}", "label": "unknown",
              "code": (copy / rel).read_text(encoding="utf-8", errors="ignore"),
              "path": str(copy / rel), "repo_root": str(copy)} for rel in pr["audited"]]
    if not items:
        return [], input_desc, pr
    blocked = getattr(args, "llm_blocked", None)
    if blocked:
        # The model server may not be used now (runner-host policy, e.g. a pre-registered
        # evaluation is running): scope, uncovered and the regression re-run still count,
        # the files that need the model are not executed -- never silently passed.
        rows = [_unrun_row(it["id"], it["path"], "error: llm_blocked",
                           f"llm_blocked: {blocked}") for it in items]
        input_desc["llm_blocked"] = blocked
        return rows, input_desc, pr
    if sandbox_unavailable:
        rows = [_unrun_row(it["id"], it["path"], "error: sandbox_unavailable",
                           f"sandbox_unavailable: {sandbox_unavailable}") for it in items]
        return rows, input_desc, pr
    if shutil.which("forge") is None:
        rows = [_unrun_row(it["id"], it["path"], "toolchain_unavailable",
                           "toolchain_unavailable: forge not found on PATH") for it in items]
        return rows, input_desc, pr
    evalset = job / f"{run_id}.input.json"
    evalset.write_text(json.dumps({"meta": {"source": "gate-pr", "n": len(items)},
                                   "items": items}, ensure_ascii=False), encoding="utf-8")
    EV.stage("ai", "AI 開始讀這個 PR 改到的合約，想可能的攻擊方式",
             attempts=args.attempts, max_turns=args.max_turns, files=len(items))
    hooks = progress.AuditHooks()
    try:
        with (job / "run.log").open("w", encoding="utf-8") as fh, contextlib.redirect_stdout(fh):
            summary = run_arbiter_call(args, evalset, run_id, job, on_turn=hooks.on_turn,
                                       on_request=hooks.on_request, on_row=hooks.on_row)
        input_desc["llm_requests_this_invocation"] = summary["usage"].get("requests", 0)
        input_desc["usage"] = summary["usage"]
        rows = [json.loads(l) for l in
                (job / f"{run_id}.results.jsonl").read_text(encoding="utf-8").splitlines()
                if l.strip()]
    except Exception as exc:  # noqa: BLE001
        rows = [_unrun_row(it["id"], it["path"], f"error: {type(exc).__name__}",
                           f"{type(exc).__name__}: {exc}"[:300]) for it in items]
        input_desc["llm_requests_this_invocation"] = None
    input_desc["results"] = str(job / f"{run_id}.results.jsonl")
    return rows, input_desc, pr


def _pr_rel(pr: dict[str, Any], row: dict[str, Any]) -> str:
    sid = str(row.get("sample_id") or "")
    return sid[4:] if sid.startswith("pr::") else sid


def _pr_functions(pr: dict[str, Any], row: dict[str, Any]) -> set[str] | None:
    """Slither's filter for one file: its touched functions (None at file granularity)."""
    if pr.get("granularity") != "function":
        return None
    return set(pr["touched"].get(_pr_rel(pr, row)) or [])


def _pr_finish(pr: dict[str, Any], files: list[dict[str, Any]], rows: list[dict[str, Any]],
               code: int, job: Path, sandbox_unavailable: str) -> int:
    """Paths relative to the repository, D9's in-PR flag, suggestions, the regression
    re-run. Returns the exit code (a failing regression test blocks: 1)."""
    from .patch import apply_diff
    from .prgate import regression_rerun, suggestions
    copy = pr["_copy"]
    for e, r in zip(files, rows):
        rel = _pr_rel(pr, r)
        e["artifact"]["uri"] = rel if rel != "input" else "PR"
        touched = set(pr["touched"].get(rel) or [])
        for fd in e["findings"]:
            name = _function_name(fd.get("vulnerable_function"))
            fd["in_changed_function"] = (name in touched) if pr.get("granularity") == "function" else None
            p = fd.get("patch") or {}
            if p.get("status") == "verified" and (copy / rel).is_file():
                head_text = (copy / rel).read_text(encoding="utf-8", errors="ignore")
                patched, err = apply_diff(head_text, p["diff"])
                p["suggestions"] = suggestions(head_text, patched, rel) if patched else []
                p["patch_for_repo"] = (patch_for_download(p["diff"], Path(rel).name)
                                       .replace(f"a/src/{Path(rel).name}", f"a/{rel}")
                                       .replace(f"b/src/{Path(rel).name}", f"b/{rel}"))
                if err:
                    p["suggestions_note"] = f"修補對不到 head 的檔案：{err[:160]}"
    if sandbox_unavailable or not copy.exists():
        pr["regression_rerun"] = {"status": "not_run" if copy.exists() else "absent",
                                  "reason": "沙箱無法使用" if sandbox_unavailable else ""}
    else:
        EV.stage("measure", "重跑 repo 裡的 ARBITER 回歸測試（之前證實過的攻擊）")
        pr["regression_rerun"] = regression_rerun(copy, job / "regression-out")
    if pr["regression_rerun"].get("status") == "failed":
        code = 1
    return code


def _slither_proposals(code: str, filename: str, item_id: str, job: Path,
                       timeout: int) -> dict[str, Any]:
    """--slither-proposals: Slither's checks as the agent's hypothesis queue (OFF by
    default; the pre-registered A/B that would decide it has not run)."""
    from .proposals import slither_jobs, slither_proposal_block, slither_rarity
    run = run_slither(code, filename, job / "slither-proposals", timeout=timeout)
    if run.status != "ran":
        return {"_desc": {"status": "not_run", "reason": run.reason}}
    corpus = RIG / "runs" / "slither.json"
    rare = slither_rarity(corpus) if corpus.exists() else {}
    jobs = job / "slither.jobs.jsonl"
    jobs.write_text("".join(json.dumps(r) + "\n" for r in slither_jobs(item_id, run.findings,
                                                                     sorted(rare))),
                    encoding="utf-8")
    return {"proposals_path": jobs,
            "proposal_renderer": lambda hits, _rare: slither_proposal_block(hits, rare),
            "_desc": {"status": "ran", "jobs": jobs.name,
                      "checks": sorted({f["check"] for f in run.findings})}}


def pick_target(project: Path) -> tuple[str | None, list[dict[str, Any]]]:
    """(the contract triage ranks first, every candidate) for a project with no --target.

    Candidates are the .sol files outside lib/, node_modules and the build output that
    triage keeps (a deployable contract with a state-changing external entry point, not
    a test, mock or script); ranked by entry points, then size."""
    from .triage import triage_all
    paths = [p for p in project.rglob("*.sol")
             if not set(p.relative_to(project).parts[:-1]) & ({"lib"} | SKIP_DIRS)
             and not p.is_symlink()]
    keep, drop = triage_all(sorted(paths))
    cands = [{"rel": t.path.relative_to(project).as_posix(), "contracts": list(t.contracts),
              "entry_points": len(t.state_changing), "size": t.path.stat().st_size} for t in keep]
    cands.sort(key=lambda c: (-c["entry_points"], -c["size"], c["rel"]))
    skipped = [{"rel": t.path.relative_to(project).as_posix(), "reason": t.reason} for t in drop]
    return (cands[0]["rel"] if cands else None), cands + [{"skipped": True, **x} for x in skipped]


def _project_rows(args: argparse.Namespace, run_id: str, job: Path,
                  sandbox_unavailable: str) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """--project: copy the project into the job, pick the target, audit it in repo mode."""
    from .patch import copy_project
    src = Path(args.project).resolve()
    job.mkdir(parents=True, exist_ok=True)
    rel = args.target
    cands: list[dict[str, Any]] = []
    if not rel:
        rel, cands = pick_target(src)
    desc: dict[str, Any] = {"mode": "project", "run_id": run_id, "workspace_mode": "repo",
                            "target": rel, "target_chosen_by": "user" if args.target else "triage",
                            "candidates": [c["rel"] for c in cands if not c.get("skipped")][:20]}
    item_id = f"project::{rel or 'none'}"
    if not rel or not (src / rel).is_file():
        desc["llm_requests_this_invocation"] = 0
        why = ("專案裡找不到可以稽核的合約（只有介面、函式庫、測試或 mock）" if not rel
               else f"專案裡沒有 {rel}")
        return [_unrun_row(item_id, rel or "", "context_unbuildable", why)], desc, rel or "Target.sol"
    copy = copy_project(src, job / "project", rel, (src / rel).read_text(encoding="utf-8", errors="ignore"))
    item = {"id": item_id, "label": "unknown", "code": (copy / rel).read_text(encoding="utf-8"),
            "path": str(copy / rel), "repo_root": str(copy)}
    if sandbox_unavailable:
        desc["llm_requests_this_invocation"] = 0
        return [_unrun_row(item_id, item["path"], "error: sandbox_unavailable",
                           f"sandbox_unavailable: {sandbox_unavailable}")], desc, rel
    if shutil.which("forge") is None:
        desc["llm_requests_this_invocation"] = 0
        return [_unrun_row(item_id, item["path"], "toolchain_unavailable",
                           "toolchain_unavailable: forge not found on PATH")], desc, rel
    evalset = job / f"{run_id}.input.json"
    evalset.write_text(json.dumps({"meta": {"source": "gate", "n": 1}, "items": [item]},
                                  ensure_ascii=False), encoding="utf-8")
    EV.stage("ai", "AI 開始讀合約，想可能的攻擊方式", attempts=args.attempts, max_turns=args.max_turns)
    hooks = progress.AuditHooks()
    try:
        with (job / "run.log").open("w", encoding="utf-8") as fh, contextlib.redirect_stdout(fh):
            summary = run_arbiter_call(args, evalset, run_id, job, on_turn=hooks.on_turn,
                                       on_request=hooks.on_request, on_row=hooks.on_row)
        desc["llm_requests_this_invocation"] = summary["usage"].get("requests", 0)
        desc["usage"] = summary["usage"]
        rows = [json.loads(l) for l in (job / f"{run_id}.results.jsonl").read_text(
            encoding="utf-8").splitlines() if l.strip()]
    except Exception as exc:  # noqa: BLE001
        rows = [_unrun_row(item_id, item["path"], f"error: {type(exc).__name__}",
                           f"{type(exc).__name__}: {exc}"[:300])]
        desc["llm_requests_this_invocation"] = None
    desc["results"] = str(job / f"{run_id}.results.jsonl")
    return rows, desc, rel


def run_arbiter_call(args: argparse.Namespace, evalset: Path, run_id: str,
                     job: Path, **extra: Any) -> dict[str, Any]:
    from .run import run_arbiter
    return run_arbiter(evalset=evalset, model=args.model, run_id=run_id, out_dir=job,
                       attempts=args.attempts, concurrency=1, max_turns=args.max_turns,
                       rpm=args.rpm, workspace_root=job / "ws", **extra)


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
        sa = e.get("static_analysis") or {}
        if sa.get("status") == "ran":
            tag = "hints" if e["verdict"] == STATIC_HINT else "reference only"
            log(f"    static analysis ({sa.get('tool')}, solc {sa.get('solc')}): "
                f"{len(sa['hints'])} at {sa.get('threshold')} of {sa.get('findings_total')} "
                f"findings [{tag}]")
            for h in sa["hints"]:
                log(f"      - {h['check']} ({h['impact']}/{h['confidence']}) "
                    f"line {h.get('line')}: {h.get('message', '')[:110]}")
            if e.get("hint_note"):
                log(f"    {e['hint_note']}")
        elif sa:
            log(f"    {sa.get('label')}: {sa.get('reason')}")
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
            for e in p.get("timeline") or []:
                extra = (f" ({e.get('turns')} turns, {e.get('elapsed_s')} s)"
                         if e.get("source") == "reattack" else
                         f" ({e.get('proposals')} proposal(s))" if e["side"] == "defend" else "")
                log(f"      round {e['round']} {e['side']:<6} {e.get('label', e['result'])}{extra}")
            rt = p.get("repo_tests") or {}
            if rt.get("status"):
                log(f"      check 4 (project tests): {rt['status']}"
                    + (f", {rt.get('before_passed')} passed before, {rt.get('after_passed')} after"
                       if rt.get("before_passed") is not None else
                       f" -- {rt.get('reason')}" if rt.get("reason") else ""))
            if (p.get("reattack") or {}).get("label"):
                log(f"      {p['reattack']['label']}")
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
    src.add_argument("--repo", help="PR mode: a git checkout at --head (needs --base, --head)")
    src.add_argument("--project", help="a project directory (e.g. an unzipped Foundry "
                                       "project): audit one contract in it, in repo mode")
    ap.add_argument("--target", help="--project: the contract to audit, relative to the "
                                     "project (default: the one triage ranks first)")
    ap.add_argument("--reattack", choices=("on", "off"), default="on",
                    help="check 5: audit an accepted patch again with the used hypotheses "
                         "ruled out (uses LLM; at most two defences)")
    ap.add_argument("--base", help="PR mode: the base commit (the PR's target)")
    ap.add_argument("--head", help="PR mode: the head commit (must be checked out)")
    ap.add_argument("--pr-comment", help="PR mode: write the PR comment (Markdown) here")
    ap.add_argument("--run-url", default="", help="PR mode: link to the CI run, for the comment")
    ap.add_argument("--llm-blocked", help="PR mode: send no model request; files that need "
                                          "an audit are not executed, with this reason")
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
    ap.add_argument("--events", help="append progress events (JSON lines) here")
    ap.add_argument("--evidence-ladder", choices=("auto", "off"), default="auto",
                    help="rungs 2-3 (dump + local chain) for proven findings, in parallel")
    ap.add_argument("--sarif", help="also write SARIF 2.1.0 here")
    ap.add_argument("--slither", choices=("auto", "off"), default="auto",
                    help="static hints (second level); auto skips quietly if not installed")
    ap.add_argument("--slither-timeout", type=int, default=180)
    ap.add_argument("--sandbox", choices=("on", "off"), default=None,
                    help="run forge/anvil/cast/Slither in a per-job container; default: "
                         "ARBITER_SANDBOX, else off")
    ap.add_argument("--slither-proposals", action="store_true",
                    help="--file only: feed Slither's checks to the agent as hypotheses. "
                         "OFF by default: the A/B that would justify it has not run")
    ap.add_argument("--regression-out", help="write Foundry regression projects here")
    args = ap.parse_args(argv)
    if args.repo and not (args.base and args.head):
        ap.error("--repo needs --base and --head")
    if args.file and args.run_id:
        done = Path(args.workdir) / args.run_id / f"{args.run_id}.results.jsonl"
        if done.exists():
            print(f"run-id {args.run_id!r} already has results; a gate run always audits "
                  "afresh -- pick a new --run-id or omit it", file=sys.stderr)
            return 2

    if args.events:
        progress.use(progress.Events(Path(args.events)))
    report = public_report(run_gate(args))
    EV.stage("done", "完成", verdicts=[e["verdict"] for e in report["files"]],
             exit_code=report["exit_code"])
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n",
                              encoding="utf-8")
    print_report(report)
    print(f"gate.json: {args.out}")
    if args.sarif:
        from .sarif import to_sarif
        Path(args.sarif).write_text(json.dumps(to_sarif(report), ensure_ascii=False, indent=1)
                                    + "\n", encoding="utf-8")
        print(f"SARIF: {args.sarif}")
    if args.pr_comment:
        from .prgate import comment_markdown
        Path(args.pr_comment).write_text(comment_markdown(report, run_url=args.run_url),
                                         encoding="utf-8")
        print(f"PR comment: {args.pr_comment}")
    if args.regression_out:
        made = [fd["regression"]["project"] for e in report["files"] for fd in e["findings"]
                if fd.get("regression", {}).get("project")]
        print(f"regression tests: {len(made)} project(s) in {args.regression_out}"
              + "".join(f"\n  {m}" for m in made))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
