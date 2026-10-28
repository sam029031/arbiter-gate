"""The patch gate: a fix is accepted on forge's evidence, never on the model's word.

A proven victim_loss finding carries the exploit the harness assembled (`pocs[].solidity`,
victim fragments, four environments and the predicate already inside). A proposed patch
is judged by re-running THAT file -- never re-composing it, because `draw_identity()`
redraws addresses on every composition and `deconflict()` renames against the original
contract -- against the patched source. Checks run in this order and the first failure
stops the gate (unless `run_all`, which the self-test uses to exercise every check):

    0  reproduce   the stored exploit still passes on the original; the report contract
                   measures A/B/G there (honest recovery, attacked recovery, attacker gain)
    L  lint        diff applies, <= 12 changed lines, no identity checks, hard-coded
                   addresses, selfdestruct, assembly or unconditional revert in added lines
    3  ABI         every function / constructor keeps name, params, returns, mutability;
                   only errors and events may be added
    1  exploit     the same file compiles against the patch and the predicate fails in all
                   four environments (a compile failure is NOT a fix)
    2  honest      with no attack, the victim recovers at least what it did before, minus
                   a tolerance, in every environment

Check 1 alone accepts an always-revert "fix": its failure message is word for word the
real fix's. Check 2 is what refuses it. An identity filter (`code.length == 0`) passes
1, 2 and 3; only L refuses it. Passing the gate means this one attack fails in four
environments, the honest path still works and the interface did not change -- not that
the contract is safe. Wording for a pass: 修補已通過驗證（針對此攻擊）.

Hermetic mode and victim_loss only. Repo-mode copies, check 4 (repo tests) and check 5
(re-audit) are later work.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .benchmark import diff_line_count
from .tools import _test_passed, parse_arguments
from .workspace import VICTIM_ENVIRONMENTS, Workspace

TARGET_PATH = "src/Target.sol"
MAX_DIFF_LINES = 12
TOLERANCE_WEI = 10
GATE_ORDER = ("0", "L", "3", "1", "2")

# forge matches --match-test against the signature, parentheses included, so an anchor
# written as `name$` matches nothing (forge 1.8.6; the 9/28 prototype ran 1.5.1).
_VICTIM_CONTRACT = "^TestArbiterVictim$"
_VICTIM_TEST = r"^testArbiterVictimLoss\(\)$"
_REPORT_CONTRACT = "^TestArbiterReport$"
_REPORT_TEST = r"^testArb(Honest|Attacked)[0-9]+\(\)$"
_POC_NAME = "ArbiterFix"
_HERMETIC_IMPORT = "../src/Target.sol"


# -- the report contract ---------------------------------------------------------------
#
# victim_loss returns only a completion marker when the attack succeeds and forge prints
# no trace for a passing test, so the numbers have to be carried out by a revert. One
# test per (environment, with/without attack): forge starts every test from clean state,
# whereas arbiterRun() runs trials back to back and a prank left open by a reverting
# arbExit() leaks into the next trial's setup (measured on the prototype: the victim
# came back with 7 ETH instead of 2).

def report_contract(custom_errors: bool = True) -> str:
    tests = []
    for i, (endow, warp, rounds) in enumerate(VICTIM_ENVIRONMENTS):
        for tag, flag in (("Honest", "false"), ("Attacked", "true")):
            tests.append(
                f"    function testArb{tag}{i}() public {{ "
                f"_arbReport({i}, {flag}, {endow}, {warp}, {rounds}); }}"
            )
    if custom_errors:
        decl = ("error ArbiterTrial(uint256 env, bool withAttack, bool ran, "
                "uint256 recovered, uint256 gain);\n")
        raise_ = "revert ArbiterTrial(env, withAttack, ran, rec, g);"
    else:
        # Below 0.8.4 there are no custom errors; same text, built by hand.
        decl = ""
        raise_ = ('revert(string(abi.encodePacked("ArbiterTrial(", _u(env), ", ", '
                  'withAttack ? "true" : "false", ", ", ran ? "true" : "false", ", ", '
                  '_u(rec), ", ", _u(g), ")")));')
    return f"""
{decl}contract TestArbiterReport is TestArbiterVictim {{
    function _arbReport(uint256 env, bool withAttack, uint256 endow, uint256 warpBy,
                        uint256 rounds) internal {{
        (bool ok, bytes memory rb) = address(this).call(abi.encodeWithSignature(
            "arbTrial(bool,uint256,uint256,uint256)", withAttack, endow, warpBy, rounds));
        uint256 rec;
        uint256 g;
        bool attackRan;
        if (ok) {{ (rec, g, attackRan) = abi.decode(rb, (uint256, uint256, bool)); }}
        bool ran = ok && attackRan;
        {raise_}
    }}
{chr(10).join(tests)}
}}
"""


_TRIAL_RE = re.compile(r"ArbiterTrial\(([^()]*)\)")


def parse_trials(output: str) -> list[dict[str, Any]]:
    """A/B/G per environment from a report run: [{env, A, B, G, honest_ran, attack_ran}]."""
    seen: dict[tuple[int, bool], tuple[bool, int, int]] = {}
    for m in _TRIAL_RE.finditer(output):
        parts = [re.sub(r"\s*\[[^\]]*\]", "", p).strip()
                 for p in m.group(1).split(",")]
        if len(parts) != 5 or not parts[0].isdigit():
            continue
        try:
            env, with_attack = int(parts[0]), parts[1] == "true"
            seen[(env, with_attack)] = (parts[2] == "true", int(parts[3]), int(parts[4]))
        except ValueError:
            continue
    rows = []
    for i in range(len(VICTIM_ENVIRONMENTS)):
        h, a = seen.get((i, False)), seen.get((i, True))
        rows.append({
            "env": i,
            "A": h[1] if h else None,
            "B": a[1] if a else None,
            "G": a[2] if a else None,
            "honest_ran": bool(h and h[0]),
            "attack_ran": bool(a and a[0]),
        })
    return rows


# -- diffs and lint ----------------------------------------------------------------------

def _nl(src: str) -> str:
    return src if src.endswith("\n") else src + "\n"


def make_diff(original: str, patched: str) -> str:
    return "".join(difflib.unified_diff(
        _nl(original).splitlines(keepends=True), _nl(patched).splitlines(keepends=True),
        f"a/{TARGET_PATH}", f"b/{TARGET_PATH}",
    ))


def apply_diff(original: str, diff: str) -> tuple[str | None, str]:
    """Apply a diff to the target. Returns (patched, error).

    `git apply` first. When it refuses, the hunks are applied by content instead: models
    trained on the apply_patch format (gpt-oss) write `@@` with no line numbers, which
    git rejects although the hunk says exactly what to change. Either way the gate
    judges the resulting source, and the diff it records is regenerated from it.
    """
    patched, git_err = _git_apply(original, diff)
    if patched is not None:
        return patched, ""
    patched, hunk_err = apply_hunks(original, diff)
    if patched is not None:
        return patched, ""
    return None, hunk_err or git_err


_HEADER_RE = re.compile(r"^(\*\*\* (Begin|End) Patch|\*\*\* (Update|Add|Delete) File:|"
                        r"diff --git |index |--- |\+\+\+ |\\ No newline)")


def apply_hunks(original: str, diff: str) -> tuple[str | None, str]:
    """Apply each hunk by locating its context and removed lines verbatim (unique)."""
    files = {m.group(1).strip() for m in re.finditer(
        r"^(?:\+\+\+ (?:b/)?|\*\*\* (?:Update|Add|Delete) File: )(\S+)", diff, re.M)}
    if files - {TARGET_PATH, "/dev/null"}:
        return None, f"diff touches files other than {TARGET_PATH}: {sorted(files)}"
    hunks: list[list[str]] = []
    for line in diff.splitlines():
        if line.startswith("@@"):
            hunks.append([])
        elif _HEADER_RE.match(line):
            continue
        elif hunks:
            hunks[-1].append(line)
    if not hunks:
        return None, "no hunks found (expected lines starting with @@)"
    lines = _nl(original).splitlines()
    for n, hunk in enumerate(hunks, 1):
        while hunk and not hunk[-1].strip():
            hunk.pop()
        old = [ln[1:] if ln[:1] in " -" else ln for ln in hunk if ln[:1] != "+"]
        new = [ln[1:] if ln[:1] in " +" else ln for ln in hunk if ln[:1] != "-"]
        if not any(o.strip() for o in old):
            return None, f"hunk {n} has no context or removed lines to anchor it"
        at = _find_block(lines, old)
        if isinstance(at, str):
            return None, f"hunk {n}: {at}"
        lines[at:at + len(old)] = new
    return "\n".join(lines) + "\n", ""


def _find_block(lines: list[str], block: list[str]) -> int | str:
    for norm in (str.rstrip, lambda s: " ".join(s.split())):
        want = [norm(b) for b in block]
        have = [norm(ln) for ln in lines]
        hits = [i for i in range(len(have) - len(want) + 1) if have[i:i + len(want)] == want]
        if len(hits) == 1:
            return hits[0]
        if len(hits) > 1:
            return f"its context matches {len(hits)} places; add more context lines"
    # Point at the first line that is not in the source, which is usually a typo.
    src = {" ".join(ln.split()) for ln in lines}
    missing = next((b for b in block if " ".join(b.split()) not in src), block[0])
    return f"these lines are not in src/Target.sol verbatim; first mismatch: {missing.strip()!r}"


def _git_apply(original: str, diff: str) -> tuple[str | None, str]:
    if shutil.which("git") is None:
        return None, "git not found on PATH"
    with tempfile.TemporaryDirectory(prefix="arbiter-patch-") as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / TARGET_PATH).write_text(_nl(original), encoding="utf-8")
        (root / "fix.diff").write_text(_nl(diff), encoding="utf-8")
        err = ""
        # -p1 for a/ b/ prefixes, -p0 for bare `--- src/Target.sol` headers.
        for strip in ("-p1", "-p0"):
            # --recount: a model writes hunk bodies well and hunk header line counts
            # badly; the counts carry no meaning git cannot recover from the body.
            check = subprocess.run(  # noqa: S603,S607
                ["git", "apply", "--check", "--recount", strip, "--include", TARGET_PATH,
                 "fix.diff"],
                cwd=root, capture_output=True, text=True,
            )
            if check.returncode != 0:
                err = (check.stderr or check.stdout).strip()
                continue
            # --include silently skips hunks for any other file; refuse those outright.
            stat = subprocess.run(  # noqa: S603,S607
                ["git", "apply", "--numstat", "--recount", strip, "fix.diff"],
                cwd=root, capture_output=True, text=True,
            )
            other = [ln.split("\t")[-1] for ln in stat.stdout.splitlines()
                     if ln.split("\t")[-1] != TARGET_PATH]
            if other:
                return None, f"diff touches files other than {TARGET_PATH}: {other}"
            subprocess.run(  # noqa: S603,S607
                ["git", "apply", "--recount", strip, "fix.diff"], cwd=root, check=True,
                capture_output=True, text=True,
            )
            return (root / TARGET_PATH).read_text(encoding="utf-8"), ""
        return None, err or "diff did not apply"


_LINT_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("tx.origin", re.compile(r"\btx\s*\.\s*origin\b")),
    ("code.length / extcodesize", re.compile(r"\.\s*code\s*\.\s*length\b|\bextcodesize\b")),
    ("hard-coded address", re.compile(r"\b0x[0-9a-fA-F]{40}\b")),
    ("selfdestruct", re.compile(r"\b(selfdestruct|suicide)\s*\(")),
    ("assembly", re.compile(r"\bassembly\b")),
    ("require(false) / assert(false)", re.compile(r"\b(require|assert)\s*\(\s*false\b")),
]
_REVERT_STMT_RE = re.compile(r"^\s*revert\b")
_CONDITIONAL_RE = re.compile(r"\b(if|else)\b")


def _added_lines(original: str, patched: str) -> list[tuple[int, str]]:
    """(index in patched, text) for every line the patch adds."""
    a, b = original.splitlines(), patched.splitlines()
    out = []
    for tag, _i1, _i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag in ("insert", "replace"):
            out.extend((j, b[j]) for j in range(j1, j2))
    return out


def lint(original: str, patched: str) -> list[dict[str, Any]]:
    """Forbidden constructs in added lines. Empty list means clean."""
    lines = patched.splitlines()
    hits = []
    for idx, text in _added_lines(original, patched):
        code = text.split("//", 1)[0]
        if not code.strip():
            continue
        for rule, rx in _LINT_RULES:
            if rx.search(code):
                hits.append({"rule": rule, "line": idx + 1, "text": text.strip()})
        if _REVERT_STMT_RE.search(code):
            # A bare revert is conditional only if the line it sits under is an if/else.
            prev = next((lines[k].split("//", 1)[0] for k in range(idx - 1, -1, -1)
                         if lines[k].strip()), "")
            if not _CONDITIONAL_RE.search(prev):
                hits.append({"rule": "unconditional revert", "line": idx + 1,
                             "text": text.strip()})
    return hits


# -- ABI -------------------------------------------------------------------------------

_ABI_KINDS = ("function", "constructor", "fallback", "receive")


def _types(params: list[dict[str, Any]]) -> list[str]:
    return [p.get("type", "") for p in params or []]


def read_abi(ws: Workspace) -> dict[str, dict[str, Any]] | None:
    """Callable surface of every contract in Target.sol, from the target-only build."""
    out = ws.root / "out" / "Target.sol"
    if not out.is_dir():
        return None
    surface: dict[str, dict[str, Any]] = {}
    for art in sorted(out.glob("*.json")):
        contract = art.stem
        for entry in json.loads(art.read_text(encoding="utf-8")).get("abi", []):
            kind = entry.get("type")
            if kind not in _ABI_KINDS:
                continue
            name = entry.get("name", "") if kind == "function" else kind
            key = f"{contract}.{name}({','.join(_types(entry.get('inputs')))})"
            surface[key] = {
                "outputs": _types(entry.get("outputs")),
                "stateMutability": entry.get("stateMutability", ""),
            }
    return surface


def abi_diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "removed": sorted(k for k in before if k not in after),
        "changed": sorted(k for k in before if k in after and before[k] != after[k]),
        "added": sorted(k for k in after if k not in before),
    }


# -- running the stored exploit --------------------------------------------------------

def _first_error(text: str) -> str:
    for line in text.splitlines():
        if "Error" in line:
            return line.strip()[:200]
    return text.strip().splitlines()[-1][:200] if text.strip() else ""


def _fail_line(text: str) -> str:
    m = re.search(r"\[FAIL[^\n]*", text)
    return m.group(0)[:300] if m else ""


class _Run:
    """One workspace with the exploit + report contract written and built."""

    def __init__(self, root: Path, sample_id: str, source: str, solidity: str,
                 custom_errors: bool) -> None:
        self.ws = Workspace(root, sample_id, source)
        target = self.ws.build()
        self.target_ok = target.ok
        self.target_error = "" if target.ok else _first_error(target.combined)
        self.abi = read_abi(self.ws) if target.ok else None
        self.poc = self.ws.write_poc(_POC_NAME, solidity + report_contract(custom_errors))
        built = self.ws.build() if target.ok else target
        self.poc_ok = built.ok
        self.poc_error = "" if built.ok else _first_error(built.combined)

    def exploit(self) -> tuple[bool, str]:
        r = self.ws.run_poc(self.poc, match_contract=_VICTIM_CONTRACT,
                            match_test=_VICTIM_TEST)
        return _test_passed(r), _fail_line(r.combined)

    def report(self) -> list[dict[str, Any]]:
        r = self.ws.run_poc(self.poc, match_contract=_REPORT_CONTRACT,
                            match_test=_REPORT_TEST)
        return parse_trials(r.combined)


def hermetic_exploit(solidity: str, target_import: str) -> str:
    """Point an in-repo exploit at `src/Target.sol` (only for a target with no imports)."""
    if target_import == _HERMETIC_IMPORT:
        return solidity
    line = f'import "{target_import}";'
    if line not in solidity:
        raise ValueError(f"exploit does not import {target_import!r}")
    return solidity.replace(line, f'import "{_HERMETIC_IMPORT}";', 1)


def exploit_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """The first proven victim_loss exploit in a results row, ready for verify_fix."""
    o = row["outcome"]
    poc = next((p for p in o.get("pocs", []) if p.get("passed") and p.get("adjudicated")),
               None)
    if poc is None:
        raise ValueError("row has no passed, adjudicated PoC")
    if poc.get("predicate") != "victim_loss":
        raise ValueError(f"predicate {poc.get('predicate')!r} is not patched yet")
    source = row["source"]
    plan = (row.get("context") or {}).get("plan") or {}
    solidity = poc["solidity"]
    if plan.get("target_import"):
        if re.search(r"^\s*import\b", source, re.MULTILINE):
            raise ValueError("target has imports; repo-mode patching is not built yet")
        solidity = hermetic_exploit(solidity, plan["target_import"])
    finding = next((f for f in o.get("findings", []) if f.get("poc_name") == poc["name"]),
                   (o.get("findings") or [{}])[0])
    return {"source": source, "solidity": solidity, "poc_name": poc["name"],
            "finding": finding, "sample_id": row["sample_id"]}


# -- the gate ----------------------------------------------------------------------------

def _check(status: str, **evidence: Any) -> dict[str, Any]:
    return {"status": status, **evidence}


def reproduce(source: str, solidity: str, root: Path, sample_id: str,
              keep: bool = False) -> dict[str, Any]:
    """Check 0 on its own: does the stored exploit pass, and what are A/B/G?"""
    custom = "error ArbiterNoHarm" in solidity
    run = _Run(root, f"{sample_id}__orig", source, solidity, custom)
    try:
        if not run.poc_ok:
            return _check("fail", reason="exploit does not compile on the original",
                          error=run.poc_error)
        passed, fail = run.exploit()
        abg = run.report()
        if not passed:
            return _check("fail", reason="not_reproducible", fail=fail, abg=abg)
        return _check("pass", abg=abg, abi=run.abi)
    finally:
        if not keep:
            run.ws.cleanup()


def verify_fix(
    original: str,
    solidity: str,
    *,
    patched: str | None = None,
    diff: str | None = None,
    root: Path,
    sample_id: str,
    baseline: dict[str, Any] | None = None,
    tolerance_wei: int = TOLERANCE_WEI,
    run_all: bool = False,
    keep: bool = False,
) -> dict[str, Any]:
    """Run the patch gate. Give `diff` (what an LLM proposes) or `patched` source.

    `baseline` is a previous `reproduce()` result for the same original and exploit, so a
    repair loop pays for check 0 once per finding rather than once per round.
    """
    if "contract TestArbiterVictim" not in solidity:
        raise ValueError("only victim_loss exploits are patched in this version")
    checks: dict[str, dict[str, Any]] = {}

    def stop() -> bool:
        return not run_all and any(c["status"] == "fail" for c in checks.values())

    # 0 -- reproduce, and the honest baseline
    base = baseline or reproduce(original, solidity, root, sample_id)
    checks["0"] = {k: v for k, v in base.items() if k != "abi"}
    if base["status"] != "pass":
        for name in GATE_ORDER[1:]:
            checks[name] = _check("skipped", reason="not_reproducible")
        return _result(False, checks, diff or "", None, None)

    # L -- the diff applies, is small, and adds nothing on the forbidden list
    if diff is None:
        diff = make_diff(original, patched or "")
        apply_err = ""
    else:
        patched, apply_err = apply_diff(original, diff)
        if patched is not None:
            diff = make_diff(original, patched)
    if patched is None:
        checks["L"] = _check("fail", reason="diff does not apply", error=apply_err)
        for name in GATE_ORDER[2:]:
            checks[name] = _check("skipped", reason="no patched source")
        return _result(False, checks, diff, None, None)
    changed = diff_line_count(original, patched)
    hits = lint(original, patched)
    l_reasons = []
    if changed == 0:
        l_reasons.append("patch changes nothing")
    if changed > MAX_DIFF_LINES:
        l_reasons.append(f"{changed} changed lines > {MAX_DIFF_LINES}")
    if hits:
        l_reasons.append("forbidden construct in added lines")
    checks["L"] = _check("fail" if l_reasons else "pass", reasons=l_reasons,
                         changed_lines=changed, lint=hits)
    if stop():
        return _finish(checks, diff, changed, patched)

    custom = "error ArbiterNoHarm" in solidity
    run = _Run(root, f"{sample_id}__patched", patched, solidity, custom)
    try:
        # 3 -- interface unchanged
        if not run.target_ok:
            checks["3"] = _check("fail", reason="patched contract does not compile",
                                 error=run.target_error)
        else:
            delta = abi_diff(base.get("abi") or {}, run.abi or {})
            bad = delta["removed"] + delta["changed"] + delta["added"]
            checks["3"] = _check("fail" if bad else "pass", abi_diff=delta)
        if stop():
            return _finish(checks, diff, changed, patched)

        # 1 -- the same exploit fails everywhere
        abg_after = None
        if not run.poc_ok:
            checks["1"] = _check(
                "fail", reason="exploit does not compile against the patch; a removed "
                "or renamed interface is not a fix", error=run.poc_error)
        else:
            passed, fail = run.exploit()
            abg_after = run.report()
            checks["1"] = _check("fail" if passed else "pass",
                                 reason="exploit still succeeds" if passed else "",
                                 fail=fail, abg=abg_after)
        if stop():
            return _finish(checks, diff, changed, patched)

        # 2 -- the honest path is intact in every environment
        if abg_after is None:
            checks["2"] = _check("fail", reason="cannot measure: exploit file does not "
                                 "compile against the patch")
        else:
            before = base.get("abg") or []
            worse = []
            for b, a in zip(before, abg_after):
                if b["A"] is None or not b["honest_ran"]:
                    continue
                if a["A"] is None or a["A"] + tolerance_wei < b["A"]:
                    worse.append({"env": b["env"], "before": b["A"], "after": a["A"]})
            checks["2"] = _check("fail" if worse else "pass", worse=worse,
                                 tolerance_wei=tolerance_wei)
        return _finish(checks, diff, changed, patched)
    finally:
        if not keep:
            run.ws.cleanup()


def _finish(checks: dict[str, Any], diff: str, changed: int, patched: str) -> dict[str, Any]:
    for name in GATE_ORDER:
        checks.setdefault(name, _check("skipped", reason="an earlier check failed"))
    accepted = all(checks[n]["status"] == "pass" for n in GATE_ORDER)
    return _result(accepted, checks, diff, changed, patched)


def _result(accepted: bool, checks: dict[str, Any], diff: str, changed: int | None,
            patched: str | None) -> dict[str, Any]:
    first = next((n for n in GATE_ORDER if checks.get(n, {}).get("status") == "fail"), None)
    return {
        "accepted": accepted,
        "first_failure": first,
        "checks": {n: checks[n] for n in GATE_ORDER if n in checks},
        "diff": diff,
        "changed_lines": changed,
        "patched": patched,
    }


def rejection_message(result: dict[str, Any]) -> str:
    """`PATCH REJECTED: <check>` plus the evidence, for the repair loop."""
    first = result["first_failure"]
    if first is None:
        return ""
    c = result["checks"][first]
    head = f"PATCH REJECTED: {first}"
    if first == "L":
        if c.get("error"):
            return f"{head} -- the diff did not apply: {c['error']}"
        detail = "; ".join(c.get("reasons", []))
        hits = "\n".join(f"  line {h['line']}: [{h['rule']}] {h['text']}"
                         for h in c.get("lint", []))
        return f"{head} -- {detail}\n{hits}".rstrip()
    if first == "3":
        if c.get("error"):
            return f"{head} -- the patched contract does not compile: {c['error']}"
        d = c["abi_diff"]
        return (f"{head} -- the external interface changed. removed: {d['removed']} "
                f"changed: {d['changed']} added: {d['added']}")
    if first == "1":
        if c.get("error"):
            return f"{head} -- {c['reason']}: {c['error']}"
        rows = ", ".join(f"env{r['env']}: B={r['B']} G={r['G']}" for r in c.get("abg") or [])
        return f"{head} -- the same exploit still succeeds ({rows})"
    if first == "2":
        if c.get("reason"):
            return f"{head} -- {c['reason']}"
        rows = ", ".join(f"env{w['env']}: before={w['before']} after={w['after']}"
                         for w in c["worse"])
        return (f"{head} -- with no attack at all, the victim now recovers less ({rows}). "
                "Blocking everyone is not a fix.")
    return f"{head} -- {c.get('reason', '')}"


# -- the repair loop ----------------------------------------------------------------------
#
# The model proposes; the gate disposes. One tool, propose_patch(diff, rationale), up to
# `rounds` proposals per finding, each rejection fed back with its evidence. The attacker
# contract is withheld on purpose so the patch targets the defect rather than this one
# exploit; the victim's own path and the A/B/G numbers are given, because check 2 is
# judged on them.

PATCH_TOOL = {
    "type": "function",
    "function": {
        "name": "propose_patch",
        "description": (
            "Propose a minimal fix as a unified diff against src/Target.sol. The patch is "
            "accepted only if the stored exploit then fails in all four environments, an "
            "honest user recovers as much as before, and the external interface is "
            "unchanged."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "diff": {"type": "string", "description": (
                    "Unified diff. Headers '--- a/src/Target.sol' and "
                    "'+++ b/src/Target.sol', hunk headers like '@@ -20,11 +20,11 @@', and "
                    "' ', '-', '+' prefixed lines copied character for character from "
                    "the numbered source (without the numbers).")},
                "rationale": {"type": "string",
                              "description": "One or two sentences: what was wrong, what changed."},
            },
            "required": ["diff", "rationale"],
        },
    },
}

_PATCH_SYSTEM = f"""You fix one proven vulnerability in a Solidity contract.

An exploit has already been executed against this contract and the harness confirmed it:
an honest user (the victim) recovers less money because of the attack, and the attacker
holds the difference. You propose a minimal patch by calling propose_patch exactly once
per turn. You never see whether a patch is accepted until the harness has run it.

The patch is accepted only if ALL of these hold:
- the diff applies to src/Target.sol and changes at most {MAX_DIFF_LINES} lines;
- the same exploit, unchanged, no longer harms the victim in any of four environments
  (default, 1000x stake, one week later, eight attack rounds);
- with no attack, the victim recovers at least as much as before in every environment;
- every function and constructor keeps its name, parameters, return types and mutability.

Allowed: reorder statements (checks-effects-interactions), add require checks, add a
private lock variable and modifier, change rounding direction, add bounds checks.
Forbidden: changing pragma, adding imports, adding file-level declarations, adding or
removing public/external functions, adding public state variables, tx.origin,
code.length / extcodesize, hard-coded addresses, selfdestruct, assembly, an
unconditional revert. Blocking callers by identity also blocks smart-contract wallets
and is rejected. Disabling the function is not a fix: the honest path must still work.
"""


def _victim_fragments(solidity: str) -> dict[str, str]:
    """The victim's own calls, taken from the fixed template (arbEnter / arbExit)."""
    out = {}
    for name in ("arbEnter", "arbExit"):
        m = re.search(rf"function {name}\(\) external \{{\n(.*?)\n    \}}", solidity, re.S)
        if m:
            body = [ln.strip() for ln in m.group(1).splitlines()
                    if ln.strip() and "Prank" not in ln]
            out[name] = "\n".join(body)
    return out


def _numbered(src: str) -> str:
    return "\n".join(f"{i:4d}  {ln}" for i, ln in enumerate(src.splitlines(), 1))


def _eth(v: int | None) -> str:
    return "?" if v is None else f"{v / 1e18:g} ETH"


def patch_prompt(exploit: dict[str, Any], abg: list[dict[str, Any]]) -> str:
    f = exploit.get("finding") or {}
    frags = _victim_fragments(exploit["solidity"])
    envs = "\n".join(
        f"  env{r['env']}: honest recovers {_eth(r['A'])}; under attack {_eth(r['B'])}; "
        f"attacker gains {_eth(r['G'])}" for r in abg)
    return f"""Proven finding
  title: {f.get('title', '')}
  vulnerable function: {f.get('vulnerable_function', '')}
  offending expression: {f.get('offending_expression', '')}
  attack path: {f.get('attack_path', '')}
  hypothesis: {f.get('poc_hypothesis', '')}

The victim's path (run by an ordinary user, must keep working):
  enter: {frags.get('arbEnter', '')}
  exit:  {frags.get('arbExit', '')}

Measured by the harness on the original contract:
{envs}

src/Target.sol (line numbers are for reference only, not part of the file):
{_numbered(exploit['source'])}

Call propose_patch with your diff."""


def _sha(text: str | None) -> str | None:
    return hashlib.sha256(text.encode("utf-8")).hexdigest() if text is not None else None


def _diff_from_text(text: str) -> str:
    m = re.search(r"```(?:diff|patch)?\n(.*?)```", text or "", re.S)
    return m.group(1) if m and "@@" in m.group(1) else ""


def repair(
    gateway: Any,
    exploit: dict[str, Any],
    *,
    root: Path,
    rounds: int = 3,
    max_tokens: int = 4096,
    on_round: Any = None,
) -> dict[str, Any]:
    """Propose-and-verify, up to `rounds` times. Returns one PatchRecord dict."""
    t0 = time.monotonic()
    req0 = gateway.usage.requests
    sid = re.sub(r"[^A-Za-z0-9_.-]", "_", exploit["sample_id"])
    record: dict[str, Any] = {
        "sample_id": exploit["sample_id"], "poc_name": exploit.get("poc_name"),
        "predicate": "victim_loss", "status": "skipped", "skip_reason": "",
        "diff": None, "changed_lines": None, "rationale": None, "rounds": [],
        "checks": {}, "abg_original": None, "honest": None, "exploit_after": None,
        "abi_diff": None, "refusals": {}, "model": gateway.model,
        "source_sha256": _sha(exploit["source"]), "patched_sha256": None,
    }
    base = reproduce(exploit["source"], exploit["solidity"], root, sid)
    record["abg_original"] = base.get("abg")
    if base["status"] != "pass":
        record["skip_reason"] = "not_reproducible"
        record["checks"] = {"0": {k: v for k, v in base.items() if k != "abi"}}
        return _close(record, gateway, req0, t0)

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": _PATCH_SYSTEM},
        {"role": "user", "content": patch_prompt(exploit, base["abg"])},
    ]
    result: dict[str, Any] = {}
    for k in range(rounds):
        msg = gateway.chat(messages, max_tokens=max_tokens, tools=[PATCH_TOOL],
                           tool_choice="auto", tag=f"patch:{sid}:r{k}")
        calls = msg.get("tool_calls") or []
        call = next((c for c in calls
                     if (c.get("function") or {}).get("name") == "propose_patch"), None)
        args = parse_arguments((call.get("function") or {}).get("arguments")) if call else {}
        diff = str(args.get("diff") or "") or _diff_from_text(str(msg.get("content") or ""))
        rationale = str(args.get("rationale") or "")
        entry = {"round": k, "diff": diff, "rationale": rationale,
                 "finish_reason": msg.get("_finish_reason")}
        if not diff.strip():
            feedback = ("PATCH REJECTED: L -- no diff received. Call propose_patch with a "
                        "unified diff against src/Target.sol.")
            entry.update(first_failure="L", message=feedback)
        else:
            result = verify_fix(exploit["source"], exploit["solidity"], diff=diff,
                                root=root, sample_id=sid, baseline=base)
            feedback = rejection_message(result)
            entry.update(first_failure=result["first_failure"], message=feedback,
                         checks={n: c["status"] for n, c in result["checks"].items()})
        record["rounds"].append(entry)
        if on_round:
            on_round(entry)
        if entry["first_failure"] is None:
            record.update(status="accepted", diff=result["diff"],
                          changed_lines=result["changed_lines"], rationale=rationale,
                          patched_sha256=_sha(result["patched"]))
            break
        record["refusals"][entry["first_failure"]] = (
            record["refusals"].get(entry["first_failure"], 0) + 1)
        assistant: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or ""}
        if call:
            assistant["tool_calls"] = [{
                "id": call.get("id") or f"call_{k}", "type": "function",
                "function": {"name": "propose_patch",
                             "arguments": json.dumps(args, ensure_ascii=False)},
            }]
            messages += [assistant, {"role": "tool", "tool_call_id": call.get("id") or f"call_{k}",
                                     "content": feedback}]
        else:
            messages += [assistant, {"role": "user", "content": feedback}]
    else:
        record["status"] = "rejected"

    if result:
        record["checks"] = result["checks"]
        c1 = result["checks"].get("1", {})
        after = c1.get("abg") or []
        record["exploit_after"] = {"fail": c1.get("fail"),
                                   "abg": [{"env": r["env"], "B": r["B"], "G": r["G"]}
                                           for r in after]}
        record["honest"] = {"original": [r["A"] for r in base["abg"]],
                            "patched": [r["A"] for r in after] or None}
        record["abi_diff"] = result["checks"].get("3", {}).get("abi_diff")
    return _close(record, gateway, req0, t0)


def _close(record: dict[str, Any], gateway: Any, req0: int, t0: float) -> dict[str, Any]:
    record["requests"] = gateway.usage.requests - req0
    record["elapsed_s"] = round(time.monotonic() - t0, 2)
    return record
