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

    4  repo tests  (repo mode, Foundry projects only) the project's own `forge test`:
                   no test that passed before the patch may fail after it; a project
                   whose tests do not run before the patch is "skipped", never a pass
    5  re-attack   (in repair(), after 0-4) the agent audits the PATCHED contract again,
                   told which hypotheses were already used (agent.audit's ruled_out);
                   a new proven attack rejects the patch and becomes the next round's
                   evidence -- at most two defences (attack, defend, attack, defend,
                   attack), then "修補未通過再攻擊"

Check 1 alone accepts an always-revert "fix": its failure message is word for word the
real fix's. Check 2 is what refuses it. An identity filter (`code.length == 0`) passes
1, 2 and 3; only L refuses it. Passing the gate means this one attack fails in four
environments, the honest path still works and the interface did not change -- not that
the contract is safe. Wording for a pass: 修補已通過驗證（針對此攻擊）; for check 5 only
"修補後再攻擊 1 次（N 回合）未成功".

Hermetic mode (one file, src/Target.sol) or repo mode (`repo={"root", "rel",
"solidity"}`): the project is copied into the work directory for every build and the
patch written into the copy, because RepoPlan reads files where they lie through
remappings and the user's files are never to be touched; plan_for() and
prepare_context() then run on the copy.

Strict predicates only (plan 6.2): victim_loss as above, and liveness_broken -- one
environment and no amounts: check 1 requires the stored exploit to stop breaking the
honest operation, check 2 refuses a patch under which that operation already fails
before any attack (the exploit's own "already fails before the attack" check), and
A/B/G and the report contract do not apply. Other predicates are not patched.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .benchmark import diff_line_count
from .repo import SKIP_DIRS, plan_for
from .tools import _test_passed, parse_arguments
from .workspace import VICTIM_ENVIRONMENTS, Workspace

TARGET_PATH = "src/Target.sol"
MAX_DIFF_LINES = 12
TOLERANCE_WEI = 10
GATE_ORDER = ("0", "L", "3", "1", "2", "4")
# Check 4 cannot pass or fail a single file or a project whose tests do not run; those
# statuses let the patch through but are shown as what they are, never as "pass".
_NEUTRAL = {"4": ("not_applicable", "skipped")}
MAX_DEFENSES = 2
PROJECT_TEST_TIMEOUT = 600

# forge matches --match-test against the signature, parentheses included, so an anchor
# written as `name$` matches nothing (forge 1.8.6; the 9/28 prototype ran 1.5.1).
_VICTIM_CONTRACT = "^TestArbiterVictim$"
_VICTIM_TEST = r"^testArbiterVictimLoss\(\)$"
# liveness_broken (plan 6.3): one environment, no amounts; the harness's own test
# contract, and the two messages its differential body can fail with.
_LIVENESS_CONTRACT = "^TestArbiterExploit$"
_LIVENESS_TEST = r"^testArbiterExploit\(\)$"
_LIVENESS_BEFORE = "already fails before the attack"
STRICT_PATCHED = ("victim_loss", "liveness_broken")
# User decision 10/30 (a+b): the rule stays; when it refuses a liveness_broken patch the
# reader is told why a correct fix can be refused too. Measured on r2's buyback exploit:
# its "honest operation" sells without holding tokens, which only works because of the bug.
LIVENESS_CHECK2_NOTE = ("檢查 2 以攻擊程式裡的『一般使用者操作』為基準；如果這個操作本身就依賴漏洞"
                        "（例如沒付代幣也能拿到錢），正確的修補也會讓它失敗而被擋下，請人工確認修補。")


def predicate_of(solidity: str) -> str | None:
    """Which strict predicate a stored exploit was composed for, from its fixed template."""
    if "contract TestArbiterVictim" in solidity:
        return "victim_loss"
    if "contract TestArbiterExploit" in solidity and _LIVENESS_BEFORE in solidity:
        return "liveness_broken"
    return None
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


def read_abi(ws: Workspace, filename: str = "Target.sol") -> dict[str, dict[str, Any]] | None:
    """Callable surface of every contract in the target file, from the target-only build
    (hermetic: out/Target.sol; repo mode: the file's own name, built by prepare_context)."""
    out = ws.root / "out" / filename
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


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


def copy_project(src: Path, dest: Path, rel: str, source: str) -> Path:
    """A copy of the project at `dest` with `source` written to `rel`; `src` is only read.

    Skips what repo.py never reads (.git, node_modules, build output) and every symlink:
    a link in an uploaded project could point anywhere on the host, and the copy is
    what a sandboxed job's container gets to see.
    """
    src, dest = Path(src).resolve(), Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    for d, dirs, files in os.walk(src):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not (Path(d) / x).is_symlink()]
        out = dest / Path(d).relative_to(src)
        out.mkdir(parents=True, exist_ok=True)
        for f in files:
            fp = Path(d) / f
            if not fp.is_symlink() and fp.is_file():
                shutil.copyfile(fp, out / f)
    target = dest / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return dest


def project_tests(project: Path, timeout: int = PROJECT_TEST_TIMEOUT) -> dict[str, Any]:
    """Check 4's measurement: the project's own `forge test --json`, run in a copy.

    status: "ran" (passed / failed test ids), "not_foundry" (no foundry.toml: Hardhat and
    the rest are not covered), "not_run" (forge could not build or run the suite).
    """
    project = Path(project)
    if not (project / "foundry.toml").is_file():
        return {"status": "not_foundry", "reason": "不是 Foundry 專案（沒有 foundry.toml）"}
    forge = shutil.which("forge")
    if forge is None:
        return {"status": "not_run", "reason": "找不到 forge"}
    t0 = time.monotonic()
    try:
        r = subprocess.run([forge, "test", "--json", "--offline"], cwd=project,  # noqa: S603
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "not_run", "reason": f"專案測試超過 {timeout} 秒"}
    elapsed = round(time.monotonic() - t0, 2)
    suites = None
    for line in reversed((r.stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                suites = json.loads(line)
                break
            except json.JSONDecodeError:
                continue
    if suites is None:
        try:
            suites = json.loads(r.stdout)
        except (json.JSONDecodeError, TypeError):
            err = _first_error((r.stderr or "") + "\n" + (r.stdout or ""))
            return {"status": "not_run", "reason": f"forge test 沒有產生結果：{err}"[:300],
                    "elapsed_s": elapsed}
    passed, failed = [], []
    for suite, body in (suites or {}).items():
        for name, res in ((body or {}).get("test_results") or {}).items():
            tid = f"{suite.rsplit('/', 1)[-1]}::{name}"
            (passed if res.get("status") == "Success" else failed).append(tid)
    return {"status": "ran", "passed": sorted(passed), "failed": sorted(failed),
            "elapsed_s": elapsed}


class _Run:
    """One workspace with the exploit (+ the report contract, victim_loss) written and built.

    `repo` (repo mode): {"root": project, "rel": target path inside it}. The project is
    copied to <root>/copies/<sample_id> with `source` at `rel`, and the workspace is
    planned on the copy, so the user's files are read once and never written.
    """

    def __init__(self, root: Path, sample_id: str, source: str, solidity: str,
                 custom_errors: bool, repo: dict[str, Any] | None = None) -> None:
        self.copy: Path | None = None
        if repo is None:
            self.ws = Workspace(root, sample_id, source)
            target = self.ws.build()
            self.target_ok = target.ok
            self.target_error = "" if target.ok else _first_error(target.combined)
            self.abi = read_abi(self.ws) if target.ok else None
        else:
            self.copy = copy_project(Path(repo["root"]), root / "copies" / _safe(sample_id),
                                     repo["rel"], source)
            plan = plan_for(self.copy / repo["rel"], repo_root=self.copy)
            self.ws = Workspace(root, sample_id, source, plan=plan)
            ctx = self.ws.prepare_context()
            self.target_ok = bool(ctx.get("ok"))
            self.target_error = "" if self.target_ok else str(ctx.get("error") or "context does not build")
            self.abi = read_abi(self.ws, Path(repo["rel"]).name) if self.target_ok else None
        self.predicate = predicate_of(solidity)
        body = solidity + (report_contract(custom_errors) if self.predicate == "victim_loss" else "")
        self.poc = self.ws.write_poc(_POC_NAME, body)
        built = self.ws.build() if self.target_ok else None
        self.poc_ok = bool(built and built.ok)
        self.poc_error = ("" if self.poc_ok else
                          _first_error(built.combined) if built else self.target_error)

    def cleanup(self) -> None:
        self.ws.cleanup()
        if self.copy is not None:
            shutil.rmtree(self.copy, ignore_errors=True)

    def exploit(self) -> tuple[bool, str]:
        if self.predicate == "liveness_broken":
            r = self.ws.run_poc(self.poc, match_contract=_LIVENESS_CONTRACT,
                                match_test=_LIVENESS_TEST)
        else:
            r = self.ws.run_poc(self.poc, match_contract=_VICTIM_CONTRACT,
                                match_test=_VICTIM_TEST)
        fail = _fail_line(r.combined)
        if not fail and _LIVENESS_BEFORE in r.combined:
            fail = _LIVENESS_BEFORE
        return _test_passed(r), fail

    def report(self) -> list[dict[str, Any]] | None:
        """A/B/G per environment (victim_loss); liveness_broken has no amounts."""
        if self.predicate != "victim_loss":
            return None
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


def exploit_from_row(row: dict[str, Any], project: bool = False) -> dict[str, Any]:
    """The first proven victim_loss exploit in a results row, ready for verify_fix.

    `solidity` is the hermetic form when the target has no imports (A/B/G, the regression
    test). In repo mode (`project`: the target sits in a project whose own tests check 4
    runs, or it imports and cannot be made hermetic) `repo` carries {root, rel, solidity}
    with the exploit as the harness composed it, importing arbiter-target/<file>; the
    patch gate then builds against copies of the project."""
    o = row["outcome"]
    poc = next((p for p in o.get("pocs", []) if p.get("passed") and p.get("adjudicated")),
               None)
    if poc is None:
        raise ValueError("row has no passed, adjudicated PoC")
    if poc.get("predicate") not in STRICT_PATCHED:
        raise ValueError(f"predicate {poc.get('predicate')!r} is not patched (plan 6.2: "
                         "strict predicates only)")
    source = row["source"]
    plan = (row.get("context") or {}).get("plan") or {}
    solidity = poc["solidity"]
    repo = None
    if plan.get("target_import"):
        imports = re.search(r"^\s*import\b", source, re.MULTILINE) is not None
        root, target = Path(plan.get("repo_root") or ""), Path(plan.get("target") or "")
        if (project or imports) and root.is_dir() and target.is_file():
            repo = {"root": str(root), "rel": target.relative_to(root).as_posix(),
                    "solidity": solidity}
        elif imports:
            raise ValueError("target has imports and its repository is no longer on disk")
        if not imports:
            solidity = hermetic_exploit(solidity, plan["target_import"])
    finding = next((f for f in o.get("findings", []) if f.get("poc_name") == poc["name"]),
                   (o.get("findings") or [{}])[0])
    target_path = Path(plan.get("target") or "")
    layout = ({"file": target_path.name, "folder": target_path.parent.name or "contracts"}
              if plan.get("target") else None)
    return {"source": source, "solidity": solidity, "poc_name": poc["name"],
            "finding": finding, "sample_id": row["sample_id"],
            "hypothesis": " ".join(str(poc.get("hypothesis") or finding.get("poc_hypothesis")
                                       or finding.get("title") or "").split())[:300],
            "repo": repo, "layout": layout}


def _exploit_solidity(exploit_or_solidity: str, repo: dict[str, Any] | None) -> str:
    return repo["solidity"] if repo else exploit_or_solidity


# -- the gate ----------------------------------------------------------------------------

class _Notifying(dict):
    """verify_fix's check table, reporting each entry as it is written."""

    def __init__(self, hook: Any) -> None:
        super().__init__()
        self._hook = hook

    def __setitem__(self, key: str, value: Any) -> None:
        super().__setitem__(key, value)
        try:
            self._hook(key, value)
        except Exception:  # noqa: BLE001 -- a display hook never decides a patch
            pass


def _check(status: str, **evidence: Any) -> dict[str, Any]:
    return {"status": status, **evidence}


def reproduce(source: str, solidity: str, root: Path, sample_id: str,
              keep: bool = False, repo: dict[str, Any] | None = None,
              with_project_tests: bool = True) -> dict[str, Any]:
    """Check 0 on its own: does the stored exploit pass, and what are A/B/G?

    In repo mode it also runs the project's own tests on the unpatched copy: check 4's
    "before" set, measured once per finding like the A baseline."""
    solidity = _exploit_solidity(solidity, repo)
    custom = "error ArbiterNoHarm" in solidity
    run = _Run(root, f"{sample_id}__orig", source, solidity, custom, repo=repo)
    try:
        if not run.poc_ok:
            return _check("fail", reason="exploit does not compile on the original",
                          error=run.poc_error)
        passed, fail = run.exploit()
        abg = run.report()
        if not passed:
            return _check("fail", reason="not_reproducible", fail=fail, abg=abg)
        out = _check("pass", abg=abg, abi=run.abi)
        if run.copy is not None and with_project_tests:
            out["repo_tests"] = project_tests(run.copy)
        return out
    finally:
        if not keep:
            run.cleanup()


def _extra_exploit_fails(root: Path, sample_id: str, patched: str, extra: dict[str, Any],
                         repo: dict[str, Any] | None) -> dict[str, Any]:
    """A later round's new exploit (found by check 5) must fail on this patch too."""
    sol = extra.get("repo_solidity") if repo else extra["solidity"]
    run = _Run(root, f"{sample_id}__x{_safe(extra.get('poc_name') or 'extra')}", patched,
               sol, "error ArbiterNoHarm" in sol, repo=repo)
    try:
        if not run.poc_ok:
            return {"poc_name": extra.get("poc_name"), "status": "fail",
                    "reason": "exploit does not compile against the patch", "error": run.poc_error}
        passed, fail = run.exploit()
        if not passed and run.predicate == "liveness_broken" and _LIVENESS_BEFORE in fail:
            # The operation that exploit watches now fails with no attack at all.
            return {"poc_name": extra.get("poc_name"), "status": "fail", "fail": fail,
                    "reason": "the honest operation already fails before the attack"}
        return {"poc_name": extra.get("poc_name"), "status": "fail" if passed else "pass",
                "fail": fail}
    finally:
        run.cleanup()


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
    on_check: Any = None,
    repo: dict[str, Any] | None = None,
    extra_exploits: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the patch gate. Give `diff` (what an LLM proposes) or `patched` source.

    `on_check(name, check)` (optional) is called as each check's result is recorded, in
    gate order, so a progress display can light them one by one.

    `baseline` is a previous `reproduce()` result for the same original and exploit, so a
    repair loop pays for check 0 once per finding rather than once per round.

    `repo` switches to repo mode (copies of the project; check 4 runs). `extra_exploits`
    are attacks check 5 proved against an earlier patch; check 1 requires each of them to
    fail on this one as well.
    """
    solidity = _exploit_solidity(solidity, repo)
    predicate = predicate_of(solidity)
    if predicate not in STRICT_PATCHED:
        raise ValueError("only victim_loss and liveness_broken exploits are patched")
    checks: dict[str, dict[str, Any]] = _Notifying(on_check) if on_check else {}

    def stop() -> bool:
        return not run_all and any(c["status"] == "fail" for c in checks.values())

    # 0 -- reproduce, and the honest baseline
    base = baseline or reproduce(original, solidity, root, sample_id, repo=repo)
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
    run = _Run(root, f"{sample_id}__patched", patched, solidity, custom, repo=repo)
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
            extra = [_extra_exploit_fails(root, sample_id, patched, x, repo)
                     for x in (extra_exploits or [])] if not passed else []
            bad = [x for x in extra if x["status"] != "pass"]
            reason = ("exploit still succeeds" if passed else
                      "an attack found by an earlier re-attack (check 5) still succeeds"
                      if bad else "")
            checks["1"] = _check("fail" if passed or bad else "pass", reason=reason,
                                 fail=fail, abg=abg_after, extra=extra)
        if stop():
            return _finish(checks, diff, changed, patched)

        # 2 -- the honest path is intact in every environment
        if not run.poc_ok:
            checks["2"] = _check("fail", reason="cannot measure: exploit file does not "
                                 "compile against the patch")
        elif predicate == "liveness_broken":
            # Plan 6.3: the exploit checks the honest operation BEFORE attacking; a patch
            # that makes it fail with no attack at all ("already fails before the
            # attack") has disabled the operation, not fixed it.
            c1 = checks.get("1") or {}
            broke = _LIVENESS_BEFORE in str(c1.get("fail") or "")
            checks["2"] = _check("fail" if broke else "pass",
                                 reason=("the honest operation now fails even with no attack"
                                         if broke else ""))
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
        if stop():
            return _finish(checks, diff, changed, patched)

        # 4 -- the project's own tests (repo mode, Foundry): nothing that passed may fail
        if run.copy is None:
            checks["4"] = _check("not_applicable", reason="單一檔案，沒有專案自己的測試")
        else:
            before = base.get("repo_tests") or {"status": "not_run", "reason": "沒有量到修補前的結果"}
            if before["status"] != "ran":
                checks["4"] = _check("skipped", reason=before.get("reason", ""),
                                     before=before["status"])
            else:
                after = project_tests(run.copy)
                if after["status"] != "ran":
                    checks["4"] = _check("fail", reason="修補後專案自己的測試跑不起來："
                                         + str(after.get("reason", "")),
                                         before_passed=len(before["passed"]))
                else:
                    broke = sorted(set(before["passed"]) - set(after["passed"]))
                    checks["4"] = _check("fail" if broke else "pass", newly_failed=broke,
                                         before_passed=len(before["passed"]),
                                         after_passed=len(after["passed"]),
                                         before_failed=len(before["failed"]),
                                         elapsed_s=after.get("elapsed_s"))
        return _finish(checks, diff, changed, patched)
    finally:
        if not keep:
            run.cleanup()


def _ok(name: str, check: dict[str, Any]) -> bool:
    return check["status"] == "pass" or check["status"] in _NEUTRAL.get(name, ())


def _finish(checks: dict[str, Any], diff: str, changed: int, patched: str) -> dict[str, Any]:
    failed = any(c["status"] == "fail" for c in checks.values())
    for name in GATE_ORDER:
        checks.setdefault(name, _check("skipped", reason="an earlier check failed" if failed
                                       else "not reached"))
    accepted = not failed and all(_ok(n, checks[n]) for n in GATE_ORDER)
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
        bad = [x for x in c.get("extra") or [] if x["status"] != "pass"]
        if bad and "earlier re-attack" in (c.get("reason") or ""):
            names = ", ".join(str(x.get("poc_name")) for x in bad)
            return (f"{head} -- the original exploit now fails, but the attack the re-audit "
                    f"found against your previous patch still succeeds ({names}). Fix that "
                    "mechanism too.")
        if c.get("abg") is None:
            return (f"{head} -- the same exploit still succeeds: after the attack the "
                    "ordinary user's operation still fails")
        rows = ", ".join(f"env{r['env']}: B={r['B']} G={r['G']}" for r in c.get("abg") or [])
        return f"{head} -- the same exploit still succeeds ({rows})"
    if first == "4":
        if c.get("reason"):
            return f"{head} -- {c['reason']}"
        names = ", ".join(c.get("newly_failed", [])[:3])
        return (f"{head} -- the project's own tests that passed before the patch now fail: "
                f"{names}. The fix must not change behaviour those tests rely on.")
    if first == "2":
        if c.get("reason") == "the honest operation now fails even with no attack":
            return (f"{head} -- with your patch the ordinary user's operation fails even "
                    "before any attack. Disabling the operation is not a fix.")
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


_PATCH_SYSTEM_LIVENESS = f"""You fix one proven vulnerability in a Solidity contract.

An exploit has already been executed against this contract and the harness confirmed it:
an ordinary user's operation succeeds before the attack and fails after it -- the attack
breaks the contract's availability. You propose a minimal patch by calling propose_patch
exactly once per turn. You never see whether a patch is accepted until the harness has
run it.

The patch is accepted only if ALL of these hold:
- the diff applies to src/Target.sol and changes at most {MAX_DIFF_LINES} lines;
- the same exploit, unchanged, no longer breaks the operation;
- with no attack, the ordinary user's operation still succeeds (making the operation
  always fail is not a fix: it is checked before the attack, and rejected);
- every function and constructor keeps its name, parameters, return types and mutability.

Allowed: reorder statements (checks-effects-interactions), add require checks (for
example on the result of an external call), add a private lock variable and modifier,
change rounding direction, add bounds checks.
Forbidden: changing pragma, adding imports, adding file-level declarations, adding or
removing public/external functions, adding public state variables, tx.origin,
code.length / extcodesize, hard-coded addresses, selfdestruct, assembly, an
unconditional revert. Blocking callers by identity also blocks smart-contract wallets
and is rejected.
"""

_LIVENESS_CALL_RE = re.compile(r"\(bool okBefore, \) = address\(target\)\.call\((.*?)\);", re.S)


def _system_prompt(predicate: str) -> str:
    return _PATCH_SYSTEM_LIVENESS if predicate == "liveness_broken" else _PATCH_SYSTEM


def patch_prompt(exploit: dict[str, Any], abg: list[dict[str, Any]] | None) -> str:
    f = exploit.get("finding") or {}
    if predicate_of(exploit["solidity"]) == "liveness_broken":
        m = _LIVENESS_CALL_RE.search(exploit["solidity"])
        return f"""Proven finding (availability: liveness_broken)
  title: {f.get('title', '')}
  vulnerable function: {f.get('vulnerable_function', '')}
  offending expression: {f.get('offending_expression', '')}
  hypothesis: {f.get('poc_hypothesis', '')}

The ordinary user's operation the attack breaks (must keep working with no attack):
  address(target).call({" ".join(m.group(1).split()) if m else "?"})

Measured by the harness on the original contract: the operation succeeds before the
attack and fails after it.

src/Target.sol (line numbers are for reference only, not part of the file):
{_numbered(exploit['source'])}

Call propose_patch with your diff."""
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


def _reattack_workspace(exploit: dict[str, Any], patched: str, root: Path,
                        sid: str) -> tuple[Workspace, Path | None, dict[str, Any] | None]:
    """The patched contract laid out the way the original audit saw it.

    A project is copied; a single file becomes a one-file repository named like the
    original, because the user message decides the agent's predicate (measured 10/28:
    hermetic 5/5 eth_profit, repo 8/8 victim_loss), and a re-attack should differ from
    the first audit in nothing but the contract and the hypotheses ruled out."""
    repo, layout = exploit.get("repo"), exploit.get("layout")
    copy = None
    if repo:
        copy = copy_project(Path(repo["root"]), root / "copies" / sid, repo["rel"], patched)
        target = copy / repo["rel"]
    elif layout:
        copy = root / "copies" / sid
        if copy.exists():
            shutil.rmtree(copy)
        target = copy / layout["folder"] / layout["file"]
        target.parent.mkdir(parents=True)
        target.write_text(patched, encoding="utf-8")
    else:
        return Workspace(root, sid, patched), None, {"ok": True, "mode": "hermetic"}
    repo_root = copy if repo else target.parent
    plan = plan_for(target, repo_root=repo_root)
    ws = Workspace(root, sid, patched, plan=plan)
    return ws, copy, ws.prepare_context()


def reattack(
    gateway: Any,
    exploit: dict[str, Any],
    patched: str,
    *,
    root: Path,
    ruled_out: list[str],
    n: int = 1,
    max_turns: int = 16,
    max_tokens: int = 4096,
    trace_sink: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Check 5, once: the agent audits the PATCHED contract, told which hypotheses earlier
    rounds already used (agent.audit's ruled_out; agent.py itself is unchanged).

    status: "proven" (with `exploit`: the new attack, re-runnable on later patches when its
    predicate is victim_loss), "not_proven", or "not_executed" (it did not complete --
    recorded as skipped, never as a pass)."""
    from .agent import audit
    from .tools import AgentOutcome
    from .workspace import BuildUnavailable

    sid = f"{_safe(exploit['sample_id'])}__reattack{n}"
    t0 = time.monotonic()
    req0 = gateway.usage.requests
    ws = copy = None
    out: dict[str, Any] = {"n": n, "ruled_out": list(ruled_out), "status": "not_executed"}
    try:
        ws, copy, ctx = _reattack_workspace(exploit, patched, root, sid)
        if not ctx.get("ok"):
            out["reason"] = f"修補後的合約在專案裡編譯不過：{ctx.get('error', '')}"[:300]
            return out
        outcome = audit(gateway, ws, max_turns=max_turns, max_tokens=max_tokens,
                        trace_sink=trace_sink if trace_sink is not None else [],
                        ruled_out=list(ruled_out))
    except BuildUnavailable as exc:
        out["reason"] = f"toolchain_unavailable: {exc}"[:300]
        return out
    except Exception as exc:  # noqa: BLE001
        out["reason"] = f"{type(exc).__name__}: {exc}"[:300]
        return out
    finally:
        if ws is not None:
            ws.cleanup()
        if copy is not None:
            shutil.rmtree(copy, ignore_errors=True)
        out["elapsed_s"] = round(time.monotonic() - t0, 2)
        out["requests"] = gateway.usage.requests - req0
    assert isinstance(outcome, AgentOutcome)
    o = outcome.as_dict()
    stop = str(o.get("stop_reason") or "")
    out.update(turns=o.get("turns"), stop_reason=stop,
               tried=[" ".join(str(p.get("hypothesis") or "").split())[:200]
                      for p in o.get("pocs") or [] if p.get("adjudicated")])
    if outcome.proven:
        poc = next((p for p in o.get("pocs") or [] if p.get("passed") and p.get("adjudicated")), {})
        finding = next((f for f in o.get("findings") or [] if f.get("poc_name") == poc.get("name")),
                       (o.get("findings") or [{}])[0])
        sol = poc.get("solidity") or ""
        new = {"poc_name": poc.get("name"), "predicate": poc.get("predicate"),
               "hypothesis": " ".join(str(poc.get("hypothesis") or "").split())[:300],
               "finding": {k: finding.get(k) for k in ("title", "vulnerable_function",
                                                        "offending_expression", "attack_path",
                                                        "severity")},
               "repo_solidity": sol, "solidity": sol}
        target_import = ws.target_import if ws is not None else _HERMETIC_IMPORT
        if not exploit.get("repo") and target_import != _HERMETIC_IMPORT:
            try:
                new["solidity"] = hermetic_exploit(sol, target_import)
            except ValueError:
                pass
        out.update(status="proven", exploit=new)
    elif stop.startswith("error") or stop in ("context_unbuildable", "toolchain_unavailable") \
            or not o.get("turns"):
        out["reason"] = stop or "the re-attack did not run"
    else:
        out["status"] = "not_proven"
    return out


def _attack_entry(rnd: int, ra: dict[str, Any]) -> dict[str, Any]:
    e = {"round": rnd, "side": "attack", "source": "reattack", "result": ra["status"],
         "turns": ra.get("turns"), "elapsed_s": ra.get("elapsed_s"),
         "requests": ra.get("requests"), "ruled_out": ra.get("ruled_out"),
         "tried": ra.get("tried"), "reason": ra.get("reason", "")}
    if ra.get("exploit"):
        x = ra["exploit"]
        e.update(poc_name=x.get("poc_name"), predicate=x.get("predicate"),
                 hypothesis=x.get("hypothesis"), finding=x.get("finding"), abg=ra.get("abg"))
    return e


def repair(
    gateway: Any,
    exploit: dict[str, Any],
    *,
    root: Path,
    rounds: int = 3,
    max_tokens: int = 4096,
    on_round: Any = None,
    on_check: Any = None,
    on_propose: Any = None,
    reattack_turns: int = 0,
    max_defenses: int = MAX_DEFENSES,
    on_attack: Any = None,
    on_turn: Any = None,
) -> dict[str, Any]:
    """Propose-and-verify, then (check 5) attack the accepted patch again.

    Each defence is up to `rounds` proposals through checks 0-4. With `reattack_turns` > 0
    an accepted patch is audited again with the hypotheses used so far ruled out; a new
    proven attack rejects it, joins the evidence every later patch must stop, and the
    next defence begins -- at most `max_defenses` (attack, defend, attack, defend,
    attack). `timeline` records every attack and defence in order. Returns one
    PatchRecord dict; status accepted / rejected / rejected_reattack / skipped.

    Optional progress hooks: `on_propose(round)` before each model request, `on_check`
    as in verify_fix, `on_round(entry)` after each proposal, `on_attack(event)` around
    each re-attack, `on_turn` passed to the re-attack's trace."""
    t0 = time.monotonic()
    req0 = gateway.usage.requests
    sid = _safe(exploit["sample_id"])
    repo = exploit.get("repo")
    record: dict[str, Any] = {
        "sample_id": exploit["sample_id"], "poc_name": exploit.get("poc_name"),
        "predicate": predicate_of(_exploit_solidity(exploit["solidity"], repo)),
        "status": "skipped", "skip_reason": "",
        "diff": None, "changed_lines": None, "rationale": None, "rounds": [],
        "checks": {}, "abg_original": None, "honest": None, "exploit_after": None,
        "abi_diff": None, "refusals": {}, "model": gateway.model,
        "source_sha256": _sha(exploit["source"]), "patched_sha256": None,
        "mode": "repo" if repo else "hermetic", "timeline": [], "reattacks": [],
        "extra_exploits": [], "reattack_requests": 0, "reattack_s": 0.0,
    }
    base = reproduce(exploit["source"], exploit["solidity"], root, sid, repo=repo)
    record["abg_original"] = base.get("abg")
    record["timeline"].append({
        "round": 1, "side": "attack", "source": "audit", "result": "proven",
        "poc_name": exploit.get("poc_name"), "hypothesis": exploit.get("hypothesis"),
        "finding": {k: (exploit.get("finding") or {}).get(k) for k in
                    ("title", "vulnerable_function", "offending_expression", "attack_path")},
        "abg": base.get("abg"), "predicate": record["predicate"]})
    if base["status"] != "pass":
        record["skip_reason"] = "not_reproducible"
        record["checks"] = {"0": {k: v for k, v in base.items() if k != "abi"}}
        return _close(record, gateway, req0, t0)
    if repo:
        rt = base.get("repo_tests") or {}
        record["repo_tests_before"] = {"status": rt.get("status"), "reason": rt.get("reason"),
                                       "passed": len(rt.get("passed") or []),
                                       "failed": len(rt.get("failed") or []),
                                       "elapsed_s": rt.get("elapsed_s")}

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": _system_prompt(record["predicate"])},
        {"role": "user", "content": patch_prompt(exploit, base["abg"])},
    ]
    result: dict[str, Any] = {}
    extra: list[dict[str, Any]] = []
    ruled_out = [exploit["hypothesis"]] if exploit.get("hypothesis") else []
    k = 0
    pending: tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any]] | None = None

    def reply(feedback: str) -> None:
        """Close the last proposal in the conversation with the harness's answer."""
        nonlocal pending
        if pending is None:
            messages.append({"role": "user", "content": feedback})
            return
        msg, call, args = pending
        pending = None
        assistant: dict[str, Any] = {"role": "assistant", "content": msg.get("content") or ""}
        if call:
            cid = call.get("id") or f"call_{k}"
            assistant["tool_calls"] = [{"id": cid, "type": "function", "function": {
                "name": "propose_patch", "arguments": json.dumps(args, ensure_ascii=False)}}]
            messages.extend([assistant, {"role": "tool", "tool_call_id": cid, "content": feedback}])
        else:
            messages.extend([assistant, {"role": "user", "content": feedback}])

    for defence in range(1, max_defenses + 1):
        accepted = None
        for _ in range(rounds):
            if on_propose:
                try:
                    on_propose(k)
                except Exception:  # noqa: BLE001
                    pass
            msg = gateway.chat(messages, max_tokens=max_tokens, tools=[PATCH_TOOL],
                               tool_choice="auto", tag=f"patch:{sid}:r{k}")
            calls = msg.get("tool_calls") or []
            call = next((c for c in calls
                         if (c.get("function") or {}).get("name") == "propose_patch"), None)
            args = parse_arguments((call.get("function") or {}).get("arguments")) if call else {}
            diff = str(args.get("diff") or "") or _diff_from_text(str(msg.get("content") or ""))
            rationale = str(args.get("rationale") or "")
            entry = {"round": k, "defence": defence, "diff": diff, "rationale": rationale,
                     "finish_reason": msg.get("_finish_reason")}
            pending = (msg, call, args)
            k += 1
            if not diff.strip():
                feedback = ("PATCH REJECTED: L -- no diff received. Call propose_patch with a "
                            "unified diff against src/Target.sol.")
                entry.update(first_failure="L", message=feedback)
            else:
                result = verify_fix(exploit["source"], exploit["solidity"], diff=diff,
                                    root=root, sample_id=sid, baseline=base, on_check=on_check,
                                    repo=repo, extra_exploits=extra)
                feedback = rejection_message(result)
                entry.update(first_failure=result["first_failure"], message=feedback,
                             checks={n: c["status"] for n, c in result["checks"].items()})
            record["rounds"].append(entry)
            if on_round:
                on_round(entry)
            if entry["first_failure"] is None:
                accepted = (result, rationale)
                break
            record["refusals"][entry["first_failure"]] = (
                record["refusals"].get(entry["first_failure"], 0) + 1)
            reply(feedback)
        tl: dict[str, Any] = {"round": defence, "side": "defend",
                              "proposals": sum(1 for r in record["rounds"] if r["defence"] == defence)}
        if accepted is None:
            tl.update(result="rejected", last_failure=record["rounds"][-1].get("first_failure"))
            record["timeline"].append(tl)
            record["status"] = "rejected"
            break
        result, rationale = accepted
        tl.update(result="accepted", diff=result["diff"], rationale=rationale,
                  checks={n: c["status"] for n, c in result["checks"].items()})
        record["timeline"].append(tl)
        record.update(diff=result["diff"], changed_lines=result["changed_lines"],
                      rationale=rationale, patched_sha256=_sha(result["patched"]))
        if reattack_turns <= 0:
            record["status"] = "accepted"
            break
        if on_attack:
            try:
                on_attack({"phase": "start", "round": defence + 1})
            except Exception:  # noqa: BLE001
                pass
        ra = reattack(gateway, exploit, result["patched"], root=root, ruled_out=ruled_out,
                      n=defence, max_turns=reattack_turns, max_tokens=max_tokens,
                      trace_sink=on_turn)
        if ra["status"] == "proven" and (ra["exploit"] or {}).get("predicate") in STRICT_PATCHED:
            x = ra["exploit"]
            xrepo = {**repo, "solidity": x["repo_solidity"]} if repo else None
            m = reproduce(result["patched"], x["solidity"], root, f"{sid}_ra{defence}",
                          repo=xrepo, with_project_tests=False)
            ra["abg"] = m.get("abg")
        record["reattacks"].append({k2: v for k2, v in ra.items() if k2 != "exploit"})
        record["reattack_requests"] += ra.get("requests") or 0
        record["reattack_s"] = round(record["reattack_s"] + (ra.get("elapsed_s") or 0), 2)
        record["timeline"].append(_attack_entry(defence + 1, ra))
        if on_attack:
            try:
                on_attack({"phase": "done", "round": defence + 1, "status": ra["status"],
                           "turns": ra.get("turns")})
            except Exception:  # noqa: BLE001
                pass
        if ra["status"] != "proven":
            record["status"] = "accepted"
            record["checks_5"] = {"status": "pass" if ra["status"] == "not_proven" else "skipped",
                                  "turns": ra.get("turns"), "reason": ra.get("reason", "")}
            break
        if defence >= max_defenses:
            record["status"] = "rejected_reattack"
            record["checks_5"] = {"status": "fail", "turns": ra.get("turns")}
            break
        x = ra["exploit"]
        if x.get("hypothesis"):
            ruled_out.append(x["hypothesis"])
        if x.get("predicate") in STRICT_PATCHED:
            extra.append(x)
            record["extra_exploits"].append({"poc_name": x.get("poc_name"),
                                             "solidity": x["solidity"],
                                             "repo_solidity": x["repo_solidity"]})
        f = x.get("finding") or {}
        abg = "; ".join(f"env{r['env']}: honest {_eth(r['A'])}, attacked {_eth(r['B'])}, "
                        f"attacker +{_eth(r['G'])}" for r in ra.get("abg") or [])
        record["refusals"]["5"] = record["refusals"].get("5", 0) + 1
        reply("PATCH REJECTED: 5 -- your patch stops the original exploit and passed checks "
              "0-4, but the contract WITH YOUR PATCH was audited again and a different attack "
              "still harms the victim:\n"
              f"  hypothesis: {x.get('hypothesis', '')}\n"
              f"  vulnerable function: {f.get('vulnerable_function', '')}\n"
              f"  attack path: {f.get('attack_path', '')}\n"
              + (f"  measured on your patch: {abg}\n" if abg else "")
              + "Propose a new patch, again as a diff against the ORIGINAL src/Target.sol "
              "from the first message, that stops the original exploit and this one.")

    if result:
        record["checks"] = result["checks"]
        c1 = result["checks"].get("1", {})
        after = c1.get("abg") or []
        record["exploit_after"] = {"fail": c1.get("fail"),
                                   "abg": [{"env": r["env"], "B": r["B"], "G": r["G"]}
                                           for r in after]}
        record["honest"] = ({"original": [r["A"] for r in base["abg"]],
                             "patched": [r["A"] for r in after] or None}
                            if base.get("abg") is not None else None)
        record["abi_diff"] = result["checks"].get("3", {}).get("abi_diff")
        c4 = result["checks"].get("4")
        if c4:
            record["repo_tests"] = c4
    if "checks_5" in record:
        record["checks"] = {**record["checks"], "5": record.pop("checks_5")}
    if (record["predicate"] == "liveness_broken" and record["status"] != "accepted"
            and any(r.get("first_failure") == "2" for r in record["rounds"])):
        record["check2_note"] = LIVENESS_CHECK2_NOTE
    elif reattack_turns <= 0 and record["status"] == "accepted":
        record["checks"] = {**record["checks"], "5": {"status": "off"}}
    return _close(record, gateway, req0, t0)


def _close(record: dict[str, Any], gateway: Any, req0: int, t0: float) -> dict[str, Any]:
    record["requests"] = gateway.usage.requests - req0
    record["elapsed_s"] = round(time.monotonic() - t0, 2)
    return record
