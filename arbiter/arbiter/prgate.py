"""PR mode for ARBITER Gate: audit what a pull request changed, say what it did not cover.

    python3 -m arbiter.gate --repo DIR --base SHA --head SHA \
        --out gate.json --sarif report.sarif --pr-comment comment.md

1. `git diff --unified=0 base head` (diffscan.git_diff / parse_diff) gives the added line
   ranges per file; deleted files come from `--diff-filter=D`.
2. The checkout at `head` is copied into the job directory (the sandbox mounts only that)
   and `forge build --ast` builds a function index from the solc AST. `src` is
   "start:length:file" in *bytes*, converted to lines here; constructor, fallback and
   receive have an empty `name` and are named by their `kind`.
3. diffscan.scope_from_diff intersects the two. Files with a touched function go through
   triage.triage_all (interfaces, libraries, mocks, tests are skipped and listed); the
   rest are audited whole, in repo mode, by the same run_arbiter call as `--file`.
4. Everything the diff touched that is not audited is reported: diffscan's four
   unscanned_reasons as 未涵蓋 (never as 未發現可證明攻擊), triage skips as 略過.

If the AST index cannot be built (the head does not compile), the scope degrades to file
level -- every .sol file with added lines is a candidate -- and the report says so; the
audit itself then records the build failure as 無法判定.

A repository that carries a TestArbiterRegression (the regression test ARBITER Gate hands
out) gets it re-run here, in the same sandbox: "every later change re-runs the same
attack". A failing regression test blocks like a proven finding (exit 1) and says which
test failed; it is reported apart from the four verdicts, which stay verdict.py's.

The PR comment (`comment_markdown`) uses the web result card's wording (webui.verdict_card)
in plain text. `suggestions` turns a verified patch into GitHub suggestion blocks;
scripts/gate_pr_publish.py posts the ones that land on lines of the PR's diff and puts the
rest in the comment as a diff.
"""

from __future__ import annotations

import difflib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .diffscan import git_diff, parse_diff, scope_from_diff
from .triage import triage_all
from .verdict import LABELS, NO_PROVABLE, NOT_EXECUTED, PROVEN, STATIC_HINT

COMMENT_MARKER = "<!-- arbiter-gate:comment -->"

# diffscan's reason strings -> (code, plain words). Matched by prefix so that a reworded
# parenthesis in diffscan would not silently drop an entry (unknown ones keep their text).
UNSCANNED = (
    ("not solidity", "not_solidity", "不是 Solidity 檔，這個工具不審"),
    ("deletion only", "deletion_only", "只有刪除，沒有新增程式碼可審"),
    ("changed but not indexed", "not_indexed",
     "檔案有改動，但不在編譯出的函式索引裡（沒有被編譯進專案，或在建置範圍外）"),
    ("changed outside any function body", "outside_function",
     "改動在函式外（狀態變數、常數、pragma、import）；這一版只稽核有函式被改到的檔案"),
)
DELETED_FILE = ("deleted_file", "整個檔案被刪除，沒有新增程式碼可審")
OVERLOAD_NOTE = "函式只記名稱：同名的多載（overload）會合成一筆。"
COPY_SKIP = {".git", "out", "cache", "broadcast", "node_modules", "artifacts"}


class PRInputError(RuntimeError):
    """The PR could not be read (bad ref, shallow history, checkout not at head)."""


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if proc.returncode != 0:
        raise PRInputError(f"git {args[0]} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def _sha(repo: Path, ref: str) -> str:
    try:
        return _git(repo, "rev-parse", "--verify", "-q", f"{ref}^{{commit}}").strip()
    except PRInputError:
        raise PRInputError(f"{ref!r} is not a commit in this checkout; a CI checkout needs "
                           "`fetch-depth: 0`") from None


def copy_tree(repo: Path, dest: Path) -> None:
    """The checkout as it is (head, submodules included), minus VCS and build output."""
    def ignore(_dir: str, names: list[str]) -> list[str]:
        return [n for n in names if n in COPY_SKIP]
    shutil.copytree(repo, dest, ignore=ignore, symlinks=True)


# -- the function index, from the solc AST ------------------------------------------------

def _line_of(data: bytes, offset: int) -> int:
    return data.count(b"\n", 0, max(0, offset)) + 1


def _functions(unit: dict[str, Any], data: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []

    def add(node: dict[str, Any], contract: str) -> None:
        try:
            start, length = (int(x) for x in str(node.get("src", "")).split(":")[:2])
        except ValueError:
            return
        if node["nodeType"] == "ModifierDefinition":
            name = f"modifier {node.get('name')}"
        else:
            name = node.get("name") or node.get("kind") or "function"
        out.append({"name": name, "contract": contract, "kind": node.get("kind") or "modifier",
                    "start_line": _line_of(data, start),
                    "end_line": _line_of(data, start + max(0, length - 1))})

    for node in unit.get("nodes") or []:
        if node.get("nodeType") in ("FunctionDefinition", "ModifierDefinition"):
            add(node, "")                       # free function
        elif node.get("nodeType") == "ContractDefinition":
            for sub in node.get("nodes") or []:
                if sub.get("nodeType") in ("FunctionDefinition", "ModifierDefinition"):
                    add(sub, node.get("name") or "")
    return out


def ast_index(root: Path, out_dir: Path, timeout: int = 600) -> tuple[dict[str, Any] | None, str]:
    """(index, error). Builds `root` with `forge build --ast` into `out_dir`.

    forge is whatever PATH resolves (the sandbox's wrapper when one is applied); it is
    called from `root`, which lies inside the job directory.
    """
    forge = shutil.which("forge")
    if forge is None:
        return None, "找不到 forge"
    cmd = [forge, "build", "--ast", "--offline", "--out", str(out_dir),
           "--cache-path", str(out_dir / "cache")]
    try:
        proc = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"forge build 超過 {timeout} 秒"
    if proc.returncode != 0:
        lines = [ln.strip() for ln in (proc.stderr + proc.stdout).splitlines() if ln.strip()]
        first = next((ln for ln in lines if re.match(r"(\w*Error|Error)", ln)
                      and "Compiler run failed" not in ln), lines[-1] if lines else "")
        return None, f"forge build 失敗：{first[:240]}"
    files: dict[str, dict[str, Any]] = {}
    for art in sorted(out_dir.rglob("*.json")):
        if "build-info" in art.parts or art.parent == out_dir / "cache":
            continue
        try:
            unit = json.loads(art.read_text(encoding="utf-8")).get("ast") or {}
        except (json.JSONDecodeError, OSError):
            continue
        rel = unit.get("absolutePath")
        if not rel or rel in files or unit.get("nodeType") != "SourceUnit":
            continue
        src = root / rel
        if not src.is_file():
            continue
        files[rel] = {"path": Path(rel).as_posix(),
                      "functions": _functions(unit, src.read_bytes())}
    return {"files": list(files.values())}, ""


# -- scope ----------------------------------------------------------------------------------

def _unscanned_entries(reasons: dict[str, list[str]]) -> list[dict[str, str]]:
    out = []
    for reason, paths in sorted(reasons.items()):
        code, label = reason, reason
        for prefix, c, lab in UNSCANNED:
            if reason.startswith(prefix):
                code, label = c, lab
                break
        out += [{"path": p, "code": code, "label": label} for p in sorted(paths)]
    return out


def prepare(repo: Path, base: str, head: str, job: Path) -> dict[str, Any]:
    """Diff, copy, index, scope and triage. Raises PRInputError if the PR cannot be read."""
    repo = repo.resolve()
    base_sha, head_sha = _sha(repo, base), _sha(repo, head)
    at = _sha(repo, "HEAD")
    if at != head_sha:
        raise PRInputError(f"the checkout is at {at[:12]}, not at --head {head_sha[:12]}; "
                           "check out the PR head before running the gate")
    try:
        diff = git_diff(base_sha, head_sha, repo)
    except RuntimeError as exc:
        raise PRInputError(str(exc).splitlines()[0]) from None
    changed = parse_diff(diff)
    deleted = [p for p in _git(repo, "diff", "--name-only", "--no-renames", "--diff-filter=D",
                               base_sha, head_sha).splitlines() if p.strip()]
    copy = job / "repo"
    copy_tree(repo, copy)
    index, index_error = ast_index(copy, job / "ast-out")
    if index is not None:
        scope = scope_from_diff(changed, index)
        granularity = "function"
        touched = {p: sorted(v) for p, v in scope.touched.items()}
        unscanned = _unscanned_entries(scope.unscanned_reasons)
        counts = scope.to_dict()
    else:
        # Plan 7.3's fallback: every .sol file with added lines, audited whole, no names.
        granularity = "file"
        touched, reasons = {}, {}
        for path, cf in changed.items():
            if not path.endswith(".sol"):
                reasons.setdefault("not solidity", []).append(path)
            elif not cf.added_ranges:
                reasons.setdefault("deletion only", []).append(path)
            else:
                touched[path] = []
        unscanned = _unscanned_entries(reasons)
        counts = {"changed_files": len(changed),
                  "changed_sol_files": sum(p.endswith(".sol") for p in changed),
                  "added_lines": sum(cf.added_lines for cf in changed.values())}
    unscanned += [{"path": p, "code": DELETED_FILE[0], "label": DELETED_FILE[1]}
                  for p in deleted if p.endswith(".sol")]
    keep, drop = triage_all([copy / p for p in sorted(touched)])
    rel = lambda t: t.path.relative_to(copy).as_posix()  # noqa: E731
    return {
        "base": base_sha, "head": head_sha, "granularity": granularity,
        "index_error": index_error,
        "changed_files": counts.get("changed_files"),
        "changed_sol_files": counts.get("changed_sol_files"),
        "added_lines": counts.get("added_lines"),
        "touched": touched,
        "overload_note": OVERLOAD_NOTE if granularity == "function" else "",
        "audited": [rel(t) for t in keep],
        "skipped": [{"path": rel(t), "reason": t.reason} for t in drop],
        "unscanned": unscanned,
        "_copy": copy,
    }


# -- the repository's own regression test ---------------------------------------------------

REGRESSION_RE = re.compile(r"^\s*contract\s+TestArbiterRegression\b", re.MULTILINE)


def regression_rerun(copy: Path, out_dir: Path, timeout: int = 600) -> dict[str, Any]:
    """Run every TestArbiterRegression in the checkout once. status: absent, passed,
    failed, not_run."""
    found = [p for p in sorted(copy.rglob("*.sol"))
             if "lib" not in p.relative_to(copy).parts[:1]
             and REGRESSION_RE.search(p.read_text(encoding="utf-8", errors="ignore"))]
    if not found:
        return {"status": "absent"}
    files = [p.relative_to(copy).as_posix() for p in found]
    forge = shutil.which("forge")
    if forge is None:
        return {"status": "not_run", "files": files, "reason": "找不到 forge"}
    cmd = [forge, "test", "--offline", "--json", "--match-contract", "^TestArbiterRegression$",
           "--out", str(out_dir), "--cache-path", str(out_dir / "cache")]
    try:
        proc = subprocess.run(cmd, cwd=copy, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "not_run", "files": files, "reason": f"超過 {timeout} 秒"}
    tests: list[dict[str, Any]] = []
    try:
        start = proc.stdout.index("{")
        data = json.loads(proc.stdout[start:])
        for suite in data.values():
            for name, res in (suite.get("test_results") or {}).items():
                tests.append({"test": name, "status": res.get("status"),
                              "reason": (res.get("reason") or "")[:200]})
    except (ValueError, AttributeError):
        pass
    if not tests:
        lines = [ln for ln in (proc.stderr + proc.stdout).splitlines() if ln.strip()]
        return {"status": "failed" if proc.returncode else "not_run", "files": files,
                "reason": "回歸測試沒有編譯或沒有執行："
                          + (lines[-1].strip()[:240] if lines else f"rc {proc.returncode}"),
                "tests": []}
    failed = [t for t in tests if t["status"] != "Success"]
    return {"status": "failed" if failed else "passed", "files": files, "tests": tests,
            "failed": [t["test"] for t in failed]}


# -- suggestions ----------------------------------------------------------------------------

def suggestions(original: str, patched: str, path: str, gap: int = 2) -> list[dict[str, Any]]:
    """GitHub suggestion blocks for `patched`, on the lines of `original` (1-based).

    Each block replaces lines start..end of the file at head with `body`. An insertion has
    no line of its own, so it is attached to the line before it (or after, at the top).
    Changes within `gap` lines of each other are one block, so a reviewer applies one fix.
    """
    a, b = original.splitlines(), patched.splitlines()
    ops = [op for op in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
           if op[0] != "equal"]
    groups: list[list[tuple[str, int, int, int, int]]] = []
    for op in ops:
        if groups and op[1] - groups[-1][-1][2] <= gap:
            groups[-1].append(op)
        else:
            groups.append([op])
    out = []
    for g in groups:
        i1, i2 = g[0][1], g[-1][2]
        j1, j2 = g[0][3], g[-1][4]
        if i1 == i2:                     # pure insertion
            if i1 > 0:
                i1 -= 1
                j1 -= 1
            else:
                i2, j2 = 1, j2 + 1
        out.append({"path": path, "start_line": i1 + 1, "end_line": i2,
                    "body": "\n".join(b[j1:j2])})
    return out


# -- the PR comment -------------------------------------------------------------------------

_MEAN = {
    PROVEN: ("AI 寫出的攻擊，在模擬區塊鏈上真的成功了。有攻擊時，一般使用者領回的錢比沒有攻擊時少，"
             "差額落到攻擊者手上；也就是說，有人可以把其他存款人的錢領走。",
             "先不要合併。參考下方的修補，修好後再推一次 commit，系統會重新稽核。"),
    STATIC_HINT: ("自動掃描工具（Slither）覺得這裡可疑，但 AI 沒能寫出真的能成功的攻擊。這是提示，不是證據。",
                  "請人看一下 Security 分頁標出的程式行。這一級不會擋合併。"),
    NO_PROVABLE: ("AI 這次沒有寫出能實際成功的攻擊，自動掃描工具也沒有標出可疑的地方。"
                  "**這不等於安全**：可能是這類漏洞目前測不到，或 AI 這次沒想到。",
                  "重要的合約仍請人審查；也可以重新執行這個檢查。"),
    NOT_EXECUTED: ("稽核沒有完成，所以這份合約沒有任何結論，不能當成通過。**這不是發現漏洞。**",
                   "請看下方原因，處理後重新執行這個檢查。"),
}
_LOOSE = ("（這次是用較寬鬆的條件 {p} 證實：攻擊者拿到了比一般使用者多的錢；沒有量受害者少拿多少。）")
_ICON = {PROVEN: "🔴", STATIC_HINT: "🟡", NO_PROVABLE: "⚪", NOT_EXECUTED: "⚫"}


def _eth(v: Any) -> str:
    return "?" if v is None else f"{int(v) / 1e18:g}"


def _abg_table(envs: list[dict[str, Any]]) -> list[str]:
    rows = ["| 情境 | 受害者初始餘額 | 經過時間 | 攻擊回合 | A 沒攻擊時取回 | B 有攻擊時取回 | G 攻擊者獲利 |",
            "|---|---|---|---|---|---|---|"]
    for r in envs:
        rows.append(f"| {r.get('env')} | {_eth(r.get('endow_wei'))} ETH | {r.get('warp_s')} 秒 | "
                    f"{r.get('rounds')} | {_eth(r.get('A'))} ETH | {_eth(r.get('B'))} ETH | "
                    f"{_eth(r.get('G'))} ETH |")
    return rows


_SKIP_KIND = {"interface": "只有 interface", "library": "只有 library", "abstract": "只有抽象合約",
              "no contract": "沒有宣告合約"}


def skip_reason(reason: str) -> str:
    """triage.py's reason for a skipped file, in the comment's words."""
    if reason.startswith("declares no deployable contract"):
        kind = reason[reason.find("(") + 1:reason.rfind(")")]
        return f"沒有可部署的合約（{_SKIP_KIND.get(kind, kind)}）"
    if reason == "no externally reachable state-changing function":
        return "沒有外部可呼叫、會改變狀態的函式"
    if reason == "path is test, mock or deployment scaffolding":
        return "路徑是測試、mock 或部署腳本"
    if reason.startswith("unreadable"):
        return "讀不到這個檔案"
    return reason


def overall(report: dict[str, Any]) -> tuple[str, str]:
    """(icon+headline, one-line meaning) for the whole PR, from the exit code."""
    code = report.get("exit_code")
    pr = report.get("pr") or {}
    if pr.get("refused"):
        return (f"{_ICON[NOT_EXECUTED]} {LABELS[NOT_EXECUTED]}",
                pr["refused"]["label"] + "**這不是發現漏洞，也不算通過。**")
    verdicts = [e["verdict"] for e in report.get("files") or []]
    if code == 1:
        if PROVEN in verdicts:
            return f"{_ICON[PROVEN]} {LABELS[PROVEN]}", "這個 PR 改到的合約有已證實的攻擊，檢查不通過（擋合併）。"
        return "🔴 回歸測試失敗（擋合併）", "repo 裡的 ARBITER 回歸測試沒有通過：之前證實過的攻擊又能成功，或回歸測試已經跑不起來。"
    if code == 2:
        return (f"{_ICON[NOT_EXECUTED]} {LABELS[NOT_EXECUTED]}",
                "至少一份合約的稽核沒有完成，所以這次不放行；這不是發現漏洞。")
    if not verdicts:
        if pr.get("unscanned"):
            why = "這個 PR 沒有改到任何合約的函式；下方「未涵蓋」列出改了但沒有審的地方。"
        elif pr.get("skipped"):
            why = "這個 PR 改到的 .sol 檔都不是可部署的合約（見下方「略過」），所以沒有送 AI 稽核。"
        else:
            why = "這個 PR 沒有改到任何合約的函式。"
        return "⚪ 這次沒有要稽核的函式", why
    if STATIC_HINT in verdicts:
        return f"{_ICON[STATIC_HINT]} {LABELS[STATIC_HINT]}", "放行（不擋合併），但自動掃描工具有提示，見下方與 Security 分頁。"
    return f"{_ICON[NO_PROVABLE]} {LABELS[NO_PROVABLE]}", "放行（不擋合併）。沒有找到可證明的攻擊不等於安全。"


_CHECK_ZH = {"0": "重現", "L": "改得乾淨", "3": "介面不變", "1": "同一招失效",
             "2": "一般使用者不受影響", "4": "專案自己的測試", "5": "換手法再攻擊"}
_STATUS_ZH = {"pass": "通過", "fail": "沒通過", "skipped": "沒有跑（不算通過）",
              "not_applicable": "不適用（單一檔案）", "off": "沒有開", "not_reached": "沒有輪到"}


def _rounds_markdown(p: dict[str, Any]) -> list[str]:
    """Every attack and defence round of the patch (check 5), and the checks it passed."""
    out: list[str] = []
    gates = p.get("gate_checks") or {}
    if gates:
        out += ["", "修補閘門：" + "、".join(
            f"{_CHECK_ZH.get(n, n)} {_STATUS_ZH.get(st, st)}" for n, st in gates.items())]
    rt = p.get("repo_tests") or {}
    if rt.get("before_passed") is not None:
        out.append(f"專案自己的測試（檢查 4）：修補前 {rt['before_passed']} 個通過，修補後 "
                   + (f"{rt['after_passed']} 個通過" if rt.get("after_passed") is not None else "跑不起來")
                   + ("；新失敗：" + "、".join(f"`{t}`" for t in rt.get("newly_failed", [])[:5])
                      if rt.get("newly_failed") else "") + "。")
    elif rt.get("status") == "skipped" and rt.get("reason"):
        out.append(f"專案自己的測試（檢查 4）：沒有跑（不算通過）：{rt['reason']}")
    tl = p.get("timeline") or []
    if tl:
        out += ["", "| 回合 | 誰 | 結果 | 細節 |", "|---|---|---|---|"]
        for e in tl:
            if e.get("side") == "attack":
                who = "攻擊（原本的稽核）" if e.get("source") == "audit" else "攻擊（換手法再攻擊）"
                hyp = (e.get("hypothesis") or "").replace("|", "\\|")
                if e.get("source") == "reattack" and e.get("result") != "proven":
                    detail = f"{e.get('turns')} 回合、{e.get('elapsed_s')} 秒"
                else:
                    detail = f"假設：{hyp[:160]}" if hyp else ""
            else:
                who = "修補"
                detail = f"{e.get('proposals')} 個提案"
            out.append(f"| {e.get('round')} | {who} | {e.get('label', '')} | {detail} |")
        ra = p.get("reattack") or {}
        if ra.get("label"):
            out += ["", f"**{ra['label']}**。" + ("「未成功」只代表這一次換手法沒有找到能成功的攻擊，"
                                                   "不代表合約安全。" if ra.get("status") == "pass" else "")]
    return out


def comment_markdown(report: dict[str, Any], *, run_url: str = "") -> str:
    pr = report.get("pr") or {}
    head, meaning = overall(report)
    out = [COMMENT_MARKER, f"## ARBITER Gate：{head}", "", meaning, ""]
    if pr.get("refused"):
        out += [f"**原因**：{pr['refused']['detail']}", ""]
    touched = pr.get("touched") or {}
    for e in report.get("files") or []:
        v = e["verdict"]
        uri = (e.get("artifact") or {}).get("uri") or e.get("id")
        fns = touched.get(uri) or []
        out += [f"### {_ICON[v]} `{uri}`：{LABELS[v]}", ""]
        f0 = (e.get("findings") or [{}])[0]
        mean, nxt = _MEAN[v]
        if v == PROVEN and f0.get("predicate") and not f0.get("predicate_strict"):
            mean = "AI 寫出的攻擊，在模擬區塊鏈上真的成功了。" + _LOOSE.format(p=f0.get("predicate"))
        out += [mean, "", f"**建議**：{nxt}", ""]
        if fns:
            out.append("這次改到的函式：" + "、".join(f"`{n}`" for n in fns))
        elif pr.get("granularity") == "file":
            out.append("這次改到的函式：（函式索引建不起來，改成整檔稽核，沒有函式名稱）")
        if v == NOT_EXECUTED:
            out += [f"原因：{e.get('reason')}" + (f"；{e['detail'][:300]}" if e.get("detail")
                                                 and e["detail"] != e.get("reason") else "")]
        if v == STATIC_HINT:
            for h in e.get("static_hints") or []:
                out.append(f"- 第 {h.get('line')} 行（{h.get('function') or '函式外'}）："
                           f"`{h.get('check')}` {h.get('impact')}/{h.get('confidence')}")
        out.append("")
        for f in e.get("findings") or []:
            fn = f.get("vulnerable_function") or "?"
            name = fn.split("(")[0].split(".")[-1]
            in_pr = f.get("in_changed_function")
            out += [f"**{f.get('title') or '已證實的攻擊'}**（{f.get('severity') or '?'}）", "",
                    f"- 有漏洞的函式：`{fn}`" + (
                        "（**就是這次改到的函式**）" if in_pr else
                        "（**不是這次改到的函式**：漏洞在這次沒改到的地方，但改到的合約已證實可攻擊，所以一樣擋）"
                        if in_pr is False else ""),
                    f"- 證實方式：攻擊程式在模擬區塊鏈上執行，滿足 `{f.get('predicate')}`（攻擊證明 `{f.get('poc_name')}`）"]
            if f.get("predicate_note"):
                out.append(f"- {f['predicate_note']}")
            abg = f.get("abg") or {}
            out.append(f"- 損失重現（A/B/G）：{abg.get('label')}"
                       + (f"（{abg['note']}）" if abg.get("note") else ""))
            if abg.get("status") == "measured":
                out += [""] + _abg_table(abg.get("environments") or []) + [
                    "", "A＝沒有攻擊時受害者取回的錢；B＝有攻擊時取回的錢；G＝攻擊者的獲利。B 比 A 少就是受害者被拿走的錢。"]
            ev = f.get("evidence") or {}
            if ev.get("reached") == 3:
                s3 = (ev.get("rung3") or {}).get("summary") or {}
                out.append(f"- 本地真鏈（第 3 階）：用真的交易重現損失，shortfall {_eth(s3.get('shortfall'))} ETH、"
                           f"attacker_gain {_eth(s3.get('attacker_gain'))} ETH")
            elif ev.get("reached"):
                out.append(f"- 證據等級：第 {ev['reached']} 階（3 階為本地真鏈重現）")
            p = f.get("patch") or {}
            out += ["", f"**修補**：{p.get('label')}"
                    + (f"（改 {p.get('changed_lines')} 行；用同一個攻擊重打已失效，"
                       + ("沒有攻擊時一般使用者的操作照常成功）" if f.get("predicate") == "liveness_broken"
                          else "誠實使用者的取回金額不變）")
                       if p.get("status") == "verified" else "")]
            out += _rounds_markdown(p)
            if p.get("check2_note"):
                out += ["", f"> ⚠️ {p['check2_note']}"]
            if p.get("status") == "verified":
                out += ["", "<details><summary>修補 diff（忽略空白）</summary>", "", "```diff",
                        p.get("diff_ignore_whitespace", "").replace("src/Target.sol", uri).rstrip(),
                        "```", "</details>"]
            reg = f.get("regression") or {}
            out += ["", "回歸測試：" + (
                "已產生（`TestArbiterRegression`），在這次執行的 Artifacts「arbiter-gate-regression」下載。"
                "把 `test/arbiter/` 放進 repo 後，之後每次修改這個檢查都會自動重跑同一個攻擊。"
                if reg.get("status") == "available" else (reg.get("note") or "未產生")), ""]
    rr = pr.get("regression_rerun") or {}
    if rr.get("status") and rr["status"] != "absent":
        out += ["### repo 裡的回歸測試（TestArbiterRegression）", ""]
        if rr["status"] == "passed":
            out.append(f"✅ 通過（{len(rr.get('tests') or [])} 個測試）：之前證實的攻擊仍然失效，誠實使用者照常取回。")
        elif rr["status"] == "failed":
            out.append("❌ 沒有通過：" + ("、".join(f"`{t}`" for t in rr.get("failed") or [])
                                         or rr.get("reason", "")))
        else:
            out.append(f"沒有執行：{rr.get('reason')}")
        out.append("")
    if pr.get("unscanned"):
        out += ["### 未涵蓋（改了，但這次沒有審）", "",
                "這些不算「未發現可證明攻擊」，是這次沒有看。", ""]
        out += [f"- `{u['path']}`：{u['label']}" for u in pr["unscanned"]] + [""]
    if pr.get("skipped"):
        out += ["### 略過（不是可部署的合約）", ""]
        out += [f"- `{s['path']}`：{skip_reason(s['reason'])}" for s in pr["skipped"]] + [""]
    notes = []
    if pr.get("overload_note"):
        notes.append(pr["overload_note"])
    if pr.get("granularity") == "file":
        notes.append(f"函式索引建不起來（{pr.get('index_error')}），這次改成檔案層級：有新增行的 .sol 整檔稽核。")
    models = "、".join(report.get("models") or []) or "?"
    inp = report.get("input") or {}
    if pr.get("head"):
        notes.append(f"檢查的 commit：`{str(pr['head'])[:12]}`（PR 的 head；之後推新的 commit 會重新檢查並更新這則留言）。")
    if not pr.get("refused"):
        notes.append(f"模型：{models}；這次送出 {inp.get('llm_requests_this_invocation')} 個 AI 請求；"
                     f"沙箱：{(inp.get('sandbox') or {}).get('status', '?')}。")
    notes.append("只有「已證實可攻擊」會擋合併；「無法判定」也不放行。其他結果都不代表合約沒有漏洞。")
    out += ["---", ""] + [f"<sub>{n}</sub><br>" for n in notes]
    if run_url:
        out.append(f"<sub>執行紀錄：{run_url}</sub>")
    return "\n".join(out).rstrip() + "\n"


def refused_report(reason_code: str, label: str, detail: str, *,
                   base: str = "", head: str = "") -> dict[str, Any]:
    """A gate.json for a PR the gate would not run on (a fork): not executed, exit 2."""
    return {"schema": "arbiter-gate/0.1", "input": {"mode": "pr", "run_id": None,
                                                   "llm_requests_this_invocation": 0,
                                                   "sandbox": {"status": "not_started"}},
            "models": [], "exit_code": 2, "files": [],
            "pr": {"base": base, "head": head, "refused": {"code": reason_code, "label": label,
                                                           "detail": detail}},
            "unscanned_reasons": [],
            "note": "稽核沒有執行；這不是發現漏洞，也不是通過。"}


def main(argv: list[str] | None = None) -> int:
    """`python3 -m arbiter.prgate refuse-fork --out gate.json --comment c.md --sarif r.sarif`"""
    import argparse
    ap = argparse.ArgumentParser(prog="python3 -m arbiter.prgate")
    ap.add_argument("action", choices=("refuse-fork",))
    ap.add_argument("--out", required=True)
    ap.add_argument("--comment", required=True)
    ap.add_argument("--sarif")
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="")
    args = ap.parse_args(argv)
    report = refused_report(
        "fork_pr", "這個 PR 來自 fork，系統沒有在這台機器上執行它的程式碼。",
        "fork 來的 PR 拿不到模型端點，而且它的程式碼不能在 runner 主機上執行；所以稽核沒有跑，"
        "結果是「無法判定」（結束碼 2），不算通過。維護者可以把變更搬到同一個 repo 的分支再開 PR。",
        base=args.base, head=args.head)
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1) + "\n",
                              encoding="utf-8")
    Path(args.comment).write_text(comment_markdown(report), encoding="utf-8")
    if args.sarif:
        from .sarif import to_sarif
        sar = to_sarif(report)
        inv = sar["runs"][0]["invocations"][0]
        inv["executionSuccessful"] = False
        inv["toolExecutionNotifications"] = [{"level": "error", "message": {
            "text": f"{LABELS[NOT_EXECUTED]}：{report['pr']['refused']['label']}"}}]
        Path(args.sarif).write_text(json.dumps(sar, ensure_ascii=False, indent=1) + "\n",
                                    encoding="utf-8")
    print(f"{LABELS[NOT_EXECUTED]}：{report['pr']['refused']['label']}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
