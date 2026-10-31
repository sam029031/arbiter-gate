#!/usr/bin/env python3
"""diffscan + PR-mode scoping, checked against fixed cases. No LLM request; needs forge.

    python3 scripts/diffscan_probe.py

bastet-cc shipped diffscan with no tests (plan 7.3), so these are the first:

  parse        parse_diff: ranges from --unified=0, a deletion-only hunk adds no range
               but keeps the file, a deleted file (+++ /dev/null) is dropped
  scope        scope_from_diff: touched names, and each of the four unscanned_reasons
  ast_index    forge build --ast: byte offsets -> lines (a multi-byte comment precedes
               the functions), constructor / receive / fallback named by kind,
               modifiers and free functions, interface declarations
  pr_*         prgate.prepare on a scratch git repo, one PR per case: a function edit,
               deletion only, a constant outside any function, a non-Solidity file, an
               interface (skipped by triage), a deleted file, a checkout not at head, a
               base that does not exist
  suggest      suggestions(): replace / insert / delete blocks rebuild the patched file
  comment      the refusal and "nothing to audit" comments: wording rules (no CLEAR, no
               「安全」 except in 「不等於安全」)

Prints one line per case and "N/N as expected"; exit 0 only if all hold.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ["PATH"] = f"{Path.home() / '.foundry' / 'bin'}:{os.environ.get('PATH', '')}"

from arbiter.diffscan import parse_diff, scope_from_diff  # noqa: E402
from arbiter.prgate import (PRInputError, ast_index, comment_markdown, prepare,  # noqa: E402
                            refused_report, suggestions)

VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// 金庫：中文註解讓位元組位移和字元位移不一樣（每個字 3 個位元組）。
uint256 constant FEE_BPS = 30;

function feeOf(uint256 x) pure returns (uint256) {
    return x * FEE_BPS / 10000;
}

contract Vault {
    mapping(address => uint256) public stakeOf;
    uint256 public constant LIMIT = 100 ether;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    constructor() payable {
        owner = msg.sender;
    }

    function stake() external payable {
        require(msg.value > 0, "zero");
        stakeOf[msg.sender] += msg.value;
    }

    function unstake() external {
        uint256 amount = stakeOf[msg.sender];
        require(amount > 0, "none");
        stakeOf[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send");
    }

    receive() external payable {}

    fallback() external payable {}
}
"""

IFACE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVault {
    function stake() external payable;
    function unstake() external;
}
"""

OLD_FILE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Old {
    uint256 public x;
    function set(uint256 v) external { x = v; }
}
"""

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((name, ok, detail))
    print(f"  [{'ok' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))


def line_of(text: str, needle: str) -> int:
    return text.splitlines().index(next(l for l in text.splitlines() if needle in l)) + 1


def sh(cwd: Path, *args: str) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True).stdout


def case_parse() -> None:
    diff = "\n".join([
        "diff --git a/src/A.sol b/src/A.sol", "--- a/src/A.sol", "+++ b/src/A.sol",
        "@@ -3,0 +4,2 @@", "+x", "+y", "@@ -10 +12 @@", "-a", "+b",
        "diff --git a/src/B.sol b/src/B.sol", "--- a/src/B.sol", "+++ b/src/B.sol",
        "@@ -5,2 +4,0 @@", "-gone", "-gone",
        "diff --git a/src/C.sol b/src/C.sol", "--- a/src/C.sol", "+++ /dev/null",
        "@@ -1,3 +0,0 @@", "-x",
    ])
    got = parse_diff(diff)
    ok = (set(got) == {"src/A.sol", "src/B.sol"} and got["src/A.sol"].added_ranges == [(4, 5), (12, 12)]
          and got["src/B.sol"].added_ranges == [] and got["src/A.sol"].added_lines == 3)
    check("parse", ok, f"{ {k: v.added_ranges for k, v in got.items()} }")


def case_scope() -> None:
    index = {"files": [{"path": "src/V.sol", "functions": [
        {"name": "stake", "start_line": 10, "end_line": 14},
        {"name": "unstake", "start_line": 16, "end_line": 22}]}]}
    diff = parse_diff("\n".join([
        "+++ b/src/V.sol", "@@ -12 +12 @@", "+changed",
        "+++ b/src/K.sol", "@@ -3 +3 @@", "+uint constant K = 2;",
        "+++ b/src/D.sol", "@@ -3,2 +2,0 @@",
        "+++ b/README.md", "@@ -1 +1 @@", "+hi",
    ]))
    index["files"].append({"path": "src/K.sol", "functions": [
        {"name": "f", "start_line": 8, "end_line": 9}]})
    index["files"].append({"path": "src/D.sol", "functions": []})
    sc = scope_from_diff(diff, index)
    r = sc.unscanned_reasons
    # src/N.sol is in the diff but not in the index
    sc2 = scope_from_diff(parse_diff("+++ b/src/N.sol\n@@ -1 +1 @@\n+x"), index)
    ok = (sc.touched == {"src/V.sol": {"stake"}}
          and any(k.startswith("changed outside") and v == ["src/K.sol"] for k, v in r.items())
          and any(k.startswith("deletion only") and v == ["src/D.sol"] for k, v in r.items())
          and r.get("not solidity") == ["README.md"]
          and any(k.startswith("changed but not indexed") for k in sc2.unscanned_reasons))
    check("scope", ok, f"touched={sc.touched} reasons={sorted(r)}")


def case_ast(tmp: Path) -> None:
    proj = tmp / "ast"
    (proj / "src").mkdir(parents=True)
    (proj / "src" / "Vault.sol").write_text(VAULT, encoding="utf-8")
    (proj / "src" / "IVault.sol").write_text(IFACE, encoding="utf-8")
    (proj / "foundry.toml").write_text('[profile.default]\nsrc = "src"\nout = "out"\n')
    index, err = ast_index(proj, tmp / "ast-out")
    if index is None:
        check("ast_index", False, err)
        return
    by = {f["path"]: {fn["name"]: (fn["start_line"], fn["end_line"]) for fn in f["functions"]}
          for f in index["files"]}
    v = by.get("src/Vault.sol", {})
    want = {
        "feeOf": (line_of(VAULT, "function feeOf"), line_of(VAULT, "function feeOf") + 2),
        "modifier onlyOwner": (line_of(VAULT, "modifier onlyOwner"), line_of(VAULT, "modifier onlyOwner") + 3),
        "constructor": (line_of(VAULT, "constructor()"), line_of(VAULT, "constructor()") + 2),
        "stake": (line_of(VAULT, "function stake"), line_of(VAULT, "function stake") + 3),
        "unstake": (line_of(VAULT, "function unstake"), line_of(VAULT, "function unstake") + 6),
        "receive": (line_of(VAULT, "receive()"),) * 2,
        "fallback": (line_of(VAULT, "fallback()"),) * 2,
    }
    bad = {k: (v.get(k), w) for k, w in want.items() if v.get(k) != w}
    iface_ok = set(by.get("src/IVault.sol", {})) == {"stake", "unstake"}
    check("ast_index", not bad and iface_ok,
          f"mismatch {bad}" if bad else f"{len(v)} functions in Vault.sol, interface {iface_ok}")


def _repo(tmp: Path) -> Path:
    repo = tmp / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text(VAULT, encoding="utf-8")
    (repo / "src" / "IVault.sol").write_text(IFACE, encoding="utf-8")
    (repo / "src" / "Old.sol").write_text(OLD_FILE, encoding="utf-8")
    (repo / "foundry.toml").write_text('[profile.default]\nsrc = "src"\nout = "out"\n')
    (repo / "README.md").write_text("demo\n")
    sh(repo, "git", "init", "-q", "-b", "main")
    sh(repo, "git", "-c", "user.name=probe", "-c", "user.email=probe@example.invalid",
       "add", "-A")
    sh(repo, "git", "-c", "user.name=probe", "-c", "user.email=probe@example.invalid",
       "commit", "-q", "-m", "base")
    return repo


def _pr(repo: Path, tmp: Path, name: str, edit) -> dict:
    sh(repo, "git", "checkout", "-q", "main")
    sh(repo, "git", "checkout", "-q", "-b", name)
    edit(repo)
    sh(repo, "git", "-c", "user.name=probe", "-c", "user.email=probe@example.invalid",
       "commit", "-q", "-am", name)
    sh(repo, "git", "add", "-A")
    if sh(repo, "git", "status", "--porcelain").strip():
        sh(repo, "git", "-c", "user.name=probe", "-c", "user.email=probe@example.invalid",
           "commit", "-q", "-m", name + " (new files)")
    job = tmp / f"job-{name}"
    return prepare(repo, "main", name, job)


def _sub(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text, old
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def cases_pr(tmp: Path) -> None:
    repo = _repo(tmp)
    V = lambda r: r / "src" / "Vault.sol"  # noqa: E731

    # The V_ half of the reentrancy pair: the state write moves after the external call.
    pr = _pr(repo, tmp, "fn-edit", lambda r: _sub(
        V(r), '        stakeOf[msg.sender] = 0;\n        (bool ok, ) = msg.sender.call{value: amount}("");\n        require(ok, "send");\n',
        '        (bool ok, ) = msg.sender.call{value: amount}("");\n        require(ok, "send");\n        stakeOf[msg.sender] = 0;\n'))
    check("pr_function_edit", pr["touched"] == {"src/Vault.sol": ["unstake"]}
          and pr["audited"] == ["src/Vault.sol"] and pr["granularity"] == "function"
          and not pr["unscanned"], f"touched={pr['touched']} audited={pr['audited']}")

    pr = _pr(repo, tmp, "del-only", lambda r: _sub(V(r), '        require(amount > 0, "none");\n', ""))
    check("pr_deletion_only", not pr["audited"]
          and [u["code"] for u in pr["unscanned"]] == ["deletion_only"], f"{pr['unscanned']}")

    pr = _pr(repo, tmp, "const", lambda r: _sub(V(r), "LIMIT = 100 ether", "LIMIT = 1000 ether"))
    check("pr_outside_function", not pr["audited"]
          and [u["code"] for u in pr["unscanned"]] == ["outside_function"], f"{pr['unscanned']}")

    pr = _pr(repo, tmp, "readme", lambda r: (r / "README.md").write_text("demo 2\n"))
    check("pr_not_solidity", not pr["audited"]
          and [u["code"] for u in pr["unscanned"]] == ["not_solidity"], f"{pr['unscanned']}")

    pr = _pr(repo, tmp, "iface", lambda r: _sub(r / "src" / "IVault.sol", "function unstake() external;",
                                               "function unstake() external;\n    function total() external view returns (uint256);"))
    check("pr_interface_skipped", not pr["audited"] and len(pr["skipped"]) == 1
          and "interface" in pr["skipped"][0]["reason"], f"skipped={pr['skipped']}")

    def rm(r: Path) -> None:
        (r / "src" / "Old.sol").unlink()
    pr = _pr(repo, tmp, "deleted", rm)
    check("pr_deleted_file", [u["code"] for u in pr["unscanned"]] == ["deleted_file"],
          f"{pr['unscanned']}")

    sh(repo, "git", "checkout", "-q", "main")
    try:
        prepare(repo, "main", "fn-edit", tmp / "job-nothead")
        check("pr_not_at_head", False, "no error raised")
    except PRInputError as exc:
        check("pr_not_at_head", "not at --head" in str(exc), str(exc)[:80])
    try:
        prepare(repo, "deadbeef" * 5, "main", tmp / "job-badbase")
        check("pr_bad_base", False, "no error raised")
    except PRInputError as exc:
        check("pr_bad_base", "fetch-depth: 0" in str(exc), str(exc)[:80])


def case_suggest() -> None:
    a = VAULT
    b = (VAULT.replace("        stakeOf[msg.sender] = 0;\n        (bool ok", "        (bool ok")
         .replace('        require(ok, "send");\n', '        require(ok, "send");\n        stakeOf[msg.sender] = 0;\n')
         .replace("    receive() external payable {}\n", "")
         .replace("pragma solidity ^0.8.20;\n", "pragma solidity ^0.8.20;\n// patched\n"))
    sug = suggestions(a, b, "src/Vault.sol")
    lines = a.splitlines()
    for s in sorted(sug, key=lambda s: -s["start_line"]):
        lines[s["start_line"] - 1:s["end_line"]] = s["body"].split("\n") if s["body"] else []
    rebuilt = "\n".join(lines) + "\n"
    check("suggest", rebuilt == b and len(sug) >= 2, f"{len(sug)} blocks; rebuilt == patched: {rebuilt == b}")


def case_comment() -> None:
    texts = []
    rep = refused_report("fork_pr", "這個 PR 來自 fork", "fork 來的 PR 不執行")
    texts.append(comment_markdown(rep))
    empty = {"exit_code": 0, "files": [], "models": ["arbiter-gpt:latest"],
             "input": {"llm_requests_this_invocation": 0, "sandbox": {"status": "on"}},
             "pr": {"granularity": "function", "touched": {}, "unscanned": [
                 {"path": "src/V.sol", "code": "deletion_only", "label": "只有刪除，沒有新增程式碼可審"}],
                    "skipped": [], "overload_note": "x"}}
    texts.append(comment_markdown(empty))
    # only test files changed (PR #4 of the demo repo): skipped, in the comment's words
    tests_only = {**empty, "pr": {**empty["pr"], "unscanned": [], "skipped": [
        {"path": "test/arbiter/ArbiterRegression.t.sol", "reason": "path is test, mock or deployment scaffolding"},
        {"path": "src/IVault.sol", "reason": "declares no deployable contract (interface)"}]}}
    texts.append(comment_markdown(tests_only))
    banned = [t for t in texts if "CLEAR" in t or re.search(r"(?<!不等於)安全", t)]
    ok = (not banned and "無法判定（稽核未完成）" in texts[0] and "這不是發現漏洞" in texts[0]
          and "未涵蓋" in texts[1] and "只有刪除" in texts[1] and rep["exit_code"] == 2
          and "路徑是測試、mock 或部署腳本" in texts[2] and "只有 interface" in texts[2]
          and "scaffolding" not in texts[2] and "下方「未涵蓋」" not in texts[2])
    check("comment", ok, "wording rules hold" if ok else "see texts")


def main() -> int:
    if shutil.which("forge") is None:
        print("forge not found; this probe needs it")
        return 2
    tmp = Path(tempfile.mkdtemp(prefix="diffscan-probe-"))
    try:
        case_parse()
        case_scope()
        case_ast(tmp)
        cases_pr(tmp)
        case_suggest()
        case_comment()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    good = sum(ok for _, ok, _ in results)
    print(f"{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
