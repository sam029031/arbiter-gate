"""Which functions a pull request changed, and which changes the gate cannot see.

ARBITER Gate's PR mode (`python3 -m arbiter.gate --repo DIR --base SHA --head SHA`)
audits the Solidity files in which a pull request touched at least one function,
instead of the whole repository: a live audit costs model requests and minutes per
file, and a PR usually changes one or two functions.

    parse_diff(git_diff(base, head, repo_root))   -> added line ranges per file
    scope_from_diff(changed, index)                -> touched functions per file,
                                                      plus unscanned_reasons

The function index is `{"files": [{"path", "functions": [{"name", "start_line",
"end_line"}]}]}`. gate.py builds it from the solc AST (`forge build --ast`), so this
module needs no Solidity parser of its own.

Two decisions, both stated because both cost recall:

- **A changed function is audited whole**, and in practice the whole file is handed to
  the agent: a bug is rarely confined to the edited line. The touched names go into the
  report so a reader can see what the PR changed.

- **Deleting code is not scanned.** A hunk with no added lines removes code, and there
  is nothing new to audit. It is recorded, because "this PR was clean" and "this PR
  had nothing to look at" are different statements.

What this cannot see is stated in `unscanned_reasons`, which the gate reports as
"未涵蓋" and never counts as "未發現可證明攻擊": a non-Solidity file, a deletion-only
change, a Solidity file the index does not hold (it did not compile into the index,
or sits outside the build), and a change outside any function body (a state
variable, a constant, a pragma, an import). The last is a real blind spot of a
function-granular gate; a constant is frequently exactly what a bug is.

`touched` keeps function names only, so overloads of one name collapse into one entry.
`git_diff` needs the full history: a shallow CI checkout needs `fetch-depth: 0`.

Provenance: borrowed byte-for-byte from Bastet-CC (`bastet-cc/bastet_cc/diffscan.py`,
commit 7b957d0, 2026-07-25, AIS3 2026 Team 011, Apache-2.0 as the rest of this
repository; see LICENSE and NOTICE). Only the docstrings were rewritten since; the
code is unchanged.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

# `git diff --unified=0` hunk header: -old,count +new,count
_HUNK = re.compile(r"^@@ -(?:\d+)(?:,(?:\d+))? \+(\d+)(?:,(\d+))? @@")
_DIFF_FILE = re.compile(r"^\+\+\+ b/(.*)$")


@dataclass
class ChangedFile:
    path: str
    added_ranges: list[tuple[int, int]] = field(default_factory=list)

    @property
    def added_lines(self) -> int:
        return sum(e - s + 1 for s, e in self.added_ranges)


def parse_diff(diff_text: str) -> dict[str, ChangedFile]:
    """Added/modified line ranges per file, from `git diff --unified=0` output.

    Zero context is what makes this precise: with the default three lines of
    context a hunk header spans code the commit did not touch, and the gate would
    audit neighbouring functions on every edit.

    A hunk with `+0` lines is a pure deletion and contributes no range. The file
    still appears in the result with an empty range list, so a caller can tell
    "touched but nothing added" from "not touched".
    """
    files: dict[str, ChangedFile] = {}
    current: ChangedFile | None = None

    for line in diff_text.splitlines():
        m = _DIFF_FILE.match(line)
        if m:
            path = m.group(1)
            if path == "/dev/null":          # file deleted outright
                current = None
                continue
            current = files.setdefault(path, ChangedFile(path=path))
            continue
        if current is None:
            continue
        h = _HUNK.match(line)
        if h:
            start = int(h.group(1))
            count = 1 if h.group(2) is None else int(h.group(2))
            if count == 0:
                continue                     # deletion-only hunk
            current.added_ranges.append((start, start + count - 1))
    return files


def git_diff(base: str, head: str = "", repo_root: Path | None = None) -> str:
    """`git diff --unified=0` between two refs, or of the working tree.

    Passing `head=""` diffs the working tree against `base`, which is what a
    developer running the gate locally before pushing wants.
    """
    cmd = ["git", "diff", "--unified=0", "--no-color", "--no-ext-diff",
           "--diff-filter=ACMR", base]
    if head:
        cmd.append(head)
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          cwd=str(repo_root) if repo_root else None)
    if proc.returncode != 0:
        raise RuntimeError(
            f"git diff failed ({proc.returncode}). Is {base!r} a valid ref, and is "
            f"the history deep enough? A shallow CI checkout needs "
            f"`fetch-depth: 0`.\n{proc.stderr.strip()}")
    return proc.stdout


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


@dataclass
class DiffScope:
    """Which indexed functions a diff touched, and what it could not reach."""
    touched: dict[str, set[str]] = field(default_factory=dict)   # path -> {fn names}
    changed_files: int = 0
    changed_sol_files: int = 0
    added_lines: int = 0
    unscanned_reasons: dict[str, list[str]] = field(default_factory=dict)

    @property
    def n_functions(self) -> int:
        return sum(len(v) for v in self.touched.values())

    def to_dict(self) -> dict:
        return {
            "changed_files": self.changed_files,
            "changed_sol_files": self.changed_sol_files,
            "added_lines": self.added_lines,
            "touched_functions": self.n_functions,
            "touched": {p: sorted(v) for p, v in sorted(self.touched.items())},
            "unscanned_reasons": {k: sorted(v)
                                  for k, v in sorted(self.unscanned_reasons.items())},
        }


def scope_from_diff(diff_files: dict[str, ChangedFile], repo_index: dict) -> DiffScope:
    """Intersect a diff's added ranges with the index's function spans.

    Paths are compared after POSIX normalisation on both sides: git always emits
    forward slashes, and the index does too since it uses `as_posix()`, but a caller
    may hand in either.
    """
    by_path = {f["path"].replace("\\", "/"): f for f in repo_index["files"]}
    scope = DiffScope(changed_files=len(diff_files))

    def note(reason: str, item: str) -> None:
        scope.unscanned_reasons.setdefault(reason, []).append(item)

    for raw_path, changed in diff_files.items():
        path = raw_path.replace("\\", "/")
        if not path.endswith(".sol"):
            note("not solidity", path)
            continue
        scope.changed_sol_files += 1
        scope.added_lines += changed.added_lines

        if not changed.added_ranges:
            note("deletion only, nothing added to audit", path)
            continue

        entry = by_path.get(path)
        if entry is None:
            # The file changed but the index does not hold it: vendored,
            # non-production, or excluded by scope.txt. A real blind spot of a
            # function-granular gate, so it is named rather than counted as clean.
            note("changed but not indexed (vendor / non-production / out of scope)",
                 path)
            continue

        hit: set[str] = set()
        for fn in entry["functions"]:
            span = (fn["start_line"], fn["end_line"])
            if any(_overlaps(span, r) for r in changed.added_ranges):
                hit.add(fn["name"])
        if hit:
            scope.touched[path] = hit
        else:
            note("changed outside any function body (state variable, constant, "
                 "pragma, import)", path)
    return scope


def restrict_index(repo_index: dict, scope: DiffScope) -> dict:
    """A copy of the index holding only the touched functions.

    Kept from Bastet-CC, where a routed planner ran over the restricted index; ARBITER
    Gate does not call it (it audits whole files). `n_bytes`, if present, is left at
    the original file size on purpose.
    """
    files = []
    for f in repo_index["files"]:
        path = f["path"].replace("\\", "/")
        keep = scope.touched.get(path)
        if not keep:
            continue
        fns = [fn for fn in f["functions"] if fn["name"] in keep]
        if fns:
            files.append({**f, "functions": fns})

    return {
        **repo_index,
        "n_files": len(files),
        "n_functions": sum(len(f["functions"]) for f in files),
        "files": files,
        "diff_scoped": True,
    }
