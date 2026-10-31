#!/usr/bin/env python3
"""Post ARBITER Gate's result on a pull request: one comment (updated in place) and, when a
verified patch lands on lines of the PR's diff, a review with suggestion blocks.

    GITHUB_TOKEN=... python3 scripts/gate_pr_publish.py --out-dir DIR \
        --repo owner/name --pr N --head SHA

Reads DIR/comment.md and DIR/gate.json (written by scripts/gate_pr.sh). GITHUB_TOKEN is
the workflow's own token (pull-requests: write, issues: write); nothing else is needed.

GitHub accepts review comments only on lines that appear in the PR's diff. A suggestion
whose lines all do is posted as a review comment ("Commit suggestion" applies it);
otherwise the comment gets the patch as a diff instead, and says why. Re-running on the
same head does not post the suggestions twice.

Standard library only. Prints statuses, never the token or a request header; an HTTP
error prints its status and GitHub's message. A token that may not write (a fork PR's)
is reported and the script exits 0 -- the check's own exit code is what fails the run.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from arbiter.prgate import COMMENT_MARKER  # noqa: E402

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
SUGGESTION_MARK = "<!-- arbiter-gate:suggestion head={head} -->"


class HTTPFail(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


def call(method: str, path: str, body: dict | None = None) -> object:
    token = os.environ.get("GITHUB_TOKEN", "")
    req = urllib.request.Request(
        f"{API}{path}", method=method,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
                 "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "arbiter-gate"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        try:
            msg = json.loads(exc.read() or b"{}").get("message", "")
        except (json.JSONDecodeError, ValueError):
            msg = ""
        raise HTTPFail(exc.code, str(msg)[:200]) from None
    return json.loads(raw) if raw else None


def paged(path: str) -> list:
    out, page = [], 1
    while True:
        sep = "&" if "?" in path else "?"
        chunk = call("GET", f"{path}{sep}per_page=100&page={page}")
        if not isinstance(chunk, list) or not chunk:
            return out
        out += chunk
        if len(chunk) < 100:
            return out
        page += 1


def commentable(patch: str) -> set[int]:
    """New-side line numbers present in one file's PR diff (context and added lines)."""
    lines: set[int] = set()
    new = 0
    for ln in (patch or "").splitlines():
        m = re.match(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", ln)
        if m:
            new = int(m.group(1))
            continue
        if ln.startswith("-") or ln.startswith("\\"):
            continue
        lines.add(new)
        new += 1
    return lines


def plan_suggestions(gate: dict, files: list[dict]) -> tuple[list[dict], list[dict]]:
    """(review comments, unplaced patches)."""
    diff_lines = {f["filename"]: commentable(f.get("patch", "")) for f in files}
    placed, unplaced = [], []
    for e in gate.get("files") or []:
        for fd in e.get("findings") or []:
            p = fd.get("patch") or {}
            if p.get("status") != "verified":
                continue
            sug = p.get("suggestions") or []
            ok = sug and all(set(range(s["start_line"], s["end_line"] + 1))
                             <= diff_lines.get(s["path"], set()) for s in sug)
            if ok:
                placed += [{"finding": fd, "s": s} for s in sug]
            else:
                unplaced.append({"finding": fd, "uri": (e.get("artifact") or {}).get("uri"),
                                 "patch": p.get("patch_for_repo") or p.get("diff") or "",
                                 "why": p.get("suggestions_note") or
                                 "修補改到的行不在這次 PR 的 diff 裡，GitHub 不允許在那些行上留建議"})
    return placed, unplaced


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--head", required=True)
    a = ap.parse_args()
    out = Path(a.out_dir)
    md_path, gate_path = out / "comment.md", out / "gate.json"
    if not md_path.exists():
        print("no comment to post (the gate did not run an audit)")
        return 0
    if not os.environ.get("GITHUB_TOKEN"):
        print("GITHUB_TOKEN is not set; nothing posted")
        return 0
    body = md_path.read_text(encoding="utf-8")
    gate = json.loads(gate_path.read_text(encoding="utf-8")) if gate_path.exists() else {}
    base = f"/repos/{a.repo}"
    try:
        placed, unplaced = [], []
        if any((fd.get("patch") or {}).get("status") == "verified"
               for e in gate.get("files") or [] for fd in e.get("findings") or []):
            placed, unplaced = plan_suggestions(gate, paged(f"{base}/pulls/{a.pr}/files"))
        extra = []
        if placed:
            mark = SUGGESTION_MARK.format(head=a.head)
            seen = any(mark in (c.get("body") or "")
                       for c in paged(f"{base}/pulls/{a.pr}/comments"))
            if not seen:
                comments = []
                for item in placed:
                    s = item["s"]
                    kept = ("沒有攻擊時一般使用者的操作照常成功"
                            if item["finding"].get("predicate") == "liveness_broken"
                            else "誠實使用者的取回金額不變")
                    c = {"path": s["path"], "line": s["end_line"], "side": "RIGHT",
                         "body": (f"{mark}\nARBITER Gate 的修補建議：已通過修補閘門"
                                  f"（用同一個攻擊重打已失效，{kept}）。"
                                  "審閱後可以按「Commit suggestion」套用。\n\n"
                                  f"```suggestion\n{s['body']}\n```\n")}
                    if s["start_line"] != s["end_line"]:
                        c.update(start_line=s["start_line"], start_side="RIGHT")
                    comments.append(c)
                call("POST", f"{base}/pulls/{a.pr}/reviews",
                     {"commit_id": a.head, "event": "COMMENT", "comments": comments,
                      "body": "ARBITER Gate：修補建議（suggestion）"})
                print(f"review posted: {len(comments)} suggestion block(s)")
            else:
                print("suggestions for this head already posted")
            spans = "、".join(
                f"`{i['s']['path']}` 第 {i['s']['start_line']} 行" if i['s']['start_line'] == i['s']['end_line']
                else f"`{i['s']['path']}` 第 {i['s']['start_line']}–{i['s']['end_line']} 行" for i in placed)
            extra.append(f"\n**修補建議**：已在 {spans} 附上 suggestion，可以在「Files changed」直接套用。\n")
        for u in unplaced:
            extra += [f"\n**修補建議（`{u['uri']}`）**：{u['why']}，所以改附在這裡。"
                      "可以用 `git apply` 套用：\n", "```diff", u["patch"].rstrip(), "```\n"]
        if extra:
            body = body.replace("\n---\n", "\n" + "\n".join(extra) + "\n---\n", 1)
        existing = [c for c in paged(f"/repos/{a.repo}/issues/{a.pr}/comments")
                    if COMMENT_MARKER in (c.get("body") or "")
                    and (c.get("user") or {}).get("type") == "Bot"]
        if existing:
            call("PATCH", f"/repos/{a.repo}/issues/comments/{existing[0]['id']}", {"body": body})
            print("PR comment updated")
        else:
            call("POST", f"/repos/{a.repo}/issues/{a.pr}/comments", {"body": body})
            print("PR comment posted")
    except HTTPFail as exc:
        if exc.status in (401, 403, 404):
            print(f"could not write to the PR ({exc}); a fork PR's token is read-only")
            return 0
        print(f"publishing failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
