"""Progress events for one gate job: what is happening now, in plain words.

gate.py writes one JSON object per line to the job's events.jsonl (--events); the web
work page reads them back. Everything here is display: no event decides a verdict, and a
failing writer never stops the job.

The seven steps of the work page's bar:

    1 upload      上傳
    2 compile     檢查能不能編譯
    3 ai          AI 分析並寫攻擊
    4 execute     系統實際執行並判定
    5 measure     量損失（A/B/G）
    6 repair      AI 修補與驗證
    7 done        完成

Steps 3 and 4 alternate during an audit: the model chooses a tool (turn event, step 4
while the harness runs it), then reads the result and thinks (request event, step 3).
Whether an attack worked is not in the agent's trace; it is read from the tool result
the next model request carries (gateway on_request hook), and said only when that text
is one of the harness's fixed phrases.
"""

from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from typing import Any

STEPS = [("upload", "上傳"), ("compile", "檢查能不能編譯"), ("ai", "AI 分析並寫攻擊"),
         ("execute", "系統實際執行並判定"), ("measure", "量損失"),
         ("repair", "AI 修補與驗證"), ("done", "完成")]
STEP_INDEX = {k: i for i, (k, _) in enumerate(STEPS)}

TOOL_TEXT = {
    "read_source": "讀合約程式",
    "grep_source": "搜尋程式碼",
    "list_repo_files": "列出專案檔案",
    "read_repo_file": "讀專案裡的其他檔案",
    "grep_repo": "搜尋整個專案",
    "run_poc": "做小實驗（不算證據）",
    "run_exploit": "寫好攻擊交給系統執行",
    "submit_finding": "回報漏洞（系統會檢查證據）",
    "conclude_safe": "AI 認為找不到攻擊",
}

# The harness's own fixed phrases (tools.py), most specific first.
_RESULTS = [
    (r"satisfied .* but it is REFUSED|REFUSED", "refused",
     "攻擊表面上成功，但用了不允許的手段（例如憑空變出錢），系統不算數"),
    (r"PASSED the harness predicate", "passed",
     "攻擊成立：系統確認有攻擊時受害者拿回的錢變少了"),
    (r"compiled but did NOT satisfy", "no_harm",
     "攻擊程式跑完了，但沒有造成損失；AI 正在修改"),
    (r"did NOT compile|failed to compile|COMPILATION FAILED", "compile_failed",
     "AI 寫的程式沒辦法編譯，正在修正"),
    (r"compiled but FAILED", "experiment_failed", "小實驗沒有成功（不算證據）"),
    (r"PoC .* PASSED|PASSED", "experiment_passed", "小實驗成功（只是探索，不算證據）"),
    (r"SUBMISSION REJECTED", "submission_rejected", "回報被系統退回：沒有對應的成功攻擊"),
    (r"Finding accepted", "finding_accepted", "系統接受回報：有已執行成功的攻擊當證據"),
    (r"NOT YET", "conclude_refused", "系統不接受：還沒實際攻擊過就想下結論"),
    (r"Safe verdict recorded", "concluded", "AI 結束搜尋：沒有找到能成功的攻擊"),
    (r"^error:", "tool_error", "工具回報錯誤，AI 正在調整"),
]


def classify_result(tool: str, text: str) -> tuple[str, str]:
    """(code, plain sentence) for one tool result; reading tools are just 'done'."""
    if tool in ("read_source", "grep_source", "list_repo_files", "read_repo_file", "grep_repo"):
        return "read", "讀完了，AI 依內容繼續"
    for pattern, code, words in _RESULTS:
        if re.search(pattern, text or "", re.MULTILINE):
            return code, words
    return "done", "執行完成，AI 依結果繼續"


def brief_args(name: str, raw: str) -> dict[str, Any]:
    """The short, safe-to-show parameters of a tool call (no attack code)."""
    try:
        args = json.loads(raw or "{}")
    except (json.JSONDecodeError, TypeError):
        return {}
    keep = {}
    for k in ("predicate", "name", "mode", "pattern", "start_line", "end_line",
              "vulnerable_function", "severity", "title", "poc_name"):
        if k in args and args[k] not in (None, ""):
            keep[k] = str(args[k])[:120]
    for k in ("hypothesis", "reason"):
        if args.get(k):
            keep[k] = str(args[k])[:200]
    return keep


class Events:
    """Append-only events.jsonl writer, safe from several threads."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.t0 = time.time()

    def emit(self, kind: str, **data: Any) -> None:
        rec = {"t": round(time.time(), 3), "kind": kind, **data}
        try:
            with self._lock, self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def stage(self, step: str, text: str, **data: Any) -> None:
        self.emit("stage", step=step, index=STEP_INDEX[step], text=text, **data)


class _Null:
    def emit(self, *a: Any, **k: Any) -> None:
        pass

    def stage(self, *a: Any, **k: Any) -> None:
        pass


EV: Events | _Null = _Null()


def use(events: Events | None) -> None:
    global EV
    EV = events or _Null()


def read(path: Path, since: int = 0) -> list[dict[str, Any]]:
    if not Path(path).exists():
        return []
    out = []
    for i, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines()):
        if i < since or not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


class AuditHooks:
    """run_arbiter's on_turn / on_request / on_row, turned into events."""

    def __init__(self) -> None:
        self.seen_tool_ids: set[str] = set()
        self.names: dict[str, str] = {}
        self.attempt: int | None = None

    def on_turn(self, e: dict[str, Any]) -> None:
        if e.get("attempt") != self.attempt:
            self.attempt = e.get("attempt")
            EV.emit("attempt", attempt=e["attempt"] + 1, attempts=e.get("attempts"))
        tools = [{"name": c.get("name"), "text": TOOL_TEXT.get(c.get("name") or "", c.get("name")),
                  "args": brief_args(c.get("name") or "", c.get("arguments") or "")}
                 for c in e.get("tool_calls") or []]
        EV.emit("turn", attempt=e["attempt"] + 1, attempts=e.get("attempts"),
                turn=e.get("turn", 0) + 1, max_turns=e.get("max_turns"), tools=tools,
                finish_reason=e.get("finish_reason"),
                thought=(e.get("content") or "")[:600])
        runs = [t for t in tools if t["name"] in ("run_exploit", "run_poc")]
        if runs:
            what = ("AI 寫好了一段攻擊程式，系統正在隔離環境裡的模擬區塊鏈上實際執行它"
                    if runs[0]["name"] == "run_exploit" else
                    "AI 在做一個小實驗（不算證據），系統正在執行")
            EV.stage("execute", what)
        elif any(t["name"] == "submit_finding" for t in tools):
            EV.stage("execute", "AI 回報找到漏洞，系統正在核對它是否有已執行成功的攻擊當證據")
        elif any(t["name"] == "conclude_safe" for t in tools):
            EV.stage("execute", "AI 認為找不到能成功的攻擊，系統正在確認它是否真的試過")

    def on_request(self, messages: list[dict[str, Any]], tag: str) -> None:
        for m in messages:
            for c in m.get("tool_calls") or []:
                self.names[c.get("id", "")] = (c.get("function") or {}).get("name", "")
        new = [m for m in messages if m.get("role") == "tool"
               and m.get("tool_call_id") not in self.seen_tool_ids]
        for m in new:
            self.seen_tool_ids.add(m.get("tool_call_id"))
            tool = self.names.get(m.get("tool_call_id", ""), "")
            code, words = classify_result(tool, m.get("content") or "")
            EV.emit("tool_result", tool=tool, code=code, text=words)
        EV.stage("ai", "AI 正在讀合約和上一步的結果，決定下一步" if new else
                 "AI 正在讀合約，想可能的攻擊方式")

    def on_row(self, row: dict[str, Any]) -> None:
        o = row.get("outcome") or {}
        EV.emit("row", sample_id=row.get("sample_id"), proven=bool(o.get("proven")),
                stop_reason=o.get("stop_reason"), attempts_used=row.get("attempts_used"),
                elapsed_s=row.get("elapsed_s"))


class _Proxy:
    """What other modules import: forwards to whichever writer `use()` installed."""

    def emit(self, *a: Any, **k: Any) -> None:
        EV.emit(*a, **k)

    def stage(self, *a: Any, **k: Any) -> None:
        EV.stage(*a, **k)


EV_PROXY = _Proxy()
