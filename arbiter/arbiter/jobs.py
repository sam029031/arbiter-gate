"""Background jobs for the web page: one worker, one job at a time, state on disk.

A job is a directory runs/gate/jobs/<id>/ with job.json (what, status, times, result
id) and events.jsonl (progress.py events). The page polls /api/job/<id>; reloading a
page only reads these files, so nothing is ever re-run. On start-up a job left
"queued" or "running" by a previous server is marked "interrupted", not resumed.

Kinds:
  upload / demo  `python3 -m arbiter.gate --file ... --mode repo --repair`, always in
                 the sandbox (the upload path's rule since P3), with --events
  playback       a recorded run replayed on the same work page: the audit's turns are
                 rebuilt from what was recorded (results trace, ledger timings, the
                 order of PoCs) and shown at 1x or 4x, marked as a recording; then
                 `gate --from-results --patches` re-runs A/B/G, the patch checks and
                 the evidence ladder with forge, live
  chain          scripts/live_attack_stakingvault.py on the original contract and on
                 the spark-test-2 patch: the reference attack on a local chain
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Callable

from . import sandbox
from .progress import TOOL_TEXT, brief_args, classify_result

RIG = Path(__file__).resolve().parent.parent
RUNS = RIG / "runs"
JOBS = RUNS / "gate" / "jobs"
UPLOAD_TIMEOUT = 900


# -- the store ----------------------------------------------------------------------------

def job_dir(jid: str) -> Path:
    return JOBS / jid


def load(jid: str) -> dict[str, Any] | None:
    p = job_dir(jid) / "job.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def save(job: dict[str, Any]) -> None:
    d = job_dir(job["id"])
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "job.json.tmp"
    tmp.write_text(json.dumps(job, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp.replace(d / "job.json")


def emit(jid: str, kind: str, **data: Any) -> None:
    with (job_dir(jid) / "events.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"t": round(time.time(), 3), "kind": kind, **data},
                            ensure_ascii=False) + "\n")


def all_jobs() -> list[dict[str, Any]]:
    out = []
    for p in JOBS.glob("*/job.json"):
        try:
            out.append(json.loads(p.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return sorted(out, key=lambda j: j["created"])


def position(jid: str) -> int:
    """How many jobs are ahead of this one (queued or running, submitted earlier)."""
    me = load(jid)
    if me is None or me["status"] not in ("queued",):
        return 0
    return sum(1 for j in all_jobs() if j["status"] in ("queued", "running")
               and j["created"] < me["created"])


ARCHIVE = RIG.parent.parent / "runs_archive"   # where old runs are moved, if present


def timing_history() -> dict[str, Any]:
    """Wall-clock of every repo-mode live audit by arbiter-gpt whose record is still on
    this machine (runs/, runs/gate/, and the runs_archive beside the checkout): one
    contract per run, the mode the web page uses. Read from the records, never typed."""
    secs: dict[str, float] = {}
    roots = [RUNS, RUNS / "gate"] + ([ARCHIVE] if ARCHIVE.exists() else [])
    for root in roots:
        for p in root.rglob("*.summary.json"):
            try:
                s = json.loads(p.read_text(encoding="utf-8"))
                inp = p.with_name(p.name.replace(".summary.json", ".input.json"))
                items = json.loads(inp.read_text(encoding="utf-8")).get("items") if inp.exists() else None
            except (json.JSONDecodeError, OSError):
                continue
            if (not items or len(items) != 1 or not items[0].get("path")
                    or "arbiter-gpt" not in str(s.get("model")) or not s.get("wall_clock_s")):
                continue
            secs[s.get("run_id") or p.stem] = float(s["wall_clock_s"])
    v = sorted(secs.values())
    return {"n": len(v), "min": round(v[0]) if v else None, "max": round(v[-1]) if v else None}


# -- the worker ---------------------------------------------------------------------------

class Queue:
    def __init__(self, runner: Callable[[dict[str, Any]], None]) -> None:
        self.runner = runner
        self.q: deque[str] = deque()
        self.cv = threading.Condition()
        JOBS.mkdir(parents=True, exist_ok=True)
        for j in all_jobs():
            if j["status"] in ("queued", "running"):
                j.update(status="interrupted", finished=time.time(),
                         error="伺服器重新啟動時這份工作還沒完成，沒有自動重跑")
                save(j)
        threading.Thread(target=self._work, daemon=True).start()

    def submit(self, kind: str, label: str, params: dict[str, Any]) -> str:
        jid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        job = {"id": jid, "kind": kind, "label": label, "params": params,
               "status": "queued", "created": time.time(), "started": None,
               "finished": None, "rid": None, "error": ""}
        save(job)
        emit(jid, "stage", step="upload", index=0,
             text=f"已收到：{label}" + ("" if kind != "playback" else "（錄製回放）"))
        with self.cv:
            self.q.append(jid)
            self.cv.notify()
        return jid

    def _work(self) -> None:
        while True:
            with self.cv:
                while not self.q:
                    self.cv.wait()
                jid = self.q.popleft()
            job = load(jid)
            if job is None:
                continue
            job.update(status="running", started=time.time())
            save(job)
            try:
                self.runner(job)
                job = load(jid) or job
                job["status"] = "done" if not job.get("error") else "failed"
            except Exception as exc:  # noqa: BLE001
                job = load(jid) or job
                job.update(status="failed", error=f"{type(exc).__name__}: {exc}"[:300])
            job["finished"] = time.time()
            save(job)


# -- playback: rebuild the audit's progress from what was recorded ------------------------

def recorded_timeline(results: Path) -> dict[str, Any]:
    """Events (with the delay before each) rebuilt from a recorded run, and what was not
    recorded. Uses the row's trace (last attempt only), the ledger's per-request time,
    and the order of PoCs; nothing else is invented."""
    row = json.loads(next(l for l in results.read_text(encoding="utf-8").splitlines() if l.strip()))
    ledger_p = results.with_name(results.name.replace(".results.jsonl", ".ledger.jsonl"))
    ledger = [json.loads(l) for l in ledger_p.read_text(encoding="utf-8").splitlines()
              if l.strip()] if ledger_p.exists() else []
    trace = row.get("trace") or []
    attempts = row.get("attempts") or []
    last_attempt = attempts[-1]["attempt"] if attempts else 0
    lat = [e for e in ledger if e.get("attempt", 0) == 0 and ":turn" in str(e.get("tag"))]
    # requests of the final attempt are the last len(trace) answered ones
    final_lat = lat[-len(trace):] if trace and len(lat) >= len(trace) else []
    runs = [c for t in trace for c in t.get("tool_calls") or []
            if c.get("name") in ("run_exploit", "run_poc")]
    pocs = (row.get("outcome") or {}).get("pocs") or []
    aligned = len(pocs) == len([c for c in runs if c.get("name") == "run_exploit"]) + \
        len([c for c in runs if c.get("name") == "run_poc"])
    model_s = sum(float(e.get("elapsed_s") or 0) for e in final_lat)
    exec_est = max(0.0, (float(row.get("elapsed_s") or 0) - model_s) / max(1, len(runs)))
    notes = []
    if not final_lat:
        notes.append("錄製紀錄裡沒有每次 AI 回應的耗時，這裡每回合用 5 秒示意")
    notes.append(f"每次執行攻擊的耗時沒有逐次記錄，這裡用平均值（約 {exec_est:.1f} 秒）示意")
    if len(attempts) > 1:
        notes.append(f"錄製時共嘗試 {len(attempts)} 次，只有最後一次有逐回合紀錄")
    if not aligned:
        notes.append("每次攻擊的成敗無法和回合一一對上，只顯示「執行完成」")

    tl: list[tuple[float, dict[str, Any]]] = []
    tl.append((1.0, {"kind": "stage", "step": "compile", "index": 1,
                     "text": "檢查合約能不能編譯（錄製時通過；耗時沒有記錄）"}))
    tl.append((1.0, {"kind": "stage", "step": "ai", "index": 2, "text": "AI 開始讀合約，想可能的攻擊方式"}))
    tl.append((0.0, {"kind": "attempt", "attempt": last_attempt + 1,
                     "attempts": len(attempts) or 1}))
    poc_i = 0
    for i, t in enumerate(trace):
        think = float(final_lat[i]["elapsed_s"]) if final_lat else 5.0
        tools = [{"name": c.get("name"), "text": TOOL_TEXT.get(c.get("name") or "", c.get("name")),
                  "args": brief_args(c.get("name") or "", c.get("arguments") or "")}
                 for c in t.get("tool_calls") or []]
        tl.append((think, {"kind": "turn", "attempt": last_attempt + 1,
                           "attempts": len(attempts) or 1, "turn": t.get("turn", i) + 1,
                           "max_turns": None, "tools": tools,
                           "finish_reason": t.get("finish_reason"),
                           "thought": (t.get("content") or "")[:600],
                           "model_seconds": round(think, 1)}))
        for c in t.get("tool_calls") or []:
            name = c.get("name") or ""
            if name in ("run_exploit", "run_poc"):
                tl.append((0.0, {"kind": "stage", "step": "execute", "index": 3,
                                 "text": "AI 寫好了一段攻擊程式，系統正在隔離環境裡的模擬區塊鏈上實際執行它"
                                 if name == "run_exploit" else "AI 在做一個小實驗（不算證據），系統正在執行"}))
                if aligned and poc_i < len(pocs):
                    p = pocs[poc_i]
                    poc_i += 1
                    code, words = (("passed", "攻擊成立：系統確認有攻擊時受害者拿回的錢變少了")
                                   if p.get("passed") and p.get("adjudicated") else
                                   ("compile_failed", "AI 寫的程式沒辦法編譯，正在修正")
                                   if p.get("compiled") is False else
                                   ("no_harm", "攻擊程式跑完了，但沒有造成損失；AI 正在修改"))
                else:
                    code, words = classify_result(name, "")
                tl.append((exec_est, {"kind": "tool_result", "tool": name, "code": code,
                                      "text": words, "estimated_seconds": round(exec_est, 1)}))
                tl.append((0.0, {"kind": "stage", "step": "ai", "index": 2,
                                 "text": "AI 正在讀上一步的結果，決定下一步"}))
            elif name == "submit_finding":
                tl.append((0.0, {"kind": "stage", "step": "execute", "index": 3,
                                 "text": "AI 回報找到漏洞，系統正在核對它是否有已執行成功的攻擊當證據"}))
                ok = (row.get("outcome") or {}).get("proven")
                tl.append((1.0, {"kind": "tool_result", "tool": name,
                                 "code": "finding_accepted" if ok else "submission_rejected",
                                 "text": "系統接受回報：有已執行成功的攻擊當證據" if ok else
                                 "回報被系統退回：沒有對應的成功攻擊"}))
            elif name == "conclude_safe":
                tl.append((1.0, {"kind": "tool_result", "tool": name, "code": "concluded",
                                 "text": "AI 結束搜尋：沒有找到能成功的攻擊"}))
        if not t.get("tool_calls"):
            tl.append((0.0, {"kind": "stage", "step": "ai", "index": 2,
                             "text": "AI 在整理想法（這一回合沒有呼叫工具）"}))
    o = row.get("outcome") or {}
    tl.append((0.5, {"kind": "row", "sample_id": row.get("sample_id"), "proven": bool(o.get("proven")),
                     "stop_reason": o.get("stop_reason"), "attempts_used": row.get("attempts_used"),
                     "elapsed_s": row.get("elapsed_s")}))
    return {"timeline": tl, "notes": notes, "row": row,
            "model": (ledger[0].get("model_served") if ledger else None),
            "recorded_on": time.strftime("%Y-%m-%d", time.localtime(results.stat().st_mtime)),
            "recorded_elapsed_s": row.get("elapsed_s")}


def recorded_patch(patches: Path | None) -> dict[str, Any] | None:
    """How the recorded patch came about: rounds the model needed, and which one passed."""
    if patches is None or not patches.exists():
        return None
    rec = next((json.loads(l) for l in patches.read_text(encoding="utf-8").splitlines()
                if l.strip() and json.loads(l).get("status") == "accepted"), None)
    if rec is None:
        return None
    rounds = rec.get("rounds") or []
    ok = next((int(r.get("round", 0)) + 1 for r in rounds if r.get("first_failure") is None),
              len(rounds))
    return {"rounds": len(rounds), "accepted_round": ok, "model": rec.get("model")}


# -- runners --------------------------------------------------------------------------------

def run_gate_job(job: dict[str, Any], argv: list[str], sandboxed: bool,
                 timeout: int, lock: threading.Lock) -> dict[str, Any] | None:
    """`python3 -m arbiter.gate` for a job, events into its events.jsonl."""
    d = job_dir(job["id"])
    out = d / "gate.json"
    env = dict(os.environ)
    if sandboxed:
        env["ARBITER_SANDBOX"] = "1"
    run_id = f"web-{job['id']}"
    if "--file" in argv or "--project" in argv:
        argv = [*argv, "--run-id", run_id]
    with lock:
        try:
            subprocess.run(  # noqa: S603
                [sys.executable, "-m", "arbiter.gate", *argv, "--out", str(out),
                 "--events", str(d / "events.jsonl")],
                cwd=RIG, capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            sandbox.remove(sandbox.container_name(run_id))
            emit(job["id"], "stage", step="done", index=6, text="超過時間限制，已終止",
                 verdicts=["not_executed"], exit_code=2)
            return None
    return json.loads(out.read_text(encoding="utf-8")) if out.exists() else None


def play(job: dict[str, Any], timeline: list[tuple[float, dict[str, Any]]], speed: float) -> None:
    for delay, ev in timeline:
        if delay > 0:
            time.sleep(delay / speed)
        emit(job["id"], **ev)
