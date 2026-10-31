"""ARBITER Gate, the local web page: upload a contract or watch a recorded audit.

    python3 -m arbiter.web [--port 8765]

Standard library only, bound to 127.0.0.1 and nothing else, nothing loaded from outside
(the finals venue's network may be unreliable). Rendering is in arbiter/webui.py; this
module holds the routes, the job runner and the downloads.

Work goes through one background worker (arbiter/jobs.py), one job at a time:

  * upload / demo contract: `gate --file --mode repo --repair`, always in the per-job
    sandbox (no switch to turn that off; no sandbox means "not executed"), progress
    events written by gate --events and shown live on /job/<id>
  * playback of a recorded run (finals backup L1): the audit's turns rebuilt from the
    recording at 1x or 4x and marked as a recording, then A/B/G, the patch checks and
    the evidence ladder re-run with forge
  * the reference chain demo: scripts/live_attack_stakingvault.py, original and patched

POST /replay (no job page, straight to the result) stays for scripts/demo_gate.sh.
Replays follow ARBITER_SANDBOX (default off); see reports/fullplan_p3_*.md.

Every download goes through gate.public_report, so none carries a host path.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import gate as gate_mod
from . import jobs, progress, sandbox, webui
from .dump import regression_unavailable_reason
from .gate import build_regression, contract_file_for, patch_for_download, public_report
from .sarif import to_sarif
from .verdict import LABELS, NOT_EXECUTED
from .webui import esc

RIG = Path(__file__).resolve().parent.parent          # the arbiter/ directory
RUNS = RIG / "runs"
WEB = RUNS / "gate" / "web"
UPLOADS = RUNS / "gate" / "uploads"
MAX_UPLOAD = 256 * 1024
# A Foundry project as a .zip: the archive, what it may unpack to, and how many files.
MAX_ZIP = 20 * 1024 * 1024
MAX_UNZIPPED = 100 * 1024 * 1024
MAX_ZIP_FILES = 5000
FILE_TIMEOUT = 900
# With check 5 (re-attack, on by default with --repair) a job is up to three audits and two
# repairs; measured in reports/fullplan_p6_*.md. The limit is raised, the work is not cut.
REPAIR_TIMEOUT = 3300
_JOB_LOCK = threading.Lock()

# The finals demo's recorded runs; everything else on disk goes into a folded section.
FEATURED_RUNS = [f"spark-test-{i}" for i in range(1, 6)]
PLAYBACK_RUNS = {"spark-test-2"}
IN_DEVELOPMENT: list[tuple[str, str]] = []
GITHUB_SHOTS = RIG / "webassets" / "github"


# -- data -------------------------------------------------------------------------------

def recorded_runs() -> list[dict[str, Any]]:
    """Every results file the page may replay, keyed by a run id it can be asked for."""
    found: dict[str, dict[str, Any]] = {}
    candidates = [(p, "audit") for p in RUNS.glob("*.results.jsonl")]
    candidates += [(p, "gate --file") for p in (RUNS / "gate").glob("*/*.results.jsonl")]
    for path, origin in candidates:
        run_id = path.name.removesuffix(".results.jsonl")
        patches = path.with_name(f"{run_id}.patches.jsonl")
        found[run_id] = {"run_id": run_id, "path": path, "origin": origin,
                         "patches": patches if patches.exists() else None,
                         "mtime": path.stat().st_mtime}
    return sorted(found.values(), key=lambda r: (-r["mtime"], r["run_id"]))


def timeout_report(argv: list[str], run_id: str, timeout: int) -> dict[str, Any]:
    """What the page shows for a job that hit its time limit: not executed, never a pass."""
    name = (Path(argv[argv.index("--file") + 1]).name if "--file" in argv else
            argv[argv.index("--target") + 1] if "--target" in argv else run_id)
    return {"schema": "arbiter-gate/0.1", "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "input": {"mode": "file", "run_id": run_id, "llm_requests_this_invocation": None,
                      "sandbox": {"status": "on", "note": "超時的 job 已終止，容器已移除。"}},
            "models": [], "exit_code": 2, "elapsed_s": timeout,
            "files": [{"id": f"file::{Path(name).stem}", "artifact": {"uri": name},
                       "verdict": NOT_EXECUTED, "label": LABELS[NOT_EXECUTED],
                       "reason": "job_timeout",
                       "detail": f"稽核超過 {timeout} 秒還沒完成，已被終止；這不代表合約沒有漏洞。",
                       "turns": None, "findings": []}],
            "note": "已證實可攻擊的判定附可重跑的攻擊證據；其他判定都不代表合約沒有漏洞。"}


def run_gate_cli(argv: list[str], timeout: int,
                 sandboxed: bool | None = None) -> tuple[dict[str, Any] | None, str]:
    """Run `python3 -m arbiter.gate` and return (gate.json, error text).

    `sandboxed` True forces the per-job sandbox (uploads), None leaves ARBITER_SANDBOX
    as it is (replays). A job that hits `timeout` is killed, its container removed, and
    it comes back as not executed."""
    WEB.mkdir(parents=True, exist_ok=True)
    out = WEB / f"{uuid.uuid4().hex[:12]}.gate.json"
    env = dict(os.environ)
    run_id = ""
    if sandboxed:
        env["ARBITER_SANDBOX"] = "1"
        if "--run-id" not in argv:
            run_id = f"web-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
            argv = [*argv, "--run-id", run_id]
    with _JOB_LOCK:
        try:
            proc = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "arbiter.gate", *argv, "--out", str(out)],
                cwd=RIG, capture_output=True, text=True, timeout=timeout, env=env,
            )
        except subprocess.TimeoutExpired:
            if run_id:
                sandbox.remove(sandbox.container_name(run_id))
                return timeout_report(argv, run_id, timeout), ""
            return None, f"gate 超過 {timeout} 秒未完成"
    if not out.exists():
        return None, (proc.stderr or proc.stdout or f"gate exited {proc.returncode}")[-2000:]
    return json.loads(out.read_text(encoding="utf-8")), ""


def save_result(report: dict[str, Any], meta: dict[str, Any]) -> str:
    rid = uuid.uuid4().hex[:12]
    WEB.mkdir(parents=True, exist_ok=True)
    (WEB / f"{rid}.json").write_text(
        json.dumps({"meta": meta, "report": report}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    return rid


def load_result(rid: str) -> dict[str, Any] | None:
    if not re.fullmatch(r"[0-9a-f]{12}", rid):
        return None
    path = WEB / f"{rid}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


# -- rendering ----------------------------------------------------------------------------


_SETUP_RE = re.compile(r"function arbSetup\(\) external \{\n(.*?)\n    \}", re.S)
_DEPLOY_VALUE_RE = re.compile(r"\bnew\s+\w+\s*\{\s*value\s*:\s*([^}]+?)\s*\}")


def deploy_funding(report: dict[str, Any], sample_id: str, poc_name: str) -> str:
    """What the exploit's own setup put into the contract, read from the stored exploit.

    Display only. gate.json does not carry it, so it is read from the results file the
    report points at; empty when that file or the expression is not there.
    """
    raw = (report.get("input") or {}).get("results")
    path = (RIG / raw) if raw and not Path(raw).is_absolute() else Path(raw or "")
    if not raw or not path.exists():
        return ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("sample_id") != sample_id:
            continue
        for poc in (row.get("outcome") or {}).get("pocs", []):
            if poc.get("name") != poc_name or not poc.get("passed"):
                continue
            setup = _SETUP_RE.search(poc.get("solidity") or "")
            value = _DEPLOY_VALUE_RE.search(setup.group(1)) if setup else None
            if value:
                return " ".join(value.group(1).split())
    return ""



DOWNLOAD_HELP = {
    "patch": "通過修補閘門的修改。可以在回歸測試資料夾裡用 patch -p1 套用；放進你的專案前請先審閱。",
    "regression": "把這份測試放進你的專案，以後每次修改都會自動再試一次同樣的攻擊，"
                  "並確認沒有攻擊時一般使用者拿回的錢沒有變少。",
    "gate": "完整的機器可讀結果（判定、A/B/G、修補驗證），給 CI 或其他工具讀。",
    "sarif": "上傳到 GitHub 的 Code scanning；已證實的漏洞會以 error 標在對應的程式行。",
}


def _results_row(report: dict[str, Any], sample_id: str) -> dict[str, Any] | None:
    raw = (report.get("input") or {}).get("results")
    if not raw:
        return None
    path = Path(raw) if Path(raw).is_absolute() else RIG / raw
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and (row := json.loads(line)).get("sample_id") == sample_id:
            return row
    return None


def _regression_reason(f: dict[str, Any]) -> str:
    reg = f.get("regression")
    if reg:  # gate.json written after the download section existed
        return "" if reg.get("status") == "available" else (reg.get("note") or "無法產生")
    return regression_unavailable_reason(f.get("predicate"), (f.get("abg") or {}).get("status"))


def _finding_at(saved: dict[str, Any], i: int, j: int) -> tuple[dict, dict] | None:
    files = saved["report"].get("files") or []
    if i >= len(files) or j >= len(files[i].get("findings") or []):
        return None
    return files[i], files[i]["findings"][j]


def _safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)[:80] or "arbiter"


def download(saved: dict[str, Any], kind: str, i: int = 0, j: int = 0) -> tuple[bytes, str, str] | str:
    """(body, content type, file name) or an error message."""
    report = public_report(saved["report"])
    if kind == "gate":
        return (json.dumps(report, ensure_ascii=False, indent=1).encode("utf-8") + b"\n",
                "application/json", "gate.json")
    if kind == "sarif":
        return (json.dumps(to_sarif(report), ensure_ascii=False, indent=1).encode("utf-8") + b"\n",
                "application/sarif+json", "report.sarif")
    hit = _finding_at(saved, i, j)
    if hit is None:
        return "找不到這個漏洞"
    entry, f = hit
    row = _results_row(saved["report"], entry["id"])
    cfile = contract_file_for(row, (entry.get("artifact") or {}).get("uri") or "Target.sol") \
        if row else ((entry.get("artifact") or {}).get("uri") or "Target.sol").split("/")[-1]
    stem = _safe_name(cfile.removesuffix(".sol"))
    if kind == "patch":
        p = f.get("patch") or {}
        if p.get("status") != "verified":
            return "這個漏洞沒有通過驗證的修補"
        return (patch_for_download(p.get("diff") or "", cfile).encode("utf-8"),
                "text/x-diff", f"{stem}.patch")
    if kind == "regression":
        reason = _regression_reason(f)
        if reason:
            return reason
        if row is None:
            return "結果檔不在這台機器上，無法產生回歸測試"
        meta = {"models": report.get("models"), "run_id": (report.get("input") or {}).get("run_id"),
                "generated_at": report.get("generated_at")}
        import tempfile
        with tempfile.TemporaryDirectory(prefix="arbiter-reg-") as tmp:
            top = f"arbiter-regression-{stem}"
            proj = Path(tmp) / top
            build_regression(row, f, proj, meta, cfile)
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for fp in sorted(proj.rglob("*")):
                    if fp.is_file():
                        zf.write(fp, fp.relative_to(Path(tmp)).as_posix())
        return buf.getvalue(), "application/zip", f"{top}.zip"
    return "未知的下載類型"


def _dl_row(href: str | None, label: str, help_text: str, missing: str = "") -> str:
    if href:
        btn = f"<a class='btn primary' href='{esc(href)}' download>{esc(label)}</a>"
    else:
        btn = f"<span class='btn' style='opacity:.55;cursor:default'>{esc(label)}</span>"
    why = f"<br><span class='note'>無法下載：{esc(missing)}</span>" if missing and not href else ""
    return f"<tr><td style='white-space:nowrap'>{btn}</td><td>{esc(help_text)}{why}</td></tr>"


def download_box(saved: dict[str, Any], rid: str) -> str:
    rows = []
    for i, e in enumerate(saved["report"].get("files") or []):
        for j, f in enumerate(e.get("findings") or []):
            p = f.get("patch") or {}
            rows.append(_dl_row(f"/result/{rid}/patch/{i}-{j}" if p.get("status") == "verified" else None,
                                "修補檔（.patch）", DOWNLOAD_HELP["patch"],
                                p.get("label") or "沒有通過驗證的修補"))
            reason = _regression_reason(f)
            if not reason and _results_row(saved["report"], e["id"]) is None:
                reason = "結果檔不在這台機器上，無法產生回歸測試"
            rows.append(_dl_row(None if reason else f"/result/{rid}/regression/{i}-{j}",
                                "回歸測試（.zip）", DOWNLOAD_HELP["regression"], reason))
    rows.append(_dl_row(f"/result/{rid}/gate.json", "gate.json", DOWNLOAD_HELP["gate"]))
    rows.append(_dl_row(f"/result/{rid}/report.sarif", "report.sarif", DOWNLOAD_HELP["sarif"]))
    return ("<h2>下載區</h2><div class='card'><div class='tbl'><table>"
            + "".join(rows) + "</table></div><p class='note'>下載的檔案只用相對路徑，"
            "不含這台機器的目錄。回歸測試全部通過只代表這一個攻擊失效、誠實路徑沒有變差，"
            "不代表合約沒有其他漏洞。</p></div>")




# -- result page extras ----------------------------------------------------------------------

def result_extras(saved: dict[str, Any]) -> dict[tuple[int, int], dict[str, Any]]:
    from .patch import apply_diff
    out: dict[tuple[int, int], dict[str, Any]] = {}
    rep = saved["report"]
    for i, e in enumerate(rep.get("files") or []):
        row = _results_row(rep, e["id"])
        cfile = contract_file_for(row, (e.get("artifact") or {}).get("uri") or "Target.sol") \
            if row else (((e.get("artifact") or {}).get("uri") or "Target.sol").split("/")[-1])
        for j, f in enumerate(e.get("findings") or []):
            ex: dict[str, Any] = {"cfile": cfile,
                                  "funding": deploy_funding(rep, e["id"], f.get("poc_name") or "")}
            p = f.get("patch") or {}
            if row and p.get("status") == "verified" and p.get("diff"):
                ex["source"] = row.get("source")
                patched, _ = apply_diff(row.get("source") or "", p["diff"])
                ex["patched"] = patched
                ex["download_diff"] = patch_for_download(p["diff"], cfile)
            out[(i, j)] = ex
    return out


# -- jobs ------------------------------------------------------------------------------------

def _gate_argv_for_run(run_id: str) -> tuple[list[str], str]:
    run = next((r for r in recorded_runs() if r["run_id"] == run_id), None)
    if run is None:
        raise ValueError(f"no recorded run {run_id}")
    argv = ["--from-results", str(run["path"])]
    if run["patches"]:
        argv += ["--patches", str(run["patches"])]
    return argv, f"預錄結果 {run_id}" + ("（含修補紀錄）" if run["patches"] else "")


def run_job(job: dict[str, Any]) -> None:
    kind, p = job["kind"], job["params"]
    if kind in ("upload", "demo", "project"):
        argv = (["--project", p["path"], "--target", p["target"], "--repair"] if kind == "project"
                else ["--file", p["path"], "--mode", "repo", "--repair"])
        report = jobs.run_gate_job(job, argv, sandboxed=True, timeout=REPAIR_TIMEOUT, lock=_JOB_LOCK)
        if report is None:
            report = timeout_report(argv, f"web-{job['id']}", REPAIR_TIMEOUT)
        source = job["label"]
    elif kind == "playback":
        run = next(r for r in recorded_runs() if r["run_id"] == p["run_id"])
        info = jobs.recorded_timeline(run["path"])
        prec = jobs.recorded_patch(run["patches"])
        notes = info["notes"] + ["損失數字、修補閘門的檢查和證據等級不是回放，是現在用 forge 當場重跑的"]
        if prec:
            notes.append(f"修補是錄製時 AI 寫的（共 {prec['rounds']} 輪，第 {prec['accepted_round']} 輪通過），"
                         "這裡不重新呼叫 AI，只重新驗證那份修補")
        job["params"].update(recorded_on=info["recorded_on"], model=info["model"], notes=notes,
                             recorded_elapsed_s=info["recorded_elapsed_s"])
        jobs.save(job)
        jobs.play(job, info["timeline"], float(p.get("speed") or 1))
        argv, _ = _gate_argv_for_run(p["run_id"])
        report = jobs.run_gate_job(job, argv, sandboxed=None, timeout=600, lock=_JOB_LOCK)
        if report is None:
            job["error"] = "重跑損失與修補驗證時超過時間限制"
            jobs.save(job)
            return
        source = f"錄製回放 {p['run_id']}"
    elif kind == "chain":
        run_chain(job)
        return
    else:
        raise ValueError(kind)
    rid = save_result(report, {"source": source, "at": time.strftime("%Y-%m-%d %H:%M:%S"),
                               "job": job["id"]})
    job = jobs.load(job["id"]) or job
    job["rid"] = rid
    jobs.save(job)


def run_chain(job: dict[str, Any]) -> None:
    d = jobs.job_dir(job["id"])
    script = RIG / "scripts" / "live_attack_stakingvault.py"
    targets = [("original", [], "在原合約上：部署金庫、受害者存款、攻擊、受害者領錢（兩條鏈）"),
               ("patched", ["--patched", "spark-test-2"], "套用 AI 修補後，同樣的步驟再跑一次（兩條鏈）")]
    cmd_prefix = [sys.executable]
    if sandbox.enabled(default=False):
        cmd_prefix = [sys.executable, "-m", "arbiter.sandbox", "exec", "--", sys.executable]
    with _JOB_LOCK:
        for i, (name, extra, text) in enumerate(targets):
            jobs.emit(job["id"], "stage", step="execute", index=3, text=text)
            out = d / f"chain-{name}.json"
            port = 8700 + 10 * i
            subprocess.run([*cmd_prefix, str(script), "--port", str(port), "--json", str(out), *extra],
                           cwd=RIG, capture_output=True, text=True, timeout=300)
            if not out.exists():
                job["error"] = f"真鏈示範（{name}）沒有產生結果"
                jobs.save(job)
                return
            data = public_report(json.loads(out.read_text(encoding="utf-8")))
            data["target"] = name
            out.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
            jobs.emit(job["id"], "tool_result", tool="chain", code="passed" if (data.get("verdict") or {}).get("proven") else "no_harm",
                      text=("攻擊成功：金庫被抽乾" if (data.get("verdict") or {}).get("proven") else "攻擊沒有成功"))
    jobs.emit(job["id"], "stage", step="done", index=6, text="完成")


def chain_runs(jid: str) -> list[dict[str, Any]]:
    d = jobs.job_dir(jid)
    return [json.loads((d / f"chain-{n}.json").read_text(encoding="utf-8"))
            for n in ("original", "patched") if (d / f"chain-{n}.json").exists()]


def latest_chain_job() -> dict[str, Any] | None:
    done = [j for j in jobs.all_jobs() if j["kind"] == "chain"]
    return done[-1] if done else None


def demo_contract(cid: str) -> tuple[str, str] | None:
    """(file name, source) of a self-made demo contract."""
    d = next((x for x in webui.DEMO_CONTRACTS if x["id"] == cid), None)
    if d is None:
        return None
    kind, ref = d["source"]
    if kind == "examples":
        return d["file"], (RIG / "examples" / ref).read_text(encoding="utf-8")
    items = json.loads((RIG / "evalsets" / "v3_authored.json").read_text(encoding="utf-8"))["items"]
    return d["file"], next(i["code"] for i in items if i["id"] == ref)


QUEUE: jobs.Queue | None = None


# -- project uploads ----------------------------------------------------------------------

def extract_project_zip(data: bytes, dest: Path) -> tuple[Path | None, str]:
    """Unpack an uploaded project into `dest`/project. (root, "") or (None, why).

    Refused: not a zip, over MAX_UNZIPPED or MAX_ZIP_FILES, any member with an absolute
    path, a drive letter or `..` (zip-slip), and symlinks (a link could point anywhere on
    this machine). __MACOSX and .git are dropped. A single top-level folder is lifted
    out when it wraps a project (foundry.toml, package.json, src/ or contracts/ under
    it), so the project root's name -- which triage would read as part of every path
    ("examples/", "test/") -- is always `project`.
    """
    import stat
    import zipfile
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return None, "這不是有效的 .zip 檔"
    members = [m for m in zf.infolist() if not m.is_dir()]
    if len(members) > MAX_ZIP_FILES:
        return None, f"壓縮檔裡的檔案太多（上限 {MAX_ZIP_FILES} 個）"
    if sum(m.file_size for m in members) > MAX_UNZIPPED:
        return None, f"解壓後太大（上限 {MAX_UNZIPPED // (1024 * 1024)} MB）"
    names = []
    for m in members:
        n = m.filename.replace("\\", "/")
        parts = [p for p in n.split("/") if p not in ("", ".")]
        if n.startswith("/") or re.match(r"^[A-Za-z]:", n) or ".." in parts:
            return None, f"壓縮檔裡有不安全的路徑：{n[:80]}"
        if stat.S_ISLNK(m.external_attr >> 16):
            return None, f"壓縮檔裡有符號連結（不接受）：{n[:80]}"
        if parts and parts[0] in ("__MACOSX",) or ".git" in parts:
            continue
        names.append((m, parts))
    if not names:
        return None, "壓縮檔是空的"
    # Lift only a wrapper folder (project.zip -> project/foundry.toml, src/...), never a
    # zip that is just src/ itself.
    tops = {parts[0] for _, parts in names}
    markers = {"foundry.toml", "remappings.txt", "package.json", "hardhat.config.js",
               "hardhat.config.ts", "truffle-config.js"}
    lift = (len(tops) == 1 and all(len(parts) > 1 for _, parts in names)
            and any(parts[1] in markers or (len(parts) > 2 and parts[1] in ("src", "contracts"))
                    for _, parts in names))
    root = (dest / "project").resolve()
    root.mkdir(parents=True, exist_ok=True)
    for m, parts in names:
        rel = parts[1:] if lift else parts
        out = (root / Path(*rel)).resolve()
        if root not in out.parents:
            return None, "壓縮檔裡有不安全的路徑"
        out.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(m) as fh:
            out.write_bytes(fh.read())
    return root, ""


# -- server ----------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "ArbiterGate/0.2"

    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, where: str) -> None:
        self.send_response(303)
        self.send_header("Location", where)
        self.end_headers()

    def _index(self, message: str = "", status: int = 200) -> None:
        runs = recorded_runs()
        featured = sorted((r for r in runs if r["run_id"] in FEATURED_RUNS),
                          key=lambda r: FEATURED_RUNS.index(r["run_id"]))
        others = [r for r in runs if r["run_id"] not in FEATURED_RUNS]
        self._send(webui.render_index(message, featured, others, jobs.timing_history(),
                                      IN_DEVELOPMENT, any(r["run_id"] in PLAYBACK_RUNS for r in runs)),
                   status)

    def do_GET(self) -> None:  # noqa: N802
        url = urlparse(self.path)
        path = url.path
        if path in ("/", "/index.html"):
            return self._index()
        if m := re.fullmatch(r"/job/([0-9a-f-]{20,40})", path):
            job = jobs.load(m.group(1))
            if job:
                return self._send(webui.render_job(job))
        if m := re.fullmatch(r"/api/job/([0-9a-f-]{20,40})", path):
            job = jobs.load(m.group(1))
            if job:
                since = int((parse_qs(url.query).get("since") or ["0"])[0] or 0)
                evs = progress.read(jobs.job_dir(job["id"]) / "events.jsonl", since)
                body = {"job": job, "events": evs, "next": since + len(evs),
                        "position": jobs.position(job["id"]),
                        "history": jobs.timing_history() if job["kind"] in ("upload", "demo", "project") else None}
                return self._send(json.dumps(public_report(body), ensure_ascii=False).encode("utf-8"),
                                  ctype="application/json; charset=utf-8")
        if path == "/github":
            return self._send(webui.render_github({p.stem for p in GITHUB_SHOTS.glob("*.png")}))
        if (m := re.fullmatch(r"/github/img/([a-z0-9-]+)\.png", path)) and (GITHUB_SHOTS / f"{m.group(1)}.png").is_file():
            return self._send((GITHUB_SHOTS / f"{m.group(1)}.png").read_bytes(), ctype="image/png")
        if path == "/chain":
            job = latest_chain_job()
            runs = chain_runs(job["id"]) if job and job["status"] == "done" else []
            return self._send(webui.render_chain(job, runs, True))
        if m := re.fullmatch(r"/chain/([0-9a-f-]{20,40})", path):
            job = jobs.load(m.group(1))
            if job:
                return self._send(webui.render_chain(job, chain_runs(job["id"]), True))
        m = re.fullmatch(r"/result/([0-9a-f]{12})", path)
        if m and (saved := load_result(m.group(1))):
            return self._send(webui.render_result(saved, m.group(1), result_extras(saved),
                                                  download_box(saved, m.group(1)), IN_DEVELOPMENT))
        m = re.fullmatch(r"/result/([0-9a-f]{12})/chainreplay/(\d+)-(\d+)", path)
        if m and (saved := load_result(m.group(1))):
            hit = _finding_at(saved, int(m.group(2)), int(m.group(3)))
            if hit:
                return self._send(webui.render_chainreplay(saved, m.group(1), public_report(hit[1])))
        m = re.fullmatch(r"/result/([0-9a-f]{12})/(gate\.json|report\.sarif|"
                         r"(patch|regression)/(\d+)-(\d+))", path)
        if m and (saved := load_result(m.group(1))):
            kind = {"gate.json": "gate", "report.sarif": "sarif"}.get(m.group(2), m.group(3))
            got = download(saved, kind, int(m.group(4) or 0), int(m.group(5) or 0))
            if isinstance(got, str):
                return self._send(webui.page("無法下載", f"<p>{esc(got)}</p><p><a href='/result/{m.group(1)}'>回結果頁</a></p>"), 404)
            body, ctype, name = got
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return None
        return self._send(webui.page("找不到", "<p>找不到這個頁面。<a href='/'>回首頁</a></p>"), 404)

    def do_POST(self) -> None:  # noqa: N802
        assert QUEUE is not None
        length = int(self.headers.get("Content-Length") or 0)
        limit = MAX_ZIP + 65536 if self.path == "/upload" else MAX_UPLOAD + 4096
        if length > limit:
            return self._index("檔案太大（.sol 上限 256 KB，.zip 上限 20 MB）", 413)
        body = self.rfile.read(length)
        form = {k: v[0] for k, v in parse_qs(body.decode("utf-8", "replace")).items()} \
            if not (self.headers.get("Content-Type") or "").startswith("multipart/") else {}
        if self.path == "/replay":
            run_id = form.get("run_id", "")
            try:
                argv, source = _gate_argv_for_run(run_id)
            except ValueError:
                return self._index("找不到這個錄製紀錄", 404)
            report, err = run_gate_cli(argv, timeout=600)
            if report is None:
                return self._index(f"重播沒有產生結果：{err}", 500)
            rid = save_result(report, {"source": source, "at": time.strftime("%Y-%m-%d %H:%M:%S")})
            return self._redirect(f"/result/{rid}")
        if self.path == "/upload":
            name, data = self._upload(body)
            if data is None:
                return self._index(name, 400)
            if name.endswith(".zip"):
                return self._project_upload(name, data)
            return self._redirect(f"/job/{self._enqueue_file('upload', name, data, f'上傳檔案 {name}')}")
        if self.path == "/project":
            uid, rel = form.get("uid", ""), form.get("target", "")
            root = UPLOADS / uid / "project"
            if not re.fullmatch(r"[0-9a-f]{12}", uid) or not root.is_dir():
                return self._index("找不到這次上傳的專案，請重新上傳", 404)
            _, cands = gate_mod.pick_target(root)
            if rel not in {c["rel"] for c in cands if not c.get("skipped")}:
                return self._index("選的合約不在候選清單裡", 400)
            return self._redirect(f"/job/{self._enqueue_project(uid, rel)}")
        if self.path == "/demo":
            got = demo_contract(form.get("id", ""))
            if got is None:
                return self._index("找不到這份示範合約", 404)
            name, code = got
            d = next(x for x in webui.DEMO_CONTRACTS if x["id"] == form["id"])
            return self._redirect(f"/job/{self._enqueue_file('demo', name, code.encode('utf-8'), f'示範合約：{d['title']}（{name}）')}")
        if self.path == "/playback":
            run_id = form.get("run_id", "")
            if run_id not in PLAYBACK_RUNS:
                return self._index("這份紀錄不能回放", 404)
            speed = 4 if form.get("speed") == "4" else 1
            jid = QUEUE.submit("playback", f"錄製回放：{run_id}（StakingVault）",
                               {"run_id": run_id, "speed": speed})
            return self._redirect(f"/job/{jid}")
        if self.path == "/chain":
            jid = QUEUE.submit("chain", "參考攻擊的真鏈示範", {})
            return self._redirect(f"/job/{jid}")
        return self._send(webui.page("找不到", "<p>找不到。</p>"), 404)

    def _enqueue_file(self, kind: str, name: str, data: bytes, label: str) -> str:
        assert QUEUE is not None
        d = UPLOADS / uuid.uuid4().hex[:12]
        d.mkdir(parents=True, exist_ok=True)
        path = d / name
        path.write_bytes(data)
        return QUEUE.submit(kind, label, {"path": str(path)})

    def _project_upload(self, name: str, data: bytes) -> None:
        uid = uuid.uuid4().hex[:12]
        root, err = extract_project_zip(data, UPLOADS / uid)
        if root is None:
            shutil.rmtree(UPLOADS / uid, ignore_errors=True)
            return self._index(err, 400)
        first, cands = gate_mod.pick_target(root)
        if first is None:
            return self._index("壓縮檔裡找不到可以稽核的合約（只有介面、函式庫、測試、mock 或腳本）", 400)
        (UPLOADS / uid / "name.txt").write_text(name, encoding="utf-8")
        if sum(1 for c in cands if not c.get("skipped")) == 1:
            return self._redirect(f"/job/{self._enqueue_project(uid, first)}")
        return self._send(webui.render_pick(uid, name, cands, first))

    def _enqueue_project(self, uid: str, rel: str) -> str:
        assert QUEUE is not None
        name = (UPLOADS / uid / "name.txt").read_text(encoding="utf-8").strip() \
            if (UPLOADS / uid / "name.txt").exists() else "project.zip"
        return QUEUE.submit("project", f"上傳專案 {name}：{rel}",
                            {"path": str(UPLOADS / uid / "project"), "target": rel})

    def _upload(self, body: bytes) -> tuple[str, bytes | None]:
        ctype = self.headers.get("Content-Type", "")
        if not ctype.startswith("multipart/form-data"):
            return "請用表單上傳 .sol 檔", None
        msg = BytesParser(policy=email_policy).parsebytes(
            b"Content-Type: " + ctype.encode() + b"\r\n\r\n" + body)
        for part in msg.iter_parts():
            if part.get_param("name", header="content-disposition") != "contract":
                continue
            filename = part.get_filename() or ""
            data = part.get_payload(decode=True) or b""
            stem = re.sub(r"[^A-Za-z0-9_]", "_", Path(filename).stem)[:60] or "Contract"
            if filename.lower().endswith(".zip"):
                if len(data) > MAX_ZIP:
                    return "壓縮檔太大（上限 20 MB）", None
                return f"{stem}.zip", data
            if not filename.endswith(".sol"):
                return "只接受 .sol 檔或 Foundry 專案的 .zip", None
            if not data.strip():
                return "檔案是空的", None
            if len(data) > MAX_UPLOAD:
                return "檔案太大（上限 256 KB）", None
            return f"{stem}.sol", data
        return "沒有收到檔案", None

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[web] {self.address_string()} {fmt % args}\n")


def main(argv: list[str] | None = None) -> int:
    global QUEUE
    ap = argparse.ArgumentParser(prog="python3 -m arbiter.web")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)
    QUEUE = jobs.Queue(run_job)
    # Loopback only, and not configurable: the sandbox isolates the job, not this page.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"ARBITER Gate web: http://127.0.0.1:{args.port}/  (local only, Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
