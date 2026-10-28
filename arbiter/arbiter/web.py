"""ARBITER Gate, minimal local web page: pick a recorded run or upload one .sol, read gate.json.

    python3 -m arbiter.web [--port 8765]

Standard library only, bound to 127.0.0.1 and nothing else. There is no sandbox yet:
an uploaded contract is compiled and executed by forge on this machine, so the page is
for the team's own machine and the finals laptop, not for the public.

Two ways in, both of which only ever run `python3 -m arbiter.gate` and render its JSON:

  * a recorded run (runs/<id>.results.jsonl, or one written by an earlier gate --file):
    `--from-results`, plus `--patches` when runs/<id>.patches.jsonl exists. No LLM
    request -- this is the finals demo's main path.
  * an uploaded .sol: `--file --mode repo --repair`, synchronously; 125-465 s measured
    in repo mode on StakingVault (9 runs, 10/28), longest when no attack is found.

Verdict wording comes from arbiter/verdict.py's LABELS. Jobs run one at a time.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import subprocess
import sys
import threading
import time
import uuid
from email.parser import BytesParser
from email.policy import default as email_policy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from .verdict import LABELS, NO_PROVABLE, NOT_EXECUTED, PROVEN, STATIC_HINT

RIG = Path(__file__).resolve().parent.parent          # the arbiter/ directory
RUNS = RIG / "runs"
WEB = RUNS / "gate" / "web"
UPLOADS = RUNS / "gate" / "uploads"
MAX_UPLOAD = 256 * 1024
FILE_TIMEOUT = 900
_JOB_LOCK = threading.Lock()

# The finals demo's recorded runs; everything else on disk goes into a folded section.
FEATURED_RUNS = [f"spark-test-{i}" for i in range(1, 6)]
ENV_NAMES = ["預設", "受害者餘額 1000 倍", "一週後", "8 輪攻擊"]
VERDICT_CLASS = {PROVEN: "v-proven", NOT_EXECUTED: "v-unrun",
                 NO_PROVABLE: "v-none", STATIC_HINT: "v-hint"}
IN_DEVELOPMENT = [
    ("沙箱隔離", "上傳的合約目前直接在這台機器上用 forge 編譯與執行；所以本頁只綁 127.0.0.1，不對外開放"),
    ("即時進度時間軸", "目前上傳後要等整個稽核跑完才出現結果頁"),
    ("網頁內的鏈上重播頁", "交易與餘額的兩欄重播頁；終端機版已完成（scripts/live_attack_stakingvault.py）"),
    ("SARIF／GitHub Action", "PR 部署閘門"),
    ("回歸測試下載", "TestArbiterRegression 的 Foundry 專案"),
]


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


def run_gate_cli(argv: list[str], timeout: int) -> tuple[dict[str, Any] | None, str]:
    """Run `python3 -m arbiter.gate` and return (gate.json, error text)."""
    WEB.mkdir(parents=True, exist_ok=True)
    out = WEB / f"{uuid.uuid4().hex[:12]}.gate.json"
    with _JOB_LOCK:
        try:
            proc = subprocess.run(  # noqa: S603
                [sys.executable, "-m", "arbiter.gate", *argv, "--out", str(out)],
                cwd=RIG, capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
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

def esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def eth(v: int | None) -> str:
    if v is None:
        return "—"
    x = v / 10**18
    return f"{x:,.6f}".rstrip("0").rstrip(".") + " ETH"


CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1f;--mute:#5f6368;--line:#dcdcd7;
--red:#b3261e;--redbg:#fdecea;--amber:#8a5a00;--amberbg:#fff4dc;--blue:#1f4e8c;--bluebg:#e8f0fb;
--green:#1e6b3a;--greenbg:#e7f4ec;--code:#f1f1ee}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--ink:#ececec;--mute:#a0a0a8;
--line:#34343a;--red:#ff8a80;--redbg:#3a1d1b;--amber:#ffcc66;--amberbg:#3a2f14;--blue:#9cc2ff;
--bluebg:#1b2a40;--green:#8fd9a8;--greenbg:#16301f;--code:#26262a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.55 system-ui,-apple-system,"Noto Sans TC","PingFang TC",sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px}
.sub{color:var(--mute);margin:0 0 20px}.card{background:var(--card);border:1px solid var(--line);
border-radius:10px;padding:16px 18px;margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:7px 9px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute);font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.tbl{overflow-x:auto}.btn{display:inline-block;border:1px solid var(--line);background:var(--card);
color:var(--ink);border-radius:7px;padding:6px 12px;font:inherit;cursor:pointer;text-decoration:none}
.btn.primary{background:var(--blue);border-color:var(--blue);color:#fff}
.verdict{border-radius:10px;padding:14px 18px;margin:14px 0;font-size:19px;font-weight:700}
.v-proven{background:var(--redbg);color:var(--red)}.v-unrun{background:var(--amberbg);color:var(--amber)}
.v-none{background:var(--bluebg);color:var(--blue)}.v-hint{background:var(--amberbg);color:var(--amber)}
.verdict small{display:block;font-size:13px;font-weight:400;margin-top:4px;color:var(--ink)}
.tag{display:inline-block;font-size:12px;border-radius:5px;padding:1px 7px;margin-left:6px;
background:var(--code);color:var(--mute);font-weight:600}.tag.ok{background:var(--greenbg);color:var(--green)}
.tag.warn{background:var(--amberbg);color:var(--amber)}.tag.dev{background:var(--amberbg);color:var(--amber)}
pre{background:var(--code);border-radius:8px;padding:12px;overflow-x:auto;font-size:13px;line-height:1.45;margin:8px 0}
.add{color:var(--green)}.del{color:var(--red)}.hunk{color:var(--blue)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--mute)}dd{margin:0;word-break:break-word}
.note{color:var(--mute);font-size:13px}form.inline{display:inline}
.runs td:last-child{white-space:nowrap}
details{margin-top:12px}summary{cursor:pointer;color:var(--mute)}
"""


def page(title: str, body: str) -> bytes:
    return f"""<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>
<style>{CSS}</style></head><body><main>{body}</main></body></html>""".encode("utf-8")


def dev_box() -> str:
    items = "".join(f"<li><b>{esc(n)}</b> <span class='tag dev'>開發中</span> "
                    f"<span class='note'>{esc(d)}</span></li>" for n, d in IN_DEVELOPMENT)
    return f"<div class='card'><b>尚未完成的部分</b><ul>{items}</ul></div>"


def _runs_table(runs: list[dict[str, Any]]) -> str:
    rows = []
    for r in runs:
        when = time.strftime("%m/%d %H:%M", time.localtime(r["mtime"]))
        badge = "<span class='tag ok'>含修補紀錄</span>" if r["patches"] else ""
        rows.append(
            f"<tr><td><code>{esc(r['run_id'])}</code>{badge}</td><td>{esc(r['origin'])}</td>"
            f"<td>{when}</td><td><form class='inline' method='post' action='/replay'>"
            f"<input type='hidden' name='run_id' value='{esc(r['run_id'])}'>"
            f"<button class='btn primary'>看結果</button></form></td></tr>")
    return ("<div class='tbl'><table class='runs'><tr><th>run</th><th>來源</th><th>時間</th><th></th></tr>"
            + "".join(rows) + "</table></div>")


def render_index(message: str = "") -> bytes:
    runs = recorded_runs()
    featured = sorted((r for r in runs if r["run_id"] in FEATURED_RUNS),
                      key=lambda r: FEATURED_RUNS.index(r["run_id"]))
    others = [r for r in runs if r["run_id"] not in FEATURED_RUNS]
    table = _runs_table(featured) if featured else "<p class='note'>找不到 spark-test-1～5 的結果檔。</p>"
    if others:
        table += (f"<details><summary>其他紀錄（{len(others)} 筆）</summary>"
                  f"{_runs_table(others)}</details>")
    msg = f"<div class='verdict v-unrun'>{esc(message)}</div>" if message else ""
    body = f"""
<h1>ARBITER Gate</h1>
<p class="sub">部署前證據閘門：只有實際在 EVM 上執行成功的攻擊，才判定為已證實可攻擊。</p>
{msg}
<h2>預錄結果</h2>
<div class="card"><p class="note">重播已完成的稽核：重新執行存下的攻擊、量 A/B/G、重新驗證修補。
不發任何 LLM 請求。</p>{table}</div>
<h2>上傳合約即時稽核</h2>
<div class="card"><form method="post" action="/upload" enctype="multipart/form-data">
<input type="file" name="contract" accept=".sol" required>
<button class="btn primary">開始稽核</button></form>
<p class="note">單一 .sol 檔、沒有 import。一次稽核加修補約 2～8 分鐘
（10/28 repo 模式實測 9 次：125～465 秒；找到攻擊時多半 2～3 分鐘，沒找到時較久），按下後請等待頁面跳轉。
會呼叫 LLM（模型見結果頁）；已證實的 victim_loss 會同時由模型產生修補，並經修補閘門驗證。</p></div>
{dev_box()}
<p class="note">「已證實可攻擊」附可重跑的攻擊證據；其他判定都不代表合約沒有漏洞。</p>
"""
    return page("ARBITER Gate", body)


def _diff_html(text: str) -> str:
    out = []
    for line in (text or "").splitlines():
        cls = ("hunk" if line.startswith("@@") else
               "add" if line.startswith("+") and not line.startswith("+++") else
               "del" if line.startswith("-") and not line.startswith("---") else "")
        out.append(f"<span class='{cls}'>{esc(line)}</span>" if cls else esc(line))
    return "\n".join(out)


def _abg_table(abg: dict[str, Any]) -> str:
    head = ("<tr><th>環境</th><th>受害者帳戶初始餘額</th><th>經過時間</th><th>攻擊輪數</th>"
            "<th>無攻擊取回</th><th>有攻擊取回</th><th>攻擊者獲利</th></tr>")
    rows = []
    for r in abg.get("environments") or []:
        name = ENV_NAMES[r["env"]] if r["env"] < len(ENV_NAMES) else str(r["env"])
        warp = "—" if not r["warp_s"] else f"{r['warp_s'] // 86400} 天"
        harmed = r["A"] is not None and r["B"] is not None and r["B"] < r["A"]
        mark = " <span class='tag warn'>受害者受損</span>" if harmed else ""
        rows.append(f"<tr><td>{esc(name)}{mark}</td><td class='num'>{eth(r['endow_wei'])}</td>"
                    f"<td>{warp}</td><td class='num'>{r['rounds']}</td>"
                    f"<td class='num'>{eth(r['A'])}</td><td class='num'>{eth(r['B'])}</td>"
                    f"<td class='num'>{eth(r['G'])}</td></tr>")
    return f"<div class='tbl'><table>{head}{''.join(rows)}</table></div>"


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


def _funding_note(funding: str) -> str:
    example = f"（例如部署時存入的 {esc(funding)}）" if funding else ""
    return (f"<p class='note'>攻擊者獲利可能來自合約中其他人的資金{example}；"
            "受害者是否受損看「無攻擊取回」和「有攻擊取回」的差。</p>")


def _finding_html(f: dict[str, Any], idx: int, funding: str = "") -> str:
    strict = ("<span class='tag ok'>strict</span>" if f.get("predicate_strict")
              else "<span class='tag warn'>寬鬆謂詞</span>")
    parts = [f"<div class='card'><b>{esc(f.get('title'))}</b>",
             "<dl>",
             f"<dt>函式</dt><dd><code>{esc(f.get('vulnerable_function'))}</code></dd>",
             f"<dt>嚴重度</dt><dd>{esc(f.get('severity'))}</dd>",
             f"<dt>謂詞</dt><dd><code>{esc(f.get('predicate'))}</code>{strict}</dd>",
             f"<dt>攻擊證明</dt><dd><code>{esc(f.get('poc_name'))}</code>（已在 EVM 上執行，謂詞成立）</dd>",
             "</dl>"]
    if f.get("predicate_note"):
        parts.append(f"<p class='verdict v-unrun' style='font-size:15px'>{esc(f['predicate_note'])}</p>")
    abg = f.get("abg") or {}
    parts.append(f"<h2>A/B/G：同一個受害者，有沒有被攻擊 <span class='tag'>{esc(abg.get('label'))}</span></h2>")
    if abg.get("status") in ("measured", "reproduction_failed"):
        parts.append(_abg_table(abg))
        parts.append(_funding_note(funding))
        parts.append("<p class='note'>合成層數字：每個環境各跑一次無攻擊、一次有攻擊，都從乾淨狀態開始；"
                     "「受害者帳戶初始餘額」是測試在受害者進場前給它帳戶的 ETH，實際存入多少由攻擊證明裡的受害者步驟決定。</p>")
    if abg.get("note"):
        parts.append(f"<p class='note'>{esc(abg['note'])}</p>")
    p = f.get("patch") or {}
    tag = "ok" if p.get("status") == "verified" else "warn"
    parts.append(f"<h2>修補 <span class='tag {tag}'>{esc(p.get('label'))}</span></h2>")
    if p.get("status") == "verified":
        gates = " ".join(f"{k}:{v}" for k, v in (p.get("gate_checks") or {}).items())
        parts.append(
            f"<dl><dt>來源</dt><dd>{'修補紀錄（已用 forge 重新驗證）' if p.get('origin') == 'patches_file' else '本次由模型產生'}"
            f"，模型 <code>{esc(p.get('model'))}</code></dd>"
            f"<dt>修改行數</dt><dd>{esc(p.get('changed_lines'))}</dd>"
            f"<dt>修補閘門</dt><dd><code>{esc(gates)}</code></dd>"
            f"<dt>模型說明</dt><dd>{esc(p.get('rationale'))}</dd></dl>"
            f"<p><button class='btn' onclick=\"tg({idx},'ws')\">忽略空白的 diff</button> "
            f"<button class='btn' onclick=\"tg({idx},'raw')\">原始 diff</button> "
            f"<span class='note' id='lbl{idx}'>目前：忽略空白（僅供閱讀）</span></p>"
            f"<pre id='ws{idx}'>{_diff_html(p.get('diff_ignore_whitespace'))}</pre>"
            f"<pre id='raw{idx}' hidden>{_diff_html(p.get('diff'))}</pre>"
            f"<h2>修補後</h2>{_abg_table({'environments': p.get('after')})}"
            "<p class='note'>修補已通過驗證（針對此攻擊）只代表：這個攻擊在 4 個環境都失效、"
            "無攻擊時的取回沒有變少、對外介面沒有改變。修補是建議，要由開發者審閱後套用並重新稽核。</p>")
    elif p.get("note"):
        parts.append(f"<p class='note'>{esc(p['note'])}</p>")
    parts.append("</div>")
    return "".join(parts)


def render_result(saved: dict[str, Any]) -> bytes:
    rep, meta = saved["report"], saved["meta"]
    inp = rep.get("input") or {}
    files = []
    for i, e in enumerate(rep.get("files") or []):
        label = LABELS[e["verdict"]]
        why = ""
        if e["verdict"] != PROVEN:
            detail = e.get("detail") if e.get("detail") not in ("", e.get("reason")) else ""
            why = f"<small>原因：<code>{esc(e.get('reason'))}</code>{'<br>' + esc(detail) if detail else ''}</small>"
        files.append(f"<div class='verdict {VERDICT_CLASS[e['verdict']]}'>{esc(label)}{why}</div>"
                     f"<p class='note'>{esc(e['id'])}　回合 {esc(e.get('turns'))}</p>")
        files += [_finding_html(f, i * 10 + j,
                                deploy_funding(rep, e["id"], f.get("poc_name") or ""))
                  for j, f in enumerate(e.get("findings") or [])]
    reqs = inp.get("llm_requests_this_invocation")
    body = f"""
<p><a class="btn" href="/">← 回首頁</a></p>
<h1>稽核結果</h1>
<div class="card"><dl>
<dt>輸入</dt><dd>{esc(meta.get('source'))}</dd>
<dt>run</dt><dd><code>{esc(inp.get('run_id'))}</code></dd>
<dt>模型</dt><dd><code>{esc(', '.join(rep.get('models') or []) or '未知')}</code></dd>
<dt>本次 LLM 請求數</dt><dd><b>{esc('未知' if reqs is None else reqs)}</b>{
    f"（稽核 {esc(inp.get('llm_requests_audit'))}、修補 {esc(inp.get('llm_requests_repair'))}）"
    if inp.get('llm_requests_audit') is not None else ''}</dd>
<dt>gate 結束碼</dt><dd><code>{esc(rep.get('exit_code'))}</code>（1＝擋部署，2＝稽核未完成，0＝未擋部署（不代表沒有漏洞））</dd>
<dt>耗時</dt><dd>{esc(rep.get('elapsed_s'))} 秒</dd>
</dl></div>
{''.join(files)}
{dev_box()}
<p class="note">「已證實可攻擊」附可重跑的攻擊證據；其他判定都不代表合約沒有漏洞。</p>
<script>
function tg(i,which){{var ws=document.getElementById('ws'+i),raw=document.getElementById('raw'+i);
ws.hidden=which!=='ws';raw.hidden=which!=='raw';
document.getElementById('lbl'+i).textContent=which==='ws'?'目前：忽略空白（僅供閱讀）':'目前：原始 diff（可套用）';}}
</script>"""
    return page("ARBITER Gate 結果", body)


# -- server -------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "ArbiterGate/0.1"

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

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            return self._send(render_index())
        m = re.fullmatch(r"/result/([0-9a-f]{12})", self.path)
        if m and (saved := load_result(m.group(1))):
            return self._send(render_result(saved))
        return self._send(page("找不到", "<p>找不到這個頁面。<a href='/'>回首頁</a></p>"), 404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_UPLOAD + 4096:
            return self._send(render_index("檔案太大（上限 256 KB）"), 413)
        body = self.rfile.read(length)
        if self.path == "/replay":
            run_id = (parse_qs(body.decode("utf-8", "replace")).get("run_id") or [""])[0]
            run = next((r for r in recorded_runs() if r["run_id"] == run_id), None)
            if run is None:
                return self._send(render_index("找不到這個 run"), 404)
            argv = ["--from-results", str(run["path"])]
            if run["patches"]:
                argv += ["--patches", str(run["patches"])]
            report, err = run_gate_cli(argv, timeout=600)
            source = f"預錄結果 {run_id}" + ("（含修補紀錄）" if run["patches"] else "")
        elif self.path == "/upload":
            name, data = self._upload(body)
            if data is None:
                return self._send(render_index(name), 400)
            job = UPLOADS / uuid.uuid4().hex[:12]
            job.mkdir(parents=True, exist_ok=True)
            path = job / name
            path.write_bytes(data)
            report, err = run_gate_cli(["--file", str(path), "--mode", "repo", "--repair"],
                                       timeout=FILE_TIMEOUT)
            source = f"上傳檔案 {name}"
        else:
            return self._send(page("找不到", "<p>找不到。</p>"), 404)
        if report is None:
            return self._send(render_index(f"gate 沒有產生結果：{err}"), 500)
        rid = save_result(report, {"source": source, "at": time.strftime("%Y-%m-%d %H:%M:%S")})
        return self._redirect(f"/result/{rid}")

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
            if not filename.endswith(".sol"):
                return "只接受 .sol 檔", None
            if not data.strip():
                return "檔案是空的", None
            if len(data) > MAX_UPLOAD:
                return "檔案太大（上限 256 KB）", None
            return f"{stem}.sol", data
        return "沒有收到檔案", None

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[web] {self.address_string()} {fmt % args}\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python3 -m arbiter.web")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)
    # Loopback only, and not configurable: there is no sandbox behind this page yet.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"ARBITER Gate web: http://127.0.0.1:{args.port}/  (local only, Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
