#!/usr/bin/env python3
"""The result page, job page and ME routes, rendered offline: no LLM, no network, no server.

Real results (runs/gate/web/, git-ignored) and synthetic gate.json / ME sidecar fixtures go
through web.result_page() -- the function GET /result/<rid> uses -- and the routes through
Handler.do_GET on an in-memory request. Each case asserts the zh-TW words that must appear
and the ones that must not:

  repro_failed     finals rid 7b8ba16f75f7 (UnstakePool, reproduction_failed, no patch):
                   沒有量到 x4, 重現失敗 and the note in zh-TW; never 沒有受損, never
                   「參考下方的修補」; the English note only under 技術細節
  loose_profit     finals rid b5d33d7911a5 (eth_profit): the loose-predicate advice, the
                   abg note in zh-TW, "plan 6.2" only under 技術細節
  verified         a StakingVault upload with a verified patch: 「參考下方的修補」 stays,
                   every scenario tag follows the conservation rule
  playback_date    rid 300cba390f44 (playback, meta without a date) shows 2026-10-28; a
                   from_results result with no job shows the recording note's date
  conservation     synthetic: harmed / short / none / unmeasured, one tag each
  patch_notes      synthetic: rejected patch notes in zh-TW, unknown English folded away
  strict_retry     synthetic: proven / not_proven / skipped strict retries
  novelty          synthetic: re-attack attempts with novelty badges, check 5 not_diverse
  units            synthetic: ERC-20 amounts with decimals and symbol, treasury TA/TB
  units_markup     an older gate.json whose unit label is the AI-written token expression
                   with an <img onerror> in it (web-security-wording-1): nothing of it reaches
                   the result page (story, tables, re-measure, timeline: 「代幣」 instead), the PR
                   comment table keeps its columns, parse_unit never stores an expression
  me_blocked       synthetic sidecar: ME testnet, blocked deploy, explorer link (Cosmos tx
                   hash route), verify link, no host path even when the sidecar carries one
  me_deployed      CREATE2 deploy, escrow paid with the settlement linked from its Cosmos hash;
                   a javascript: link is not a link
  me_claimed       a deployment the auditor only declared
  me_absent        no sidecar or a broken one: no card, the page still renders
  me_links         old /tx/ and /address/ links, an EVM hash in a transactions link and a
                   foreign host are never links; links built from cosmosTx and the block;
                   every 0x hash with its cast receipt command under 技術細節
  me_patched       contract v2 sidecar with "patched": the timeline 紀錄 #3 已證實可攻擊 ->
                   鏈上合約拒絕部署 -> 修補 -> 紀錄 #4 未發現可證明攻擊（不等於安全）->
                   由 AuditRegistry 部署到 0x...; each step's explorer link, the escrow
                   settlement line, verify links for both records and the deployed address
  me_real          a real sidecar written by the anvil demo (tests/data/me_anvil_demo.me.json,
                   or --sidecar): anvil named, no explorer link, verify links carry net=anvil
  job_words        the job page's check words come from CHECK_WORDS (not_reached, not_diverse)
  job_reattack     the live re-attack line: AI 沒有換手法（不算通過） / 換了手法，未成功 /
                   未成功 (a gate without technique), never a promise of another repair
  timeout          a web job that hits REPAIR_TIMEOUT (raised for the strict re-proof) is
                   saved and shown as 無法判定（稽核未完成）
  pr_strict        PR comment: one zh-TW line per strict re-proof (proven / not_proven /
                   skipped / error), none without one, English reasons left out
  sarif_strict     SARIF: strict_retry in result properties and message, counted in run
                   properties (N 次中 M 次), valid against the schema (venv-tools, if present)
  home_verify      the home page links 「鏈上驗證（ME Network）」 to /verify
  verify_routes    /verify, its assets and /me/deployments/<net>.json serve files; traversal,
                   encoded dots, hidden files, symlinks out and unknown types are 404
  wording          every page above: no bare 安全, CLEAR or 首創, no host path, no mainland
                   form 托管 (zh-TW 託管), balanced HTML

    python3 scripts/webui_probe.py [--sidecar runs/gate/web/<rid>.me.json] [--out DIR]

--out keeps what the cases rendered: result.html (the verified StakingVault result with the
real anvil sidecar), result-testnet-fixture.html (the same result with the synthetic ME
testnet chain), job.html, strict.gate.json, strict.sarif and strict.comment.md.
"""

from __future__ import annotations

import argparse
import copy
import io
import json
import re
import shutil
import subprocess
import sys
import tempfile
from html import unescape
from html.parser import HTMLParser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter import patch, prgate, sarif, units, web, webui  # noqa: E402
from arbiter.verdict import LABELS, NOT_EXECUTED, PROVEN  # noqa: E402

REAL_WEB = web.WEB
RIG = Path(__file__).resolve().parent.parent
REAL_SIDECAR = RIG / "tests" / "data" / "me_anvil_demo.me.json"
# The tools venv (jsonschema) next to the checkout: ~/innoserve/venv-tools for the main checkout
# and for the worktrees under ~/innoserve/wt/.
VENV_PY = next((d / "venv-tools" / "bin" / "python" for d in RIG.parents
                if (d / "venv-tools" / "bin" / "python").exists()), None)
REPRO, LOOSE, VERIFIED, PLAYBACK = "7b8ba16f75f7", "b5d33d7911a5", "be2e752405bb", "300cba390f44"
INTERNAL_ENGLISH = ["exploit does not compile", "is not patched", "plan 6.2", "strict predicates only",
                    "round(s)", "refusals", "recorded patch no longer", "brand new internal message",
                    "no strict predicate"]

results: list[tuple[str, bool, str]] = []
pages: dict[str, str] = {}


def check(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'WRONG'}] {name:14s} {detail}")


def outside_details(html: str) -> str:
    """The page with every outermost <details>...</details> block removed."""
    out, depth, pos = [], 0, 0
    for m in re.finditer(r"<details\b|</details>", html):
        if m.group(0) != "</details>":
            if depth == 0:
                out.append(html[pos:m.start()])
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                pos = m.end()
    out.append(html[pos:] if depth == 0 else "")
    return "".join(out)


def text_of(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", re.sub(r"<(script|style)\b.*?</\1>", "", html, flags=re.S)))


class Balance(HTMLParser):
    TAGS = {"div", "details", "summary", "table", "tr", "ul", "dl", "a", "pre", "h1", "h2", "h3", "span", "b"}

    def __init__(self) -> None:
        super().__init__()
        self.stack: list[str] = []
        self.bad: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag in self.TAGS:
            self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag not in self.TAGS:
            return
        if self.stack and self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.bad.append(f"</{tag}> with {self.stack[-1:] or 'nothing'} open")


def balanced(html: str) -> list[str]:
    p = Balance()
    p.feed(html)
    return p.bad + ([f"unclosed {p.stack}"] if p.stack else [])


def render(rid: str) -> str:
    body = web.result_page(rid)
    assert body is not None, rid
    pages[rid] = body.decode("utf-8")
    return pages[rid]


# -- fixtures ---------------------------------------------------------------------------

def envs(rows: list[tuple]) -> list[dict]:
    return [{"env": i, "endow_wei": 10**19, "warp_s": 0, "rounds": 1, "A": a, "B": b, "G": g}
            for i, (a, b, g) in enumerate(rows)]


def finding(**kw: object) -> dict:
    f = {"title": "probe finding", "vulnerable_function": "withdraw", "severity": "high",
         "vuln_class": "reentrancy", "poc_name": "PocProbe", "predicate": "victim_loss",
         "predicate_strict": True, "predicate_note": "",
         "abg": {"status": "measured", "label": "已重現（合成層）",
                 "environments": envs([(10**19, 0, 10**19)] * 4)},
         "patch": {"status": "not_generated", "label": "未產生修補"},
         "regression": {"status": "unavailable", "note": "測試用合成資料"}}
    f.update(kw)
    return f


def saved(*files: list[dict], mode: str = "file", **meta: object) -> dict:
    entries = [{"id": f"file::Probe{i}", "artifact": {"uri": f"Probe{i}.sol"}, "verdict": PROVEN,
                "label": LABELS[PROVEN], "reason": "finding_submitted", "turns": 3, "findings": fs}
               for i, fs in enumerate(files)]
    return {"meta": {"source": "probe", "at": "2026-11-21 23:00:00", **meta},
            "report": {"schema": "arbiter-gate/0.1", "models": ["arbiter-gpt:latest"], "exit_code": 1,
                       "elapsed_s": 1.0, "input": {"mode": mode, "run_id": "probe"}, "files": entries}}


H = "0x" + "ab" * 32
ADDR = "0x" + "12" * 20
EXPLORER = "https://www.explorer-testnet.me/zh-TW"
RPC_ME = "https://beta-hub-8545.explorer-testnet.me"
# me1 (bech32) forms of the fixture addresses, from me/arbiter_me/bech32.py to_me1()
ME1 = {"12": "me1zgfpyysjzgfpyysjzgfpyysjzgfpyysjr2uwmw", "56": "me12et9v4jk2et9v4jk2et9v4jk2et9v4jknc3h4h",
       "58": "me1tpv9skzctpv9skzctpv9skzctpv9skzcaszzm0"}


def tx_url(cosmos: str) -> str:
    """The explorer's transaction route: a Cosmos tx hash (64 hex digits, no 0x)."""
    return f"{EXPLORER}/transactions/{cosmos}?netType=hub"


def account_url(byte: str) -> str:
    return f"{EXPLORER}/accountDetails/{ME1[byte]}"


ME = {"schema": "arbiter-me/0.1", "network": "me-testnet", "chainId": 400, "registry": ADDR, "escrow": None,
      "record": {"id": 3, "tx": H, "block": 123, "verdict": 3, "verdictLabel": "已證實可攻擊",
                 "sourceHash": "0x" + "01" * 32, "gateJsonHash": "0x" + "02" * 32, "exploitHash": "0x" + "03" * 32,
                 "patchHash": "0x" + "00" * 32, "parentId": 0, "auditor": "0x" + "34" * 20, "model": "arbiter-gpt"},
      "deploy": {"status": "blocked", "reason": "鏈上合約拒絕：NotDeployable(3)", "address": None, "tx": None,
                 "linkKind": 0, "runtimeCodeHash": None, "preflight": {"ok": False, "gas": None, "error": "NotDeployable"}},
      "escrow_request": None,
      "explorer": {"record_tx": tx_url("A1" * 32), "deploy_tx": None, "address": None},
      "evidence": {"uri": "/home/tester/innoserve/arbiter-audit/arbiter/runs/gate/web/x.gate.json",
                   "files": [{"name": "gate.json", "sha256": "0x" + "02" * 32}]},
      "recordedAt": "2026-11-22T08:00:00+08:00"}


def write(d: Path, rid: str, data: dict, me: dict | str | None = None) -> None:
    (d / f"{rid}.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    if me is not None:
        (d / f"{rid}.me.json").write_text(me if isinstance(me, str) else json.dumps(me), encoding="utf-8")


def handler_get(path: str) -> tuple[int, str, bytes]:
    """Handler.do_GET on an in-memory request: (status, content type, body)."""
    h = web.Handler.__new__(web.Handler)
    h.path, h.command, h.request_version = path, "GET", "HTTP/1.1"
    h.requestline, h.client_address = f"GET {path} HTTP/1.1", ("127.0.0.1", 0)
    h.wfile, h.close_connection = io.BytesIO(), True
    h.log_message = lambda *a: None  # type: ignore[method-assign]
    h.do_GET()
    head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    ctype = next((ln.split(":", 1)[1].strip() for ln in lines if ln.lower().startswith("content-type:")), "")
    return int(lines[0].split()[1]), ctype, body


# -- cases ------------------------------------------------------------------------------

def real_cases() -> None:
    t = render(REPRO)
    out = outside_details(t)
    ok = (t.count("沒有量到") >= 4 and "重現失敗" in t and "攻擊程式在原合約上編譯失敗，無法重現" in t
          and "沒有受損" not in t and "參考下方的修補" not in t and webui.NEXT_PROVEN["reproduction_failed"] in t
          and "exploit does not compile on the original" in t and "exploit does not compile" not in out)
    check("repro_failed", ok, f"沒有量到 x{t.count('沒有量到')}, 重現失敗 {'重現失敗' in t}, "
          f"沒有受損 {'沒有受損' in t}, 參考下方的修補 {'參考下方的修補' in t}")

    t = render(LOOSE)
    out = outside_details(t)
    ok = (webui.NEXT_PROVEN["loose"] in t and "參考下方的修補" not in t
          and "這次是用寬鬆條件 eth_profit 證實的" in t and "plan 6.2" in t and "plan 6.2" not in out)
    check("loose_profit", ok, "loose advice, abg note in zh-TW, English only under 技術細節")

    t = render(VERIFIED)
    rep = web.load_result(VERIFIED)
    want = {}
    for r in rep["report"]["files"][0]["findings"][0]["abg"]["environments"]:
        words = webui.HARM_TAGS[webui.harm(r)][1]
        want[words] = want.get(words, 0) + 1
    tags = re.findall(r"<td><span class='tag[^']*'>([^<]+)</span></td>", t)
    got = {w: tags.count(w) for w in want}
    ok = webui.NEXT_PROVEN["verified"] in t and got == want and sum(want.values()) == 4
    check("verified", ok, f"verified advice kept; tags {got}")

    t = render(PLAYBACK)
    banner = re.search(r"<div class='banner rec'>.*?</div>", t, re.S)
    meta_has = "recorded_on" in (web.load_result(PLAYBACK) or {}).get("meta", {})
    with tempfile.TemporaryDirectory(prefix="webui-probe-") as tmp:
        web.WEB = Path(tmp)
        s = saved([finding()], mode="from_results")
        s["report"]["input"]["results"] = "runs/spark-test-2.results.jsonl"
        write(Path(tmp), "a1a1a1a1a1a1", s)
        t2 = render("a1a1a1a1a1a1")
        web.WEB = REAL_WEB
    ok = bool(banner) and "2026-10-28" in banner.group(0) and not meta_has and "2026-10-28 的實際紀錄" in t2
    check("playback_date", ok, f"banner: {text_of(banner.group(0)) if banner else None}; no-job result dated: "
          f"{'2026-10-28' in t2}")


def synthetic_cases(d: Path) -> None:
    web.WEB = d
    write(d, "c0c0c0c0c0c0", saved([finding(abg={"status": "measured", "label": "已重現（合成層）", "environments": envs(
        [(10, 0, 10), (10, 5, 1), (10, 10, 0), (None, None, None)])})]))
    t = render("c0c0c0c0c0c0")
    words = [w for (_, whose), (_, w) in webui.HARM_TAGS.items() if whose == "victim"]
    counts = {w: t.count(f">{w}<") for w in words}
    ok = all(n == 1 for n in counts.values())
    check("conservation", ok, " / ".join(f"{w[:8]}…x{n}" for w, n in counts.items()))

    write(d, "c1c1c1c1c1c1", saved(
        [finding(patch={"status": "rejected", "label": "未能產生通過驗證的修補", "note": "2 round(s), refusals {'1': 2, 'L': 1}"})],
        [finding(patch={"status": "rejected", "label": "未能產生通過驗證的修補",
                        "note": "recorded patch no longer passes the gate (first failure: check 2)"})],
        [finding(patch={"status": "rejected", "label": "未能產生通過驗證的修補", "note": "brand new internal message"})]))
    t = render("c1c1c1c1c1c1")
    out = outside_details(t)
    ok = ("AI 試了 2 輪修補，都沒有通過修補閘門的檢查（沒通過的檢查：檢查 1 共 2 次、檢查 L 共 1 次）" in t
          and "錄製時的修補這次重新驗證沒有通過（第一個沒通過的是檢查 2）" in t
          and "原因沒有對應的白話說明" in t and "brand new internal message" in t
          and not any(x in out for x in INTERNAL_ENGLISH) and "參考下方的修補" not in t
          and t.count(webui.NEXT_PROVEN["no_patch"]) == 3)
    check("patch_notes", ok, "rejected notes in zh-TW, unknown English only under 技術細節, no-patch advice x3")

    loose = {"predicate": "eth_profit", "predicate_strict": False,
             "predicate_note": "以寬鬆謂詞 eth_profit 證實；A/B/G 與修補目前只支援 victim_loss",
             "abg": {"status": "not_supported", "label": "此謂詞或模式尚不支援 A/B/G", "environments": envs([(None,) * 3] * 4)}}
    write(d, "c2c2c2c2c2c2", saved(
        [finding(**loose, strict_retry={"status": "proven", "predicate": "victim_loss", "poc_name": "PocStrict",
                                        "turns": 3, "requests": 4, "elapsed_s": 50.5, "label": "x"})],
        [finding(**loose, strict_retry={"status": "not_proven", "turns": 5, "requests": 6, "elapsed_s": 70})],
        [finding(**loose, strict_retry={"status": "skipped", "reason": "no strict predicate for this class"})]))
    t = render("c2c2c2c2c2c2")
    plain = text_of(t)
    head = "寬鬆條件證實 → 系統要求 AI 改用嚴格條件再證明一次："
    ok = (f"{head}成功（3 回合）" in plain and f"{head}沒有成功（5 回合）" in plain and f"{head}沒有進行" in plain
          and "PocStrict" in t and "no strict predicate" not in outside_details(t)
          and t.count(webui.NEXT_PROVEN["loose"]) == 3)
    check("strict_retry", ok, "proven (3 回合) / not_proven (5 回合) / skipped, loose advice x3")

    attempts = [{"name": f"Poc{n}", "hypothesis": f"hypothesis {n}", "passed": n == "new_class",
                 "fingerprint": {"entry": "withdraw", "class": n}, "novelty": n}
                for n in ("same", "new_entry", "new_class", "unknown")]
    gates = {"0": "pass", "L": "pass", "3": "pass", "1": "pass", "2": "pass", "4": "not_applicable", "5": "not_diverse"}
    write(d, "c3c3c3c3c3c3", saved([finding(patch={
        "status": "verified", "label": "修補已通過驗證（針對此攻擊）", "origin": "repair", "changed_lines": 2,
        "rationale": "probe", "diff": "", "gate_checks": gates,
        "reattack": {"enabled": True, "status": "not_diverse", "attempts": attempts, "novel": False,
                     "attacks": 4, "requests": 9, "elapsed_s": 100}})]))
    t = render("c3c3c3c3c3c3")
    badges = re.findall(r"<li><span class='tag[^']*'>([^<]+)</span>", t)
    ok = (badges == ["同一手法", "換入口", "換手法", "無法判斷"] and t.count("AI 沒有換手法（不算通過）") >= 2
          and "lamp not_diverse" in t and "&quot;class&quot;: &quot;new_entry&quot;" in t)
    check("novelty", ok, f"badges {badges}; check 5 not_diverse shown {t.count('AI 沒有換手法（不算通過）')}x")

    usdc = {"token": "USDC", "decimals": 6}
    tok = {"token": "0x" + "cd" * 20, "decimals": 18}
    rows = envs([(1000 * 10**6, 0, 1000 * 10**6), (None, None, 100 * 10**18), (5, 5, 0), (None, None, None)])
    rows[0]["unit"] = usdc
    rows[1].update(TA=100 * 10**18, TB=0)
    rows[2]["unit"] = tok
    rows[2].update(A="123456789000000000000000", B="123456789000000000000000")
    write(d, "c4c4c4c4c4c4", saved([finding(abg={"status": "measured", "label": "已重現（合成層）", "environments": rows})]))
    t = render("c4c4c4c4c4c4")
    ok = ("1,000 USDC" in t and "123,456.789 0xcdcd…cdcd" in t and "公庫餘額（沒攻擊）" in t
          and "公庫受損（攻擊者多拿的 ≥ 公庫少掉的）" in t and t.count(">沒有量到<") == 1
          and webui.amount(1, {"token": "T", "decimals": 30}) == "0 T" and webui.amount(None, usdc) == "—")
    check("units", ok, "ERC-20 decimals/symbol, address shortened, treasury TA/TB judged by the same rule")

    # web-security-wording-1: before parse_unit was fixed, a token without a plain symbol() got the
    # AI-written token expression as its label; saved results still carry it. It is valid Solidity
    # and evaluates to the real token, so the harness measured a real loss in it.
    expr = 'bytes("<img src=x onerror=document.title=7777>").length > 0 ? address(token) : address(0)'
    bad = {"token": expr, "decimals": 18}
    rows = envs([(5 * 10**18, 0, 5 * 10**18)] * 4)
    for r in rows:
        r["unit"] = bad
    write(d, "c5c5c5c5c5c5", saved([finding(
        abg={"status": "measured", "label": "已重現（合成層）", "environments": rows},
        patch={"status": "verified", "label": "修補已通過驗證（針對此攻擊）", "origin": "repair", "changed_lines": 1,
               "rationale": "probe", "diff": "", "gate_checks": {}, "after": copy.deepcopy(rows),
               "timeline": [{"side": "attack", "source": "audit", "round": 1, "result": "proven", "abg": rows,
                             "finding": {}}]})]))
    t = render("c5c5c5c5c5c5")
    raw = re.sub(r"<(script|style)\b.*?</\1>", "", t, flags=re.S)
    tags = re.findall(r"<(\w+)", raw)
    pipe = {"token": "address(t) | x", "decimals": 18}
    table = prgate._abg_table([{**rows[0], "unit": pipe}, {**rows[1], "unit": bad}])
    cols = {ln.count("|") for ln in table}
    unit_line = 'ArbiterUnit(6 [6e0], "USDC")'
    ok = ("onerror" not in t and "<img" not in t and "img" not in tags and expr not in t
          and webui.esc(expr) not in t and "token)" not in text_of(t)
          and "5 代幣" in text_of(t) and t.count("5 代幣") >= 16  # story, bars, 4 scenarios, re-measure, timeline
          and webui.amount(5, {"token": "<b>x</b>", "decimals": 0}) == "5 代幣"
          and webui.amount(5, {"token": "USDC", "decimals": 0}) == "5 USDC"
          and len(cols) == 1 and "address(t)" not in "".join(table) and "<img" not in "".join(table)
          and units.unit_name(bad) == "token" and units.unit_name({"token": "HOOK"}) == "HOOK"
          and units.format_amount(5 * 10**18, bad, zh=True) == "5 token"
          and patch.parse_unit("", expr) == {"token": None, "decimals": None}
          and patch.parse_unit(unit_line, expr) == {"token": "USDC", "decimals": 6}
          and patch.parse_unit('ArbiterUnit(18, "Wrapped Ether")', expr) == {"token": None, "decimals": 18})
    check("units_markup", ok, f"expression label never printed ({t.count('5 代幣')}x 「5 代幣」, img tags "
          f"{tags.count('img')}), PR table columns {sorted(cols)}, parse_unit keeps symbols only")

    web.WEB = REAL_WEB


def chain_steps(t: str) -> list[tuple[str, str]]:
    """The ME card's timeline: (class, title text) of each step, in order."""
    m = re.search(r"<ol class='mechain'>(.*?)</ol>", t, re.S)
    return [(c, unescape(text_of(b)).strip()) for c, b in re.findall(r"<li class='([^']*)'><b>(.*?)</b>", m.group(1) if m else "")]


def hrefs(t: str) -> list[str]:
    return re.findall(r"href='([^']*)'", t)


def patched_fixture() -> dict:
    """A contract v2 sidecar on the ME testnet: record #3 proven and refused, the patched child
    #4 deployed through the registry, the escrow fee settled by #3 (BRIEF 4.2 + "patched")."""
    me = copy.deepcopy(ME)
    me["escrow"] = "0x" + "21" * 20
    me["record"].update(patchHash="0x" + "0f" * 32, initcodeHash="0x" + "09" * 32, toolCommit="0x" + "0b" * 20,
                        cosmosTx="E5" * 32)
    me["deploy"].update(tx="0x" + "cd" * 32, cosmosTx="F6" * 32)
    me["explorer"] = {"record_tx": tx_url("E5" * 32), "deploy_tx": tx_url("F6" * 32), "address": None,
                      "registry": account_url("12")}
    me["evidence"] = {"uri": "https://evidence.example.org/staking-vault/original", "manifest": "0x" + "0e" * 32,
                      "files": [{"name": "gate.json", "sha256": "0x" + "02" * 32}]}
    me["escrow_request"] = {"id": 1, "fee_wei": "1000000000000000", "status": "paid", "settleTx": "0x" + "99" * 32,
                            "recordId": 3, "recipient": "0x" + "34" * 20, "cosmosTx": "D4" * 32}
    me["patched"] = {
        "record": {"id": 4, "tx": "0x" + "44" * 32, "block": 130, "verdict": 1,
                   "verdictLabel": "未發現可證明攻擊（不等於安全）", "sourceHash": "0x" + "05" * 32,
                   "gateJsonHash": "0x" + "02" * 32, "exploitHash": "0x" + "00" * 32, "patchHash": "0x" + "0f" * 32,
                   "parentId": 3, "auditor": "0x" + "34" * 20, "model": "arbiter-gpt", "initcodeHash": "0x" + "0a" * 32,
                   "toolCommit": "0x" + "0b" * 20},
        "deploy": {"status": "deployed", "reason": "", "address": "0x" + "58" * 20, "tx": "0x" + "55" * 32,
                   "linkKind": 2, "runtimeCodeHash": "0x" + "0d" * 32, "preflight": {"ok": True, "gas": 206909, "error": None}},
        "explorer": {"record_tx": tx_url("A7" * 32), "deploy_tx": tx_url("B8" * 32), "address": account_url("58"),
                     "registry": account_url("12")},
        "evidence": {"uri": "https://evidence.example.org/staking-vault/patched", "manifest": "0x" + "1e" * 32,
                     "files": [{"name": "src/StakingVault.sol", "sha256": "0x" + "05" * 32}]},
        "recordedAt": "2026-11-22T08:05:00+08:00"}
    return me


def me_cases(d: Path, sidecar: Path, out: Path | None) -> None:
    web.WEB = d
    write(d, "d0d0d0d0d0d0", saved([finding()]), ME)
    t = render("d0d0d0d0d0d0")
    link = f"<a href='{tx_url('A1' * 32)}' target='_blank' rel='noopener'>"
    ok = ("ME Network" in t and "測試網" in t and "紀錄 #3：已證實可攻擊" in t and "鏈上合約拒絕部署" in t
          and "鏈上合約拒絕：NotDeployable(3)" in t
          and link in t and "href='/verify?record=3'" in t and "在驗證頁查看" in t
          and "/home/" not in t and "0x" + "02" * 32 in t and "0x" + "02" * 32 not in outside_details(t)
          and t.index("鏈上紀錄") < t.index("4 種情境"))
    check("me_blocked", ok, "testnet, record #3, blocked deploy, explorer link (_blank, noopener), verify link, no host path")

    me = copy.deepcopy(ME)
    me["record"].update(id=4, verdict=1)
    dep_tx = "0x" + "ef" * 32
    me["deploy"] = {"status": "deployed", "linkKind": 2, "address": "0x" + "56" * 20, "tx": dep_tx,
                    "runtimeCodeHash": "0x" + "77" * 32}
    me["explorer"].update(address=account_url("56"), deploy_tx="javascript:alert(1)")
    me["escrow"] = ADDR
    me["escrow_request"] = {"id": 1, "fee_wei": "10000000000000000", "status": "paid", "settleTx": "0x" + "99" * 32,
                            "cosmosTx": "B2" * 32}
    write(d, "d1d1d1d1d1d1", saved([finding()]), me)
    t = render("d1d1d1d1d1d1")
    ok = ("由 AuditRegistry 部署到" in t and "部署的就是紀錄 #4 稽核過的 bytecode" in t and "CREATE2" in t
          and "0x" + "56" * 20 in t and f"href='{account_url('56')}'" in t
          and "javascript:" not in t and "0.01 MEC" in t and "已付給稽核者" in t
          and "未發現可證明攻擊（不等於安全）" in t and f"href='{tx_url('B2' * 32)}'" in t
          and f"href='/verify?address=0x{'56' * 20}'" in t)
    check("me_deployed", ok, "CREATE2 deploy with address link, escrow paid 0.01 MEC (settlement linked by its "
          "Cosmos hash), javascript: link dropped")

    me = copy.deepcopy(ME)
    me["record"].update(id=5, verdict=1)
    me["deploy"] = {"status": "deployed", "linkKind": 1, "address": "0x" + "57" * 20}
    write(d, "d2d2d2d2d2d2", saved([finding()]), me)
    t = render("d2d2d2d2d2d2")
    check("me_claimed", "稽核者自行宣告的部署" in t and "CREATE2）" not in t, "declared deployment, no CREATE2 claim")

    write(d, "d3d3d3d3d3d3", saved([finding()]))
    write(d, "d4d4d4d4d4d4", saved([finding()]), "{not json")
    write(d, "d5d5d5d5d5d5", saved([finding()]), {"schema": "other/1", "record": ME["record"]})
    plain = [render(r) for r in ("d3d3d3d3d3d3", "d4d4d4d4d4d4", "d5d5d5d5d5d5")]
    s = web.load_result("d3d3d3d3d3d3")
    old = webui.render_result(s, "d3d3d3d3d3d3", {}, "", []).decode("utf-8")  # the old 5-argument call
    ok = all("在驗證頁查看" not in t and "稽核結果" in t for t in plain + [old])
    check("me_absent", ok, "no sidecar / broken JSON / other schema / old call: no card, page renders")

    # wave-1 explorer links (/tx/0x..., /address/0x...), an EVM hash where the explorer wants a Cosmos
    # hash, and another host: none is a link; the card builds the explorer's own routes instead
    me = copy.deepcopy(ME)
    me["record"].update(id=6, cosmosTx=None)
    me["deploy"].update(tx="0x" + "cd" * 32, cosmosTx="C3" * 32)
    me["explorer"] = {"record_tx": f"https://www.explorer-testnet.me/tx/{H}",
                      "deploy_tx": f"{EXPLORER}/transactions/0x{'cd' * 32}?netType=hub",
                      "address": f"https://www.explorer-testnet.me/address/0x{'56' * 20}",
                      "registry": f"https://explorer.example.net/zh-TW/accountDetails/{ME1['12']}"}
    me["escrow_request"] = {"id": 2, "fee_wei": "1000000000000000", "status": "refunded", "settleTx": "0x" + "98" * 32}
    me["patched"] = copy.deepcopy(patched_fixture()["patched"])
    me["patched"]["explorer"] = {"record_tx": "https://www.explorer-testnet.me/tx/0x" + "44" * 32,
                                 "deploy_tx": "https://www.explorer-testnet.me/tx/0x" + "55" * 32,
                                 "address": "https://www.explorer-testnet.me/address/0x" + "58" * 20}
    write(d, "d6d6d6d6d6d6", saved([finding()]), me)
    t = render("d6d6d6d6d6d6")
    bad = [h for h in hrefs(t) if re.search(r"/tx/|/address/|transactions/0x|explorer\.example", h)]
    cmd = f"cast receipt {H} --rpc-url {RPC_ME}"
    ok = (not bad and H in t and f"href='{EXPLORER}/blocks/123?netType=hub'" in t
          and f"href='{tx_url('C3' * 32)}'" in t and "已退回付款人（稽核沒有完成）" in t
          and cmd in t and cmd not in outside_details(t)
          and f"Cosmos 交易 <span class='hash'>{'C3' * 32}</span>" in t
          and chain_steps(t)[-1][1] == "由 AuditRegistry 部署到 0x58585858…585858"
          and f"href='/verify?address=0x{'58' * 20}'" in t)
    check("me_links", ok, "no /tx/, /address/, EVM-hash or foreign-host link; block and refusal linked from the "
          "explorer's routes; cast receipt under 技術細節" + (f"; BAD {bad}" if bad else ""))

    write(d, "d7d7d7d7d7d7", saved([finding()]), patched_fixture())
    t = render("d7d7d7d7d7d7")
    steps = chain_steps(t)
    want = [("bad", "紀錄 #3：已證實可攻擊"), ("bad", "鏈上合約拒絕部署"), ("info", "修補"),
            ("info", "紀錄 #4：未發現可證明攻擊（不等於安全）"), ("ok", "由 AuditRegistry 部署到 0x58585858…585858")]
    order_ok = (len(steps) == 5 and all(c == wc and s.startswith(ws) for (c, s), (wc, ws) in zip(steps, want)))
    links = [tx_url(c * 32) for c in ("E5", "F6", "A7", "B8", "D4")] + [account_url("58"), account_url("12")]
    got = hrefs(t)
    outside = outside_details(t)
    ok = (order_ok and all(u in got for u in links) and "上一筆紀錄 #3（修補前）" in t
          and "委託 #1：0.001 MEC，已付給稽核者（稽核有完成），費用不隨判定改變" in t and "由紀錄 #3 結算" in t
          and all(f"/verify?{q}" in got for q in ("record=3", "record=4", f"address=0x{'58' * 20}"))
          and "紀錄 #4（修補後）" in t and all(h in t and h not in outside for h in
                                            ("0x" + "0a" * 32, "0x" + "0b" * 20, "0x" + "1e" * 32, "0x" + "0d" * 32))
          and "href='https://evidence.example.org/staking-vault/patched'" in t
          # the patched record carries its Cosmos hashes only inside its explorer URLs
          and all(f"Cosmos 交易 <span class='hash'>{c * 32}</span>" in t for c in ("E5", "F6", "D4", "A7", "B8"))
          and not [h for h in got if "/tx/" in h or "/address/" in h])
    check("me_patched", ok, " → ".join(s for _, s in steps)
          + f"; {sum(u in got for u in links)}/{len(links)} explorer links")
    if out:
        shutil.copyfile(REAL_WEB / f"{VERIFIED}.json", d / f"{VERIFIED}.json")
        (d / f"{VERIFIED}.me.json").write_text(json.dumps(patched_fixture()), encoding="utf-8")
        (out / "result-testnet-fixture.html").write_text(render(VERIFIED), encoding="utf-8")

    real = json.loads(sidecar.read_text(encoding="utf-8"))
    shutil.copyfile(REAL_WEB / f"{VERIFIED}.json", d / f"{VERIFIED}.json")
    shutil.copyfile(sidecar, d / f"{VERIFIED}.me.json")
    t = render(VERIFIED)
    pages["me_real"] = t
    steps = chain_steps(t)
    rec, pat = real["record"], real.get("patched") or {}
    vhref = next((h for h in hrefs(t) if h.startswith(f"/verify?record={rec['id']}")), "")
    n_steps = 5 if pat.get("record") else 2
    ok = (real.get("schema") == "arbiter-me/0.1" and len(steps) == n_steps
          and steps[0][1] == f"紀錄 #{rec['id']}：{webui.ME_STEP_VERDICTS[rec['verdict']]}"
          and (not pat or steps[-1][1].startswith("由 AuditRegistry 部署到"))
          and (real.get("chainId") != 31337 or ("本機測試鏈 anvil" in t and "net=anvil" in vhref
                                               and f"registry={real['registry']}" in vhref
                                               and not [h for h in hrefs(t) if "explorer-testnet" in h]))
          and rec["gateJsonHash"] in t and rec["gateJsonHash"] not in outside_details(t)
          and (not real.get("escrow_request") or
               f"由紀錄 #{real['escrow_request'].get('recordId')} 結算" in t))
    check("me_real", ok, f"{sidecar.name}: chain {real.get('chainId')}, " + " → ".join(s for _, s in steps))
    if out:
        (out / "result.html").write_text(t, encoding="utf-8")
    web.WEB = REAL_WEB


def timeout_case(d: Path) -> None:
    """web.run_job for an upload whose gate hits REPAIR_TIMEOUT (jobs.run_gate_job returns None)."""
    seen: dict = {}
    orig = (web.jobs.run_gate_job, web.jobs.JOBS)

    def no_gate(job: dict, argv: list, sandboxed: bool, timeout: int, lock: object) -> None:
        seen.update(timeout=timeout, argv=argv)
        return None

    web.WEB, web.jobs.JOBS = d, d / "jobs"
    web.jobs.run_gate_job = no_gate
    try:
        web.run_job({"id": "20261122-010000-abcdef", "kind": "upload", "label": "Probe.sol",
                     "params": {"path": str(d / "Probe.sol")}})
        job = web.jobs.load("20261122-010000-abcdef") or {}
        saved_ = web.load_result(job.get("rid") or "") or {}
        e = (saved_.get("report") or {}).get("files", [{}])[0]
        t = render(job["rid"]) if job.get("rid") else ""
    finally:
        web.jobs.run_gate_job, web.jobs.JOBS = orig
        web.WEB = REAL_WEB
    # the old limit was the measured three audits and two repairs; the strict re-proof adds
    # up to --max-turns requests (about 7 minutes) before that repair can start
    ok = (web.REPAIR_TIMEOUT >= 3300 + 7 * 60 and seen.get("timeout") == web.REPAIR_TIMEOUT
          and e.get("verdict") == NOT_EXECUTED and e.get("label") == "無法判定（稽核未完成）"
          and e.get("reason") == "job_timeout" and f"{web.REPAIR_TIMEOUT} 秒" in str(e.get("detail"))
          and "無法判定（稽核未完成）" in t and webui.REASONS["job_timeout"] in t and "未發現可證明攻擊" not in t
          and saved_.get("report", {}).get("exit_code") == 2)
    pages["timeout"] = t
    check("timeout", ok, f"REPAIR_TIMEOUT {web.REPAIR_TIMEOUT} s passed to the gate; the timed-out job reads "
          f"{e.get('label')} ({e.get('reason')})")


def strict_gate() -> dict:
    """A gate.json whose proven findings carry each strict_retry status, and one without."""
    loose = {"predicate": "eth_profit", "predicate_strict": False,
             "predicate_note": "以寬鬆謂詞 eth_profit 證實；A/B/G 與修補目前只支援 victim_loss"}
    rep = saved([
        finding(poc_name="PocStrict", strict_retry={
            "status": "proven", "reason": "", "predicate": "victim_loss", "poc_name": "PocStrict", "turns": 3,
            "requests": 4, "elapsed_s": 50.5, "label": "以嚴格謂詞 victim_loss 重新證實：受害者確實因攻擊少拿回錢"}),
        finding(**loose, strict_retry={"status": "not_proven", "reason": "turn_budget_exhausted", "predicate": None,
                                       "poc_name": None, "turns": 5, "requests": 6, "elapsed_s": 70.0,
                                       "label": "嚴格謂詞重試沒有成功，保留原本的寬鬆證明"}),
        finding(**loose, strict_retry={"status": "skipped", "reason": "no strict predicate for this class",
                                       "label": "沒有進行嚴格謂詞重試"}),
        finding(**loose, strict_retry={"status": "error", "reason": "ConnectionError: gateway closed", "turns": 1,
                                       "requests": 1, "label": "嚴格謂詞重試沒有完成（執行錯誤），保留原本的寬鬆證明"}),
        finding(poc_name="PocPlain")])["report"]
    rep["generated_at"] = "2026-11-22T01:00:00+0800"
    return rep


def pr_and_sarif(out: Path) -> None:
    rep = strict_gate()
    md = prgate.comment_markdown(rep)
    head = "- 寬鬆條件證實 → 系統要求 AI 改用嚴格條件再證明一次："
    lines = [head + "成功，滿足 victim_loss（受害者少拿回錢，而且差額在攻擊者手上）。用了 3 回合、4 個 AI 請求。",
             head + "沒有成功；原本的寬鬆證實仍然成立，但沒有受害者損失的數字。用了 5 回合、6 個 AI 請求。",
             head + "沒有進行。",
             head + "沒有完成（執行錯誤）；原本的寬鬆證實仍然成立。用了 1 回合、1 個 AI 請求。"]
    ok = (all(ln in md.splitlines() for ln in lines) and md.count(head) == 4
          and "no strict predicate" not in md and "ConnectionError" not in md
          and "CLEAR" not in md and "首創" not in md and not re.search(r"(?<!不等於)安全", md)
          and "%" not in md)
    check("pr_strict", ok, f"{md.count(head)} strict re-proof lines in the PR comment, English reasons left out")

    doc = sarif.to_sarif(rep)
    res = doc["runs"][0]["results"]
    props = [r["properties"].get("strict_retry") for r in res]
    run_sr = doc["runs"][0]["properties"].get("strict_retry") or {}
    gate_json, sarif_path = out / "strict.gate.json", out / "strict.sarif"
    gate_json.write_text(json.dumps(rep, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    sarif_path.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    (out / "strict.comment.md").write_text(md, encoding="utf-8")
    if VENV_PY:
        p = subprocess.run([str(VENV_PY), str(RIG / "scripts" / "sarif_validate.py"), str(sarif_path), str(gate_json)],
                           capture_output=True, text=True)
        valid = (p.returncode == 0 and "valid SARIF" in p.stdout and "INVALID" not in p.stdout
                 and ": yes" in p.stdout)
        vtext = "schema valid" if valid else f"INVALID: {(p.stdout + p.stderr)[-300:]}"
    else:
        valid, vtext = True, "schema check skipped (no venv-tools with jsonschema)"
    ok = (len(res) == sarif.proven_count(rep) == 5 and valid
          and [x and x["status"] for x in props] == ["proven", "not_proven", "skipped", "error", None]
          and props[0]["text"] == sarif.strict_retry_text(rep["files"][0]["findings"][0]["strict_retry"])
          and props[0]["poc_name"] == "PocStrict" and "沒有成功" in res[1]["message"]["text"]
          and "寬鬆條件證實" not in res[4]["message"]["text"]
          and run_sr == {"triggered": 4, "by_status": {"proven": 1, "not_proven": 1, "skipped": 1, "error": 1},
                         "note": "寬鬆條件證實後，系統要求 AI 改用嚴格條件再證明一次：4 次中 1 次成功"}
          and "strict_retry" not in sarif.to_sarif(saved([finding()])["report"])["runs"][0]["properties"])
    check("sarif_strict", ok, f"result properties {[x and x['status'] for x in props]}; run: "
          f"{run_sr.get('note')}; {vtext}")


def job_and_home() -> None:
    job = webui.render_job({"id": "20261121-230000-abcdef", "label": "probe"}).decode("utf-8")
    pages["job"] = job
    ok = ('"not_reached": "沒有輪到"' in job and '"not_diverse": "AI 沒有換手法（不算通過）"' in job
          and "var w=WORDS[s]||" in job and "'off':'這次沒有開'}[s]" not in job)
    check("job_words", ok, "job page check words injected from CHECK_WORDS")
    fn = re.search(r"function reattackText\(e\)\{.*?\n\}", job, re.S)
    body = fn.group(0) if fn else ""
    ok = ("換手法再攻擊：'+reattackText(e)" in job and "WORDS.not_diverse" in body
          and "e.status==='not_proven'&&e.novel===false" in body and "e.novel===true?'換了手法，未成功':'未成功'" in body
          and "'成功（修補被打穿）'" in body and "'沒有完成（不算通過）'" in body and "AI 會再修一次" not in job)
    check("job_reattack", ok, "re-attack line: AI 沒有換手法（不算通過） / 換了手法，未成功 / 未成功 (older gate)")
    home = webui.render_index("", [], [], {}, [], True).decode("utf-8")
    pages["home"] = home
    check("home_verify", "href=\"/verify\">鏈上驗證（ME Network）" in home, "home links 鏈上驗證（ME Network） to /verify")


def verify_routes(d: Path) -> None:
    vdir, deps, outside = d / "me" / "web" / "verify", d / "me" / "deployments", d / "secret"
    for p in (vdir / "lib", deps, outside):
        p.mkdir(parents=True)
    (vdir / "index.html").write_text("<!doctype html><title>verify</title>", encoding="utf-8")
    (vdir / "verify.js").write_text("console.log(1)", encoding="utf-8")
    (vdir / "lib" / "keccak.js").write_text("//k", encoding="utf-8")
    (vdir / ".hidden.js").write_text("//h", encoding="utf-8")
    (vdir / "notes.py").write_text("x=1", encoding="utf-8")
    (deps / "me-testnet.json").write_text('{"chainId": 400}', encoding="utf-8")
    (outside / "secret.js").write_text("SECRET", encoding="utf-8")
    (vdir / "link.js").symlink_to(outside / "secret.js")
    web.VERIFY_DIR, web.DEPLOYMENTS_DIR = vdir, deps
    good = {"/verify": "text/html", "/verify/": "text/html", "/verify/verify.js": "text/javascript",
            "/verify/lib/keccak.js": "text/javascript", "/me/deployments/me-testnet.json": "application/json"}
    bad = ["/verify/../secret/secret.js", "/verify/%2e%2e/secret/secret.js", "/verify/..%2Fsecret%2Fsecret.js",
           "/verify//etc/passwd", "/verify/lib/../../secret/secret.js", "/verify/link.js", "/verify/.hidden.js",
           "/verify/notes.py", "/verify/lib/", "/verify/a\\..\\secret.js", "/me/deployments/../../secret/secret.js",
           "/me/deployments/ME-TESTNET.json", "/me/deployments/me-testnet.js", "/verifyx"]
    got_good = {p: handler_get(p) for p in good}
    got_bad = {p: handler_get(p) for p in bad}
    ok_good = all(s == 200 and c.startswith(good[p]) for p, (s, c, _) in got_good.items())
    ok_bad = all(s == 404 and b"SECRET" not in body for s, _, body in got_bad.values())
    friendly = got_bad["/verify/link.js"][2].decode("utf-8")
    web.VERIFY_DIR = d / "nowhere"
    missing = handler_get("/verify")
    ok = (ok_good and ok_bad and "找不到驗證頁的檔案" in friendly and missing[0] == 404
          and "找不到驗證頁的檔案" in missing[2].decode("utf-8"))
    leaked = [p for p, (s, _, b) in got_bad.items() if s != 404 or b"SECRET" in b]
    check("verify_routes", ok, f"{len(good)} served, {len(bad)} refused with a zh-TW 404"
          + (f"; LEAKED {leaked}" if leaked else ""))


def wording() -> None:
    problems = []
    for name, t in pages.items():
        page_text = re.sub(r"<(script|style)\b.*?</\1>", "", t, flags=re.S)
        if "安全" in page_text.replace("不等於安全", ""):
            problems.append(f"{name}: 安全")
        for word in ("CLEAR", "首創", "/home/", "/mnt/c", "C:\\Users", "托管"):
            if word in page_text:
                problems.append(f"{name}: {word}")
        problems += [f"{name}: {x}" for x in balanced(t)[:2]]
    check("wording", not problems, f"{len(pages)} pages checked" + (f"; {problems[:6]}" if problems else ""))


def main() -> int:
    ap = argparse.ArgumentParser(description="result page, job page and ME routes, rendered offline")
    ap.add_argument("--sidecar", type=Path, default=REAL_SIDECAR,
                    help="a real ME sidecar (<rid>.me.json) to render (default: tests/data/me_anvil_demo.me.json)")
    ap.add_argument("--out", type=Path, help="keep the rendered pages, gate.json, SARIF and PR comment here")
    args = ap.parse_args()
    missing = [r for r in (REPRO, LOOSE, VERIFIED, PLAYBACK) if not (REAL_WEB / f"{r}.json").is_file()]
    if missing:
        print(f"material missing: runs/gate/web/{{{','.join(missing)}}}.json (saved web results, git-ignored)")
        return 2
    print("result page, job page and ME routes, rendered offline\n")
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
    try:
        real_cases()
        with tempfile.TemporaryDirectory(prefix="webui-probe-") as tmp:
            for sub in ("web", "me", "timeout", "strict"):
                (Path(tmp) / sub).mkdir()
            synthetic_cases(Path(tmp) / "web")
            me_cases(Path(tmp) / "me", args.sidecar, args.out)
            verify_routes(Path(tmp))
            timeout_case(Path(tmp) / "timeout")
            pr_and_sarif(args.out or Path(tmp) / "strict")
    finally:
        web.WEB = REAL_WEB
    job_and_home()
    wording()
    if args.out:
        (args.out / "job.html").write_text(pages["job"], encoding="utf-8")
        print(f"kept in {args.out}")
    good = sum(ok for _, ok, _ in results)
    print(f"\n{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
