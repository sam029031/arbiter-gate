"""HTML for the ARBITER Gate page: plain Traditional Chinese, no external resources.

Every page should answer three questions for someone who does not know blockchains:
what is happening now, what does the result mean, and what should I do. Technical
detail is always there, folded into <details> blocks that start closed. Terms (ETH, EVM,
reentrancy, ...) carry a one-line explanation shown on hover or tap. CSS and JS are
inline: the finals venue's network may be unreliable, so nothing loads from a CDN.
"""

from __future__ import annotations

import difflib
import html
import json
import time
from typing import Any

from .progress import STEPS
from .verdict import LABELS, NO_PROVABLE, NOT_EXECUTED, PROVEN, STATIC_HINT

ENV_NAMES = ["預設", "受害者餘額 1000 倍", "一週後", "8 輪攻擊"]
ENV_DESC = [
    "受害者帳戶先拿到 10 ETH，攻擊跑 1 輪",
    "受害者帳戶先拿到 10,000 ETH，看金額變大會不會不同",
    "受害者存錢後過了一週才領，看時間會不會影響",
    "攻擊者重複攻擊 8 輪",
]
CHECKS = [
    ("0", "重現", "在原合約上，這個攻擊確實成立（確認拿來驗證的攻擊是真的）"),
    ("L", "改得乾淨", "修改不超過 12 行，而且沒有用「只准某些帳號」或寫死地址這類取巧寫法"),
    ("3", "介面不變", "對外的函式名稱和參數都沒變，不會弄壞其他程式的呼叫"),
    ("1", "同一招失效", "同一個攻擊在 4 種情境都不再成立"),
    ("2", "一般使用者不受影響", "沒有攻擊時，一般使用者領回的錢不比修補前少"),
    ("4", "專案自己的測試", "上傳的是 Foundry 專案時，專案原本通過的測試，修補後仍然要通過"),
    ("5", "換手法再攻擊", "AI 對修補後的合約再攻擊一次，而且不能用之前用過的攻擊方式"),
]
CHECK_WORDS = {"pass": "通過", "fail": "沒通過", "skipped": "沒有跑（不算通過）",
               "not_applicable": "不適用（單一檔案）", "off": "這次沒有開",
               "not_reached": "沒有輪到"}
GLOSSARY = {
    "ETH": "以太坊上的錢（以太幣）。",
    "智能合約": "放在區塊鏈上、會自動執行的程式；部署之後通常不能再改。",
    "合約": "智能合約：放在區塊鏈上、會自動執行的程式。",
    "重入": "合約先把錢轉出去、後更新帳本；攻擊者在收錢的瞬間再呼叫一次，就能重複領錢。",
    "修補": "AI 提出的程式修改建議，要經過修補閘門的每一道檢查才會顯示「通過驗證」。",
    "EVM": "以太坊的虛擬機器，也就是執行智能合約的環境。",
    "區塊鏈": "大家共同記帳、寫進去就很難竄改的帳本。",
    "模擬區塊鏈": "在這台電腦上模擬的區塊鏈，可以隨意建立帳戶和金額來做實驗。",
    "本地真鏈": "在這台電腦上跑的一條私人區塊鏈（anvil）：交易是真的，但不是正式網路。",
    "沙箱": "隔離的執行環境：不能連網、拿不到任何金鑰，結束就銷毀。",
    "Slither": "一套開源的自動掃描工具，只看程式寫法，不會實際執行攻擊。",
    "gas": "執行一筆交易要付的手續費單位。",
    "回歸測試": "以後每次修改程式都自動再跑一次的測試，用來確認同一個問題沒有回來。",
    "revert": "交易失敗，這筆交易做的所有變更都撤回。",
    "victim_loss": "系統判定攻擊成立的條件：有攻擊時受害者領回的比沒攻擊時少，而且差額在攻擊者手上。",
    "謂詞": "系統判定「攻擊成立」的條件，由系統訂，不是 AI 自己說了算。",
    "SARIF": "程式掃描結果的標準檔案格式，GitHub 看得懂。",
    "forge": "編譯和測試智能合約的工具（Foundry）。",
    "合成層": "在測試框架裡模擬：可以用特殊指令直接準備帳戶和金額。",
    "PoC": "概念驗證程式：真的能跑起來、證明漏洞存在的攻擊程式。",
}


def esc(v: Any) -> str:
    return html.escape("" if v is None else str(v))


def eth(v: int | None) -> str:
    if v is None:
        return "—"
    x = v / 10**18
    return f"{x:,.6f}".rstrip("0").rstrip(".") + " ETH"


def term(word: str, key: str | None = None) -> str:
    tip = GLOSSARY.get(key or word)
    if not tip:
        return esc(word)
    return f"<span class='term' tabindex='0' data-tip='{esc(tip)}'>{esc(word)}</span>"


CSS = """
:root{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1f;--mute:#5f6368;--line:#dcdcd7;
--red:#b3261e;--redbg:#fdecea;--amber:#8a5a00;--amberbg:#fff4dc;--blue:#1f4e8c;--bluebg:#e8f0fb;
--green:#1e6b3a;--greenbg:#e7f4ec;--grey:#5f6368;--greybg:#eeeeea;--code:#f1f1ee;--hl:#fff1b8}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--card:#1d1d20;--ink:#ececec;--mute:#a0a0a8;
--line:#34343a;--red:#ff8a80;--redbg:#3a1d1b;--amber:#ffcc66;--amberbg:#3a2f14;--blue:#9cc2ff;
--bluebg:#1b2a40;--green:#8fd9a8;--greenbg:#16301f;--grey:#b0b0b8;--greybg:#2a2a2e;--code:#26262a;--hl:#4a3f10}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:16px/1.6 system-ui,-apple-system,"Noto Sans TC","PingFang TC","Microsoft JhengHei",sans-serif}
main{max-width:1000px;margin:0 auto;padding:20px 16px 56px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:19px;margin:30px 0 10px}h3{font-size:16px;margin:16px 0 6px}
.sub{color:var(--mute);margin:0 0 18px}.card{background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:16px 18px;margin:12px 0}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:7px 9px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--mute);font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.tbl{overflow-x:auto}.btn{display:inline-block;border:1px solid var(--line);background:var(--card);
color:var(--ink);border-radius:8px;padding:7px 14px;font:inherit;cursor:pointer;text-decoration:none;margin:2px 0}
.btn.primary{background:var(--blue);border-color:var(--blue);color:#fff}.btn.small{padding:3px 10px;font-size:14px}
.note{color:var(--mute);font-size:14px}form.inline{display:inline}
details{margin-top:10px}summary{cursor:pointer;color:var(--mute)}
pre{background:var(--code);border-radius:8px;padding:12px;overflow-x:auto;font-size:13px;line-height:1.45;margin:8px 0;white-space:pre}
.add{color:var(--green)}.del{color:var(--red)}.hunk{color:var(--blue)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:0}dt{color:var(--mute)}dd{margin:0;word-break:break-word}
.tag{display:inline-block;white-space:nowrap;font-size:12px;border-radius:5px;padding:1px 7px;margin-left:6px;background:var(--code);color:var(--mute);font-weight:600}
.tag.ok{background:var(--greenbg);color:var(--green)}.tag.warn{background:var(--amberbg);color:var(--amber)}
.tag.bad{background:var(--redbg);color:var(--red)}
.term{border-bottom:1px dotted currentColor;cursor:help;position:relative;outline:none}
.term:hover::after,.term:focus::after{content:attr(data-tip);position:absolute;left:0;top:1.6em;z-index:20;
width:max-content;max-width:min(320px,80vw);white-space:normal;background:var(--ink);color:var(--bg);
font-size:13px;font-weight:400;line-height:1.5;padding:7px 10px;border-radius:7px;box-shadow:0 4px 14px rgba(0,0,0,.2)}
.banner{border-radius:10px;padding:10px 14px;margin:0 0 14px;font-weight:700;display:flex;gap:10px;align-items:center}
.banner.live{background:var(--greenbg);color:var(--green)}.banner.rec{background:var(--amberbg);color:var(--amber)}
.dot{width:10px;height:10px;border-radius:50%;background:currentColor;flex:none}
.banner.live .dot{animation:pulse 1.2s infinite}@keyframes pulse{50%{opacity:.25}}
.vcard{border-radius:14px;padding:18px 20px;margin:14px 0;display:grid;grid-template-columns:56px 1fr;gap:4px 16px}
.vcard .icon{grid-row:span 3;width:52px;height:52px;border-radius:50%;display:flex;align-items:center;
justify-content:center;font-size:30px;font-weight:800;color:#fff}
.vcard h2{margin:0;font-size:22px}.vcard .mean{font-size:17px}.vcard .next{font-weight:700}
.v-proven{background:var(--redbg);color:var(--ink)}.v-proven .icon{background:var(--red)}.v-proven h2{color:var(--red)}
.v-hint{background:var(--amberbg)}.v-hint .icon{background:var(--amber)}.v-hint h2{color:var(--amber)}
.v-none{background:var(--bluebg)}.v-none .icon{background:var(--blue)}.v-none h2{color:var(--blue)}
.v-unrun{background:var(--greybg)}.v-unrun .icon{background:var(--grey)}.v-unrun h2{color:var(--grey)}
.steps{display:grid;grid-template-columns:repeat(7,1fr);gap:4px;margin:10px 0 6px}
.step{border-radius:8px;padding:8px 6px;font-size:13px;text-align:center;background:var(--greybg);color:var(--mute);line-height:1.3}
.step.done{background:var(--greenbg);color:var(--green)}.step.skip{background:transparent;border:1px dashed var(--line);color:var(--mute)}.step.now{background:var(--blue);color:#fff;font-weight:700;
box-shadow:0 0 0 3px var(--bluebg)}
.now{font-size:21px;font-weight:700;margin:14px 0 6px;line-height:1.45}
.log{list-style:none;padding:0;margin:0}.log li{border-bottom:1px solid var(--line);padding:7px 2px}
.log .res{display:block;color:var(--mute);font-size:14px}.res.passed,.res.finding_accepted{color:var(--green);font-weight:700}
.res.refused,.res.submission_rejected{color:var(--red)}
.lights{display:grid;gap:6px;margin:8px 0}.light{display:grid;grid-template-columns:22px 150px 1fr;gap:8px;align-items:start}
.lamp{width:18px;height:18px;border-radius:50%;background:var(--greybg);border:2px solid var(--line);margin-top:3px}
.lamp.pass{background:#2e9d5b;border-color:#2e9d5b}.lamp.fail{background:var(--red);border-color:var(--red)}
.lamp.skipped,.lamp.not_reached{background:var(--line)}.lamp.not_applicable,.lamp.off{background:var(--bg);border-style:dashed}
.lamp.wait{animation:pulse 1s infinite;border-color:var(--blue)}
.tl{display:flex;flex-wrap:wrap;gap:6px;align-items:stretch;margin:10px 0}.tl .arrow{align-self:center;color:var(--mute)}
.tl details{border:1px solid var(--line);border-radius:10px;padding:8px 10px;background:var(--card);min-width:150px;max-width:100%}
.tl details[open]{flex-basis:100%}.tl summary{cursor:pointer;font-weight:700}.tl .r{font-size:12px;color:var(--mute);display:block}
.tl .att.proven{border-color:var(--red)}.tl .att.proven summary{color:var(--red)}.tl .def.accepted summary{color:#2e9d5b}
.tl .att.not_proven summary{color:#2e9d5b}.tl .def.rejected summary,.tl .att.not_executed summary{color:var(--amber)}
.bars{display:grid;gap:8px;margin:12px 0}.bar{display:grid;grid-template-columns:150px 1fr 90px;gap:8px;align-items:center;font-size:14px}
.bar .track{background:var(--greybg);border-radius:6px;height:22px;overflow:hidden}
.bar .fill{height:100%;border-radius:6px}.fill.a{background:#6b9bd1}.fill.b{background:#e07a5f}.fill.g{background:#9a6fb0}
.story{display:grid;grid-template-columns:1fr auto 1fr auto 1fr;gap:8px;align-items:stretch;margin:12px 0}
.story .box{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:15px}
.story .arrow{align-self:center;font-size:22px;color:var(--mute)}
.envt td.cell{cursor:pointer}.envt td.cell:hover{background:var(--hl)}#envexplain{min-height:2.4em}
.sbs{display:grid;grid-template-columns:1fr 1fr;gap:8px}.sbs pre{margin:0;font-size:12.5px}
.ln{color:var(--mute);user-select:none}.chg{background:var(--hl);display:inline-block;min-width:100%}
.ladder{display:grid;gap:8px;margin:10px 0}.rung{display:grid;grid-template-columns:70px 1fr;gap:10px;
border:2px solid var(--line);border-radius:10px;padding:10px 12px;background:var(--card)}
.rung.pass{border-color:#2e9d5b}.rung.fail{border-color:var(--red)}.rung .n{font-size:20px;font-weight:800;color:var(--mute)}
.rung.pass .n{color:#2e9d5b}.rung.fail .n{color:var(--red)}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.cards .card{margin:0;display:flex;flex-direction:column;gap:6px}
.cards h2{margin:0;font-size:19px}.big{font-size:17px}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.demo{display:block;width:100%;text-align:left;margin:6px 0}
@media (max-width:760px){.cards,.cols,.sbs,.story{grid-template-columns:1fr}.story .arrow{transform:rotate(90deg);justify-self:center}
.steps{grid-template-columns:repeat(4,1fr)}.light{grid-template-columns:22px 1fr}.light .what{grid-column:2}
.bar{grid-template-columns:110px 1fr 70px}.vcard{grid-template-columns:44px 1fr}.vcard .icon{width:40px;height:40px;font-size:22px}}
"""


def page(title: str, body: str, script: str = "") -> bytes:
    return f"""<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>
<style>{CSS}</style></head><body><main>{body}</main>{f'<script>{script}</script>' if script else ''}</body></html>""".encode("utf-8")


# -- verdicts in plain words --------------------------------------------------------------

REASONS = {
    "agent_concluded_no_attack": "AI 檢查後認為找不到能成功的攻擊",
    "turn_budget_exhausted": "AI 用完了回合上限，還沒寫出能成功的攻擊",
    "finding_submitted": "AI 回報了漏洞",
    "context_unbuildable": "合約沒辦法編譯，所以稽核沒有開始",
    "toolchain_unavailable": "這台機器找不到編譯工具（forge）",
    "sandbox_unavailable": "隔離環境（沙箱）沒辦法啟動；沒有隔離就不執行",
    "job_timeout": "超過時間限制，工作被終止",
    "zero completed turns": "AI 模型一個回合都沒有回應",
    "GatewayError": "連不上 AI 模型",
}
NEXT_UNRUN = {
    "context_unbuildable": "請先確認合約能用 forge build 編譯（錯誤位置在下方技術細節），修好再上傳。",
    "toolchain_unavailable": "請在這台機器安裝 Foundry（forge）後再試。",
    "sandbox_unavailable": "請打開 Docker Desktop，等它啟動完成後再上傳一次。",
    "job_timeout": "可以再試一次；如果一直超時，請改用較小的合約。",
    "zero completed turns": "請確認 AI 模型主機有開、連線正常，再試一次。",
    "GatewayError": "請確認 AI 模型主機有開、連線正常，再試一次。",
}


def reason_key(reason: str | None) -> str:
    r = str(reason or "")
    for k in REASONS:
        if r.startswith(k) or k in r:
            return k
    return r


def plain_reason(reason: str | None) -> str:
    k = reason_key(reason)
    return REASONS.get(k, "原因沒有對應的白話說明（原始代號見技術細節）")


VCLASS = {PROVEN: "v-proven", STATIC_HINT: "v-hint", NO_PROVABLE: "v-none", NOT_EXECUTED: "v-unrun"}
ICON = {PROVEN: "!", STATIC_HINT: "?", NO_PROVABLE: "i", NOT_EXECUTED: "…"}


def verdict_card(e: dict[str, Any]) -> str:
    v = e["verdict"]
    f0 = (e.get("findings") or [{}])[0]
    if v == PROVEN:
        loose = f0.get("predicate") and not f0.get("predicate_strict")
        mean = ("AI 寫出的攻擊，在" + term("模擬區塊鏈") + "上真的成功了。"
                + ("有攻擊時，一般使用者領回的錢比沒有攻擊時少，差額落到攻擊者手上；也就是說，有人可以把其他存款人的錢領走。"
                   if not loose else
                   f"（這次是用較寬鬆的條件 {esc(f0.get('predicate'))} 證實：攻擊者拿到了比一般使用者多的錢；沒有量受害者少拿多少。）"))
        nxt = "建議先不要部署。參考下方的修補，修好後重新稽核一次。"
    elif v == STATIC_HINT:
        mean = ("自動掃描工具（" + term("Slither") + "）覺得這裡可疑，但 AI 沒能寫出真的能成功的攻擊。"
                "這是提示，不是證據。")
        nxt = "建議請人看一下下方標出的程式行。這一級不會擋部署。"
    elif v == NO_PROVABLE:
        mean = (f"AI 這次沒有寫出能實際成功的攻擊（{esc(plain_reason(e.get('reason')))}），"
                "自動掃描工具也沒有標出可疑的地方。<b>這不等於安全</b>：可能是這類漏洞目前測不到，或 AI 這次沒想到。")
        nxt = "重要的合約仍建議請人審查；也可以再跑一次。"
    else:
        k = reason_key(e.get("reason"))
        mean = f"稽核沒有完成：{esc(plain_reason(e.get('reason')))}。所以這份合約沒有任何結論，不能當成通過。"
        nxt = NEXT_UNRUN.get(k, "請看下方技術細節的錯誤訊息，處理後再試一次。")
    return (f"<div class='vcard {VCLASS[v]}'><div class='icon'>{ICON[v]}</div>"
            f"<h2>{esc(LABELS[v])}</h2><div class='mean'>{mean}</div>"
            f"<div class='next'>建議：{nxt}</div></div>")


# -- the story: A/B/G as pictures ---------------------------------------------------------

def _harmed(envs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in envs if r.get("A") is not None and r.get("B") is not None and r["B"] < r["A"]]


def story(f: dict[str, Any]) -> str:
    abg = f.get("abg") or {}
    envs = abg.get("environments") or []
    if abg.get("status") != "measured" or not envs:
        return ""
    harmed = _harmed(envs)
    r = harmed[0] if harmed else envs[0]
    name = ENV_NAMES[r["env"]] if r["env"] < len(ENV_NAMES) else str(r["env"])
    top = max(r["A"] or 0, r["B"] or 0, r["G"] or 0, 1)

    def bar(label: str, v: int | None, cls: str) -> str:
        w = 0 if not v else max(2, round(100 * v / top))
        return (f"<div class='bar'><span>{label}</span><div class='track'><div class='fill {cls}' "
                f"style='width:{w}%'></div></div><b>{eth(v)}</b></div>")
    others = [e for e in envs if e not in harmed]
    extra = ""
    if harmed and others:
        g = sorted({e["G"] for e in others if e.get("G")})
        extra = (f"<p class='note'>另外 {len(others)} 種情境裡，受害者照常領回"
                 + (f"，但攻擊者仍多拿了 {' / '.join(eth(x) for x in g)}（來自合約裡其他人的錢）" if g else "")
                 + "。</p>")
    return f"""
<h2>發生了什麼事</h2>
<div class='card'>
<div class='story'>
 <div class='box'><b>1. 一般使用者</b><br>存錢進合約，之後領回。沒有攻擊時，他領回 <b>{eth(r['A'])}</b>。</div>
 <div class='arrow'>→</div>
 <div class='box'><b>2. 攻擊者</b><br>用 AI 寫的攻擊程式（{term('重入')}等手法）呼叫合約。<br><span class='note'>AI 的描述：{esc(f.get('title'))}</span></div>
 <div class='arrow'>→</div>
 <div class='box'><b>3. 結果</b><br>同一個使用者只領回 <b>{eth(r['B'])}</b>，攻擊者多了 <b>{eth(r['G'])}</b>。</div>
</div>
<div class='bars'>{bar('沒攻擊時領回', r['A'], 'a')}{bar('有攻擊時領回', r['B'], 'b')}{bar('攻擊者多拿', r['G'], 'g')}</div>
<p class='note'>上面是「{esc(name)}」情境（{esc(ENV_DESC[r['env']] if r['env'] < len(ENV_DESC) else '')}）。</p>{extra}
</div>"""


def env_table(abg: dict[str, Any], idx: int) -> str:
    envs = abg.get("environments") or []
    if not envs:
        return ""
    rows = []
    for r in envs:
        name = ENV_NAMES[r["env"]] if r["env"] < len(ENV_NAMES) else str(r["env"])
        harmed = r.get("A") is not None and r.get("B") is not None and r["B"] < r["A"]
        tag = "<span class='tag bad'>受害者受損</span>" if harmed else "<span class='tag'>沒有受損</span>"
        def cell(v: int | None, what: str) -> str:
            text = f"「{name}」情境：{what} {eth(v)}。{ENV_DESC[r['env']] if r['env'] < len(ENV_DESC) else ''}"
            return (f"<td class='num cell' title='{esc(text)}' data-explain='{esc(text)}' "
                    f"onclick=\"explain(this)\">{eth(v)}</td>")
        rows.append(f"<tr><td>{esc(name)}</td>"
                    + cell(r.get("A"), "沒有攻擊時，受害者照自己的步驟存錢再領錢，最後領回")
                    + cell(r.get("B"), "有攻擊時，同一個受害者照同樣的步驟，最後只領回")
                    + cell(r.get("G"), "攻擊者在這個情境裡多拿到")
                    + f"<td>{tag}</td></tr>")
    return (f"<h3>4 種情境 <span class='note'>（點一下數字看它代表什麼）</span></h3>"
            f"<div class='tbl'><table class='envt'><tr><th>情境</th><th>沒攻擊時領回</th>"
            f"<th>有攻擊時領回</th><th>攻擊者多拿</th><th></th></tr>{''.join(rows)}</table></div>"
            f"<p class='note' id='envexplain'>每個情境都從乾淨狀態開始，各跑一次「沒有攻擊」和「有攻擊」，"
            f"只差在攻擊有沒有發生。數字是{term('合成層')}量的。</p>")


# -- patch --------------------------------------------------------------------------------

def side_by_side(before: str, after: str) -> str:
    a, b = before.splitlines(), after.splitlines()
    sm = difflib.SequenceMatcher(None, [x.strip() for x in a], [x.strip() for x in b], autojunk=False)
    ca, cb = set(), set()
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            ca.update(range(i1, i2))
            cb.update(range(j1, j2))
    lo = max(0, min(ca | cb | {0}) - 4) if (ca or cb) else 0
    hi_a = min(len(a), (max(ca) if ca else 0) + 6)
    hi_b = min(len(b), (max(cb) if cb else 0) + 6)
    def col(lines: list[str], chg: set[int], hi: int) -> str:
        out = []
        for i in range(lo, hi):
            text = esc(lines[i]) if i < len(lines) else ""
            out.append(f"<span class='ln'>{i + 1:>3} </span>"
                       + (f"<span class='chg'>{text}</span>" if i in chg else text))
        return "\n".join(out)
    return (f"<div class='sbs'><div><b>修改前</b><pre>{col(a, ca, hi_a)}</pre></div>"
            f"<div><b>修改後</b><pre>{col(b, cb, hi_b)}</pre></div></div>"
            f"<p class='note'>黃底是改動的行。前 {len(ca)} 行、後 {len(cb)} 行有變動。</p>")


def check_lights(statuses: dict[str, str]) -> str:
    out = []
    for name, short, what in CHECKS:
        st = statuses.get(name, "")
        word = CHECK_WORDS.get(st, "")
        out.append(f"<div class='light'><span class='lamp {esc(st)}'></span><b>{esc(short)} {word}</b>"
                   f"<span class='what note'>{esc(what)}</span></div>")
    return f"<div class='lights'>{''.join(out)}</div>"


def diff_html(text: str) -> str:
    out = []
    for line in (text or "").splitlines():
        cls = ("hunk" if line.startswith("@@") else
               "add" if line.startswith("+") and not line.startswith("+++") else
               "del" if line.startswith("-") and not line.startswith("---") else "")
        out.append(f"<span class='{cls}'>{esc(line)}</span>" if cls else esc(line))
    return "\n".join(out)


# -- evidence ladder ----------------------------------------------------------------------

RUNG_TEXT = [
    ("合成層", "在測試框架裡證實：攻擊在系統準備好的環境中成立。"),
    ("獨立專案", "把攻擊抽成一個獨立的 Foundry 專案，別人拿去也能重跑出同樣結果。"),
    ("本地真鏈", "在這台電腦的私人區塊鏈上用真的交易重播：要當誰就要有私鑰，要花錢就要有餘額，每筆都付 gas。"),
]


def ladder(ev: dict[str, Any] | None, link: str = "") -> str:
    if not ev:
        return ""
    st = ["pass", (ev.get("rung2") or {}).get("status", "not_run"),
          (ev.get("rung3") or {}).get("status", "not_run")]
    words = {"pass": "成立", "fail": "沒有成立", "not_run": "沒有跑", "error": "沒有完成"}
    rungs = []
    for i in (2, 1, 0):
        name, what = RUNG_TEXT[i]
        extra = ""
        if i == 2 and st[2] == "fail":
            extra = f"<p class='note'><b>為什麼沒有成立：</b>{esc((ev.get('rung3') or {}).get('reason'))}</p>"
        if i == 2 and (ev.get("rung3") or {}).get("worlds") and link:
            extra += f"<p><a class='btn small' href='{esc(link)}'>看這次的真鏈重播（每筆交易）</a></p>"
        rungs.append(f"<div class='rung {st[i] if st[i] in ('pass', 'fail') else ''}'><div class='n'>第 {i + 1} 階</div>"
                     f"<div><b>{name}：{words.get(st[i], st[i])}</b><br><span class='note'>{what}</span>{extra}</div></div>")
    return (f"<h2>證據等級：爬到第 {ev.get('reached', 1)} 階</h2><div class='card'><div class='ladder'>{''.join(rungs)}</div>"
            "<p class='note'>階數越高，證據越不依賴我們的測試框架。另有"
            "<a href='/chain'>參考攻擊的真鏈示範</a>（已知攻擊，在本地真鏈上的完整交易）。</p></div>")


def worlds_html(worlds: list[dict[str, Any]]) -> str:
    cols = []
    for w in sorted(worlds, key=lambda w: bool(w.get("with_attack"))):
        rows = "".join(
            f"<tr><td>{esc(s.get('what'))}</td><td style='white-space:nowrap'>{'成功' if s.get('ok') else '<b class=del>失敗（revert）</b>'}</td>"
            f"<td class='num'>{esc(s.get('gas_used') or '—')}</td>"
            f"<td><code>{esc((s.get('tx') or '（沒有送出）')[:18])}{'…' if s.get('tx') else ''}</code></td></tr>"
            for s in w.get("steps") or [])
        title = "有攻擊" if w.get("with_attack") else "沒有攻擊"
        summary = (f"受害者領回 <b>{eth(w.get('recovered'))}</b>；攻擊者多拿 <b>{eth(w.get('attacker_gain'))}</b>"
                   if "recovered" in w else "")
        cols.append(f"<div class='card'><h3>{title}</h3><p>{summary}</p><div class='tbl'><table>"
                    f"<tr><th>步驟</th><th>結果</th><th>{term('gas')}</th><th>交易</th></tr>{rows}</table></div></div>")
    return f"<div class='cols'>{''.join(cols)}</div>"


GLOSS_SCRIPT = ""
EXPLAIN_SCRIPT = """function explain(td){var b=document.getElementById('envexplain');if(b){b.textContent=td.dataset.explain;}}
function tg(i,w){var a=document.getElementById('ws'+i),b=document.getElementById('raw'+i);if(!a)return;a.hidden=w!=='ws';b.hidden=w!=='raw';}"""


def render_glossary() -> str:
    items = "".join(f"<li>{term(k)}：{esc(v)}</li>" for k, v in GLOSSARY.items() if k not in ("合約",))
    return f"<details><summary>名詞小辭典</summary><ul>{items}</ul></details>"


def job_page_script(jid: str) -> str:
    return "var JID=" + json.dumps(jid) + ";\n" + JOB_JS


JOB_JS = r"""
var since=0, state={visited:{}, stage:null, idx:0, log:[], turns:{}, repair:null, checks:{}, ladder:{}, done:null,
 attempt:null, staticTxt:null}, job=null, started=null, redirectAt=null, stay=/[?&]stay=1/.test(location.search);
var STEPS=__STEPS__;
var CHECKS=__CHECKS__;
var LABELS=__LABELS__;
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function fmt(sec){sec=Math.max(0,Math.round(sec));var m=Math.floor(sec/60),s=sec%60;return (m?m+' 分 ':'')+s+' 秒';}
function onEvent(e){
 if(e.kind==='stage'){state.stage=e;state.idx=e.index;state.visited[e.index]=1;}
 else if(e.kind==='attempt'){state.attempt=e;}
 else if(e.kind==='turn'){state.attempt={attempt:e.attempt,attempts:e.attempts};state.turnNow=e;
   state.log.push({kind:'turn',e:e,res:[]});}
 else if(e.kind==='tool_result'){var last=null;for(var i=state.log.length-1;i>=0;i--){if(state.log[i].kind==='turn'){last=state.log[i];break;}}
   if(last){last.res.push(e);}else{state.log.push({kind:'note',text:e.text});}}
 else if(e.kind==='static'){state.staticTxt=e.status==='ran'?(e.hints?('自動掃描工具標出 '+e.hints+' 個可疑處（'+e.checks.join('、')+'）'):'自動掃描工具沒有標出達到門檻的可疑處'):('靜態分析未執行：'+(e.reason||''));}
 else if(e.kind==='repair_round'){state.repair=e;state.checks={};}
 else if(e.kind==='check'){state.checks[e.name]=e.status;}
 else if(e.kind==='repair_result'){state.repairDone=e;}
 else if(e.kind==='reattack_start'){state.log.push({kind:'note',text:'⚔️ 第 '+e.round+' 回合：修補通過檢查，AI 換一種手法再攻擊修補後的合約'});}
 else if(e.kind==='reattack_done'){state.log.push({kind:'note',text:'⚔️ 第 '+e.round+' 回合的再攻擊：'+({'proven':'成功（修補被打穿，AI 會再修一次）','not_proven':'未成功（'+e.turns+' 回合）','not_executed':'沒有完成（不算通過）'}[e.status]||e.status)});}
 else if(e.kind==='ladder'){state.ladder[e.rung]=e;}
 else if(e.kind==='abg'){state.abg=e;}
 else if(e.kind==='row'){state.row=e;}
 if(e.kind==='stage'&&e.step==='done'){state.done=e;}
}
function render(d){
 job=d.job;
 var pb=job.kind==='playback', p=job.params||{};
 document.getElementById('banner').className='banner '+(pb?'rec':'live');
 document.getElementById('banner').innerHTML='<span class=dot></span>'+(pb?('錄製回放：'+esc(p.recorded_on)+' 的實際紀錄（模型 '+esc(p.model)+'）'+(p.speed>1?'，'+p.speed+' 倍速':'，原速')):(job.status==='done'||job.status==='failed'?'現場執行（已結束）':'現場執行中'));
 var bar='';for(var i=0;i<STEPS.length;i++){var c, note='';
  if(state.done){c=state.visited[i]||i===0?'done':'skip';if(c==='skip'){note='<br><small>這次不需要</small>';}}
  else{c=i<state.idx?(state.visited[i]||i<2?'done':'skip'):(i===state.idx?'now':'');}
  bar+='<div class="step '+c+'">'+(i+1)+'<br>'+esc(STEPS[i][1])+note+'</div>';}
 document.getElementById('steps').innerHTML=bar;
 var now='';
 if(job.status==='queued'){now='排隊中：前面還有 '+d.position+' 份工作在跑，輪到時會自動開始。';}
 else if(job.status==='interrupted'){now='這份工作在伺服器重新啟動時中斷了，沒有自動重跑。';}
 else if(state.done){var v=(state.done.verdicts||[]).map(function(x){return LABELS[x]||x;}).join('、');now='完成'+(v?('：'+esc(v)):'')+'。'+(job.rid?'按「看結果」看這代表什麼、該怎麼辦。':'');}
 else if(state.stage){now=esc(state.stage.text);}
 document.getElementById('now').innerHTML=now;
 var sub=[];
 if(state.attempt&&!state.done){var t=state.turnNow;sub.push('第 '+state.attempt.attempt+' 次嘗試（共最多 '+(state.attempt.attempts||'?')+' 次）'+(t?('，第 '+t.turn+' 回合'+(t.max_turns?'（上限 '+t.max_turns+'）':'')):''));}
 if(job.started){var end=job.finished||(Date.now()/1000);sub.push('已經過 '+fmt(end-job.started));}
 if(!pb&&d.history&&d.history.n){sub.push('參考：這台機器上留存的 '+d.history.n+' 次即時稽核（repo 模式，arbiter-gpt）花了 '+d.history.min+'～'+d.history.max+' 秒');}
 document.getElementById('sub').innerHTML=esc(sub.join('　·　'));
 var log='';
 state.log.forEach(function(l){
  if(l.kind==='note'){log+='<li>'+esc(l.text)+'</li>';return;}
  var e=l.e, names=(e.tools||[]).map(function(t){return esc(t.text||t.name);}).join('、')||'整理想法（沒有呼叫工具）';
  var res=l.res.map(function(r){return '<span class="res '+esc(r.code)+'">→ '+esc(r.text)+(r.estimated_seconds!=null?'（耗時沒有記錄）':'')+'</span>';}).join('');
  var tech='<details><summary>技術細節</summary><pre>'+esc(JSON.stringify({tools:e.tools,finish_reason:e.finish_reason,model_seconds:e.model_seconds},null,1))+'</pre>'+(e.thought?'<b>AI 的想法（原文節錄，不是系統的判定）</b><pre style="white-space:pre-wrap">'+esc(e.thought)+'</pre>':'')+'</details>';
  log+='<li><b>第 '+e.turn+' 回合</b>：'+names+res+tech+'</li>';
 });
 document.getElementById('log').innerHTML=log||'<li class="note">還沒有活動。</li>';
 var extra='';
 if(state.staticTxt){extra+='<p>🔎 '+esc(state.staticTxt)+'（這只是提示，不是證據）</p>';}
 if(state.abg){extra+='<p>📏 量損失：'+(state.abg.status==='pass'?'完成，4 種情境都量到了':'沒有重現')+'</p>';}
 if(state.repair){
  var src=state.repair.source==='recorded'?'重新驗證錄製的修補（不呼叫 AI）':(state.repair.source==='recorded_model'?'錄製時 AI 寫的修補':'AI 寫的修補');
  var lights='';CHECKS.forEach(function(c){var s=state.checks[c[0]]||(state.repairDone?'skipped':'');var w={'pass':'通過','fail':'沒通過','skipped':'沒有跑（不算通過）','not_applicable':'不適用（單一檔案）','off':'這次沒有開'}[s]||'檢查中…';
   lights+='<div class="light"><span class="lamp '+(s||'wait')+'"></span><b>'+esc(c[1])+' '+w+'</b><span class="what note">'+esc(c[2])+'</span></div>';});
  extra+='<div class="card"><b>🔧 修補：第 '+state.repair.round+' 輪</b>　<span class="note">'+esc(src)+'</span><div class="lights">'+lights+'</div>'+
   (state.repairDone?('<b>'+(state.repairDone.accepted?'修補通過修補閘門的檢查（針對此攻擊）':'這一輪的修補沒有通過')+'</b>'):'')+'</div>';
 }
 var lad=[1,2,3].map(function(r){var e=state.ladder[r];return e?('<li>'+esc(e.text)+'</li>'):'';}).join('');
 if(lad){extra+='<div class="card"><b>🪜 證據等級</b><ul>'+lad+'</ul></div>';}
 document.getElementById('extra').innerHTML=extra;
 var notes=(p.notes||[]);document.getElementById('notes').innerHTML=notes.length?('<b>這是錄製回放：</b><ul>'+notes.map(function(n){return '<li>'+esc(n)+'</li>';}).join('')+'</ul>'):'';
 var fin=document.getElementById('finish');
 if(job.rid){fin.innerHTML='<a class="btn primary" href="/result/'+esc(job.rid)+'">看結果 →</a> <button class="btn small" onclick="stay=true;this.remove()">留在這頁</button>';
  if(!redirectAt&&!stay){redirectAt=Date.now()+5000;}
  if(redirectAt&&!stay&&Date.now()>redirectAt){location.href='/result/'+job.rid;}}
 else if(job.status==='failed'){fin.innerHTML='<b>工作失敗：</b>'+esc(job.error)+' <a class="btn" href="/">回首頁</a>';}
 else if(job.kind==='chain'&&job.status==='done'){fin.innerHTML='<a class="btn primary" href="/chain/'+esc(job.id)+'">看真鏈示範結果 →</a>';}
}
function poll(){fetch('/api/job/'+JID+'?since='+since).then(function(r){return r.json();}).then(function(d){
 (d.events||[]).forEach(onEvent);since=d.next;render(d);
 if(d.job.kind==='chain'&&d.job.status==='done'&&!stay){location.href='/chain/'+d.job.id;return;}
 if(!(d.job.status==='done'||d.job.status==='failed'||d.job.status==='interrupted')||(d.job.rid&&!stay)){setTimeout(poll,1500);} else {render(d);}
}).catch(function(){setTimeout(poll,3000);});}
poll();setInterval(function(){if(job)render({job:job,position:0,history:null});},1000);
""".replace("__STEPS__", json.dumps(STEPS, ensure_ascii=False)).replace(
    "__CHECKS__", json.dumps(CHECKS, ensure_ascii=False)).replace(
    "__LABELS__", json.dumps(LABELS, ensure_ascii=False))


def render_job(job: dict[str, Any]) -> bytes:
    body = f"""
<p><a class="btn small" href="/">← 回首頁</a></p>
<div id="banner" class="banner live"><span class="dot"></span>載入中…</div>
<h1>{esc(job.get('label'))}</h1>
<div id="steps" class="steps"></div>
<div class="now" id="now">載入中…</div>
<p class="note" id="sub"></p>
<div id="finish"></div>
<div id="extra"></div>
<h2>活動紀錄 <span class="note">（每一回合一行；點「技術細節」看 AI 的原始參數）</span></h2>
<div class="card"><ul class="log" id="log"></ul></div>
<div class="note" id="notes"></div>
<details><summary>這一頁在顯示什麼？</summary><p class="note">AI 會反覆「讀程式 → 寫攻擊 → 交給系統在{term('模擬區塊鏈')}上執行」。
AI 不能自己說有漏洞：只有系統實際執行、而且受害者真的少拿回錢，才算證實。執行都在{term('沙箱')}裡，不能連網、拿不到金鑰。</p>{render_glossary()}</details>
"""
    return page("ARBITER Gate 工作進度", body, job_page_script(job["id"]))


# -- home -----------------------------------------------------------------------------------

DEMO_CONTRACTS = [
    {"id": "staking-vault", "file": "StakingVault.sol", "source": ("examples", "StakingVault.sol"),
     "title": "存款金庫", "desc": "大家把 ETH 存進來、之後領回；領錢的順序寫錯了。",
     "why": "arbiter-gpt：10/28 的 5 次中 4 次證實（repo 模式）；10/30 網頁上傳 10 次中 6 次證實（victim_loss 4 次、寬鬆標準 eth_profit 2 次）"},
    {"id": "unstake-pool", "file": "UnstakePool.sol", "source": ("v3", "V_reentrancy_unstake"),
     "title": "另一種寫法的質押金庫", "desc": "和上一份同一類問題，程式寫法不同。",
     "why": "arbiter-gpt：10/29 吞吐量測試 2 次中 2 次證實（victim_loss）；40 份評測（單檔）3 次中 3 次證實（victim_loss 2 次、寬鬆標準 eth_profit 1 次）"},
    {"id": "treasury", "file": "TreasuryPayout.sol", "source": ("v3", "V_missing_access_control_disburse"),
     "title": "公庫發錢", "desc": "公庫有一個發錢的功能，少了「只有管理者能用」的檢查。",
     "why": "arbiter-gpt：40 份評測（單檔）3 次中 3 次證實，都是寬鬆標準 eth_profit（不量 A/B/G、不產生修補）。AIS3 時期（nemotron、舊判定條件）另有證實紀錄"},
    {"id": "share-vault", "file": "ShareVault.sol", "source": ("v3", "V_first_depositor_share_inflation"),
     "title": "按份額分潤的金庫", "desc": "第一個存款的人可以灌水，讓後來的人分到的份額變少。",
     "why": "arbiter-gpt：40 份評測（單檔）3 次中 0 次證實。AIS3 時期（nemotron、舊判定條件）證實過"},
]

FEATURED_TEXT = {
    "spark-test-1": "AI 這次沒寫出成功的攻擊，但自動掃描工具標出可疑處 → 「靜態工具提示但未證實」",
    "spark-test-2": "已證實可攻擊，附通過修補閘門檢查的 AI 修補（建議先看這份）",
    "spark-test-3": "已證實可攻擊，附 AI 修補",
    "spark-test-4": "已證實可攻擊，附 AI 修補（第 2 輪才通過）",
    "spark-test-5": "已證實可攻擊，這次沒有產生修補",
}


def dev_box(items: list[tuple[str, str]]) -> str:
    if not items:
        return ""
    lis = "".join(f"<li><b>{esc(n)}</b> <span class='tag warn'>開發中</span> <span class='note'>{esc(d)}</span></li>"
                  for n, d in items)
    return f"<div class='card'><b>尚未完成的部分</b><ul>{lis}</ul></div>"


def _runs_rows(runs: list[dict[str, Any]], featured: bool) -> str:
    rows = []
    for r in runs:
        when = time.strftime("%m/%d %H:%M", time.localtime(r["mtime"]))
        what = FEATURED_TEXT.get(r["run_id"], r.get("origin", "")) if featured else esc(r.get("origin"))
        rows.append(f"<tr><td><code>{esc(r['run_id'])}</code></td><td>{esc(what) if featured else what}</td>"
                    f"<td class='note'>{when}</td><td><form class='inline' method='post' action='/replay'>"
                    f"<input type='hidden' name='run_id' value='{esc(r['run_id'])}'>"
                    f"<button class='btn small'>看結果</button></form></td></tr>")
    return "<div class='tbl'><table>" + "".join(rows) + "</table></div>"


def render_index(message: str, featured: list[dict[str, Any]], others: list[dict[str, Any]],
                 history: dict[str, Any], dev: list[tuple[str, str]],
                 playback_ok: bool) -> bytes:
    msg = f"<div class='vcard v-unrun'><div class='icon'>…</div><h2>無法處理</h2><div class='mean'>{esc(message)}</div></div>" if message else ""
    demos = "".join(
        f"<form class='inline' method='post' action='/demo'><input type='hidden' name='id' value='{esc(d['id'])}'>"
        f"<button class='btn demo' title='{esc(d['why'])}'><b>{esc(d['title'])}</b><br><span class='note'>{esc(d['desc'])}</span></button></form> "
        for d in DEMO_CONTRACTS)
    hist = (f"這台機器上留存的 {history['n']} 次即時稽核（repo 模式，arbiter-gpt）花了 {history['min']}～{history['max']} 秒"
            if history.get("n") else "")
    pb = ("<form class='inline' method='post' action='/playback'><input type='hidden' name='run_id' value='spark-test-2'>"
          "<input type='hidden' name='speed' value='1'><button class='btn primary'>原速重播（約 2 分鐘）</button></form> "
          "<form class='inline' method='post' action='/playback'><input type='hidden' name='run_id' value='spark-test-2'>"
          "<input type='hidden' name='speed' value='4'><button class='btn'>4 倍速（約 40 秒）</button></form>"
          if playback_ok else "<p class='note'>找不到 spark-test-2 的錄製紀錄。</p>")
    body = f"""
<h1>ARBITER Gate</h1>
<p class="sub">部署前的證據閘門：AI 寫攻擊、系統在{term('沙箱')}裡的{term('模擬區塊鏈')}上實際執行。
只有真的成功、而且受害者真的少拿回錢的攻擊，才判定「已證實可攻擊」。</p>
{msg}
<div class="cards">
 <div class="card"><h2>① 上傳一份合約</h2><p>選一個 <code>.sol</code> 檔，或把 Foundry 專案壓成 <code>.zip</code>（上限 20 MB），AI 會試著攻擊它，系統負責判定。
  找到攻擊時，AI 會寫修補，修補通過檢查後再換一種手法攻擊一次。約 2～8 分鐘（10/30 實測 6 次：154～398 秒，找到攻擊的 4 次含修補與再攻擊）。</p>
  <form method="post" action="/upload" enctype="multipart/form-data"><input type="file" name="contract" accept=".sol,.zip" required>
  <button class="btn primary">開始稽核</button></form>
  <p class="note">{esc(hist)}。會呼叫 AI 模型；編譯和執行都在沙箱裡。</p>
  <details open><summary>或從示範合約選一份（自製示範合約）</summary>{demos}
  <p class="note">這幾份是我們自己寫的示範合約，都有刻意放進去的漏洞。滑過按鈕看挑選理由；能不能每次都證實，要看 AI 當次的表現。</p></details>
 </div>
 <div class="card"><h2>② 看一次錄好的完整稽核（不用等）</h2>
  <p>重播 2026-10-28 一次真實的稽核紀錄：AI 怎麼一步步找到漏洞、修補怎麼通過檢查。損失和修補會用 {term('forge')} 當場重跑一次。</p>
  {pb}
  <details><summary>直接看錄好的結果（約 10 秒）</summary>{_runs_rows(featured, True)}</details>
 </div>
 <div class="card"><h2>③ 看 GitHub 自動把關的示範</h2>
  <p>開 PR 時自動稽核：證實可攻擊就擋下合併，並在 PR 留言附上證據與修補；套用修補後重新檢查、放行。</p>
  <p><a class="btn primary" href="/github">看示範 PR（本機截圖，不用網路）</a>
  <a class="btn" href="{GITHUB_DEMO_REPO}/pull/1" target="_blank" rel="noopener">在 GitHub 上看 PR #1 ↗</a></p>
  <p class="note">2026-10-30 在公開示範 repo 的實際紀錄（arbiter-gpt）。</p>
  <p><a class="btn" href="/chain">另外：參考攻擊的真鏈示範 →</a></p>
 </div>
</div>
{f"<details><summary>其他紀錄（{len(others)} 筆，測試與排練用）</summary>{_runs_rows(others, False)}</details>" if others else ''}
{dev_box(dev)}
{render_glossary()}
<p class="note">「已證實可攻擊」附可重跑的攻擊證據；其他判定都不代表合約沒有漏洞。</p>"""
    return page("ARBITER Gate", body)


# -- result page ----------------------------------------------------------------------------

# -- GitHub PR demo ---------------------------------------------------------------------------

GITHUB_DEMO_REPO = "https://github.com/sam029031/arbiter-gate-demo"

# (screenshot, heading, link on GitHub, what it shows). Screenshots: webassets/github/,
# taken 2026-10-30 without logging in, so the page works with no network.
GITHUB_DEMO: list[tuple[str, str, str, str]] = [
    ("pr1-red-to-green", "PR #1：先被擋下，套用修補後放行", "/pull/1",
     "把 unstake() 改成「先轉帳、再清除持倉」。第一個 commit（紅叉）被擋下：AI 在模擬區塊鏈上證實了重入攻擊，"
     "留言附上 A/B/G 和通過修補閘門的修補，修補以 suggestion 貼在改到的行上。"
     "套用 suggestion 的第二個 commit（綠勾）重新稽核，結果「未發現可證明攻擊（不等於安全）」，放行。"),
    ("pr1-red-run", "PR #1 紅燈那次的執行紀錄", "/actions/runs/40991523483/attempts/2",
     "結束碼 1（擋合併），Artifacts 有回歸測試 arbiter-gate-regression。"
     "同一個 commit 一共跑了 2 次：第 1 次 AI 沒有證實（結果是「靜態工具提示但未證實」，放行），第 2 次證實並擋下。"),
    ("pr1-green-run", "PR #1 套用修補後的執行紀錄", "/actions/runs/40992745484",
     "結束碼 0（放行），這次送出 5 個 AI 請求。"),
    ("pr5-regression-blocks", "PR #5：repo 已有回歸測試時，再次引入同一個漏洞", "/pull/5",
     "回歸測試 TestArbiterRegression 的 testExploitBlocked 失敗，光這一項就會擋下；這次 AI 也再次證實了攻擊。"),
    ("pr4-regression-passes", "PR #4：把回歸測試放進 repo", "/pull/4",
     "只加測試檔：不送 AI 稽核（測試檔列在「略過」），回歸測試 5 個全部通過，放行。"),
    ("pr2-deletion-only", "PR #2：只刪除程式碼", "/pull/2",
     "沒有新增程式碼可審：列在「未涵蓋」，不算「未發現可證明攻擊」，0 個 AI 請求。"),
    ("pr3-outside-function", "PR #3：只改函式外的常數", "/pull/3",
     "改動不在任何函式裡：列在「未涵蓋」，0 個 AI 請求。這一版只稽核有函式被改到的檔案。"),
]


def render_github(available: set[str]) -> bytes:
    intro = ("<div class='banner rec'><span class='dot'></span>錄製紀錄：2026-10-30 在公開示範 repo 的實際 PR（截圖存在本機）</div>"
             "<h1>GitHub 自動把關的示範</h1>"
             "<p class='sub'>每個 PR 都會跑 ARBITER Gate：只有「已證實可攻擊」會擋合併；「無法判定」也不放行；"
             "其他結果都不代表合約沒有漏洞。AI 稽核在自己的 runner 上執行，金鑰不放 GitHub。</p>")
    blocks = []
    for name, title, link, what in GITHUB_DEMO:
        img = (f"<a href='/github/img/{name}.png' target='_blank'><img src='/github/img/{name}.png' alt='{esc(title)}' "
               "style='width:100%;border:1px solid var(--line);border-radius:8px'></a>"
               if name in available else "<p class='note'>這張截圖不在這台機器上。</p>")
        blocks.append(f"<div class='card'><h2>{esc(title)}</h2><p>{esc(what)}</p>"
                      f"<p><a class='btn small' href='{GITHUB_DEMO_REPO}{link}' target='_blank' rel='noopener'>在 GitHub 上看 ↗</a></p>"
                      f"<details open><summary>截圖</summary>{img}</details></div>")
    notes = ("<div class='card'><h2>沒有截圖的部分</h2><ul>"
             "<li><b>Security 分頁</b>：code scanning 的 alert 要登入、有權限才看得到，所以沒有放截圖。"
             "PR #1 紅燈時有一筆 error 級 alert（<code>arbiter/proven/reentrancy</code>），套用修補後變成「已修正」。</li>"
             "<li><b>fork 來的 PR</b>：沒有實際開（要另一個 GitHub 帳號），用離線測試確認：fork PR 不會被 checkout，"
             "結果是「無法判定」（結束碼 2），不算通過。</li></ul></div>")
    body = f"<p><a class='btn small' href='/'>← 回首頁</a></p>{intro}{''.join(blocks)}{notes}"
    return page("ARBITER Gate GitHub 示範", body)


def render_pick(uid: str, name: str, cands: list[dict[str, Any]], first: str) -> bytes:
    """After a project upload: which contract to audit (triage's first pick preselected)."""
    keep = [c for c in cands if not c.get("skipped")]
    skipped = [c for c in cands if c.get("skipped")]
    rows = "".join(
        f"<label class='pick'><input type='radio' name='target' value='{esc(c['rel'])}'"
        f"{' checked' if c['rel'] == first else ''}> <code>{esc(c['rel'])}</code> "
        f"<span class='note'>合約 {esc('、'.join(c.get('contracts') or []))}；"
        f"{esc(c.get('entry_points'))} 個會改變狀態的對外函式"
        f"{'（系統建議）' if c['rel'] == first else ''}</span></label><br>" for c in keep)
    from .prgate import skip_reason
    sk = "".join(f"<li><code>{esc(c['rel'])}</code> <span class='note'>{esc(skip_reason(str(c.get('reason'))))}</span></li>"
                 for c in skipped[:40])
    body = (f"<p><a class='btn small' href='/'>← 回首頁</a></p><h1>選一份合約來稽核</h1>"
            f"<p class='sub'>{esc(name)} 裡有 {len(keep)} 份可以部署的合約。系統建議的是對外函式最多的那一份；"
            "一次稽核一份，其他的可以之後再選。</p>"
            f"<form method='post' action='/project' class='card'><input type='hidden' name='uid' value='{esc(uid)}'>"
            f"{rows}<p><button class='btn primary'>開始稽核</button></p></form>"
            + (f"<details><summary>略過的檔案（{len(skipped)} 個：介面、函式庫、測試、mock、腳本）</summary><ul>{sk}</ul></details>"
               if skipped else ""))
    return page("選擇合約", body)


def static_html(e: dict[str, Any]) -> str:
    sa = e.get("static_analysis")
    if not sa:
        return ""
    if sa.get("status") != "ran":
        return (f"<p class='note'><span class='tag warn'>{esc(sa.get('label') or '靜態分析未執行')}</span> "
                f"{esc(sa.get('reason'))}</p>")
    hints = sa.get("hints") or []
    if not hints:
        return (f"<p class='note'>自動掃描（{term('Slither')}）：沒有達到顯示門檻的可疑處。</p>")
    items = "".join(
        f"<li>第 <b>{esc(h.get('line'))}</b> 行"
        f"{'（函式 <code>' + esc(h.get('function')) + '</code>）' if h.get('function') else ''}："
        f"<code>{esc(h.get('check'))}</code> <span class='tag'>{esc(h.get('impact'))}/{esc(h.get('confidence'))}</span>"
        f"<br><span class='note'>{esc(h.get('message'))}</span></li>" for h in hints)
    if e["verdict"] == STATIC_HINT:
        head = ("<p><b>這是自動掃描工具的提示，系統沒有證實它真的能被攻擊。</b></p>"
                "<p class='note'>AI 試著寫出能實際成功的攻擊，但沒有成功，所以這裡只列出掃描工具標出的可疑位置。</p>")
    else:
        head = (f"<p class='note'>參考：自動掃描工具（{term('Slither')}）也標出下列位置。"
                "判定的依據是上面實際執行成功的攻擊，不是這些提示。</p>")
    return f"<div class='card'><h3>自動掃描工具標出的地方</h3>{head}<ul>{items}</ul></div>"


def _after_table(after: list[dict[str, Any]] | None) -> str:
    if not after:
        return ""
    rows = "".join(
        f"<tr><td>{esc(ENV_NAMES[r['env']] if r['env'] < len(ENV_NAMES) else r['env'])}</td>"
        f"<td class='num'>{eth(r.get('A'))}</td><td class='num'>{eth(r.get('B'))}</td>"
        f"<td class='num'>{eth(r.get('G'))}</td></tr>" for r in after)
    return ("<h3>修補後再量一次</h3><div class='tbl'><table><tr><th>情境</th><th>沒攻擊時領回</th>"
            f"<th>有攻擊時領回</th><th>攻擊者多拿</th></tr>{rows}</table></div>")


def _tl_cell(e: dict[str, Any], cfile: str) -> str:
    side = e.get("side")
    res = e.get("result") or ""
    head = f"第 {esc(e.get('round'))} 回合：{esc(e.get('label') or res)}"
    body = []
    if side == "attack":
        who = "原本的稽核" if e.get("source") == "audit" else "修補後再攻擊（AI 換一種手法）"
        body.append(f"<p class='note'>{who}</p>")
        f = e.get("finding") or {}
        if e.get("hypothesis"):
            body.append(f"<p><b>攻擊假設</b>（AI 原文）：{esc(e['hypothesis'])}</p>")
        if f.get("vulnerable_function"):
            body.append(f"<p>漏洞函式：<code>{esc(f['vulnerable_function'])}</code></p>")
        if f.get("attack_path"):
            body.append(f"<p class='note'>攻擊路徑（AI 原文）：{esc(f['attack_path'])}</p>")
        if e.get("abg"):
            rows = "".join(f"<tr><td>{esc(r.get('env'))}</td><td>{eth(r.get('A'))}</td><td>{eth(r.get('B'))}</td>"
                           f"<td>{eth(r.get('G'))}</td></tr>" for r in e["abg"])
            body.append("<div class='tbl'><table><tr><th>情境</th><th>A 沒攻擊時取回</th><th>B 有攻擊時取回</th>"
                        f"<th>G 攻擊者獲利</th></tr>{rows}</table></div>")
        if e.get("source") == "reattack":
            if e.get("ruled_out"):
                body.append("<p class='note'>這次不准再用的攻擊假設：</p><ul>"
                            + "".join(f"<li class='note'>{esc(h)}</li>" for h in e["ruled_out"]) + "</ul>")
            if res != "proven" and e.get("tried"):
                body.append("<p class='note'>這次試過、但沒有成功的攻擊假設：</p><ul>"
                            + "".join(f"<li class='note'>{esc(h)}</li>" for h in e["tried"] if h) + "</ul>")
            if e.get("reason"):
                body.append(f"<p class='note'>沒有完成的原因：{esc(e['reason'])}</p>")
            body.append(f"<p class='note'>用了 {esc(e.get('turns'))} 回合、{esc(e.get('requests'))} 個 AI 請求、"
                        f"{esc(e.get('elapsed_s'))} 秒。</p>")
    else:
        body.append(f"<p>AI 提了 {esc(e.get('proposals'))} 個修補，"
                    + ("最後一個通過了檢查 0～4。" if res == "accepted" else "都沒有通過。") + "</p>")
        if e.get("checks"):
            body.append(check_lights(e["checks"]))
        if res == "accepted" and e.get("diff"):
            body.append(f"<details><summary>這一版的修補 diff</summary><pre>"
                        f"{diff_html(str(e['diff']).replace('src/Target.sol', f'src/{cfile}'))}</pre></details>")
    kind = "att" if side == "attack" else "def"
    return f"<details class='{kind} {esc(res)}'><summary>{head}<span class='r'>點開看{'攻擊假設和證據' if side == 'attack' else '檢查結果'}</span></summary>{''.join(body)}</details>"


def timeline_html(p: dict[str, Any], cfile: str) -> str:
    """Attack / defence rounds in order (check 5), each cell expandable."""
    tl = p.get("timeline") or []
    if not tl:
        return ""
    cells = "<span class='arrow'>→</span>".join(_tl_cell(e, cfile) for e in tl)
    ra = p.get("reattack") or {}
    lab = ra.get("label") or ""
    if ra.get("enabled") is False:
        lab = "這次沒有開「換手法再攻擊」（檢查 5）"
    tail = (f"<p><b>{esc(lab)}</b></p>" if lab else "")
    cost = (f"<p class='note'>再攻擊一共 {esc(ra.get('attacks'))} 次、{esc(ra.get('requests'))} 個 AI 請求、"
            f"{esc(ra.get('elapsed_s'))} 秒。「未成功」只代表這一次換手法沒有找到能成功的攻擊，"
            "不代表合約安全，也不代表修好了所有漏洞。</p>" if ra.get("attacks") else "")
    return f"<div class='card'><h3>攻防過程</h3><div class='tl'>{cells}</div>{tail}{cost}</div>"


def finding_html(f: dict[str, Any], idx: int, rid: str, i: int, j: int, ex: dict[str, Any]) -> str:
    parts = []
    if f.get("predicate_note"):
        parts.append(f"<div class='vcard v-hint'><div class='icon'>!</div><h2>證實的條件比較寬鬆</h2>"
                     f"<div class='mean'>{esc(f['predicate_note'])}。這類結果目前沒有損失數字、修補與回歸測試。</div>"
                     f"<div class='next'>建議：仍視為已證實可攻擊處理。</div></div>")
    parts.append(story(f))
    abg = f.get("abg") or {}
    if abg.get("status") in ("measured", "reproduction_failed"):
        funding = ex.get("funding")
        parts.append("<div class='card'>" + env_table(abg, idx)
                     + (f"<p class='note'>攻擊者多拿的錢可能來自合約裡其他人的資金（例如部署時存入的 {esc(funding)}）。</p>" if funding else "")
                     + "</div>")
    elif abg.get("label"):
        parts.append(f"<p class='note'>損失數字：{esc(abg.get('label'))}{('：' + esc(abg.get('note'))) if abg.get('note') else ''}</p>")
    p = f.get("patch") or {}
    cfile = ex.get("cfile") or "Target.sol"
    parts.append(f"<h2>{term('修補', '修補')}建議 <span class='tag {'ok' if p.get('status') == 'verified' else 'warn'}'>{esc(p.get('label'))}</span></h2>")
    parts.append(timeline_html(p, cfile))
    if p.get("check2_note"):
        parts.append(f"<div class='vcard v-hint'><div class='icon'>!</div><h2>修補被「一般使用者不受影響」擋下</h2>"
                     f"<div class='mean'>{esc(p['check2_note'])}</div></div>")
    if p.get("status") == "verified":
        gates = p.get("gate_checks") or {}
        sbs = side_by_side(ex["source"], ex["patched"]) if ex.get("source") and ex.get("patched") else ""
        ws = (p.get("diff_ignore_whitespace") or "").replace("src/Target.sol", f"src/{cfile}")
        raw = ex.get("download_diff") or p.get("diff") or ""
        parts.append(
            "<div class='card'>"
            f"<p>AI 提出的修改，改了 <b>{esc(p.get('changed_lines'))}</b> 行，"
            f"{'是這次由 AI 產生的' if p.get('origin') == 'repair' else '來自錄製時 AI 產生的修補，剛剛重新驗證過'}。"
            "通過了下面的檢查（只針對列出的攻擊）。</p>"
            f"<p class='note'>AI 的說明（原文）：{esc(p.get('rationale'))}</p>"
            f"<h3>修改前後（<code>src/{esc(cfile)}</code>）</h3>{sbs}"
            f"<h3>修補閘門的檢查</h3>{check_lights(gates)}"
            f"{_after_table(p.get('after'))}"
            + ("<p class='note'>「通過驗證」只代表：這個攻擊不再讓一般使用者的操作失敗、沒有攻擊時這個操作照常成功、對外介面沒有改變。"
               if f.get("predicate") == "liveness_broken" else
               "<p class='note'>「通過驗證」只代表：這個攻擊在 4 種情境都失效、沒有攻擊時的領回沒有變少、對外介面沒有改變。") +
            "修補是建議，要由開發者審閱後套用並重新稽核。</p>"
            f"<details><summary>技術細節：diff（檔名和下載的 .patch 一致）</summary>"
            f"<p><button class='btn small' onclick=\"tg({idx},'ws')\">忽略空白的 diff</button> "
            f"<button class='btn small' onclick=\"tg({idx},'raw')\">原始 diff（可套用）</button></p>"
            f"<pre id='ws{idx}'>{diff_html(ws)}</pre><pre id='raw{idx}' hidden>{diff_html(raw)}</pre>"
            f"<p class='note'>修補閘門代號：<code>{esc(' '.join(f'{k}:{v}' for k, v in gates.items()))}</code></p></details>"
            "</div>")
    elif p.get("note"):
        parts.append(f"<p class='note'>{esc(p['note'])}</p>")
    else:
        parts.append("<p class='note'>這次沒有產生修補。</p>")
    ev = f.get("evidence")
    parts.append(ladder(ev, f"/result/{rid}/chainreplay/{i}-{j}" if rid else ""))
    tech = {k: f.get(k) for k in ("title", "vulnerable_function", "severity", "vuln_class", "predicate",
                                  "predicate_strict", "poc_name", "offending_expression", "attack_path", "region")}
    parts.append(f"<details><summary>技術細節：這個發現的原始欄位</summary><pre>{esc(json.dumps(tech, ensure_ascii=False, indent=1))}</pre></details>")
    return "".join(parts)


def sandbox_text(sb: dict[str, Any] | None) -> str:
    status = (sb or {}).get("status")
    if status == "on":
        return "沙箱：每個工作一個容器，不能對外連線、拿不到金鑰；AI 模型在容器外呼叫" + (f"。{esc(sb['note'])}" if sb.get("note") else "")
    if status == "unavailable":
        return f"<b>沙箱無法使用</b>：{esc(sb.get('reason'))}。{esc(sb.get('note'))}"
    if status == "off":
        return "沒有用沙箱（重播錄好的攻擊；這些攻擊在錄製時已在這台機器上執行過）"
    return "沒有記錄（這份結果早於沙箱功能）"


def render_result(saved: dict[str, Any], rid: str, extras: dict[tuple[int, int], dict[str, Any]],
                  downloads: str, dev: list[tuple[str, str]]) -> bytes:
    rep, meta = saved["report"], saved["meta"]
    inp = rep.get("input") or {}
    models = ", ".join(rep.get("models") or []) or "未知"
    if inp.get("mode") == "from_results":
        banner = (f"<div class='banner rec'><span class='dot'></span>錄製結果：{esc(inp.get('run_id'))}（模型 {esc(models)}）。"
                  "損失數字、修補檢查和證據等級是剛剛用 forge 重跑的</div>")
    else:
        banner = (f"<div class='banner live'><span class='dot'></span>即時稽核結果（{esc(meta.get('at'))}，模型 {esc(models)}）</div>")
    blocks = []
    for i, e in enumerate(rep.get("files") or []):
        blocks.append(verdict_card(e))
        if e.get("fixture_note"):
            blocks.append(f"<p class='note'><span class='tag warn'>測試用合成資料</span> {esc(e['fixture_note'])}</p>")
        blocks.append(f"<p class='note'>{esc(e['id'])}　·　AI 用了 {esc(e.get('turns'))} 回合</p>")
        if e["verdict"] == NOT_EXECUTED and e.get("detail"):
            blocks.append(f"<details><summary>技術細節：錯誤訊息</summary><pre style='white-space:pre-wrap'>{esc(e['detail'])}</pre></details>")
        if e["verdict"] != PROVEN:
            blocks.append(static_html(e))
        for j, f in enumerate(e.get("findings") or []):
            blocks.append(finding_html(f, i * 10 + j, rid, i, j, extras.get((i, j), {})))
        if e["verdict"] == PROVEN:
            blocks.append(static_html(e))
    reqs = inp.get("llm_requests_this_invocation")
    tech = f"""<details><summary>技術細節：這次執行</summary><div class='card'><dl>
<dt>輸入</dt><dd>{esc(meta.get('source'))}</dd><dt>run</dt><dd><code>{esc(inp.get('run_id'))}</code></dd>
<dt>模型</dt><dd><code>{esc(models)}</code></dd>
<dt>本次 AI 請求數</dt><dd>{esc('未知' if reqs is None else reqs)}{f"（稽核 {esc(inp.get('llm_requests_audit'))}、修補 {esc(inp.get('llm_requests_repair'))}）" if inp.get('llm_requests_audit') is not None else ''}</dd>
<dt>gate 結束碼</dt><dd><code>{esc(rep.get('exit_code'))}</code>（1＝擋部署，2＝稽核未完成，0＝未擋部署（不代表沒有漏洞））</dd>
<dt>耗時</dt><dd>{esc(rep.get('elapsed_s'))} 秒</dd><dt>執行環境</dt><dd>{sandbox_text(inp.get('sandbox'))}</dd>
<dt>原因代號</dt><dd>{esc(', '.join(str(e.get('reason')) for e in rep.get('files') or []))}</dd>
</dl></div></details>"""
    body = f"""<p><a class="btn small" href="/">← 回首頁</a></p>{banner}<h1>稽核結果</h1>
{''.join(blocks)}{downloads}{tech}{dev_box(dev)}{render_glossary()}
<p class="note">「已證實可攻擊」附可重跑的攻擊證據；其他判定都不代表合約沒有漏洞。</p>"""
    return page("ARBITER Gate 結果", body, EXPLAIN_SCRIPT)


def render_chainreplay(saved: dict[str, Any], rid: str, f: dict[str, Any]) -> bytes:
    r3 = (f.get("evidence") or {}).get("rung3") or {}
    s = r3.get("summary") or {}
    ok = r3.get("status") == "pass"
    body = f"""<p><a class="btn small" href="/result/{esc(rid)}">← 回結果頁</a></p>
<div class='banner {'live' if ok else 'rec'}'><span class='dot'></span>AI 寫的攻擊在{term('本地真鏈')}上的重播（第 3 階）</div>
<h1>本地真鏈重播：{'成立' if ok else '沒有成立'}</h1>
<div class='card'><p>左邊是沒有攻擊的世界，右邊是有攻擊的世界；兩條鏈的準備步驟相同，只差攻擊有沒有發生。
每一步都是真的交易：要當誰就要有私鑰、要花錢就要有餘額、每筆都付 {term('gas')}。</p>
<p>受害者沒有攻擊時領回 <b>{eth(s.get('recovered_clean'))}</b>，有攻擊時領回 <b>{eth(s.get('recovered_attacked'))}</b>，攻擊者獲利 <b>{eth(s.get('attacker_gain'))}</b>。</p>
{'' if ok else f"<p><b>為什麼沒有成立：</b>{esc(r3.get('reason'))}</p>"}
<p class='note'>想看一個在本地真鏈上成立的完整例子，請看<a href='/chain'>參考攻擊的真鏈示範</a>。</p></div>
{worlds_html(r3.get('worlds') or [])}
<details><summary>名詞</summary>{render_glossary()}</details>"""
    return page("ARBITER Gate 本地真鏈重播", body)


def render_chain(job: dict[str, Any] | None, runs: list[dict[str, Any]], can_start: bool) -> bytes:
    intro = (f"<div class='banner rec'><span class='dot'></span>這段鏈上攻擊是事先寫好的參考攻擊（victim_probe 的 DRAIN），不是 AI 這次產生的；"
             "修補是 AI（arbiter-gpt）產生的（spark-test-2 的修補紀錄）</div>"
             f"<h1>參考攻擊的真鏈示範</h1><p class='sub'>同一個存款金庫合約，在{term('本地真鏈')}上用真的交易跑兩次："
             "原合約一次、套用 AI 修補後一次。每次都有「沒有攻擊」和「有攻擊」兩條鏈。</p>")
    start = ("<form method='post' action='/chain'><button class='btn primary'>現在在本地真鏈上跑一次（約 30 秒，不呼叫 AI）</button></form>"
             if can_start else "")
    if not runs:
        status = ""
        if job:
            status = f"<p class='note'>工作狀態：{esc(job.get('status'))}。<a href='/job/{esc(job['id'])}'>看進度</a></p>"
        body = f"<p><a class='btn small' href='/'>← 回首頁</a></p>{intro}<div class='card'>{start}{status}</div>"
        return page("ARBITER Gate 真鏈示範", body)
    blocks = []
    for r in runs:
        v = r.get("verdict") or {}
        proven = v.get("proven")
        title = "原合約" if r["target"] == "original" else "套用 AI 修補後"
        verdict = ("<div class='vcard v-proven'><div class='icon'>!</div><h2>攻擊成功</h2>"
                   f"<div class='mean'>金庫被抽走 {eth(v.get('target_drained_wei'))}；受害者存了 {eth(v.get('victim_paid_in_wei'))}，"
                   f"有攻擊時領回 {eth(v.get('B_recovered_attacked_wei'))}（沒有攻擊時領回 {eth(v.get('A_recovered_control_wei'))}），"
                   f"攻擊者合約多了 {eth(v.get('G_attacker_contract_gain_wei'))}。</div><div class='next'>這就是部署前要擋下的情況。</div></div>"
                   if proven else
                   "<div class='vcard v-none'><div class='icon'>i</div><h2>攻擊沒有成功</h2>"
                   f"<div class='mean'>受害者沒有攻擊時領回 {eth(v.get('A_recovered_control_wei'))}，有攻擊時領回 {eth(v.get('B_recovered_attacked_wei'))}；"
                   f"攻擊者沒有多拿到錢。</div><div class='next'>這只代表這一個攻擊在這份修補上失效，不代表合約沒有其他漏洞。</div></div>")
        worlds = []
        for key, wt in (("control", False), ("attacked", True)):
            t = (r.get(key) or {}).get("transcript") or {}
            worlds.append({"with_attack": wt, "steps": t.get("steps") or [],
                           **({"recovered": (r.get("verdict") or {}).get("B_recovered_attacked_wei" if wt else "A_recovered_control_wei"),
                               "attacker_gain": (r.get("verdict") or {}).get("G_attacker_contract_gain_wei") if wt else 0})})
        blocks.append(f"<h2>{title}</h2>{verdict}{worlds_html(worlds)}")
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(job["finished"])) if job and job.get("finished") else ""
    body = (f"<p><a class='btn small' href='/'>← 回首頁</a></p>{intro}"
            f"<p class='note'>這次執行：{esc(when)}。{start and '可以再跑一次：'}</p>{start}{''.join(blocks)}"
            f"<details><summary>技術細節：判定規則</summary><pre>{esc((runs[0].get('verdict') or {}).get('rule'))}</pre></details>"
            f"{render_glossary()}")
    return page("ARBITER Gate 真鏈示範", body)
