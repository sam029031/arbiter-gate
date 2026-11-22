"""Look up and re-check an audit record from the chain: 「經得起追問」.

Lookup by a deployed address, a record id, a source file (sha256 -> recordsBySource) or a
transaction hash (its Registered/Linked logs). For each record it shows what the chain
says (verdict, auditor, parent chain, children, link kind, recorded vs current codehash),
then, on request, re-checks it independently of whoever registered it:

    --evidence DIR   re-hash the evidence bundle and compare with the on-chain hashes
    --rebuild        compile the source with the recorded recipe; compare initcode/runtime
    --replay         run the recorded attack (regression project) with forge: it must
                     succeed on the original source and fail on the patched source
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from .build import compile_source
from .chain import ZERO32, ChainError, find_tool
from .contracts import EVENT_LINKED, EVENT_REGISTERED, LINK_LABELS, PRED_LABELS, RECORD_FIELDS, VERDICT_LABELS
from .deploy import TZ
from .record import load_manifest, sha256_hex
from .session import Session, add_network_args, open_session

_HEX = re.compile(r"^0x[0-9a-fA-F]*$")


# ------------------------------------------------------------------ lookup


def lookup(sess: Session, target: str | None, source: Path | None = None) -> tuple[str, list[int]]:
    reg = sess.registry
    if source:
        h = sha256_hex(Path(source).read_bytes())
        return f"原始碼 sha256 {h}", reg.records_by_source(h)
    t = (target or "").strip()
    if t.isdigit():
        return f"紀錄 #{t}", [int(t)]
    if _HEX.match(t) and len(t) == 42:
        if t.lower() == reg.address.lower():
            # the registry cannot deploy itself; its own audit can only be linked as a claim
            claims = reg.claims_of(t)
            if claims:
                return f"AuditRegistry 本身 {t}（稽核者自行宣告的位址，未經閘門）", list(claims)
            raise ChainError("這是 AuditRegistry 本身的地址，沒有任何紀錄宣告它；請給部署出來的合約地址或紀錄編號")
        rid = reg.deployment_of(t)
        if rid:
            return f"地址 {t}（由登錄合約依稽核過的 bytecode 部署）", [rid]
        claims = reg.claims_of(t)
        if claims:
            return f"地址 {t}（稽核者自行宣告的部署，未經閘門）", list(claims)
        ch = sess.client.code_hash(t)
        if ch == ZERO32:
            return f"地址 {t}（沒有程式碼）", []
        return f"地址 {t}（沒有連結；以 runtime codehash {ch} 查同一份程式碼）", reg.records_by_codehash(ch)
    if _HEX.match(t) and len(t) == 66:
        receipt = sess.client.receipt(t)
        if receipt:
            ids = [e["id"] for e in reg.registered(receipt)] + [e["id"] for e in reg.linked(receipt)]
            return f"交易 {t}", sorted(set(ids))
        return f"雜湊 {t}（當作原始碼 sha256 查）", reg.records_by_source(t.lower())
    raise ChainError("請給 0x 地址、紀錄編號、交易雜湊，或用 --source 指定原始碼檔案")


def describe(sess: Session, rid: int) -> dict:
    reg = sess.registry
    rec = reg.record(rid)
    chain, cur, seen = [], rec, {rid}
    while cur["parentId"] and cur["parentId"] not in seen:
        seen.add(cur["parentId"])
        cur = reg.record(cur["parentId"])
        chain.append({"id": cur["id"], "verdict": cur["verdict"], "sourceHash": cur["sourceHash"]})
    kids = [{"id": k, "verdict": reg.record(k)["verdict"]} for k in reg.children(rid)]
    out = {"record": rec, "verdictLabel": VERDICT_LABELS.get(rec["verdict"], "?"), "parents": chain,
           "children": kids}
    auditors = [a.lower() for a in (sess.deployment or {}).get("auditors") or []]
    out["auditorListed"] = rec["auditor"].lower() in auditors if auditors else None
    from_block = int(((sess.deployment or {}).get("registry") or {}).get("block") or 0)
    lg = reg.find_event_tx(EVENT_REGISTERED, rid, from_block)
    out["registeredTx"] = lg["transactionHash"] if lg else None
    if rec["deployed"]:
        now = sess.client.code_hash(rec["deployed"])
        out["currentCodehash"] = now
        out["codehashMatches"] = now == rec["runtimeCodeHash"]
        lg = reg.find_event_tx(EVENT_LINKED, rid, from_block)
        out["linkedTx"] = lg["transactionHash"] if lg else None
    esc = sess.escrow
    if esc:
        try:
            q = esc.settled_by(rid)
            out["settledRequest"] = q or None
        except ChainError:
            out["settledRequest"] = None
    return out


# ------------------------------------------------------------------ independent checks


def _role(manifest: dict, role: str) -> dict | None:
    return next((f for f in manifest.get("files", []) if f.get("role") == role), None)


def _safe_rel(name: str) -> bool:
    """A bundle-relative path that stays inside the bundle."""
    s = str(name)
    return bool(s) and "\\" not in s and not Path(s).is_absolute() and ".." not in Path(s).parts


def check_evidence(sess: Session, rec: dict, bundle: Path) -> dict:
    """Re-hash every file of the bundle and compare with the manifest and with the chain."""
    m = load_manifest(bundle)
    checks = []
    for f in m.get("files", []):
        p = Path(bundle) / f["name"]
        actual = sha256_hex(p.read_bytes()) if p.exists() else None
        checks.append({"what": f"檔案 {f['name']} 與 manifest", "expected": f["sha256"], "actual": actual,
                       "ok": actual == f["sha256"]})
    exploit_expect = rec["exploitHash"]
    if rec["parentId"] and exploit_expect == ZERO32:  # patched child: the exploit is the parent's
        exploit_expect = sess.registry.record(rec["parentId"])["exploitHash"]
    pairs = [("gate_json", "gate.json", rec["gateJsonHash"]), ("source", "原始碼", rec["sourceHash"]),
             ("exploit", "攻擊程式", exploit_expect), ("patch", "修補", rec["patchHash"])]
    for role, word, onchain in pairs:
        f = _role(m, role)
        if f is None and onchain == ZERO32:
            continue
        actual = sha256_hex((Path(bundle) / f["name"]).read_bytes()) if f else None
        checks.append({"what": f"{word}的 sha256 與鏈上紀錄", "expected": onchain, "actual": actual,
                       "ok": actual == onchain})
    if rec["parentId"]:
        f = _role(m, "parent_source")
        if f:
            parent = sess.registry.record(rec["parentId"])
            actual = sha256_hex((Path(bundle) / f["name"]).read_bytes())
            checks.append({"what": "上一版原始碼與上一版紀錄", "expected": parent["sourceHash"], "actual": actual,
                           "ok": actual == parent["sourceHash"]})
    mi = m.get("recordInput") or {}
    diff = [k for k in RECORD_FIELDS if str(mi.get(k)).lower() != str(rec[k]).lower()]
    checks.append({"what": "manifest 的紀錄內容與鏈上紀錄", "expected": "全部欄位相同",
                   "actual": "相同" if not diff else f"不同：{', '.join(diff)}", "ok": not diff})
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


def rebuild(sess: Session, rec: dict, bundle: Path | None, source: Path | None) -> dict:
    """Compile with the recorded recipe and compare with initcodeHash (and the live code)."""
    recipe = {}
    if bundle and (Path(bundle) / "compiler.json").exists():
        recipe = json.loads((Path(bundle) / "compiler.json").read_text())
    src_path = source
    if not src_path and bundle:
        f = _role(load_manifest(bundle), "source")
        src_path = Path(bundle) / f["name"] if f else None
    if not src_path:
        raise ChainError("--rebuild 需要 --evidence 資料夾或 --source 原始碼")
    text = Path(src_path).read_bytes()
    if sha256_hex(text) != rec["sourceHash"]:
        return {"ok": False, "checks": [{"what": "原始碼 sha256 與鏈上紀錄", "expected": rec["sourceHash"],
                                         "actual": sha256_hex(text), "ok": False}]}
    imports = {}
    for unit, rel in (recipe.get("imports") or {}).items():
        if not (bundle and _safe_rel(unit) and _safe_rel(rel)):
            raise ChainError(f"compiler.json 的 imports 不能用：{unit} → {rel}")
        p = Path(bundle) / rel
        if not p.is_file():
            raise ChainError(f"證據資料夾缺少 {rel}（編譯時 import 的檔案）")
        imports[unit] = p.read_text(encoding="utf-8")
    b = compile_source(text.decode("utf-8"), recipe.get("file") or Path(src_path).name, recipe.get("contract"),
                       evm_version=(recipe.get("settings") or {}).get("evmVersion", "paris"),
                       ctor_args=recipe.get("constructorArgs", "0x"), imports=imports or None)
    checks = [{"what": f"用 {b.solc}（{b.evm_version}）重新編譯的 initcode 與鏈上 initcodeHash",
               "expected": rec["initcodeHash"], "actual": b.initcode_hash, "ok": b.initcode_hash == rec["initcodeHash"]}]
    if rec["deployed"]:
        live = sess.client.code_hash(rec["deployed"])
        if b.has_immutables:
            checks.append({"what": "runtime 程式碼（合約有 immutable，部署時才寫入，只比對 initcode）",
                           "expected": live, "actual": "略過", "ok": True})
        else:
            checks.append({"what": "重新編譯的 runtime 與鏈上部署地址的程式碼", "expected": live,
                           "actual": b.runtime_hash, "ok": live == b.runtime_hash})
    return {"ok": all(c["ok"] for c in checks), "checks": checks, "contract": b.contract}


def _forge_tests(proj: Path) -> dict[str, bool]:
    proc = subprocess.run([find_tool("forge"), "test", "--json", "--offline"], cwd=proj, capture_output=True,
                          text=True, timeout=900)
    start = proc.stdout.find("{")
    try:
        data = json.loads(proc.stdout[start:]) if start >= 0 else {}
    except json.JSONDecodeError:
        data = {}
    if not data:
        raise ChainError(f"forge test 沒有結果：{(proc.stderr or proc.stdout)[-800:]}")
    out = {}
    for suite in data.values():
        for name, r in (suite.get("test_results") or {}).items():
            out[name.split("(")[0]] = r.get("status") == "Success"
    return out


def replay(sess: Session, rec: dict, bundle: Path) -> dict:
    """Re-run the proven attack: it must succeed on the original and fail on the patched source."""
    m = load_manifest(bundle)
    reg_zip = _role(m, "regression")
    if not reg_zip:
        raise ChainError("證據裡沒有 regression.zip，無法重跑攻擊")
    src = _role(m, "source")
    parent_src = _role(m, "parent_source")
    original = Path(bundle) / (parent_src or src)["name"]
    patched_src = Path(bundle) / src["name"] if parent_src else None
    patch = _role(m, "patch")
    checks = []
    with tempfile.TemporaryDirectory(prefix="arbiter-me-replay-") as tmp:
        with zipfile.ZipFile(Path(bundle) / reg_zip["name"]) as zf:
            for n in zf.namelist():
                if n.startswith("/") or ".." in Path(n).parts:
                    raise ChainError(f"regression.zip 有不安全的路徑：{n}")
            zf.extractall(tmp)
        proj = next(p for p in Path(tmp).iterdir() if p.is_dir())
        target = proj / "src" / original.name
        same = target.exists() and target.read_bytes() == original.read_bytes()
        checks.append({"what": "回歸專案裡的合約就是被稽核的原始碼", "expected": "相同",
                       "actual": "相同" if same else "不同", "ok": same})
        before = _forge_tests(proj)
        reproduced = before.get("testExploitBlocked") is False
        honest = [k for k in before if k.startswith("testHonestPath")]
        checks.append({"what": "攻擊在原始碼上重現（testExploitBlocked 失敗 = 攻擊成功）",
                       "expected": "重現", "actual": "重現" if reproduced else "沒有重現", "ok": reproduced})
        checks.append({"what": "原始碼上沒有攻擊時的誠實路徑（testHonestPath*）",
                       "expected": f"{len(honest)} 個通過", "actual": f"{sum(before[k] for k in honest)} 個通過",
                       "ok": all(before[k] for k in honest)})
        if patched_src is not None:
            shutil.copyfile(patched_src, target)
            how = "修補後的原始碼（這筆紀錄的 src）"
        elif patch:
            proc = subprocess.run(["git", "apply", "-p1", str(Path(bundle) / patch["name"])], cwd=proj,
                                  capture_output=True, text=True)
            if proc.returncode != 0:
                raise ChainError(f"patch.diff 套用失敗：{proc.stderr.strip()}")
            how = "套用 patch.diff 之後"
        else:
            how = None
        if how:
            after = _forge_tests(proj)
            blocked = after.get("testExploitBlocked") is True
            checks.append({"what": f"{how}攻擊失敗（testExploitBlocked 通過）", "expected": "攻擊失敗",
                           "actual": "攻擊失敗" if blocked else "攻擊仍然成功", "ok": blocked})
            checks.append({"what": f"{how}誠實路徑仍然通過", "expected": f"{len(honest)} 個通過",
                           "actual": f"{sum(after.get(k, False) for k in honest)} 個通過",
                           "ok": all(after.get(k, False) for k in honest)})
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


# ------------------------------------------------------------------ CLI


def _fmt_checks(title: str, res: dict) -> list[str]:
    lines = [f"  {title}：{'全部符合' if res['ok'] else '有不符合'}"]
    for c in res["checks"]:
        mark = "符合" if c["ok"] else "不符"
        lines.append(f"    [{mark}] {c['what']}" + ("" if c["ok"] else f"\n           預期 {c['expected']}\n           實際 {c['actual']}"))
    return lines


def _text(sess: Session, d: dict) -> str:
    net, r = sess.net, d["record"]
    lines = [f"紀錄 #{r['id']}  判定 {r['verdict']}：{d['verdictLabel']}"]
    if r["verdict"] == 3:
        lines.append(f"  證明條件  {PRED_LABELS.get(r['predicateClass'])}；證據層級 {r['evidenceTier']}")
    lines += [f"  原始碼    sha256 {r['sourceHash']}", f"  initcode  keccak256 {r['initcodeHash']}",
              f"  gate.json sha256 {r['gateJsonHash']}"]
    if r["exploitHash"] != ZERO32:
        lines.append(f"  攻擊程式  sha256 {r['exploitHash']}")
    if r["patchHash"] != ZERO32:
        lines.append(f"  修補      sha256 {r['patchHash']}")
    listed = {True: "（在部署資訊的稽核者名單內）", False: "（不在部署資訊的稽核者名單內）", None: ""}[d["auditorListed"]]
    lines += [f"  稽核者    {r['auditor']}{listed}", f"  模型      {r['model'] or '未記錄'}；工具 commit {r['toolCommit'][2:12]}",
              f"  登錄時間  {_dt.datetime.fromtimestamp(r['timestamp'], TZ):%Y-%m-%d %H:%M:%S}（UTC+8，區塊時間）"]
    if d.get("registeredTx"):
        lines.append(f"  登錄交易  {d['registeredTx']}")
    if d["parents"]:
        lines.append("  上一版    " + " ← ".join(f"#{p['id']}（判定 {p['verdict']}）" for p in d["parents"]))
    if d["children"]:
        lines.append("  後續版本  " + "、".join(f"#{c['id']}（判定 {c['verdict']}）" for c in d["children"]))
    lines.append(f"  部署      {LINK_LABELS.get(r['linkKind'])}")
    if r["deployed"]:
        lines.append(f"            地址 {r['deployed']}")
        if url := net.address_url(r["deployed"]):
            lines.append(f"            {url}")
        lines.append(f"            紀錄的 codehash {r['runtimeCodeHash']}")
        lines.append(f"            目前的 codehash {d['currentCodehash']}（{'相同' if d['codehashMatches'] else '不同！'}）")
    if d.get("settledRequest"):
        lines.append(f"  委託      這筆紀錄結算了委託 #{d['settledRequest']}")
    for key, title in (("evidence", "證據檔案"), ("rebuild", "重新編譯"), ("replay", "重跑攻擊")):
        if key in d:
            lines += _fmt_checks(title, d[key])
    lines.append("  說明：紀錄是稽核者的主張；判定 1 代表沒有找到可證明的攻擊，不等於安全。")
    return "\n".join(lines)


def add_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("target", nargs="?", help="部署地址（0x…）、紀錄編號、交易雜湊或原始碼 sha256")
    ap.add_argument("--source", type=Path, help="用原始碼檔案查（sha256 → recordsBySource）")
    ap.add_argument("--evidence", type=Path, help="證據資料夾：重算雜湊並和鏈上比對")
    ap.add_argument("--rebuild", action="store_true", help="用紀錄的編譯設定重新編譯並比對")
    ap.add_argument("--replay", action="store_true", help="用 forge 重跑證據裡的攻擊（需要 --evidence）")
    ap.add_argument("--json", action="store_true", help="輸出 JSON")
    add_network_args(ap, signer=False)


def run(args: argparse.Namespace) -> int:
    if not args.target and not args.source:
        raise ChainError("請給要查的地址 / 紀錄編號 / 交易雜湊，或 --source")
    if args.replay and not args.evidence:
        raise ChainError("--replay 需要 --evidence 證據資料夾")
    sess = open_session(args, need_deployment=True)
    what, ids = lookup(sess, args.target, args.source)
    results = []
    for rid in ids:
        d = describe(sess, rid)
        rec = d["record"]
        if args.evidence:
            d["evidence"] = check_evidence(sess, rec, args.evidence)
        if args.rebuild:
            d["rebuild"] = rebuild(sess, rec, args.evidence, args.source)
        if args.replay:
            d["replay"] = replay(sess, rec, args.evidence)
        results.append(d)
    ok = bool(results) and all(all(d[k]["ok"] for k in ("evidence", "rebuild", "replay") if k in d)
                               and d.get("codehashMatches", True) for d in results)
    if args.json:
        print(json.dumps({"query": what, "network": sess.net.name, "registry": sess.registry.address,
                          "records": results, "ok": ok}, ensure_ascii=False, indent=1))
    else:
        print(f"查詢：{what}  網路 {sess.net.name}  登錄合約 {sess.registry.address}")
        if not results:
            print("  鏈上沒有相符的紀錄。")
        for d in results:
            print(_text(sess, d))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="me_verify.py", description="從 ME 鏈上查詢並獨立重驗 ARBITER Gate 稽核紀錄。")
    add_args(ap)
    args = ap.parse_args(argv)
    try:
        return run(args)
    except ChainError as exc:
        print(f"錯誤：{exc}")
        return 2
