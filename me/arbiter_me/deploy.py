"""Register a gate result on ME and deploy through the registry when the verdict allows it.

    verdict 1/2 -> deployAudited: the registry deploys the exact audited bytecode (CREATE2,
                   address predicted before sending) and links it (LINK_GATED);
    verdict 3/0 -> nothing is deployed; the registry's own refusal (NotDeployable) is shown by
                   eth_call, and with --record-refusal also sent as a reverting transaction.

Results go to me.json next to gate.json (and runs/gate/web/<rid>.me.json with --rid), the
sidecar the web result page reads (BRIEF 4.2). A patched child record is added to an existing
sidecar under "patched" so the page's main card keeps describing the gate result itself.

Nothing is sent when an --escrow-request could not be settled by the new record (wrong
auditor, wrong source, closed, past its window). The sidecar is written right after the
record is registered and again after each later step, with the steps still to do under
"pending"; a step that fails is recorded there instead of aborting. Running the same command
again picks up the same record (identical on-chain fields, same auditor) and does only the
pending steps, so an interrupted run never registers a duplicate.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
from pathlib import Path

from . import abi
from .build import Build
from .chain import ChainError, Client, RpcError, format_mec
from .contracts import (EVENT_LINKED, LINK_LABELS, RECORD_FIELDS, REQUEST_STATUS, REQUEST_STATUS_ZH, VERDICT_LABELS,
                        Registry, revert_text, simulate)
from .record import DIRTY_MARK, WEB_DIR, RecordPlan, load_gate, plan_record
from .session import Session, add_network_args, open_session

PUSH0_HINT = ("節點拒絕 PUSH0 指令（invalid opcode: PUSH0）：ME 測試網不支援 shanghai 以後的 EVM。"
              "請用 evm_version = \"paris\" 編譯（solc --evm-version paris；foundry.toml 設 evm_version = \"paris\"）。")
REFUSAL_GAS = 400_000
TZ = _dt.timezone(_dt.timedelta(hours=8))
SETTLE_GRACE = 3600  # AuditEscrow.SETTLE_GRACE
REGISTER_MARGIN = 60  # a new record must be mined before the request's deadline; leave a minute
PENDING_REASON = "登錄後這一步還沒有完成（中斷時會停在這裡；重跑同一個指令會接著做，不會重複登錄）"


def salt_for(rid: int) -> str:
    return "0x" + int(rid).to_bytes(32, "big").hex()


def preflight(client: Client, deploy_code: str, sender: str | None = None) -> dict:
    """Ask the node to simulate the creation (eth_estimateGas) before anything is paid."""
    try:
        return {"ok": True, "gas": client.estimate_gas(None, deploy_code, sender=sender), "error": None}
    except RpcError as exc:
        push0 = "push0" in exc.message.lower()
        return {"ok": False, "gas": None, "push0": push0, "error": PUSH0_HINT if push0 else exc.message}


def register_record(sess: Session, plan: RecordPlan) -> dict:
    reg = sess.registry
    receipt = sess.send(reg.address, Registry.register_data(plan.input))
    ev = reg.registered(receipt)
    if not ev:
        raise ChainError(f"登錄交易沒有 Registered 事件：{receipt['transactionHash']}")
    return {"id": ev[0]["id"], "tx": receipt["transactionHash"], "block": int(str(receipt["blockNumber"]), 0),
            "auditor": ev[0]["auditor"], "cosmosTx": sess.client.cosmos_tx_hash(receipt["transactionHash"])}


def deploy_through_registry(sess: Session, rid: int, build: Build, salt: str | None = None) -> dict:
    reg = sess.registry
    salt = salt or salt_for(rid)
    predicted = reg.predict(rid, sess.require_signer().address, salt)
    data = Registry.deploy_data(rid, build.deploy_code, salt)
    ok, _, err = simulate(sess.client, reg.address, data, sender=sess.require_signer().address)
    if not ok:
        return {"status": "failed", "reason": revert_text(err), "address": None, "tx": None, "linkKind": 0,
                "runtimeCodeHash": None, "predicted": predicted}
    receipt = sess.require_signer().send(sess.client, reg.address, data)
    linked = [e for e in reg.linked(receipt) if e["id"] == rid]
    if not linked:
        raise ChainError(f"部署交易沒有 Linked 事件：{receipt['transactionHash']}")
    ev = linked[0]
    onchain = sess.client.code_hash(ev["deployed"])
    checks = {"predicted_address": ev["deployed"] == predicted.lower(),
              "codehash_matches_event": onchain == ev["runtimeCodeHash"],
              "link_gated": ev["linkKind"] == 2}
    if not build.has_immutables:
        checks["codehash_matches_build"] = onchain == build.runtime_hash
    status = "deployed" if all(checks.values()) else "failed"
    return {"status": status, "reason": "" if status == "deployed" else f"部署後檢查失敗：{checks}",
            "address": ev["deployed"], "tx": receipt["transactionHash"], "linkKind": ev["linkKind"],
            "runtimeCodeHash": ev["runtimeCodeHash"], "predicted": predicted.lower(), "salt": salt,
            "checks": checks, "cosmosTx": sess.client.cosmos_tx_hash(receipt["transactionHash"])}


def show_refusal(sess: Session, rid: int, build: Build | None, salt: str | None = None,
                 record: bool = False) -> dict:
    """eth_call deployAudited for a record that must not deploy; decode the registry's refusal."""
    reg = sess.registry
    salt = salt or salt_for(rid)
    data = Registry.deploy_data(rid, build.deploy_code if build else "0x", salt)
    sender = sess.signer.address if sess.signer else None
    ok, _, err = simulate(sess.client, reg.address, data, sender=sender)
    if ok:
        raise ChainError("登錄合約沒有拒絕部署：這不應該發生（判定 0/3 必須被擋）")
    out = {"status": "blocked", "reason": revert_text(err), "error": err[0] if err else None,
           "errorArgs": err[1] if err else None, "address": None, "tx": None, "linkKind": 0,
           "runtimeCodeHash": None}
    if record:
        receipt = sess.require_signer().send(sess.client, reg.address, data, gas_limit=REFUSAL_GAS,
                                             allow_revert=True)
        out["tx"] = receipt["transactionHash"]
        out["txStatus"] = str(receipt.get("status"))
        out["cosmosTx"] = sess.client.cosmos_tx_hash(receipt["transactionHash"])
    return out


# ------------------------------------------------------------------ escrow pre-check


def check_escrow_request(sess: Session, req_id: int, plan: RecordPlan, record_id: int | None = None) -> dict:
    """Raise before anything is sent when this record could not settle request `req_id`:
    the same checks AuditEscrow.settle makes (open, named auditor, source hash, window)."""
    esc = sess.escrow
    if not esc:
        raise ChainError("部署資訊裡沒有 AuditEscrow，無法結算委託")
    q = esc.get(req_id)
    if record_id is not None and q["status"] != 1 and q["recordId"] == record_id:
        return q  # already settled by this record (an interrupted run); the settle step records it
    problems = []
    if q["status"] != 1:
        problems.append(f"委託 #{req_id} 的狀態是「{REQUEST_STATUS_ZH.get(q['status'], q['status'])}」，不是等待稽核")
    if sess.signer and q["auditor"].lower() != sess.signer.address.lower():
        problems.append(f"委託指定的稽核者是 {q['auditor']}，不是送交易的帳號 {sess.signer.address}（只有它能結算）")
    if q["sourceHash"].lower() != plan.input["sourceHash"].lower():
        problems.append(f"委託的原始碼 sha256 是 {q['sourceHash']}，這筆紀錄是 {plan.input['sourceHash']}")
    now = sess.client.block_timestamp()
    if record_id is None:
        if now + REGISTER_MARGIN > q["deadline"]:
            problems.append("委託期限已到（或剩不到 1 分鐘），新登錄的紀錄不能結算它")
    else:
        rec = sess.registry.record(record_id)
        if record_id < q["minRecordId"]:
            problems.append(f"紀錄 #{record_id} 比委託早登錄")
        if rec["timestamp"] > q["deadline"]:
            problems.append(f"紀錄 #{record_id} 在委託期限之後才登錄")
        if now > q["deadline"] + SETTLE_GRACE:
            problems.append("已過結算期限（委託期限後 1 小時）")
    if problems:
        raise ChainError(f"委託 #{req_id} 不能用這筆紀錄結算，沒有送出任何交易：" + "；".join(problems))
    return q


# ------------------------------------------------------------------ sidecar (BRIEF 4.2)


def sidecar(sess: Session, plan: RecordPlan, reg: dict | None, deploy: dict, escrow_req: dict | None,
            pending: list[str] | None = None) -> dict:
    net, inp = sess.net, plan.input
    record = None
    if reg:
        record = {"id": reg["id"], "tx": reg["tx"], "block": reg["block"], "verdict": inp["verdict"],
                  "verdictLabel": VERDICT_LABELS[inp["verdict"]], "sourceHash": inp["sourceHash"],
                  "gateJsonHash": inp["gateJsonHash"], "exploitHash": inp["exploitHash"],
                  "patchHash": inp["patchHash"], "parentId": inp["parentId"], "auditor": reg["auditor"],
                  "model": inp["model"], "initcodeHash": inp["initcodeHash"], "toolCommit": inp["toolCommit"],
                  "toolCommitSource": plan.tool.get("source"), "toolCommitDirty": bool(plan.tool.get("dirty")),
                  "cosmosTx": reg.get("cosmosTx")}
    dep = {k: deploy.get(k) for k in ("status", "reason", "address", "tx", "linkKind", "runtimeCodeHash", "cosmosTx")}
    dep["preflight"] = deploy.get("preflight")
    escrow = (sess.deployment or {}).get("escrow") or {}
    doc = {
        "schema": "arbiter-me/0.1", "network": net.name, "chainId": net.chain_id,
        "registry": sess.registry.address, "escrow": escrow.get("address"),
        "record": record, "deploy": dep, "escrow_request": escrow_req,
        "explorer": {"record_tx": net.tx_url(reg and reg["tx"], reg and reg.get("cosmosTx")),
                     "deploy_tx": net.tx_url(deploy.get("tx"), deploy.get("cosmosTx")),
                     "address": net.address_url(deploy.get("address")),
                     "registry": net.address_url(sess.registry.address)},
        "evidence": {"uri": inp["evidenceURI"] or plan.bundle.name, "manifest": plan.manifest_sha256,
                     "files": [{"name": f["name"], "sha256": f["sha256"]} for f in plan.files]},
        "recordedAt": _dt.datetime.now(TZ).isoformat(timespec="seconds"),
    }
    if pending:
        doc["pending"] = list(pending)  # steps still to do for this record (a rerun does them)
    return doc


_PATCHED_KEYS = ("record", "deploy", "explorer", "evidence", "recordedAt", "escrow_request", "pending")


def _merge_write(path: Path, doc: dict, patched: bool) -> Path:
    base = None
    if path.exists():
        try:
            base = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            base = None
    if patched:
        if base is not None and base.get("registry") == doc["registry"]:
            base["patched"] = {k: doc[k] for k in _PATCHED_KEYS if k in doc}
            doc = base
        else:
            path = path.with_name(path.name.replace(".json", ".patched.json"))
    elif (base is not None and base.get("registry") == doc["registry"] and isinstance(base.get("patched"), dict)
          and ((base.get("record") or {}).get("id") == (doc.get("record") or {}).get("id"))):
        doc = {**doc, "patched": base["patched"]}  # rewriting the same record keeps its patched child
    path.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return path


def write_sidecars(doc: dict, plan: RecordPlan, web_dir: Path | None = None) -> list[Path]:
    out = []
    if plan.gate.path:
        out.append(_merge_write(plan.gate.path.parent / "me.json", doc, plan.patched))
    if plan.gate.rid:
        d = web_dir or WEB_DIR
        out.append(_merge_write(d / f"{plan.gate.rid}.me.json", doc, plan.patched))
    return out


def _sidecar_parts(plan: RecordPlan, web_dir: Path | None) -> list[dict]:
    """The sidecar sections an earlier run of this command wrote for this plan."""
    paths = []
    if plan.gate.path:
        paths.append(plan.gate.path.parent / "me.json")
    if plan.gate.rid:
        paths.append((web_dir or WEB_DIR) / f"{plan.gate.rid}.me.json")
    parts = []
    for p in paths:
        cands = [p.with_name(p.name.replace(".json", ".patched.json")), p] if plan.patched else [p]
        for c in cands:
            try:
                doc = json.loads(c.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if plan.patched and c == p:
                part = doc.get("patched") if isinstance(doc.get("patched"), dict) else None
                if part:
                    parts.append({**part, "registry": doc.get("registry"), "chainId": doc.get("chainId")})
            else:
                parts.append(doc)
    return parts


def resume_point(sess: Session, plan: RecordPlan, web_dir: Path | None = None) -> dict | None:
    """An earlier run's sidecar section for exactly this record, with steps still pending: the
    record on chain has the same twelve RecordInput fields and the signer is its auditor."""
    for part in _sidecar_parts(plan, web_dir):
        rec = part.get("record") or {}
        if not (part.get("pending") and rec.get("id")):
            continue
        if str(part.get("registry") or "").lower() != sess.registry.address.lower() \
                or part.get("chainId") != sess.net.chain_id:
            continue
        try:
            onchain = sess.registry.record(int(rec["id"]))
        except ChainError:
            continue
        if any(str(onchain[k]).lower() != str(plan.input[k]).lower() for k in RECORD_FIELDS):
            continue
        if sess.signer and onchain["auditor"].lower() != sess.signer.address.lower():
            continue
        return part
    return None


def _linked_tx(sess: Session, rid: int, address: str, since: int) -> str | None:
    """The deployAudited transaction that linked `address` to record `rid` (logs read in
    windows of at most 10,000 blocks from the record's registration time)."""
    try:
        start = sess.client.block_at_timestamp(since)
        topics = [abi.topic(EVENT_LINKED), "0x" + int(rid).to_bytes(32, "big").hex(),
                  "0x" + "00" * 12 + address.lower().removeprefix("0x")]
        logs = sess.client.find_logs(sess.registry.address, topics, start, max_windows=20)
        return logs[0]["transactionHash"] if logs else None
    except ChainError:
        return None


def _deploy_step(sess: Session, plan: RecordPlan, reg: dict, register_only: bool, record_refusal: bool,
                 pre: dict) -> dict:
    v = plan.verdict
    if register_only:
        return {"status": "not_requested", "reason": "只登錄紀錄", "address": None, "tx": None, "linkKind": 0,
                "runtimeCodeHash": None}
    if v in (1, 2):
        if not pre["ok"]:
            return {"status": "failed", "reason": pre["error"], "address": None, "tx": None, "linkKind": 0,
                    "runtimeCodeHash": None}
        reg_c, rid = sess.registry, reg["id"]
        predicted = reg_c.predict(rid, sess.require_signer().address, salt_for(rid)).lower()
        if reg_c.deployment_of(predicted) == rid:  # an interrupted run already deployed it
            rec = reg_c.record(rid)
            tx = _linked_tx(sess, rid, predicted, rec["timestamp"])
            return {"status": "deployed", "reason": "", "address": predicted, "tx": tx, "linkKind": 2,
                    "runtimeCodeHash": sess.client.code_hash(predicted), "predicted": predicted,
                    "salt": salt_for(rid), "cosmosTx": sess.client.cosmos_tx_hash(tx) if tx else None}
        return deploy_through_registry(sess, rid, plan.build)
    return show_refusal(sess, reg["id"], plan.build, record=record_refusal)


def _settle_step(sess: Session, req_id: int, rid: int) -> dict:
    from . import escrow  # late: the probe replaces escrow.settle to simulate a failure
    q = sess.escrow.get(req_id)
    if q["status"] != 1 and q["recordId"] == rid:  # an interrupted run already settled it
        return {"id": req_id, "fee_wei": str(q["fee"]), "status": REQUEST_STATUS.get(q["status"], "?"),
                "settleTx": None, "recordId": rid, "note": "上一次中斷的執行已經結算（交易雜湊沒有記下）"}
    try:
        return escrow.settle(sess, req_id, rid)
    except ChainError as exc:
        return {"id": req_id, "fee_wei": str(q["fee"]), "status": "open", "settleTx": None, "recordId": rid,
                "settleError": str(exc)}


# ------------------------------------------------------------------ CLI


def add_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("gate", nargs="?", type=Path, help="gate.json 路徑")
    ap.add_argument("--rid", help="網頁結果編號（runs/gate/web/<rid>.json），同時寫 <rid>.me.json")
    ap.add_argument("--source", type=Path, required=True, help="被稽核的原始碼檔案")
    ap.add_argument("--file", dest="file_id", help="gate.json 有多個檔案時，指定 id 或索引")
    ap.add_argument("--results", type=Path, help="results.jsonl（預設讀 gate.json 的 input.results）")
    ap.add_argument("--contract", help="要部署的合約名稱（預設與檔名相同）")
    ap.add_argument("--ctor-args", default="0x", help="ABI 編碼後的建構子參數（hex）")
    ap.add_argument("--evidence-out", type=Path, help="證據資料夾（預設 gate.json 旁的 me-evidence[-patched]）")
    ap.add_argument("--evidence-uri", default="", help="證據資料夾公開的位置（寫進鏈上紀錄）")
    ap.add_argument("--tool-commit", help="產生結果的 ARBITER Gate git commit（預設目前 HEAD）")
    ap.add_argument("--parent", type=int, default=0, help="上一版紀錄的編號（修補後的紀錄用）")
    ap.add_argument("--patch", action="store_true", help="套用 gate.json 裡通過驗證的修補，登錄修補後的版本")
    ap.add_argument("--record-refusal", action="store_true",
                    help="判定 0/3 時把被拒絕的部署也送上鏈（交易會失敗，在瀏覽器上看得到拒絕）")
    ap.add_argument("--escrow-request", type=int, help="登錄後用這筆紀錄結算這個委託編號")
    ap.add_argument("--web-dir", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--dry-run", action="store_true", help="只建紀錄與證據、做 preflight，不送交易")
    ap.add_argument("--json", action="store_true", help="輸出 JSON")
    add_network_args(ap)


def run(args: argparse.Namespace, register_only: bool = False) -> int:
    sess = open_session(args, need_deployment=True)
    try:
        return _run(sess, args, register_only)
    finally:
        sess.close()


def _run(sess: Session, args: argparse.Namespace, register_only: bool) -> int:
    gate = load_gate(args.gate, args.rid, args.web_dir)
    base = (args.gate.parent if args.gate else (args.web_dir or WEB_DIR))
    default_out = base / (("me-evidence-patched" if args.patch else "me-evidence") if args.gate
                          else f"{args.rid}.me-evidence{'-patched' if args.patch else ''}")
    plan = plan_record(gate, args.source, out_dir=args.evidence_out or default_out, file_id=args.file_id,
                       results=args.results, patched=args.patch, parent_id=args.parent, contract=args.contract,
                       ctor_args=args.ctor_args, evidence_uri=args.evidence_uri,
                       tool_commit_override=args.tool_commit, evm_version=sess.net.evm_version)
    if args.parent and not args.patch:
        raise ChainError("--parent 只用在修補後的紀錄（加上 --patch）")
    sender = sess.signer.address if sess.signer else None
    pre = preflight(sess.client, plan.build.deploy_code, sender) if plan.build else \
        {"ok": False, "gas": None, "error": "沒有可編譯的 bytecode"}

    prev = resume_point(sess, plan, args.web_dir)
    prev_q = (prev or {}).get("escrow_request") or {}
    settled_before = prev_q.get("id") == args.escrow_request and prev_q.get("status") in ("paid", "refunded")
    if args.escrow_request and not settled_before:
        # Refuse before anything is sent when the request could not be settled by this record.
        check_escrow_request(sess, args.escrow_request, plan, int(prev["record"]["id"]) if prev else None)

    if args.dry_run:
        out = {"dryRun": True, "recordInput": plan.input, "preflight": pre, "bundle": str(plan.bundle),
               "manifest": plan.manifest_sha256, "notes": plan.notes, "toolCommitDirty": plan.tool.get("dirty")}
        print(json.dumps(out, ensure_ascii=False, indent=1) if args.json else _dry_text(sess, plan, pre))
        return 0

    pre_out = {k: pre.get(k) for k in ("ok", "gas", "error")}
    placeholder = {"status": "failed", "reason": PENDING_REASON, "address": None, "tx": None, "linkKind": 0,
                   "runtimeCodeHash": None, "preflight": pre_out}
    if prev:
        r = prev["record"]
        reg = {"id": int(r["id"]), "tx": r.get("tx"), "block": r.get("block"), "auditor": r.get("auditor"),
               "cosmosTx": r.get("cosmosTx"), "resumed": True}
        pending = [s for s in prev["pending"] if s in ("deploy", "settle")]
        deploy = placeholder if "deploy" in pending else (prev.get("deploy") or placeholder)
        escrow_req = prev.get("escrow_request") if settled_before else None
        if args.escrow_request and not settled_before and "settle" not in pending:
            pending.append("settle")
        if not args.escrow_request and "settle" in pending:
            pending.remove("settle")  # this run was not asked to settle anything
    else:
        reg = register_record(sess, plan)
        pending = ["deploy"] + (["settle"] if args.escrow_request else [])
        deploy, escrow_req = placeholder, None
    paths = write_sidecars(sidecar(sess, plan, reg, deploy, escrow_req, pending), plan, args.web_dir)

    if "deploy" in pending:
        try:
            deploy = _deploy_step(sess, plan, reg, register_only, args.record_refusal, pre)
            pending.remove("deploy")  # an outcome (deployed / blocked / a refusal the node explained)
        except ChainError as exc:  # interrupted (RPC, cast, receipt timeout): stays pending
            deploy = {"status": "failed", "reason": f"{exc}（紀錄已登錄；重跑同一個指令會再試這一步）", "address": None,
                      "tx": None, "linkKind": 0, "runtimeCodeHash": None}
        deploy["preflight"] = pre_out
        paths = write_sidecars(sidecar(sess, plan, reg, deploy, escrow_req, pending), plan, args.web_dir)

    if "settle" in pending:
        escrow_req = _settle_step(sess, args.escrow_request, reg["id"])
        if escrow_req["status"] in ("paid", "refunded"):
            pending.remove("settle")
        paths = write_sidecars(sidecar(sess, plan, reg, deploy, escrow_req, pending), plan, args.web_dir)

    doc = sidecar(sess, plan, reg, deploy, escrow_req, pending)
    if args.json:
        print(json.dumps({**doc, "resumed": bool(prev),
                          "sidecars": [str(p) for p in paths], "bundle": str(plan.bundle),
                          "notes": plan.notes}, ensure_ascii=False, indent=1))
    else:
        print(_summary(sess, plan, reg, deploy, escrow_req, paths, pending))
    done = deploy["status"] in ("deployed", "blocked", "not_requested")
    return 0 if done and not pending else 1


def _commit_line(plan: RecordPlan) -> str:
    mark = f"（gate.json 記錄：產生結果的程式{DIRTY_MARK}）" if plan.tool.get("dirty") else ""
    return f"  工具      commit {plan.input['toolCommit']}{mark}"


def _dry_text(sess: Session, plan: RecordPlan, pre: dict) -> str:
    inp = plan.input
    lines = [f"ARBITER Gate × ME：預演（沒有送出任何交易）  網路 {sess.net.name}（chain {sess.net.chain_id}）",
             f"  判定      {inp['verdict']} {VERDICT_LABELS[inp['verdict']]}",
             f"  原始碼    sha256 {inp['sourceHash']}",
             f"  initcode  keccak256 {inp['initcodeHash']}",
             _commit_line(plan),
             f"  preflight {'通過，約 ' + str(pre['gas']) + ' gas' if pre['ok'] else '失敗：' + str(pre['error'])}",
             f"  證據      {len(plan.files)} 個檔案，manifest sha256 {plan.manifest_sha256}"]
    lines += [f"  註：{n}" for n in plan.notes]
    return "\n".join(lines)


def _summary(sess: Session, plan: RecordPlan, reg: dict, deploy: dict, escrow_req: dict | None,
             paths: list[Path], pending: list[str] | None = None) -> str:
    net, inp = sess.net, plan.input
    lines = [f"ARBITER Gate × ME：{'修補後版本的' if plan.patched else ''}稽核紀錄已登錄  網路 {net.name}（chain {net.chain_id}）",
             f"  紀錄 #{reg['id']}  判定 {inp['verdict']}：{VERDICT_LABELS[inp['verdict']]}"
             + (f"（上一版 #{inp['parentId']}）" if inp["parentId"] else ""),
             f"  登錄交易  {reg['tx']}" + ("（上一次執行登錄的；這次接著完成剩下的步驟，沒有重複登錄）" if reg.get("resumed") else "")]
    if url := net.tx_url(reg["tx"], reg.get("cosmosTx")):
        lines.append(f"            {url}")
    lines.append(_commit_line(plan))
    st = deploy["status"]
    if st == "deployed":
        lines += [f"  部署      已由登錄合約部署稽核過的 bytecode：{deploy['address']}",
                  f"            {LINK_LABELS[deploy['linkKind']]}；runtime codehash {deploy['runtimeCodeHash']}",
                  f"  部署交易  {deploy['tx']}"]
        if url := net.address_url(deploy["address"]):
            lines.append(f"            {url}")
    elif st == "blocked":
        lines.append(f"  部署      已擋下：{deploy['reason']}")
        if deploy.get("tx"):
            lines.append(f"  拒絕交易  {deploy['tx']}（交易失敗是預期的，瀏覽器上看得到）")
    elif st == "failed":
        lines.append(f"  部署      失敗：{deploy['reason']}")
    else:
        lines.append("  部署      沒有要求部署")
    if escrow_req:
        words = {"paid": "已付款給稽核者", "refunded": "已退款給委託人", "open": "還沒結算"}
        lines.append(f"  委託      #{escrow_req['id']} {words.get(escrow_req['status'], escrow_req['status'])}，"
                     f"{format_mec(int(escrow_req['fee_wei']))}"
                     + (f"（交易 {escrow_req['settleTx']}）" if escrow_req.get("settleTx") else "")
                     + (f"（{escrow_req['note']}）" if escrow_req.get("note") else ""))
        if escrow_req.get("settleError"):
            lines.append(f"            結算失敗：{escrow_req['settleError']}")
    if pending:
        lines.append(f"  未完成    {'、'.join({'deploy': '部署', 'settle': '結算委託'}.get(s, s) for s in pending)}"
                     "：已記在 me.json，重跑同一個指令會接著做（不會重複登錄）")
    lines.append(f"  證據      {len(plan.files)} 個檔案（{plan.bundle.name}），manifest sha256 {plan.manifest_sha256}")
    lines += [f"  me.json   {p.name}" for p in paths]
    lines += [f"  註：{n}" for n in plan.notes]
    lines.append("  提醒：判定 1 代表「沒有找到可證明的攻擊」，不等於安全。")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="me_deploy.py", description="把 ARBITER Gate 的結果登錄到 ME，判定允許時經由登錄合約部署。")
    add_args(ap)
    args = ap.parse_args(argv)
    try:
        return run(args)
    except ChainError as exc:
        print(f"錯誤：{exc}")
        return 2
