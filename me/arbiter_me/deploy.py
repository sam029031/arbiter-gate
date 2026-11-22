"""Register a gate result on ME and deploy through the registry when the verdict allows it.

    verdict 1/2 -> deployAudited: the registry deploys the exact audited bytecode (CREATE2,
                   address predicted before sending) and links it (LINK_GATED);
    verdict 3/0 -> nothing is deployed; the registry's own refusal (NotDeployable) is shown by
                   eth_call, and with --record-refusal also sent as a reverting transaction.

Results go to me.json next to gate.json (and runs/gate/web/<rid>.me.json with --rid), the
sidecar the web result page reads (BRIEF 4.2). A patched child record is added to an existing
sidecar under "patched" so the page's main card keeps describing the gate result itself.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
from pathlib import Path

from .build import Build
from .chain import ChainError, Client, RpcError, format_mec
from .contracts import LINK_LABELS, VERDICT_LABELS, Registry, revert_text, simulate
from .record import WEB_DIR, RecordPlan, load_gate, plan_record
from .session import Session, add_network_args, open_session

PUSH0_HINT = ("節點拒絕 PUSH0 指令（invalid opcode: PUSH0）：ME 測試網不支援 shanghai 以後的 EVM。"
              "請用 evm_version = \"paris\" 編譯（solc --evm-version paris；foundry.toml 設 evm_version = \"paris\"）。")
REFUSAL_GAS = 400_000
TZ = _dt.timezone(_dt.timedelta(hours=8))


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


# ------------------------------------------------------------------ sidecar (BRIEF 4.2)


def sidecar(sess: Session, plan: RecordPlan, reg: dict | None, deploy: dict, escrow_req: dict | None) -> dict:
    net, inp = sess.net, plan.input
    record = None
    if reg:
        record = {"id": reg["id"], "tx": reg["tx"], "block": reg["block"], "verdict": inp["verdict"],
                  "verdictLabel": VERDICT_LABELS[inp["verdict"]], "sourceHash": inp["sourceHash"],
                  "gateJsonHash": inp["gateJsonHash"], "exploitHash": inp["exploitHash"],
                  "patchHash": inp["patchHash"], "parentId": inp["parentId"], "auditor": reg["auditor"],
                  "model": inp["model"], "initcodeHash": inp["initcodeHash"], "toolCommit": inp["toolCommit"],
                  "cosmosTx": reg.get("cosmosTx")}
    dep = {k: deploy.get(k) for k in ("status", "reason", "address", "tx", "linkKind", "runtimeCodeHash", "cosmosTx")}
    dep["preflight"] = deploy.get("preflight")
    escrow = (sess.deployment or {}).get("escrow") or {}
    return {
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


def _merge_write(path: Path, doc: dict, patched: bool) -> Path:
    if patched:
        if path.exists():
            base = json.loads(path.read_text(encoding="utf-8"))
            if base.get("registry") == doc["registry"]:
                base["patched"] = {k: doc[k] for k in ("record", "deploy", "explorer", "evidence", "recordedAt")}
                doc = base
            else:
                path = path.with_name(path.name.replace(".json", ".patched.json"))
        else:
            path = path.with_name(path.name.replace(".json", ".patched.json"))
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

    if args.dry_run:
        out = {"dryRun": True, "recordInput": plan.input, "preflight": pre, "bundle": str(plan.bundle),
               "manifest": plan.manifest_sha256, "notes": plan.notes}
        print(json.dumps(out, ensure_ascii=False, indent=1) if args.json else _dry_text(sess, plan, pre))
        return 0

    reg = register_record(sess, plan)
    v = plan.verdict
    if register_only:
        deploy = {"status": "not_requested", "reason": "只登錄紀錄", "address": None, "tx": None, "linkKind": 0,
                  "runtimeCodeHash": None}
    elif v in (1, 2):
        if not pre["ok"]:
            deploy = {"status": "failed", "reason": pre["error"], "address": None, "tx": None, "linkKind": 0,
                      "runtimeCodeHash": None}
        else:
            deploy = deploy_through_registry(sess, reg["id"], plan.build)
    else:
        deploy = show_refusal(sess, reg["id"], plan.build, record=args.record_refusal)
    deploy["preflight"] = {k: pre.get(k) for k in ("ok", "gas", "error")}

    escrow_req = None
    if args.escrow_request:
        from .escrow import settle
        escrow_req = settle(sess, args.escrow_request, reg["id"])

    doc = sidecar(sess, plan, reg, deploy, escrow_req)
    paths = write_sidecars(doc, plan, args.web_dir)
    if args.json:
        print(json.dumps({**doc,
                          "sidecars": [str(p) for p in paths], "bundle": str(plan.bundle),
                          "notes": plan.notes}, ensure_ascii=False, indent=1))
    else:
        print(_summary(sess, plan, reg, deploy, escrow_req, paths))
    return 0 if deploy["status"] in ("deployed", "blocked", "not_requested") else 1


def _dry_text(sess: Session, plan: RecordPlan, pre: dict) -> str:
    inp = plan.input
    lines = [f"ARBITER Gate × ME：預演（沒有送出任何交易）  網路 {sess.net.name}（chain {sess.net.chain_id}）",
             f"  判定      {inp['verdict']} {VERDICT_LABELS[inp['verdict']]}",
             f"  原始碼    sha256 {inp['sourceHash']}",
             f"  initcode  keccak256 {inp['initcodeHash']}",
             f"  preflight {'通過，約 ' + str(pre['gas']) + ' gas' if pre['ok'] else '失敗：' + str(pre['error'])}",
             f"  證據      {len(plan.files)} 個檔案，manifest sha256 {plan.manifest_sha256}"]
    lines += [f"  註：{n}" for n in plan.notes]
    return "\n".join(lines)


def _summary(sess: Session, plan: RecordPlan, reg: dict, deploy: dict, escrow_req: dict | None,
             paths: list[Path]) -> str:
    net, inp = sess.net, plan.input
    lines = [f"ARBITER Gate × ME：{'修補後版本的' if plan.patched else ''}稽核紀錄已登錄  網路 {net.name}（chain {net.chain_id}）",
             f"  紀錄 #{reg['id']}  判定 {inp['verdict']}：{VERDICT_LABELS[inp['verdict']]}"
             + (f"（上一版 #{inp['parentId']}）" if inp["parentId"] else ""),
             f"  登錄交易  {reg['tx']}"]
    if url := net.tx_url(reg["tx"], reg.get("cosmosTx")):
        lines.append(f"            {url}")
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
        lines.append(f"  委託      #{escrow_req['id']} {escrow_req['status']}，{format_mec(int(escrow_req['fee_wei']))}"
                     f"（交易 {escrow_req.get('settleTx')}）")
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
