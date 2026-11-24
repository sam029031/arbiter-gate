"""Two wallets on ME: a requester pays for an audit through AuditEscrow, the auditor it names
settles with its own record, the requester deploys the audited bytecode through the registry,
and a second request that the auditor leaves alone goes back to the requester after its deadline.

The 11/23 run (demo.py) sent every transaction from one wallet: the requester, the auditor and
the deployer were one address, and the escrow paid the fee back to its own payer. Here the
requester, who is also the developer deploying the contract, is a second wallet. Both wallets
belong to the team: what this shows is the contracts enforcing their rules between two
different addresses, not an outside party using them.

    me.py two-party request --account REQUESTER --source X.sol    two fees naming the auditor
    (audit X.sol with ARBITER Gate: a gate.json, like any other audit)
    me.py two-party settle  --account AUDITOR --gate JOB/gate.json register + settle request 1
    me.py two-party deploy  --account REQUESTER                    deployAudited, as the requester
    me.py two-party refund  --account ANY                          request 2, after its deadline
    me.py two-party status

Each step is recorded in me/deployments/<network>.two-party.json and skipped when it is run
again; a transaction sent by a run that stopped before saving is found on chain, not sent
twice. On me-testnet EVIDENCE.md is rewritten after every step that changed something:
demo.evidence_md adds the "兩個錢包的託管示範" section from this state.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
from pathlib import Path

from . import abi, demo, deploy, escrow
from .bech32 import to_me1
from .chain import ANVIL_DEV_KEYS, ChainError, DevKeySigner, KeystoreSigner, format_mec, parse_mec
from .contracts import (EVENT_EXPIRED, EVENT_REGISTERED, EVENT_REQUESTED, EVENT_SETTLED, ME_DIR, REQUEST_STATUS_ZH,
                        VERDICT_LABELS)
from .record import gate_info, load_gate, normalize_source, plan_record, sha256_hex
from .session import Session, add_network_args, open_session

TZ = _dt.timezone(_dt.timedelta(hours=8))
PAID_TTL = 7 * 24 * 3600  # request 1: the auditor settles it
EXPIRE_TTL = 3600  # request 2: AuditEscrow.MIN_TTL; nobody settles it
GRACE = deploy.SETTLE_GRACE
GAS_MARGIN_WEI = 10**15  # 0.001 MEC, far above what the requester's transactions cost on ME
FOLDER = "two-party"  # me/evidence/two-party: the record's evidence bundle


def state_path(net: str) -> Path:
    return ME_DIR / "deployments" / f"{net}.two-party.json"


def load_state(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _save(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def _ts(seconds: int) -> str:
    return _dt.datetime.fromtimestamp(int(seconds), TZ).strftime("%Y-%m-%d %H:%M:%S")


def _chain_time(sess: Session) -> int:
    return int(str(sess.client.rpc("eth_getBlockByNumber", ["latest", False])["timestamp"]), 0)


def _url(sess: Session, tx: str | None, cosmos: str | None) -> str:
    url = sess.net.tx_url(tx, cosmos) if tx else None
    return f"\n  {url}" if url else ""


def _word(n: int) -> str:
    return "0x" + int(n).to_bytes(32, "big").hex()


def _event_tx(sess: Session, address: str, event: str, req_id: int) -> str | None:
    """The transaction that emitted `event` (first topic = the request id) at `address`."""
    logs = sess.client.get_logs(address, [abi.topic(event), _word(req_id)])
    return logs[0]["transactionHash"] if logs else None


def _signer(sess: Session, args: argparse.Namespace):
    """The account that sends this step. The session is opened without it, so a step that has
    nothing to send (done already, too early) never asks for a keystore password."""
    if not sess.signer:
        if getattr(args, "dev", False):
            sess.signer = DevKeySigner(sess.client, ANVIL_DEV_KEYS[args.dev_key])
        elif getattr(args, "account", None):
            sess.signer = KeystoreSigner(args.account)
        else:
            raise ChainError("這一步要送交易：加上 --account <keystore 名稱>（anvil 用 --dev）")
    return sess.signer


def _source(state: dict) -> Path:
    p = ME_DIR.parent / state["source"]
    if not p.exists():
        raise ChainError(f"找不到原始碼 {state['source']}")
    return p


def _evidence_base() -> str:
    """Where me/evidence is published (ME_EVIDENCE_BASE_ROOT, as for the 11/23 demo)."""
    _, own = demo.evidence_urls()
    return own.removesuffix("/self")


# ------------------------------------------------------------------ steps


def _adopt_request(sess: Session, state: dict, requester: str, ttl: int, taken: set[int]) -> dict | None:
    """A request this requester already sent for this source, auditor and deadline length whose
    state was never saved (the run stopped between the transaction and the save)."""
    esc = sess.escrow
    n = esc.request_count()
    for rid in range(n, max(0, n - 50), -1):
        if rid in taken:
            continue
        q = esc.get(rid)
        if (str(q["requester"]).lower() == requester and str(q["auditor"]).lower() == state["auditor"]
                and str(q["sourceHash"]).lower() == state["sourceHash"] and q["status"] == 1
                and int(q["deadline"]) - int(q["createdAt"]) == ttl):
            tx = _event_tx(sess, esc.address, EVENT_REQUESTED, rid)
            return {"id": rid, "fee_wei": str(q["fee"]), "status": "open", "deadline": int(q["deadline"]), "tx": tx,
                    "cosmosTx": sess.client.cosmos_tx_hash(tx) if tx else None, "reused": True}
    return None


def step_request(sess: Session, args: argparse.Namespace, state: dict, path: Path) -> int:
    auditor = str(args.auditor or ((sess.deployment or {}).get("auditors") or [""])[0]).lower()
    if not auditor:
        raise ChainError("部署資訊沒有列出稽核者：加上 --auditor 0x…")
    src = Path(args.source)
    rel = demo._rel(src)
    if not (ME_DIR.parent / rel).is_file():
        raise ChainError(f"{src} 要放在這個 repository 裡（狀態檔只記相對路徑）")
    h = sha256_hex(normalize_source(src.read_bytes()))
    if state.get("sourceHash") and state["sourceHash"] != h:
        raise ChainError(f"{src.name} 和先前委託的原始碼不同（先前的 sha256 {state['sourceHash']}）")
    reqs = state.get("requests") or {}
    todo = [(slot, ttl) for slot, ttl in (("paid", PAID_TTL), ("expire", EXPIRE_TTL)) if slot not in reqs]
    if not todo:
        print("兩筆委託都已建立，跳過。")
        return 0
    me = _signer(sess, args).address.lower()
    if me == auditor:
        raise ChainError("委託人和稽核者是同一個地址；這個示範要用第二個錢包當委託人（--account 換成另一個 keystore）")
    if state.get("requester") and state["requester"] != me:
        raise ChainError(f"先前的委託由 {state['requester']} 送出，這一步要用同一個錢包")
    fee = parse_mec(args.fee)
    bal, need = sess.client.balance(me), fee * len(todo) + GAS_MARGIN_WEI
    if bal < need:
        print(f"委託人 {me}（{to_me1(me)}）餘額 {format_mec(bal)}，需要約 {format_mec(need)}。")
        print(f"請到水龍頭領取測試幣：{sess.net.faucet or '（這個網路沒有水龍頭）'}（貼上 me1 地址）")
        return 3
    state.update(network=sess.net.name, auditor=auditor, requester=me, source=rel, file=src.name, sourceHash=h,
                 contract=args.contract or src.stem, ctorArgs=args.ctor_args)
    if args.note:
        state["note"] = args.note
    state["requests"] = reqs
    _save(path, state)
    taken = {int(r["id"]) for r in reqs.values()}
    for slot, ttl in todo:
        out = _adopt_request(sess, state, me, ttl, taken) or escrow.request(sess, h, auditor, fee, ttl)
        out["ttl"] = ttl
        reqs[slot] = out
        taken.add(int(out["id"]))
        _save(path, state)
        what = "稽核者會用紀錄結算" if slot == "paid" else "稽核者不處理，示範逾期退款"
        print(f"委託 #{out['id']}（{what}）：鎖住 {format_mec(int(out['fee_wei']))}，期限 {_ts(out['deadline'])}（UTC+8）"
              + ("；沿用先前中斷時已送出的委託" if out.get("reused") else "")
              + f"\n  交易 {out['tx']}" + _url(sess, out["tx"], out.get("cosmosTx")))
    return 0


def _identical_record(sess: Session, plan, auditor: str, req_id: int) -> dict | None:
    """The record a stopped run already registered: same auditor and fields, after the request."""
    reg = sess.registry
    rid = reg.latest_record(auditor, plan.input["sourceHash"])
    if not rid or rid < int(sess.escrow.get(req_id)["minRecordId"]):
        return None
    rec = reg.record(rid)
    if any(str(rec[k]).lower() != str(v).lower() for k, v in plan.input.items()):
        return None
    log = reg.find_event_tx(EVENT_REGISTERED, rid)
    tx = log["transactionHash"] if log else None
    return {"id": rid, "tx": tx, "block": int(str(log["blockNumber"]), 0) if log else None, "auditor": auditor,
            "cosmosTx": sess.client.cosmos_tx_hash(tx) if tx else None, "reused": True}


def step_settle(sess: Session, args: argparse.Namespace, state: dict, path: Path) -> int:
    reqs = state.get("requests") or {}
    if "paid" not in reqs:
        raise ChainError("還沒有委託：先由委託人跑 two-party request")
    paid = int(reqs["paid"]["id"])
    if state.get("record") and state.get("settle"):
        print(f"紀錄 #{state['record']['id']} 已登錄並結算委託 #{paid}，跳過。")
        return 0
    if not state.get("record") and not args.gate:
        raise ChainError("加上 --gate <gate.json>：ARBITER Gate 對這份原始碼的稽核結果")
    me = _signer(sess, args).address.lower()
    if me != state["auditor"]:
        raise ChainError(f"這一步要用委託指定的稽核者 {state['auditor']} 送出（現在是 {me}）")
    if not state.get("record"):
        gate = load_gate(Path(args.gate))
        bundle = args.evidence_root / FOLDER
        base = _evidence_base()
        plan = plan_record(gate, _source(state), out_dir=bundle, contract=state["contract"],
                           ctor_args=state["ctorArgs"], evidence_uri=f"{base}/{FOLDER}" if base else "",
                           tool_commit_override=args.tool_commit, evm_version=sess.net.evm_version)
        if str(plan.input["sourceHash"]).lower() != state["sourceHash"]:
            raise ChainError("gate.json 稽核的原始碼和委託的 sourceHash 不同")
        reg = _identical_record(sess, plan, me, paid)
        if not reg:
            deploy.check_escrow_request(sess, paid, plan)
            reg = deploy.register_record(sess, plan)
        state["record"] = {**reg, "verdict": plan.verdict, "input": plan.input,
                           "gate": gate_info(plan.gate, plan.entry), "bundle": demo._rel(bundle)}
        _save(path, state)
        print(f"紀錄 #{reg['id']}：判定 {plan.verdict}（{VERDICT_LABELS[plan.verdict]}）"
              + ("；沿用先前中斷時已登錄的紀錄" if reg.get("reused") else "")
              + f"\n  交易 {reg['tx']}" + _url(sess, reg["tx"], reg.get("cosmosTx")))
        for note in plan.notes:
            print(f"  注意：{note}")
    out = deploy._settle_step(sess, paid, int(state["record"]["id"]))
    if out.get("status") not in ("paid", "refunded"):
        raise ChainError(f"委託 #{paid} 沒有結算：{out.get('settleError') or out.get('status')}（重跑同一個指令會再試）")
    if not out.get("settleTx"):  # settled by a run that stopped before saving
        out["settleTx"] = _event_tx(sess, sess.escrow.address, EVENT_SETTLED, paid)
        out["cosmosTx"] = sess.client.cosmos_tx_hash(out["settleTx"]) if out["settleTx"] else None
        out.setdefault("recipient", me if out["status"] == "paid" else state["requester"])
    state["settle"] = out
    _save(path, state)
    word = "付給稽核者" if out["status"] == "paid" else "退回委託人（判定 0：稽核沒有完成）"
    print(f"委託 #{paid}：{format_mec(int(out['fee_wei']))} {word}"
          + (f"\n  交易 {out['settleTx']}" + _url(sess, out["settleTx"], out.get("cosmosTx")) if out.get("settleTx") else ""))
    return 0


def step_deploy(sess: Session, args: argparse.Namespace, state: dict, path: Path) -> int:
    rec = state.get("record")
    if not rec:
        raise ChainError("還沒有稽核紀錄：先由稽核者跑 two-party settle")
    if (state.get("deploy") or {}).get("status") in ("deployed", "blocked"):
        print(f"紀錄 #{rec['id']} 的部署已經做過（{state['deploy']['status']}），跳過。")
        return 0
    me = _signer(sess, args).address.lower()
    if me != state["requester"]:
        raise ChainError(f"這一步要用委託人 {state['requester']} 送出：示範的是開發者用稽核者的紀錄自己部署")
    out = deploy.deploy_existing(sess, int(rec["id"]), _source(state), state["contract"], state["ctorArgs"],
                                 record_refusal=True)
    out["deployer"] = me
    state["deploy"] = out
    _save(path, state)
    if out["status"] == "deployed":
        print(f"紀錄 #{rec['id']}：委託人經由登錄合約部署到 {out['address']}（LINK_GATED）"
              + (f"\n  交易 {out['tx']}" + _url(sess, out["tx"], out.get("cosmosTx")) if out.get("tx") else ""))
        return 0
    if out["status"] == "blocked":
        print(f"紀錄 #{rec['id']} 不能部署：{out['reason']}" + (f"\n  被拒絕的交易 {out['tx']}" if out.get("tx") else ""))
        return 0
    print(f"部署失敗：{out['reason']}（重跑同一個指令會再試）")
    return 1


def step_refund(sess: Session, args: argparse.Namespace, state: dict, path: Path) -> int:
    reqs = state.get("requests") or {}
    if "expire" not in reqs:
        raise ChainError("還沒有委託：先由委託人跑 two-party request")
    rid = int(reqs["expire"]["id"])
    if state.get("refund"):
        print(f"委託 #{rid} 已經退款，跳過。")
        return 0
    esc = sess.escrow
    q = esc.get(rid)
    if q["status"] == 3:  # refunded by a run that stopped before saving, or by another account
        tx = _event_tx(sess, esc.address, EVENT_EXPIRED, rid)
        if tx:
            state["refund"] = {"id": rid, "fee_wei": str(q["fee"]), "status": "refunded", "settleTx": tx,
                               "recipient": str(q["requester"]).lower(), "cosmosTx": sess.client.cosmos_tx_hash(tx),
                               "reused": True}
            _save(path, state)
            print(f"委託 #{rid} 已經退款（交易 {tx}）。")
            return 0
    if q["status"] != 1:
        raise ChainError(f"委託 #{rid} 已經是「{REQUEST_STATUS_ZH.get(q['status'], q['status'])}」，不能逾期退款")
    earliest = int(q["deadline"]) + GRACE + 1
    now = _chain_time(sess)
    if now < earliest:
        print(f"委託 #{rid} 還不能退款：期限 {_ts(q['deadline'])} 再加 1 小時寬限，最早 {_ts(earliest)}（UTC+8）以後"
              f"（鏈上現在 {_ts(now)}）。")
        return 1
    signer = _signer(sess, args)
    out = escrow.refund(sess, rid)
    out["by"] = signer.address.lower()
    state["refund"] = out
    _save(path, state)
    print(f"委託 #{rid}：{format_mec(int(out['fee_wei']))} 退回委託人 {out['recipient']}"
          f"\n  交易 {out['settleTx']}" + _url(sess, out["settleTx"], out.get("cosmosTx")))
    return 0


def _next(sess: Session, state: dict) -> str:
    reqs = state.get("requests") or {}
    if len(reqs) < 2:
        return "委託人跑 two-party request"
    if not state.get("record") or not state.get("settle"):
        return f"用 ARBITER Gate 稽核 {state['source']}，再由稽核者跑 two-party settle --gate <gate.json>"
    if (state.get("deploy") or {}).get("status") not in ("deployed", "blocked"):
        return "委託人跑 two-party deploy"
    if not state.get("refund"):
        q = sess.escrow.get(int(reqs["expire"]["id"]))
        return (f"two-party refund（委託 #{reqs['expire']['id']} 最早 {_ts(int(q['deadline']) + GRACE + 1)}（UTC+8）"
                "以後能退款）")
    return "全部完成"


def step_status(sess: Session, state: dict) -> int:
    if not state:
        print("還沒有開始。第一步（委託人）：python3 me/me.py two-party request --account <委託人 keystore> --source <原始碼>")
        return 0
    lines = [f"稽核者 {state['auditor']}", f"委託人 {state['requester']}",
             f"原始碼 {state['source']}（sha256 {state['sourceHash']}）"]
    for slot, label in (("paid", "稽核者結算"), ("expire", "逾期退款")):
        r = (state.get("requests") or {}).get(slot)
        if r:
            q = sess.escrow.get(int(r["id"]))
            lines.append(f"委託 #{r['id']}（{label}）：{REQUEST_STATUS_ZH.get(q['status'], q['status'])}，"
                         f"期限 {_ts(q['deadline'])}（UTC+8）")
    if (rec := state.get("record")):
        lines.append(f"紀錄 #{rec['id']}：判定 {rec['verdict']}（{VERDICT_LABELS[rec['verdict']]}）")
    if (d := state.get("deploy")):
        lines.append(f"部署：{d['status']}" + (f" {d['address']}" if d.get("address") else ""))
    print("\n".join(lines))
    print("下一步：" + _next(sess, state))
    return 0


# ------------------------------------------------------------------ EVIDENCE.md


def evidence_parts(sess: Session, st: dict, evidence_root: Path, tx, ad, start: int) -> dict:
    """EVIDENCE.md pieces from this demo's state: a section with its own transaction table
    (numbered after the 11/23 table, with who sent each), a contracts row, a gate.json row and
    the verify command. `tx` and `ad` are evidence_md's cell helpers."""
    reqs, rec = st.get("requests") or {}, st.get("record")
    stl, dep, ref = st.get("settle"), st.get("deploy") or {}, st.get("refund")
    name, bundle = st.get("file", "?"), evidence_root / FOLDER
    rows: list[tuple[str, str, str]] = []

    def add(t: str | None, cosmos: str | None, who: str, what: str) -> None:
        if t:
            rows.append((tx(t, cosmos)[1], who, what))

    by_req, by_aud = "委託人", "稽核者"
    paid, exp = reqs.get("paid"), reqs.get("expire")
    if paid:
        add(paid["tx"], paid.get("cosmosTx"), by_req,
            f"委託 #{paid['id']}：委託人鎖住 {format_mec(int(paid['fee_wei']))}，指定稽核者與 {name} 的 sha256，期限 7 天")
    if exp:
        add(exp["tx"], exp.get("cosmosTx"), by_req,
            f"委託 #{exp['id']}：委託人再鎖住 {format_mec(int(exp['fee_wei']))}，期限 1 小時（合約允許的最短期限）；"
            "稽核者不處理這一筆")
    if rec:
        v = rec["verdict"]
        add(rec["tx"], rec.get("cosmosTx"), by_aud,
            f"紀錄 #{rec['id']}：稽核者登錄 ARBITER Gate 對 {name} 的稽核結果，判定 {v}（{VERDICT_LABELS[v]}）；"
            "原始碼、gate.json 與建立程式碼的雜湊上鏈")
    if stl and rec and paid:
        word = ("從合約付給稽核者（判定 1、2、3 都照付，費用和結論無關）" if stl.get("status") == "paid"
                else "退回委託人（判定 0：稽核沒有完成）")
        add(stl.get("settleTx"), stl.get("cosmosTx"), by_aud,
            f"紀錄 #{rec['id']} 結算委託 #{paid['id']}：{format_mec(int(stl['fee_wei']))} {word}；"
            "只有委託指定的稽核者能結算，而且只能用委託之後登錄的紀錄")
    if dep.get("status") == "deployed":
        add(dep.get("tx"), dep.get("cosmosTx"), by_req,
            f"**委託人用紀錄 #{rec['id']} 經由部署閘門部署 {st.get('contract')}**（deployAudited）：登錄合約用 CREATE2 "
            f"把稽核過的 bytecode 部署到依「紀錄 #{rec['id']}、委託人地址、salt」事先預測的地址（LINK_GATED）")
    elif dep.get("tx"):
        add(dep["tx"], dep.get("cosmosTx"), by_req,
            f"委託人對紀錄 #{rec['id']} 呼叫 deployAudited：合約拒絕部署（{dep.get('error')}），交易失敗是預期的")
    if ref and exp:
        add(ref.get("settleTx"), ref.get("cosmosTx"), by_req if ref.get("by") == st.get("requester") else "其他帳戶",
            f"委託 #{exp['id']} 過了期限再加 1 小時寬限都沒有結算：refundExpired 把 {format_mec(int(ref['fee_wei']))} "
            "退回委託人（任何人都能送）")

    section = [
        "## 兩個錢包的託管示範",
        "",
        "上表的交易都由同一個錢包送出：委託人、稽核者、部署者是同一個地址，託管結算等於付錢給自己。"
        "這一節另用第二個錢包當委託人，合約也由它部署。兩個錢包都由我們隊伍保管，展示的是合約在兩個不同地址之間"
        "照規則運作，不代表已經有外部的委託人。",
        "",
        *([st["note"], ""] if st.get("note") else []),
        "| 角色 | 地址 |",
        "|---|---|",
        f"| 稽核者（部署資訊列出的稽核者，和上表相同） | {ad(st.get('auditor'))} |",
        f"| 委託人，也是部署合約的開發者（第二個錢包） | {ad(st.get('requester'))} |",
        "",
        "| # | EVM 交易 | 瀏覽器（Cosmos 交易） | 送出者 | 展示的功能 |",
        "|---|---|---|---|---|",
        *[f"| {i} | {cells} | {who} | {what} |" for i, (cells, who, what) in enumerate(rows, start)],
        "",
    ]
    contracts, gate_rows, verify = [], [], []
    if dep.get("status") == "deployed":
        contracts.append(f"| {st.get('contract')}（委託人部署） | {ad(dep['address'])} | 由委託人經登錄合約部署，"
                         f"鏈上可查它就是紀錄 #{rec['id']} 稽核過的 bytecode |")
    if rec:
        info, ri = demo._gate_facts(bundle, rec), demo._input(sess, rec)
        same = str(ri["gateJsonHash"]).lower() == str(info["sha256"]).lower()
        gate_rows.append(
            f"| {name}（第二個錢包委託稽核的合約） | `{info.get('gateVerdict')}` → {info['verdict']} "
            f"{VERDICT_LABELS[info['verdict']]} | {demo._when(info.get('generatedAt'))} | "
            f"{demo._commit_cell(info, str(ri['toolCommit']))} | {info.get('model') or '未記錄'} | "
            f"`{info['sha256']}`{'' if same else '（和鏈上 gateJsonHash 不同！）'} | `{demo._rel(bundle)}` |")
        target = dep["address"] if dep.get("status") == "deployed" else rec["id"]
        verify.append(f"python3 me/me.py verify {target} --network {sess.net.name} --evidence {demo._rel(bundle)} --rebuild")
    return {"section": section, "contracts": contracts, "gate_rows": gate_rows, "verify": verify}


def write_evidence(sess: Session, args: argparse.Namespace, state: dict) -> None:
    target = args.evidence_md or (ME_DIR / "EVIDENCE.md" if sess.net.name == "me-testnet" else None)
    if not target or not state:
        return
    dpath = Path(args.demo_state or demo._state_path(sess.net.name))
    if not dpath.exists():
        print(f"（沒有 {demo._rel(dpath)}，EVIDENCE.md 沒有更新）")
        return
    dstate = json.loads(dpath.read_text(encoding="utf-8"))
    Path(target).write_text(demo.evidence_md(sess, dstate, args.evidence_root, two_party=state), encoding="utf-8")
    print(f"{Path(target).name} 已更新")


# ------------------------------------------------------------------ CLI


def add_args(ap: argparse.ArgumentParser) -> None:
    sub = ap.add_subparsers(dest="tp_cmd", required=True)
    p = sub.add_parser("request", help="委託人鎖兩筆稽核費：一筆讓稽核者結算，一筆用最短期限示範逾期退款")
    p.add_argument("--source", type=Path, required=True, help="要稽核的原始碼（要在這個 repository 裡）")
    p.add_argument("--contract", help="要部署的合約名稱（預設與檔名相同）")
    p.add_argument("--ctor-args", default="0x", help="ABI 編碼後的建構子參數（hex）")
    p.add_argument("--auditor", help="指定的稽核者（預設：部署資訊列出的第一位稽核者）")
    p.add_argument("--fee", default="0.001", help="每筆委託的費用，單位 MEC（預設 0.001）")
    p.add_argument("--note", help="寫進 EVIDENCE.md 這一節的說明（例如這份合約的來源）")
    p = sub.add_parser("settle", help="稽核者登錄稽核結果，並用這筆紀錄結算第一筆委託")
    p.add_argument("--gate", type=Path, help="ARBITER Gate 對這份原始碼的 gate.json")
    p.add_argument("--tool-commit", help="產生結果的 ARBITER Gate git commit（預設讀 gate.json）")
    sub.add_parser("deploy", help="委託人用稽核者的紀錄經由登錄合約部署（deployAudited）")
    sub.add_parser("refund", help="第二筆委託過了期限再加 1 小時寬限：把費用退回委託人（任何人都能送）")
    sub.add_parser("status", help="目前進度與下一步（不送交易）")
    for p in sub.choices.values():
        add_network_args(p)
        p.add_argument("--state", type=Path, help=argparse.SUPPRESS)
        p.add_argument("--demo-state", type=Path, help=argparse.SUPPRESS)
        p.add_argument("--evidence-md", type=Path, help=argparse.SUPPRESS)
        p.add_argument("--evidence-root", type=Path, default=demo.EVIDENCE_DIR, help=argparse.SUPPRESS)


STEPS = {"request": step_request, "settle": step_settle, "deploy": step_deploy, "refund": step_refund}


def run(args: argparse.Namespace) -> int:
    quiet = argparse.Namespace(**{**vars(args), "account": None, "dev": False})
    sess = open_session(quiet, need_deployment=True)
    path = args.state or state_path(sess.net.name)
    state = load_state(path)
    try:
        if args.tp_cmd == "status":
            return step_status(sess, state)
        before = json.dumps(state, sort_keys=True)
        code = STEPS[args.tp_cmd](sess, args, state, path)
        if json.dumps(state, sort_keys=True) != before:
            write_evidence(sess, args, state)
        return code
    finally:
        sess.close()
