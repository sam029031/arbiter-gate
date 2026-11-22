"""Pay for an audit in MEC through AuditEscrow: request, settle, refund, status.

The fee is released by a registry record for the same source hash, by the auditor the
requester named: paid for any finished verdict (1, 2 or 3), refunded for verdict 0 or when
no record settles it before the deadline. The fee never depends on which verdict it was.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
from pathlib import Path

from .chain import ChainError, format_mec, parse_mec
from .contracts import REQUEST_STATUS, REQUEST_STATUS_ZH
from .record import sha256_hex
from .session import Session, add_network_args, open_session

DEFAULT_TTL = 7 * 24 * 3600


def _escrow(sess: Session):
    esc = sess.escrow
    if not esc:
        raise ChainError("部署資訊裡沒有 AuditEscrow")
    return esc


def request(sess: Session, source_hash: str, auditor: str, fee_wei: int, ttl: int = DEFAULT_TTL) -> dict:
    esc = _escrow(sess)
    receipt = sess.send(esc.address, esc.request_data(source_hash, auditor, ttl), value=fee_wei)
    ev = esc.requested(receipt)
    if not ev:
        raise ChainError(f"委託交易沒有 Requested 事件：{receipt['transactionHash']}")
    return {"id": ev[0]["id"], "fee_wei": str(ev[0]["fee"]), "status": "open", "deadline": ev[0]["deadline"],
            "tx": receipt["transactionHash"], "cosmosTx": sess.client.cosmos_tx_hash(receipt["transactionHash"])}


def settle(sess: Session, req_id: int, record_id: int) -> dict:
    """BRIEF 4.2 escrow_request shape: {id, fee_wei, status, settleTx}."""
    esc = _escrow(sess)
    receipt = sess.send(esc.address, esc.settle_data(req_id, record_id))
    ev = esc.settled(receipt)
    if not ev:
        raise ChainError(f"結算交易沒有 Settled 事件：{receipt['transactionHash']}")
    return {"id": req_id, "fee_wei": str(ev[0]["amount"]), "status": "refunded" if ev[0]["refunded"] else "paid",
            "settleTx": receipt["transactionHash"], "recordId": record_id, "recipient": ev[0]["recipient"],
            "cosmosTx": sess.client.cosmos_tx_hash(receipt["transactionHash"])}


def refund(sess: Session, req_id: int) -> dict:
    esc = _escrow(sess)
    receipt = sess.send(esc.address, esc.refund_data(req_id))
    ev = esc.expired(receipt)
    if not ev:
        raise ChainError(f"退款交易沒有 Expired 事件：{receipt['transactionHash']}")
    return {"id": req_id, "fee_wei": str(ev[0]["amount"]), "status": "refunded",
            "settleTx": receipt["transactionHash"], "recipient": ev[0]["requester"],
            "cosmosTx": sess.client.cosmos_tx_hash(receipt["transactionHash"])}


def status(sess: Session, req_id: int) -> dict:
    q = _escrow(sess).get(req_id)
    q["statusName"] = REQUEST_STATUS.get(q["status"], "?")
    q["fee_wei"] = str(q.pop("fee"))
    return q


def _text(q: dict) -> str:
    ts = lambda s: _dt.datetime.fromtimestamp(s, _dt.timezone(_dt.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M")  # noqa: E731
    lines = [f"委託 #{q['id']}：{REQUEST_STATUS_ZH.get(q['status'], q['status'])}",
             f"  委託人    {q['requester']}", f"  稽核者    {q['auditor']}",
             f"  原始碼    sha256 {q['sourceHash']}", f"  費用      {format_mec(int(q['fee_wei']))}",
             f"  期限      {ts(q['deadline'])}（UTC+8）"]
    if q.get("recordId"):
        lines.append(f"  結算紀錄  #{q['recordId']}")
    return "\n".join(lines)


def add_args(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("request", help="付費委託稽核（鎖住費用）")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--source", type=Path, help="要稽核的原始碼檔案（算 sha256）")
    g.add_argument("--source-hash", help="原始碼的 sha256（0x…）")
    p.add_argument("--auditor", required=True, help="指定的稽核者地址（0x…）")
    p.add_argument("--fee", required=True, help="費用，單位 MEC（例如 0.01）")
    p.add_argument("--ttl", type=int, default=DEFAULT_TTL, help="期限秒數（1 小時到 30 天，預設 7 天）")
    p = sub.add_parser("settle", help="用登錄紀錄結算委託（任何人都可以送）")
    p.add_argument("request_id", type=int)
    p.add_argument("record_id", type=int)
    p = sub.add_parser("refund", help="委託到期還沒結算：退款給委託人")
    p.add_argument("request_id", type=int)
    p = sub.add_parser("status", help="查詢委託狀態")
    p.add_argument("request_id", type=int)
    for p in sub.choices.values():
        add_network_args(p)
        p.add_argument("--json", action="store_true", help="輸出 JSON")


def run(args: argparse.Namespace) -> int:
    sess = open_session(args, need_deployment=True, need_signer=args.escrow_cmd != "status")
    try:
        if args.escrow_cmd == "request":
            src = args.source_hash or sha256_hex(Path(args.source).read_bytes())
            out = request(sess, src, args.auditor, parse_mec(args.fee), args.ttl)
        elif args.escrow_cmd == "settle":
            out = settle(sess, args.request_id, args.record_id)
        elif args.escrow_cmd == "refund":
            out = refund(sess, args.request_id)
        else:
            out = status(sess, args.request_id)
    finally:
        sess.close()
    if args.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    elif args.escrow_cmd == "status":
        print(_text(out))
    else:
        url = sess.net.tx_url(out.get("tx") or out.get("settleTx"), out.get("cosmosTx"))
        words = {"open": "已建立，等待稽核", "paid": "已付款給稽核者", "refunded": "已退款給委託人"}
        print(f"委託 #{out['id']}：{words[out['status']]}，{format_mec(int(out['fee_wei']))}"
              f"\n  交易 {out.get('tx') or out.get('settleTx')}" + (f"\n  {url}" if url else ""))
    return 0
