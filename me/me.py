#!/usr/bin/env python3
"""ARBITER Gate × ME Network: one command for the on-chain layer.

    python3 me/me.py wallet to-me1 0x…            0x 地址轉 me1
    python3 me/me.py wallet to-0x me1…            me1 轉 0x
    python3 me/me.py wallet balance 0x…|me1…      MEC 餘額
    python3 me/me.py contracts deploy --account NAME
    python3 me/me.py preflight Contract.sol       ME 能不能部署（paris / PUSH0 檢查）
    python3 me/me.py register gate.json --source X.sol --account NAME
    python3 me/me.py deploy   gate.json --source X.sol --account NAME [--patch --parent ID]
    python3 me/me.py verify   0x…|ID|tx [--evidence DIR --rebuild --replay]
    python3 me/me.py escrow   request|settle|refund|status …
    python3 me/me.py demo --account NAME [--job DIR --rid RID]   早上的實鏈示範（me/scripts/me_live_demo.sh）
    python3 me/me.py two-party request|settle|deploy|refund|status …   兩個錢包的託管示範（委託人不是稽核者）

Every subcommand takes --network (me-testnet default, or anvil) and --rpc.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arbiter_me import deploy, escrow, verify  # noqa: E402
from arbiter_me.bech32 import to_0x, to_me1  # noqa: E402
from arbiter_me.build import compile_source, uses_push0  # noqa: E402
from arbiter_me.chain import ChainError, Client, format_mec, network  # noqa: E402
from arbiter_me.contracts import creation_code, deploy_contracts, deployments_path  # noqa: E402
from arbiter_me.session import add_network_args, open_session  # noqa: E402


def cmd_wallet(args) -> int:
    if args.wallet_cmd == "to-me1":
        print(to_me1(args.address))
    elif args.wallet_cmd == "to-0x":
        print(to_0x(args.address))
    else:
        addr = to_0x(args.address) if args.address.lower().startswith("me1") else args.address
        client = Client(network(args.network, args.rpc))
        wei = client.balance(addr)
        if args.json:
            print(json.dumps({"address": addr, "me1": to_me1(addr), "wei": str(wei), "mec": format_mec(wei)}))
        else:
            print(f"{addr}（{to_me1(addr)}）餘額 {format_mec(wei)}")
    return 0


def cmd_contracts(args) -> int:
    sess = open_session(args, need_deployment=False, need_signer=True)
    try:
        out = args.deployments or deployments_path(sess.net.name)
        if out.exists() and not args.force:
            raise ChainError(f"{out.name} 已存在（合約已部署）；確定要重新部署請加 --force")
        data = deploy_contracts(sess.client, sess.signer, out)
    finally:
        sess.close()
    net = sess.net
    print(f"AuditRegistry  {data['registry']['address']}  交易 {data['registry']['tx']}")
    print(f"AuditEscrow    {data['escrow']['address']}  交易 {data['escrow']['tx']}")
    if net.explorer:
        print(f"  {net.address_url(data['registry']['address'])}")
    print(f"部署資訊寫入 {out.name}")
    return 0


def cmd_preflight(args) -> int:
    client = Client(network(args.network, args.rpc))
    client.check_network()
    if args.target in ("AuditRegistry", "AuditEscrow"):
        code, label = creation_code(args.target), args.target
        if args.target == "AuditEscrow":
            code += "00" * 12 + "11" * 20  # any registry address; the constructor only stores it
    else:
        src = Path(args.target)
        b = compile_source(src.read_text(encoding="utf-8"), src.name, args.contract, evm_version=args.evm_version,
                           ctor_args=args.ctor_args)
        code, label = b.deploy_code, f"{b.contract}（solc {b.solc}，evm {b.evm_version}）"
    res = deploy.preflight(client, code)
    res["push0InBytecode"] = uses_push0(code)
    if args.json:
        print(json.dumps({"target": label, **res}, ensure_ascii=False))
    elif res["ok"]:
        print(f"preflight 通過：{label} 可以部署到 {client.network.name}，約 {res['gas']} gas")
    else:
        print(f"preflight 失敗：{label}\n  {res['error']}")
    return 0 if res["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="me.py", description="ARBITER Gate × ME Network 鏈上工具")
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("wallet", help="地址格式轉換與餘額")
    ws = w.add_subparsers(dest="wallet_cmd", required=True)
    for name, h in (("to-me1", "0x 地址轉 me1"), ("to-0x", "me1 地址轉 0x"), ("balance", "查 MEC 餘額")):
        p = ws.add_parser(name, help=h)
        p.add_argument("address")
        if name == "balance":
            add_network_args(p, signer=False)
            p.add_argument("--json", action="store_true")

    c = sub.add_parser("contracts", help="部署 AuditRegistry 與 AuditEscrow")
    cs = c.add_subparsers(dest="contracts_cmd", required=True)
    p = cs.add_parser("deploy", help="部署兩個合約並寫入 me/deployments/<network>.json")
    add_network_args(p)
    p.add_argument("--force", action="store_true", help="部署資訊已存在時仍重新部署")

    p = sub.add_parser("preflight", help="用節點模擬部署（eth_estimateGas），檢查 PUSH0 / paris")
    p.add_argument("target", help=".sol 檔案，或 AuditRegistry / AuditEscrow")
    p.add_argument("--contract")
    p.add_argument("--ctor-args", default="0x")
    p.add_argument("--evm-version", default="paris", help="預設 paris（ME 測試網不支援 PUSH0）")
    p.add_argument("--json", action="store_true")
    add_network_args(p, signer=False)

    deploy.add_args(sub.add_parser("register", help="只登錄稽核紀錄（不部署）"))
    deploy.add_args(sub.add_parser("deploy", help="登錄紀錄；判定 1/2 經由登錄合約部署，0/3 顯示拒絕"))
    verify.add_args(sub.add_parser("verify", help="查詢並獨立重驗鏈上紀錄"))
    e = sub.add_parser("escrow", help="MEC 付費委託：request / settle / refund / status")
    escrow.add_args(e.add_subparsers(dest="escrow_cmd", required=True))

    p = sub.add_parser("demo", help="ME 測試網實鏈示範（可重跑，已完成的步驟會跳過）")
    from arbiter_me import demo
    demo.add_args(p)
    p = sub.add_parser("two-party", help="兩個錢包的託管示範：委託人付費、稽核者結算、委託人部署、逾期退款")
    from arbiter_me import two_party
    two_party.add_args(p)

    args = ap.parse_args(argv)
    try:
        if args.cmd == "wallet":
            return cmd_wallet(args)
        if args.cmd == "contracts":
            return cmd_contracts(args)
        if args.cmd == "preflight":
            return cmd_preflight(args)
        if args.cmd in ("register", "deploy"):
            return deploy.run(args, register_only=args.cmd == "register")
        if args.cmd == "verify":
            return verify.run(args)
        if args.cmd == "escrow":
            return escrow.run(args)
        if args.cmd == "two-party":
            return two_party.run(args)
        return demo.run(args)
    except (ChainError, ValueError, FileNotFoundError) as exc:
        print(f"錯誤：{exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
