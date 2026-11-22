"""What every ME command shares: network, deployment file, signer, and a checked send."""
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from .chain import ANVIL_DEV_KEYS, ChainError, Client, DevKeySigner, KeystoreSigner, Signer, network
from .contracts import Escrow, Registry, load_deployment, revert_text, simulate


@dataclass
class Session:
    client: Client
    deployment: dict | None = None
    signer: Signer | None = None

    @property
    def net(self):
        return self.client.network

    @property
    def registry(self) -> Registry:
        if not self.deployment:
            raise ChainError(f"{self.net.name} 沒有部署資訊（me/deployments/{self.net.name}.json）")
        return Registry(self.client, self.deployment["registry"]["address"])

    @property
    def escrow(self) -> Escrow | None:
        esc = (self.deployment or {}).get("escrow")
        return Escrow(self.client, esc["address"]) if esc else None

    def require_signer(self) -> Signer:
        if not self.signer:
            raise ChainError("這一步要送交易：加上 --account <keystore 名稱>（anvil 用 --dev）")
        return self.signer

    def send(self, to: str, data: str, value: int = 0) -> dict:
        """Simulate first so a revert is reported with its decoded reason, then send."""
        signer = self.require_signer()
        ok, _, err = simulate(self.client, to, data, sender=signer.address, value=value)
        if not ok:
            raise ChainError(revert_text(err))
        return signer.send(self.client, to, data, value=value)

    def close(self) -> None:
        if self.signer:
            self.signer.close()


def add_network_args(ap: argparse.ArgumentParser, signer: bool = True) -> None:
    ap.add_argument("--network", default="me-testnet", help="me-testnet（預設）或 anvil")
    ap.add_argument("--rpc", help="改用這個 RPC URL（例如 anvil 的 http://127.0.0.1:8720）")
    ap.add_argument("--deployments", type=Path, help="部署資訊檔（預設 me/deployments/<network>.json）")
    if signer:
        g = ap.add_mutually_exclusive_group()
        g.add_argument("--account", help="Foundry keystore 名稱（~/.foundry/keystores/<名稱>），密碼只問一次")
        g.add_argument("--dev", action="store_true", help="anvil 專用：使用 anvil 公開的測試金鑰")
        ap.add_argument("--dev-key", type=int, default=0, choices=range(len(ANVIL_DEV_KEYS)),
                        help="--dev 時用第幾個 anvil 測試帳號（0 或 1）")


def open_session(args: argparse.Namespace, need_deployment: bool = True, need_signer: bool = False) -> Session:
    client = Client(network(args.network, getattr(args, "rpc", None)))
    client.check_network()
    deployment = None
    path = getattr(args, "deployments", None)
    if need_deployment:
        deployment = load_deployment(client.network.name, path)
    elif path and Path(path).exists():
        deployment = json.loads(Path(path).read_text())
    signer: Signer | None = None
    if getattr(args, "dev", False):
        signer = DevKeySigner(client, ANVIL_DEV_KEYS[getattr(args, "dev_key", 0)])
    elif getattr(args, "account", None):
        signer = KeystoreSigner(args.account)
    if need_signer and not signer:
        raise ChainError("這一步要送交易：加上 --account <keystore 名稱>（anvil 用 --dev）")
    return Session(client=client, deployment=deployment, signer=signer)
