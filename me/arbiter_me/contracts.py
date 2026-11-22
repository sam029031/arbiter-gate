"""Build, deploy and address the ME contracts (AuditRegistry, AuditEscrow).

Deployment addresses live in me/deployments/<network>.json so every tool (CLI, web card,
static verify page) reads the same file. Its optional "auditors" list names the addresses
the deployer vouches for; `verify` shows whether a record's auditor is one of them.
"""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
from pathlib import Path

from . import abi
from .chain import ZERO32, ChainError, Client, RpcError, Signer, find_tool

ME_DIR = Path(__file__).resolve().parent.parent
CONTRACTS_DIR = ME_DIR / "contracts"
DEPLOYMENTS_DIR = ME_DIR / "deployments"

# Solidity signatures used by the tools (kept next to the code that uses them).
RECORD_INPUT_TUPLE = "(bytes32,bytes32,uint8,uint8,uint8,bytes32,bytes32,bytes32,uint256,bytes20,string,string)"
RECORD_TUPLE = f"({RECORD_INPUT_TUPLE},address,uint64,address,bytes32,uint8)"
REQUEST_TUPLE = "(address,address,bytes32,uint128,uint64,uint64,uint8,uint256,uint256)"
SIG = {
    "register": f"register({RECORD_INPUT_TUPLE})",
    "getRecord": f"getRecord(uint256)({RECORD_TUPLE})",
    "recordCount": "recordCount()(uint256)",
    "recordsBySource": "recordsBySource(bytes32)(uint256[])",
    "recordsByCodehash": "recordsByCodehash(bytes32)(uint256[])",
    "childrenOf": "childrenOf(uint256)(uint256[])",
    "deploymentOf": "deploymentOf(address)(uint256)",
    "predictAddress": "predictAddress(uint256,address,bytes32)(address)",
    "claimsOf": "claimsOf(address)(uint256[])",
    "deploymentsOf": "deploymentsOf(uint256)(address[])",
    "recordsByInitcode": "recordsByInitcode(bytes32)(uint256[])",
    "latestRecord": "latestRecord(address,bytes32)(uint256)",
    "isLinkCurrent": "isLinkCurrent(uint256)(bool)",
    "deployAudited": "deployAudited(uint256,bytes,bytes32)",
    "linkDeployment": "linkDeployment(uint256,address)",
    "escrow.request": "request(bytes32,address,uint64)",
    "escrow.settle": "settle(uint256,uint256)",
    "escrow.refundExpired": "refundExpired(uint256)",
    "escrow.getRequest": f"getRequest(uint256)({REQUEST_TUPLE})",
    "escrow.settledBy": "settledBy(uint256)(uint256)",
    "escrow.requestCount": "requestCount()(uint256)",
}
EVENT_REGISTERED = "Registered(uint256,bytes32,address,uint8,uint256)"
EVENT_LINKED = "Linked(uint256,address,bytes32,uint8)"
EVENT_REQUESTED = "Requested(uint256,address,address,bytes32,uint256,uint64)"
EVENT_SETTLED = "Settled(uint256,uint256,address,uint256,bool)"
EVENT_EXPIRED = "Expired(uint256,address,uint256)"

RECORD_FIELDS = ("sourceHash", "initcodeHash", "verdict", "predicateClass", "evidenceTier", "gateJsonHash",
                 "exploitHash", "patchHash", "parentId", "toolCommit", "model", "evidenceURI")
REQUEST_FIELDS = ("requester", "auditor", "sourceHash", "fee", "createdAt", "deadline", "status", "minRecordId",
                  "recordId")

VERDICT_LABELS = {0: "無法判定（稽核未完成）", 1: "未發現可證明攻擊（不等於安全）",
                  2: "靜態工具提示但未證實", 3: "已證實可攻擊"}
PRED_LABELS = {0: "無", 1: "寬鬆條件（攻擊者獲利 / 狀態改變）", 2: "嚴格條件（受害者損失 / 功能被破壞）"}
LINK_LABELS = {0: "尚未連結部署", 1: "稽核者自行宣告的位址（LINK_CLAIMED）",
               2: "由登錄合約部署稽核過的 bytecode（LINK_GATED）"}
REQUEST_STATUS = {0: "none", 1: "open", 2: "paid", 3: "refunded"}
REQUEST_STATUS_ZH = {0: "不存在", 1: "等待稽核", 2: "已付款給稽核者", 3: "已退款給委託人"}

# Custom errors of both contracts, plus Solidity's built-ins.
_ERRORS = {
    "Error": ["string"], "Panic": ["uint256"],
    "ZeroSourceHash": [], "OutOfRange": [], "InconsistentProof": [], "BadParent": [], "TooLong": [],
    "BadURI": [], "ContradictsProvenRecord": [], "RecordTooOld": [],
    "UnknownRecord": ["uint256"], "NotAuditor": [], "AlreadyLinked": [], "NotDeployable": ["uint8"],
    "NoCode": [], "InitcodeMismatch": [], "AddressTaken": [], "DeployFailed": [],
    "NoFee": [], "FeeTooLarge": [], "ZeroAuditor": [], "BadTtl": [], "UnknownRequest": ["uint256"],
    "NotOpen": [], "WrongAuditor": [], "WrongSource": [], "OutsideWindow": [], "RecordAlreadyUsed": ["uint256"],
    "NotExpired": [], "TransferFailed": [],
}
ERRORS = {abi.selector(f"{n}({','.join(t)})"): (n, t) for n, t in _ERRORS.items()}

_ERROR_ZH = {
    "NotDeployable": lambda a: f"登錄合約拒絕部署：這筆紀錄的判定是 {a[0]}（{VERDICT_LABELS.get(a[0], '?')}）",
    "InitcodeMismatch": lambda a: "要部署的 bytecode 和紀錄裡的 initcodeHash 不同",
    "AlreadyLinked": lambda a: "這筆紀錄已經連結過部署位址",
    "UnknownRecord": lambda a: f"沒有編號 {a[0]} 的紀錄",
    "AddressTaken": lambda a: "預測的部署位址已經有程式碼",
    "InconsistentProof": lambda a: "紀錄內容不一致（已證實可攻擊才能帶攻擊程式雜湊）",
    "BadParent": lambda a: "上一版紀錄不存在、不是同一位稽核者登錄的、和這筆是同一份原始碼，或沒有附修補檔雜湊",
    "BadURI": lambda a: "證據網址只能是空的或 https:// 開頭的一般網址",
    "ContradictsProvenRecord": lambda a: "同一位稽核者已把這份 bytecode 登錄為「已證實可攻擊」，不能經由閘門部署",
    "RecordTooOld": lambda a: "這筆紀錄比委託早登錄，不能用來結算",
    "NotAuditor": lambda a: "只有紀錄（或委託）指定的稽核者能做這件事",
    "TooLong": lambda a: "模型名稱或證據網址太長",
    "WrongAuditor": lambda a: "紀錄的稽核者不是委託指定的稽核者",
    "WrongSource": lambda a: "紀錄的原始碼雜湊和委託不同",
    "OutsideWindow": lambda a: "紀錄的登錄時間不在委託期間內，或已過結算期限（期限後 1 小時）",
    "RecordAlreadyUsed": lambda a: f"這筆紀錄已經結算過委託 #{a[0]}",
    "NotExpired": lambda a: "委託還沒過期（期限後再等 1 小時的結算寬限），不能退款",
    "NotOpen": lambda a: "委託已經結算或退款",
    "UnknownRequest": lambda a: f"沒有編號 {a[0]} 的委託",
    "Error": lambda a: f"合約回傳錯誤：{a[0]}",
}


def decode_revert(data: str | None) -> tuple[str, list] | None:
    """Revert bytes -> (error name, args), or None when unknown/empty."""
    if not data or len(data) < 10:
        return None
    hit = ERRORS.get(data[:10].lower())
    if not hit:
        return None
    name, types = hit
    try:
        return name, abi.decode(types, "0x" + data[10:])
    except ValueError:
        return name, []


def revert_text(err: tuple[str, list] | None) -> str:
    if not err:
        return "交易會失敗（原因無法解碼）"
    name, args = err
    sig = f"{name}({', '.join(map(str, args))})"
    zh = _ERROR_ZH.get(name)
    return f"{zh(args)}（{sig}）" if zh else sig


def simulate(client: Client, to: str | None, data: str, sender: str | None = None,
             value: int = 0) -> tuple[bool, str | None, tuple[str, list] | None]:
    """eth_call a write. Returns (ok, return data, decoded revert)."""
    try:
        return True, client.call(to, data, sender=sender, value=value), None
    except RpcError as exc:
        if exc.data is None and "revert" not in exc.message.lower():
            raise
        return False, None, decode_revert(exc.data)


def view(client: Client, to: str, sig: str, *args, out: list[str]) -> list:
    """A view call whose revert (UnknownRecord, UnknownRequest, ...) is reported in words."""
    try:
        return client.view(to, sig, *args, out=out)
    except RpcError as exc:
        if exc.data is None and "revert" not in exc.message.lower():
            raise
        raise ChainError(revert_text(decode_revert(exc.data))) from None


# ------------------------------------------------------------------ build and deploy


def forge_build() -> None:
    proc = subprocess.run([find_tool("forge"), "build"], cwd=CONTRACTS_DIR, capture_output=True, text=True)
    if proc.returncode != 0:
        raise ChainError("forge build failed:\n" + proc.stdout[-2000:] + proc.stderr[-2000:])


def artifact(name: str) -> dict:
    path = CONTRACTS_DIR / "out" / f"{name}.sol" / f"{name}.json"
    if not path.exists():
        forge_build()
    return json.loads(path.read_text())


def creation_code(name: str) -> str:
    return artifact(name)["bytecode"]["object"]


def escrow_ctor_args(registry: str) -> str:
    """abi.encode(registry): AuditEscrow's only constructor argument, 0x-hex."""
    return "0x" + abi.encode(["address"], [registry]).hex()


def artifact_runtime(name: str, immutables: dict[str, str] | None = None) -> str:
    """The artifact's deployed bytecode with every immutable slot filled the way the
    constructor fills it. `immutables` maps the AST id of each immutable to its 32-byte value
    (0x-hex); AuditEscrow has one, `registry`, so `{"*": <word>}` fills all slots."""
    dep = artifact(name)["deployedBytecode"]
    code = bytearray(abi.hexbytes(dep["object"]))
    for ast_id, refs in (dep.get("immutableReferences") or {}).items():
        value = (immutables or {}).get(ast_id, (immutables or {}).get("*"))
        if value is None:
            raise ChainError(f"{name}：immutable {ast_id} 沒有給值")
        word = abi.hexbytes(value).rjust(32, b"\0")
        for r in refs:
            code[r["start"]:r["start"] + r["length"]] = word[-r["length"]:]
    return "0x" + code.hex()


def expected_runtime_hash(name: str, registry: str | None = None) -> str:
    """keccak256 of the runtime code a correct deployment of `name` has on chain: the
    artifact's deployed bytecode (AuditEscrow: with the registry address in its immutable)."""
    return abi.keccak_hex(artifact_runtime(name, {"*": escrow_ctor_args(registry)} if registry else None))


def deployments_path(network: str) -> Path:
    return DEPLOYMENTS_DIR / f"{network}.json"


def load_deployment(network: str, path: Path | None = None) -> dict:
    path = path or deployments_path(network)
    if not path.exists():
        raise ChainError(f"{network} 還沒有部署合約：先執行 `python3 me/me.py contracts deploy --network {network}`")
    return json.loads(path.read_text())


def _created(client: Client, receipt: dict) -> dict:
    address = receipt["contractAddress"]
    return {"address": address, "tx": receipt["transactionHash"], "block": int(str(receipt["blockNumber"]), 0),
            "codehash": client.code_hash(address)}


def deploy_registry(client: Client, signer: Signer) -> dict:
    """Plain CREATE of AuditRegistry (a registry cannot be deployed through itself)."""
    client.check_network()
    forge_build()
    reg_code = creation_code("AuditRegistry")
    # ME compatibility preflight: the node simulates the creation before we pay for it
    client.estimate_gas(None, reg_code, sender=signer.address)
    return _created(client, signer.send(client, None, reg_code))


def deploy_escrow(client: Client, signer: Signer, registry: str) -> dict:
    """Plain CREATE of AuditEscrow(registry)."""
    forge_build()
    return _created(client, signer.send(client, None, creation_code("AuditEscrow") + escrow_ctor_args(registry)[2:]))


def write_deployment(client: Client, signer: Signer, registry: dict, escrow: dict,
                     out_path: Path | None = None) -> dict:
    net = client.network
    data = {
        "network": net.name,
        "chainId": net.chain_id,
        "rpc": net.rpc,
        "explorer": net.explorer,
        "deployer": signer.address,
        "auditors": [signer.address],
        "registry": registry,
        "escrow": escrow,
        "compiler": {"solc": "0.8.24", "evm_version": "paris", "optimizer_runs": 200, "metadata": "none"},
        "deployedAt": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    }
    out_path = out_path or deployments_path(net.name)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2) + "\n")
    return data


def deploy_contracts(client: Client, signer: Signer, out_path: Path | None = None) -> dict:
    """Deploy AuditRegistry then AuditEscrow(registry), both plain CREATE; write the deployment file."""
    registry = deploy_registry(client, signer)
    escrow = deploy_escrow(client, signer, registry["address"])
    return write_deployment(client, signer, registry, escrow, out_path)


# ------------------------------------------------------------------ typed access


def _logs(receipt: dict, address: str, event: str) -> list[dict]:
    t0 = abi.topic(event)
    return [lg for lg in receipt.get("logs") or []
            if lg["address"].lower() == address.lower() and lg["topics"] and lg["topics"][0].lower() == t0]


def _topic_int(t: str) -> int:
    return int(t, 16)


def _topic_addr(t: str) -> str:
    return "0x" + t[-40:].lower()


class Registry:
    def __init__(self, client: Client, address: str):
        self.client, self.address = client, address

    def _view(self, sig: str, *args, out: list[str]):
        return view(self.client, self.address, sig, *args, out=out)

    def record_count(self) -> int:
        return self._view("recordCount()", out=["uint256"])[0]

    def record(self, rid: int) -> dict:
        (r,) = self._view("getRecord(uint256)", rid, out=[RECORD_TUPLE])
        inp, auditor, ts, deployed, runtime_hash, link = r
        rec = dict(zip(RECORD_FIELDS, inp))
        rec.update(id=rid, auditor=auditor, timestamp=ts, deployed=None if int(deployed, 16) == 0 else deployed,
                   runtimeCodeHash=None if runtime_hash == ZERO32 else runtime_hash, linkKind=link)
        return rec

    def records_by_source(self, source_hash: str) -> list[int]:
        return self._view("recordsBySource(bytes32)", source_hash, out=["uint256[]"])[0]

    def records_by_codehash(self, code_hash: str) -> list[int]:
        return self._view("recordsByCodehash(bytes32)", code_hash, out=["uint256[]"])[0]

    def children(self, rid: int) -> list[int]:
        return self._view("childrenOf(uint256)", rid, out=["uint256[]"])[0]

    def deployment_of(self, address: str) -> int:
        """Record that deployed `address` through deployAudited (gated only), or 0."""
        return self._view("deploymentOf(address)", address, out=["uint256"])[0]

    def claims_of(self, address: str) -> list[int]:
        """Records whose auditor claimed `address` with linkDeployment (unverified claims)."""
        return self._view("claimsOf(address)", address, out=["uint256[]"])[0]

    def deployments_of(self, rid: int) -> list[str]:
        return self._view("deploymentsOf(uint256)", rid, out=["address[]"])[0]

    def records_by_initcode(self, initcode_hash: str) -> list[int]:
        return self._view("recordsByInitcode(bytes32)", initcode_hash, out=["uint256[]"])[0]

    def latest_record(self, auditor: str, source_hash: str) -> int:
        return self._view("latestRecord(address,bytes32)", auditor, source_hash, out=["uint256"])[0]

    def is_link_current(self, rid: int) -> bool:
        return self._view("isLinkCurrent(uint256)", rid, out=["bool"])[0]

    def predict(self, rid: int, caller: str, salt: str) -> str:
        """Address deployAudited(rid, initcode, salt) sent by `caller` produces (v2: bound to the
        record id and the caller, so nobody can take someone else's planned address)."""
        return self._view("predictAddress(uint256,address,bytes32)", rid, caller, salt, out=["address"])[0]

    @staticmethod
    def register_data(inp: dict) -> str:
        return abi.encode_call(SIG["register"], [inp[k] for k in RECORD_FIELDS])

    @staticmethod
    def deploy_data(rid: int, initcode: str, salt: str) -> str:
        return abi.encode_call(SIG["deployAudited"], rid, initcode, salt)

    @staticmethod
    def link_data(rid: int, deployed: str) -> str:
        return abi.encode_call(SIG["linkDeployment"], rid, deployed)

    def registered(self, receipt: dict) -> list[dict]:
        out = []
        for lg in _logs(receipt, self.address, EVENT_REGISTERED):
            verdict, parent = abi.decode(["uint8", "uint256"], lg["data"])
            out.append({"id": _topic_int(lg["topics"][1]), "sourceHash": lg["topics"][2].lower(),
                        "auditor": _topic_addr(lg["topics"][3]), "verdict": verdict, "parentId": parent,
                        "tx": lg.get("transactionHash"), "block": int(str(lg.get("blockNumber") or "0x0"), 0)})
        return out

    def linked(self, receipt: dict) -> list[dict]:
        out = []
        for lg in _logs(receipt, self.address, EVENT_LINKED):
            code_hash, kind = abi.decode(["bytes32", "uint8"], lg["data"])
            out.append({"id": _topic_int(lg["topics"][1]), "deployed": _topic_addr(lg["topics"][2]),
                        "runtimeCodeHash": code_hash, "linkKind": kind, "tx": lg.get("transactionHash"),
                        "block": int(str(lg.get("blockNumber") or "0x0"), 0)})
        return out

    def find_event_tx(self, event: str, rid: int, from_block: int = 0) -> dict | None:
        """The log of `event` for record `rid` (Registered or Linked), via eth_getLogs."""
        topic_id = "0x" + rid.to_bytes(32, "big").hex()
        logs = self.client.get_logs(self.address, [abi.topic(event), topic_id], from_block)
        return logs[0] if logs else None


class Escrow:
    def __init__(self, client: Client, address: str):
        self.client, self.address = client, address

    def request_count(self) -> int:
        return view(self.client, self.address, "requestCount()", out=["uint256"])[0]

    def get(self, req_id: int) -> dict:
        (r,) = view(self.client, self.address, "getRequest(uint256)", req_id, out=[REQUEST_TUPLE])
        return {"id": req_id, **dict(zip(REQUEST_FIELDS, r))}

    def settled_by(self, record_id: int) -> int:
        return view(self.client, self.address, "settledBy(uint256)", record_id, out=["uint256"])[0]

    @staticmethod
    def request_data(source_hash: str, auditor: str, ttl: int) -> str:
        return abi.encode_call(SIG["escrow.request"], source_hash, auditor, ttl)

    @staticmethod
    def settle_data(req_id: int, record_id: int) -> str:
        return abi.encode_call(SIG["escrow.settle"], req_id, record_id)

    @staticmethod
    def refund_data(req_id: int) -> str:
        return abi.encode_call(SIG["escrow.refundExpired"], req_id)

    def requested(self, receipt: dict) -> list[dict]:
        out = []
        for lg in _logs(receipt, self.address, EVENT_REQUESTED):
            src, fee, deadline = abi.decode(["bytes32", "uint256", "uint64"], lg["data"])
            out.append({"id": _topic_int(lg["topics"][1]), "requester": _topic_addr(lg["topics"][2]),
                        "auditor": _topic_addr(lg["topics"][3]), "sourceHash": src, "fee": fee,
                        "deadline": deadline})
        return out

    def settled(self, receipt: dict) -> list[dict]:
        out = []
        for lg in _logs(receipt, self.address, EVENT_SETTLED):
            amount, refunded = abi.decode(["uint256", "bool"], lg["data"])
            out.append({"id": _topic_int(lg["topics"][1]), "recordId": _topic_int(lg["topics"][2]),
                        "recipient": _topic_addr(lg["topics"][3]), "amount": amount, "refunded": refunded})
        return out

    def expired(self, receipt: dict) -> list[dict]:
        out = []
        for lg in _logs(receipt, self.address, EVENT_EXPIRED):
            (amount,) = abi.decode(["uint256"], lg["data"])
            out.append({"id": _topic_int(lg["topics"][1]), "requester": _topic_addr(lg["topics"][2]),
                        "amount": amount})
        return out
