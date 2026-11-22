"""Dogfood: ARBITER Gate audited our own two contracts, and the chain says so.

    AuditRegistry  deployed with a plain CREATE (a registry cannot deploy itself through itself);
                   its audit record, then linkDeployment(record, registry) -> LINK_CLAIMED. The
                   claim is sent only after checking that the registry's on-chain codehash equals
                   the runtime hash of the Foundry artifact the record's initcodeHash comes from.
    AuditEscrow    its audit record (initcode = creation bytecode ++ abi.encode(registry)), then
                   deployAudited -> LINK_GATED: the registry deploys the exact audited bytecode.
                   Verdict 0/3 (or a refused deployAudited) -> a plain deployment, reason recorded.

The audits are me/dogfood/<Contract>.gate.json, registered byte for byte (gateJsonHash = sha256
of the file). Dropping newer audits of the same two files in place is all it takes to record
new ones. A gate.json that audited another version of the source (artifact.sha256 differs from
the file in me/contracts/src) is refused on a real network; an anvil rehearsal lets it through
with a warning, because a record must point at the source that was actually audited.

Every step here can be repeated after an interruption without sending a duplicate: a record
this auditor already registered with identical content, an existing link and an existing gated
deployment are found on chain and reused.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .build import Build
from .chain import ChainError
from .contracts import (CONTRACTS_DIR, EVENT_LINKED, EVENT_REGISTERED, ME_DIR, RECORD_FIELDS, Registry, artifact,
                        deploy_escrow, escrow_ctor_args, expected_runtime_hash, revert_text, simulate)
from .deploy import deploy_through_registry, register_record
from .record import GateInput, RecordPlan, gate_info, load_gate, plan_record, sha256_hex, stale_source
from .session import Session

DOGFOOD_DIR = ME_DIR / "dogfood"
SRC_DIR = CONTRACTS_DIR / "src"


@dataclass(frozen=True)
class SelfTarget:
    key: str  # "registry" | "escrow" (state keys, evidence folder names)
    contract: str
    imports: tuple[str, ...] = ()  # source units the file imports (siblings in me/contracts/src)

    @property
    def source(self) -> Path:
        return SRC_DIR / f"{self.contract}.sol"

    @property
    def default_gate(self) -> Path:
        return DOGFOOD_DIR / f"{self.contract}.gate.json"


TARGETS = {"registry": SelfTarget("registry", "AuditRegistry"),
           "escrow": SelfTarget("escrow", "AuditEscrow", ("AuditRegistry.sol",))}


@dataclass
class SelfInput:
    target: SelfTarget
    gate: GateInput
    entry: dict
    stale: str | None  # the sha256 the audit covered, when it is not today's source (rehearsal only)

    @property
    def info(self) -> dict:
        out = gate_info(self.gate, self.entry)
        out["source"] = f"me/contracts/src/{self.target.contract}.sol"
        out["sourceSha256"] = sha256_hex(self.target.source.read_bytes())
        out["stale"] = bool(self.stale)
        return out


def _entry(gate: GateInput, target: SelfTarget) -> dict:
    files = gate.report.get("files") or []
    want = f"{target.contract}.sol"
    hits = [e for e in files
            if Path(str((e.get("artifact") or {}).get("uri") or e.get("path") or "")).name == want]
    if len(hits) == 1:
        return hits[0]
    if len(files) == 1:
        return files[0]
    raise ChainError(f"{gate.path.name if gate.path else 'gate.json'} 裡找不到 {want} 的稽核結果")


def _shown(path: Path) -> str:
    """A path as the repository sees it (me/dogfood/...), else just its name."""
    p, root = Path(os.path.abspath(path)), Path(os.path.abspath(ME_DIR.parent))
    return p.relative_to(root).as_posix() if p.is_relative_to(root) else p.name


def load_self(target: SelfTarget, gate_path: Path | None, *, rehearsal: bool) -> SelfInput:
    """Read one dogfood audit and check it covers today's source (before anything is sent)."""
    path = Path(gate_path or target.default_gate)
    if not path.is_file():
        raise ChainError(f"找不到 {target.contract} 的稽核結果 {_shown(path)}；放入 gate.json，或加 --no-dogfood 不做自我稽核")
    gate = load_gate(path)
    entry = _entry(gate, target)
    src_sha = sha256_hex(target.source.read_bytes())
    stale = stale_source(entry, src_sha)
    if stale and not rehearsal:
        raise ChainError(f"{path.name} 稽核的是另一版 {target.contract}.sol（sha256 {stale}），不是目前的原始碼"
                         f"（{src_sha}）。紀錄必須指向被稽核的那份原始碼：請放入對目前原始碼重新稽核的 gate.json，"
                         "或加 --no-dogfood 不做自我稽核。")
    return SelfInput(target=target, gate=gate, entry=entry, stale=stale)


def plan_self(inp: SelfInput, out_dir: Path, evidence_uri: str, registry: str) -> RecordPlan:
    """The record and evidence bundle (gate.json, src/, imports/, compiler.json, manifest.json).

    initcodeHash is what will be (or was) deployed: the Foundry artifact's creation bytecode
    (plus abi.encode(registry) for the escrow). The bundle's own recipe must rebuild exactly
    those bytes, so `me.py verify --rebuild` works from the bundle alone; otherwise refuse."""
    t = inp.target
    ctor = escrow_ctor_args(registry) if t.key == "escrow" else "0x"
    plan = plan_record(inp.gate, t.source, out_dir=out_dir, file_id=inp.entry.get("id"), ctor_args=ctor,
                       evidence_uri=evidence_uri, imports={u: SRC_DIR / u for u in t.imports} or None,
                       stale_ok=bool(inp.stale))
    art = artifact(t.contract)
    if plan.build is None or plan.build.initcode != art["bytecode"]["object"] \
            or plan.build.runtime != art["deployedBytecode"]["object"]:
        raise ChainError(f"{t.contract}：證據資料夾的編譯設定重建出的 bytecode 和 Foundry 編譯產物"
                         "（me/contracts/out）不同，不能登錄")
    return plan


def artifact_build(contract: str, ctor_args: str = "0x") -> Build:
    """A Build of the Foundry artifact itself (what deploy_through_registry sends)."""
    art = artifact(contract)
    return Build(contract=contract, file_name=f"{contract}.sol", initcode=art["bytecode"]["object"],
                 runtime=art["deployedBytecode"]["object"], abi=art.get("abi", []),
                 has_immutables=bool(art["deployedBytecode"].get("immutableReferences")),
                 solc=((art.get("metadata") or {}).get("compiler") or {}).get("version", "0.8.24"),
                 evm_version="paris", ctor_args=ctor_args.lower())


def _from_block(sess: Session) -> int:
    return int(((sess.deployment or {}).get("registry") or {}).get("block") or 0)


def _tx_of(sess: Session, event: str, rid: int) -> tuple[str | None, int | None]:
    lg = sess.registry.find_event_tx(event, rid, _from_block(sess))
    if not lg:
        return None, None
    return lg["transactionHash"], int(str(lg.get("blockNumber") or "0x0"), 0)


def register_once(sess: Session, plan: RecordPlan) -> dict:
    """register(), unless this auditor's latest record for the source has exactly this content
    (the earlier run was interrupted after sending, before saving its state)."""
    reg = sess.registry
    me = sess.require_signer().address
    rid = reg.latest_record(me, plan.input["sourceHash"])
    if rid:
        rec = reg.record(rid)
        if all(str(rec[k]).lower() == str(plan.input[k]).lower() for k in RECORD_FIELDS):
            tx, block = _tx_of(sess, EVENT_REGISTERED, rid)
            return {"id": rid, "tx": tx, "block": block, "auditor": rec["auditor"],
                    "cosmosTx": sess.client.cosmos_tx_hash(tx) if tx else None, "reused": True}
    return register_record(sess, plan)


def claim(sess: Session, rid: int, address: str, expected_codehash: str, what: str) -> dict:
    """linkDeployment(rid, address) -> LINK_CLAIMED, only when the code at `address` is the
    audited build (codehash equals `expected_codehash`) and the verdict allows a link."""
    reg = sess.registry
    onchain = sess.client.code_hash(address)
    out = {"address": address.lower(), "codehash": onchain, "expectedCodehash": expected_codehash,
           "codehashMatches": onchain == expected_codehash, "tx": None, "linkKind": 0}
    rec = reg.record(rid)
    if rec["linkKind"]:  # linked already (interrupted rerun)
        tx, block = _tx_of(sess, EVENT_LINKED, rid)
        same = rec["linkKind"] == 1 and (rec["deployed"] or "").lower() == address.lower()
        out.update(status="claimed" if same else "linked_elsewhere", tx=tx, block=block, linkKind=rec["linkKind"],
                   runtimeCodeHash=rec["runtimeCodeHash"], reused=True,
                   cosmosTx=sess.client.cosmos_tx_hash(tx) if tx else None,
                   reason="" if same else f"紀錄 #{rid} 已連結到 {rec['deployed']}")
        return out
    if onchain != expected_codehash:
        out.update(status="not_claimed",
                   reason=f"{what} 鏈上的程式碼（codehash {onchain}）不是稽核過的編譯產物（{expected_codehash}），不宣告")
        return out
    if rec["verdict"] not in (1, 2):
        out.update(status="not_claimed",
                   reason=f"紀錄 #{rid} 的判定是 {rec['verdict']}：登錄合約只讓判定 1/2 的紀錄連結部署")
        return out
    data = Registry.link_data(rid, address)
    ok, _, err = simulate(sess.client, reg.address, data, sender=sess.require_signer().address)
    if not ok:
        out.update(status="not_claimed", reason=revert_text(err))
        return out
    receipt = sess.require_signer().send(sess.client, reg.address, data)
    ev = [e for e in reg.linked(receipt) if e["id"] == rid]
    if not ev:
        raise ChainError(f"宣告交易沒有 Linked 事件：{receipt['transactionHash']}")
    out.update(status="claimed", tx=receipt["transactionHash"], block=int(str(receipt["blockNumber"]), 0),
               linkKind=ev[0]["linkKind"], runtimeCodeHash=ev[0]["runtimeCodeHash"], reason="",
               cosmosTx=sess.client.cosmos_tx_hash(receipt["transactionHash"]))
    return out


def deploy_escrow_gated(sess: Session, rid: int, registry: str) -> dict:
    """deployAudited(rid, AuditEscrow initcode, salt): the registry deploys the audited escrow.
    Returns the deploy_through_registry result plus a check that the deployed runtime is the
    artifact's with the registry address in its immutable slot."""
    reg = sess.registry
    build = artifact_build("AuditEscrow", escrow_ctor_args(registry))
    expected = expected_runtime_hash("AuditEscrow", registry)
    existing = reg.deployments_of(rid)
    if existing:  # deployed already (interrupted rerun)
        addr = existing[0].lower()
        tx, block = _tx_of(sess, EVENT_LINKED, rid)
        onchain = sess.client.code_hash(addr)
        return {"status": "deployed", "reason": "", "address": addr, "tx": tx, "block": block, "linkKind": 2,
                "runtimeCodeHash": onchain, "reused": True, "checks": {"runtime_matches_artifact": onchain == expected},
                "cosmosTx": sess.client.cosmos_tx_hash(tx) if tx else None}
    dep = deploy_through_registry(sess, rid, build)
    if dep.get("address"):
        dep["checks"]["runtime_matches_artifact"] = sess.client.code_hash(dep["address"]) == expected
        if not dep["checks"]["runtime_matches_artifact"]:
            dep["status"], dep["reason"] = "failed", f"部署後檢查失敗：{dep['checks']}"
        rcpt = sess.client.receipt(dep["tx"]) or {}
        dep["block"] = int(str(rcpt.get("blockNumber") or "0x0"), 0)
    return dep


def deploy_escrow_plain(sess: Session, registry: str, reason: str) -> dict:
    """Fallback: a plain CREATE of AuditEscrow(registry), with the reason it was not gated."""
    info = deploy_escrow(sess.client, sess.require_signer(), registry)
    info.update(deployedVia="create", reason=reason, cosmosTx=sess.client.cosmos_tx_hash(info["tx"]))
    return info
