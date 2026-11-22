"""The live ME testnet demonstration, run once by a person with a funded keystore.

Inputs (all checked before the first transaction):
  --job DIR   the StakingVault audit (gate.json; default $ME_DEMO_JOB, else the 2026-11-06 run)
  --rid RID   the web UI's saved copy of the same result, for the result page's card
              (default $ME_DEMO_RID; the built-in copy only when it is the same gate.json)
  me/dogfood/AuditRegistry.gate.json, me/dogfood/AuditEscrow.gate.json: ARBITER Gate's audits
              of our own two contracts (--self-registry-gate / --self-escrow-gate override)

Steps (each recorded in me/deployments/<network>.demo.json, so a rerun skips what is done):
  1a deploy AuditRegistry (plain CREATE: a registry cannot be deployed through itself)
  1b register the AuditRegistry audit: we audited our own contract with ARBITER Gate
  1c linkDeployment(1b, registry) -> LINK_CLAIMED, after checking that the registry's on-chain
     codehash equals the runtime hash of the artifact the record's initcodeHash comes from
  1d register the AuditEscrow audit (initcode = creation bytecode ++ abi.encode(registry))
  1e deploy AuditEscrow THROUGH the registry (deployAudited -> LINK_GATED); this escrow is the
     one every later step uses. Verdict 0/3 -> plain deployment with the reason recorded.
     When me/deployments/<network>.json exists from a run without dogfood, nothing is
     redeployed: 1b-1d are added, the existing escrow stays, and 1e only claims it (when its
     code is the audited build).
  2  escrow request: lock a small MEC fee for the StakingVault source, naming the auditor
  3  register the proven StakingVault result (verdict 3); deployAudited is refused by the
     registry, and the refusal is sent as a (reverting) transaction so it shows on the explorer;
     the record settles the escrow request (fee paid: the audit finished)
  4  register the patched StakingVault (verdict 1, parent = step 3) and deploy it through the
     registry (CREATE2 at the predicted address, LINK_GATED)
  5  write me/EVIDENCE.md (every address and tx with explorer links and the feature it shows,
     and when and by which code each gate.json was produced) and the web result page's sidecars
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .bech32 import to_me1
from .chain import ChainError, Client, KeystoreSigner, DevKeySigner, format_mec, network, parse_mec
from .contracts import (ME_DIR, VERDICT_LABELS, deploy_escrow, deploy_registry, deployments_path,
                        expected_runtime_hash, load_deployment, write_deployment)
from .deploy import TZ, deploy_through_registry, preflight, register_record, show_refusal, sidecar, write_sidecars
from .dogfood import TARGETS, SelfInput, claim, deploy_escrow_gated, deploy_escrow_plain, load_self, plan_self, \
    register_once
from .escrow import request as escrow_request, settle as escrow_settle
from .record import (ARBITER_DIR, WEB_DIR, GateInput, gate_info, load_gate, load_manifest, pick_entry, plan_record,
                     sha256_hex, stale_source)
from .session import Session

JOB = ARBITER_DIR / "runs" / "gate" / "jobs" / "20261106-200206-977ff0"
RID = "be2e752405bb"  # the web UI's saved copy of the same result
SOURCE = ARBITER_DIR / "examples" / "StakingVault.sol"
EVIDENCE_DIR = ME_DIR / "evidence"  # staking-vault/{original,patched} and self/{registry,escrow}
# Where me/evidence is published (raw.githubusercontent serves it with CORS *, so the verify page
# can re-hash the files); evidenceURI is <root>/staking-vault/... and <root>/self/...
EVIDENCE_ROOT_URL = "https://raw.githubusercontent.com/sam029031/arbiter-gate/me-hackathon/me/evidence"
FEE = "0.001"
# Every transaction of a fresh run with an upper bound of its gas: gasUsed measured on anvil on
# 2026-11-22 (with the default evidenceURI) times 1.15, rounded up. 5,889,636 gas in all were
# used; the node's gas price turns these into MEC (on ME each transaction costs at least 1 umec).
GAS_BUDGET = {
    "1a deploy AuditRegistry": 1_960_000,  # measured 1,703,872
    "1b register AuditRegistry audit": 540_000,  # 466,220
    "1c linkDeployment AuditRegistry": 215_000,  # 186,190
    "1d register AuditEscrow audit": 520_000,  # 447,984
    "1e deployAudited AuditEscrow": 1_380_000,  # 1,195,403
    "2 escrow request": 220_000,  # 188,842
    "3 register StakingVault": 620_000,  # 539,310
    "3 refusal": 400_000,  # the gas limit it is sent with; it reverts by design (ME charges >= half)
    "3 settle": 165_000,  # 143,122
    "4 register patched StakingVault": 650_000,  # 564,977
    "4 deployAudited patched StakingVault": 465_000,  # 403,036
}
TX_COUNT = len(GAS_BUDGET)  # 11 transactions in a fresh run
UMEC_WEI = 10**10
STEPS = ("1a", "1b", "1c", "1d", "1e", "2", "3", "4")


class _Stop(Exception):
    """--stop-after reached (rehearsals use it to test resuming)."""


def _state_path(net: str) -> Path:
    return ME_DIR / "deployments" / f"{net}.demo.json"


def _save(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def _rel(p: Path | None) -> str:
    """A path as the repository sees it (me/evidence/...), else just its name."""
    if p is None:
        return "—"
    # abspath, not resolve: arbiter/runs may be a symlink into another checkout
    p, root = Path(os.path.abspath(p)), Path(os.path.abspath(ME_DIR.parent))
    return p.relative_to(root).as_posix() if p.is_relative_to(root) else p.name


# ------------------------------------------------------------------ inputs


def resolve_job(arg: str | None, gate_arg: Path | None = None) -> tuple[Path, Path]:
    """(job directory, gate.json): --job, else $ME_DEMO_JOB, else the 2026-11-06 recording. A
    bare job name is looked up in arbiter/runs/gate/jobs/; a path to a gate.json works too."""
    if gate_arg:
        return Path(gate_arg).parent, Path(gate_arg)
    raw = (arg or os.environ.get("ME_DEMO_JOB") or "").strip()
    job = Path(raw).expanduser() if raw else JOB
    if raw and not job.exists() and "/" not in raw:
        job = ARBITER_DIR / "runs" / "gate" / "jobs" / raw
    if job.is_file():
        return job.parent, job
    return job, job / "gate.json"


def evidence_urls() -> tuple[str, str]:
    """(staking-vault base, self base) for the records' evidenceURI. ME_EVIDENCE_BASE_ROOT names
    the published me/evidence folder (default EVIDENCE_ROOT_URL; set but empty = no URI); the
    older ME_EVIDENCE_BASE_URL still names the staking-vault folder itself."""
    old = (os.environ.get("ME_EVIDENCE_BASE_URL") or "").strip().rstrip("/")
    root = os.environ.get("ME_EVIDENCE_BASE_ROOT")
    if root is None:
        root = old.removesuffix("/staking-vault") if old.endswith("/staking-vault") else ("" if old else EVIDENCE_ROOT_URL)
    root = root.strip().rstrip("/")
    return old or (f"{root}/staking-vault" if root else ""), (f"{root}/self" if root else "")


@dataclass
class Inputs:
    job: Path
    gate_path: Path
    rid: str | None = None
    gate: GateInput | None = None  # the StakingVault audit; None when steps 3 and 4 are done
    dogfood: bool = True
    selfs: dict[str, SelfInput] = field(default_factory=dict)  # dogfood audits still to register
    rehearsal: bool = False  # anvil (chain 31337)
    staking_uri: str = ""
    self_uri: str = ""
    notes: list[str] = field(default_factory=list)


def _load_staking(args, gate_path: Path) -> tuple[GateInput, str | None, str | None]:
    """The StakingVault gate.json, plus the web result id when that saved copy is the same result."""
    explicit = args.rid or os.environ.get("ME_DEMO_RID") or None
    rid = explicit or RID
    web = (args.web_dir or WEB_DIR) / f"{rid}.json"
    if not web.exists():
        if explicit:
            raise ChainError(f"找不到網頁結果 {rid}（runs/gate/web/{rid}.json）")
        return load_gate(gate_path), None, None
    try:
        return load_gate(gate_path, rid, args.web_dir), rid, None
    except ChainError:
        if explicit:
            raise
        return load_gate(gate_path), None, f"網頁結果 {rid} 不是這份 gate.json，不寫 {rid}.me.json（要寫請加 --rid）"


def check_staking(gate: GateInput, original: bool, patched: bool) -> None:
    """The story needs a proven exploit (verdict 3) of arbiter/examples/StakingVault.sol and a
    verified patch that was attacked again (verdict 1). Checked on a scratch copy of the bundle."""
    src_sha = sha256_hex(SOURCE.read_bytes())
    entry = pick_entry(gate.report, src_sha)
    if stale := stale_source(entry, src_sha):
        raise ChainError(f"{_rel(gate.path)} 稽核的不是 arbiter/examples/StakingVault.sol（它稽核的檔案 sha256 {stale}）")
    with tempfile.TemporaryDirectory(prefix="arbiter-me-demo-") as tmp:
        if original:
            v = plan_record(gate, SOURCE, out_dir=Path(tmp) / "o").verdict
            if v != 3:
                raise ChainError(f"示範的步驟 3 需要「已證實可攻擊」的稽核結果；{_rel(gate.path)} 的判定是 {v}"
                                 f"（{VERDICT_LABELS[v]}），請換一份 --job")
        if patched:
            v = plan_record(gate, SOURCE, out_dir=Path(tmp) / "p", patched=True, parent_id=1).verdict
            if v != 1:
                raise ChainError(f"示範的步驟 4 需要修補後再攻擊過（check 5）的修補；{_rel(gate.path)} 修補後的判定是 {v}"
                                 "，不能經由閘門部署，請換一份 --job")


def resolve_inputs(args, client: Client, state: dict) -> Inputs:
    """Read and check every input the remaining steps need, before anything is sent."""
    job, gate_path = resolve_job(args.job, args.gate)
    staking_uri, self_uri = evidence_urls()
    inp = Inputs(job=job, gate_path=gate_path, rehearsal=client.network.chain_id == 31337,
                 dogfood=not args.no_dogfood and os.environ.get("ME_DEMO_DOGFOOD", "1") != "0",
                 staking_uri=staking_uri, self_uri=self_uri)
    pending_o, pending_p = not state.get("blocked"), not state.get("patched")
    if pending_o or pending_p:
        if not gate_path.is_file():
            raise ChainError(f"找不到示範用的稽核結果 {_rel(gate_path)}（--job / ME_DEMO_JOB）")
        inp.gate, inp.rid, note = _load_staking(args, gate_path)
        if note:
            inp.notes.append(note)
        done = ((state.get("blocked") or {}).get("gate") or {}).get("sha256")
        if done and done != inp.gate.sha256:  # step 4 derives from step 3: the same audit, always
            raise ChainError(f"步驟 3 已用另一份 gate.json（sha256 {done[:18]}…）登錄；步驟 4 必須用同一份，"
                             "請改回原本的 --job / ME_DEMO_JOB")
        check_staking(inp.gate, pending_o, pending_p)
    else:
        done = (state["blocked"].get("gate") or {}).get("sha256")
        if done and gate_path.is_file() and sha256_hex(gate_path.read_bytes()) != done:
            inp.notes.append("步驟 3、4 已用另一份 gate.json 登錄，這次的 --job 用不到（要換結果請換一組部署與 state）")
    if inp.dogfood:
        s = state.get("self") or {}
        for key, target in TARGETS.items():
            if not (s.get(key) or {}).get("record"):
                inp.selfs[key] = load_self(target, getattr(args, f"self_{key}_gate"), rehearsal=inp.rehearsal)
        if inp.selfs:
            with tempfile.TemporaryDirectory(prefix="arbiter-me-self-") as tmp:
                for key, si in inp.selfs.items():  # compiles; the rebuild must equal the artifact
                    plan_self(si, Path(tmp) / key, "", "0x" + "11" * 20)
        for si in inp.selfs.values():
            if si.stale:
                inp.notes.append(f"排練：{si.gate.path.name} 稽核的是另一版 {si.target.contract}.sol"
                                 f"（sha256 {si.stale[:18]}…），正式網路會拒絕登錄")
    return inp


def pending_gas(state: dict, have_contracts: bool, dogfood: bool = True) -> list[str]:
    """GAS_BUDGET keys of the transactions this run may still send."""
    s, c = state.get("self") or {}, state.get("contracts") or {}
    sr, se = s.get("registry") or {}, s.get("escrow") or {}
    out = []
    if not have_contracts and not c.get("registry"):
        out.append("1a deploy AuditRegistry")
    if dogfood:
        out += [k for k, done in (("1b register AuditRegistry audit", sr.get("record")),
                                  ("1c linkDeployment AuditRegistry", sr.get("link")),
                                  ("1d register AuditEscrow audit", se.get("record"))) if not done]
        if not se.get("deploy"):  # an escrow that exists already is only claimed (a linkDeployment)
            out.append("1c linkDeployment AuditRegistry" if have_contracts else "1e deployAudited AuditEscrow")
    elif not have_contracts and not c.get("escrow"):
        out.append("1e deployAudited AuditEscrow")  # a plain CREATE costs less than this
    if not state.get("escrow"):
        out.append("2 escrow request")
    if not state.get("blocked"):
        out += ["3 register StakingVault", "3 refusal", "3 settle"]
    if not state.get("patched"):
        out += ["4 register patched StakingVault", "4 deployAudited patched StakingVault"]
    return out


def needed_wei(client: Client, state: dict, have_contracts: bool, dogfood: bool = True) -> int:
    txs = pending_gas(state, have_contracts, dogfood)
    gas = sum(GAS_BUDGET[k] for k in txs)
    price = max(client.gas_price(), 1)
    fee = 0 if state.get("escrow") else parse_mec(FEE)
    # ME charges at least 1 umec (10^10 wei) per transaction, whatever the gas
    return fee + gas * price * 3 + len(txs) * UMEC_WEI


def add_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--account", help="Foundry keystore 名稱（me/scripts/new_wallet.sh 建立的）")
    ap.add_argument("--network", default="me-testnet")
    ap.add_argument("--job", help="StakingVault 的稽核結果資料夾（含 gate.json；預設 $ME_DEMO_JOB，"
                                  "再預設 2026-11-06 的錄製）")
    ap.add_argument("--rid", help="同一份結果的網頁編號（runs/gate/web/<rid>.json；預設 $ME_DEMO_RID）")
    ap.add_argument("--self-registry-gate", type=Path,
                    help="AuditRegistry 的稽核結果（預設 me/dogfood/AuditRegistry.gate.json）")
    ap.add_argument("--self-escrow-gate", type=Path,
                    help="AuditEscrow 的稽核結果（預設 me/dogfood/AuditEscrow.gate.json）")
    ap.add_argument("--no-dogfood", action="store_true",
                    help="不做自我稽核（兩個合約一般部署；之後再跑會補上紀錄，AuditEscrow 維持原樣）")
    ap.add_argument("--rpc", help=argparse.SUPPRESS)
    ap.add_argument("--dev", action="store_true", help=argparse.SUPPRESS)  # anvil rehearsal of the same flow
    ap.add_argument("--deployments", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--evidence-md", type=Path, default=ME_DIR / "EVIDENCE.md", help=argparse.SUPPRESS)
    ap.add_argument("--state", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--web-dir", type=Path, help=argparse.SUPPRESS)
    ap.add_argument("--evidence-root", type=Path, default=EVIDENCE_DIR, help=argparse.SUPPRESS)
    ap.add_argument("--gate", type=Path, help=argparse.SUPPRESS)  # a gate.json path instead of --job
    ap.add_argument("--stop-after", choices=STEPS, help=argparse.SUPPRESS)  # rehearsing an interruption


def run(args: argparse.Namespace) -> int:
    client = Client(network(args.network, args.rpc))
    client.check_network()
    net = client.network
    dep_path = args.deployments or deployments_path(net.name)
    state_path = args.state or _state_path(net.name)
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    inp = resolve_inputs(args, client, state)
    need = needed_wei(client, state, dep_path.exists(), inp.dogfood)
    print(f"網路 {net.name}（chain {net.chain_id}）：這次示範最多需要 {format_mec(need)}"
          f"（含 {FEE} MEC 委託費，結算後付回同一個帳號；gas 價格 {client.gas_price()} wei，已乘 3 倍保留）")
    if inp.gate is not None:
        print(f"StakingVault 稽核結果：{_rel(inp.gate_path)}" + (f"（網頁結果 {inp.rid}）" if inp.rid else ""))
    if not inp.dogfood:
        print("自我稽核：這次不做（--no-dogfood）")
    elif inp.selfs:
        print("自我稽核：" + "、".join(_rel(si.gate.path) for si in inp.selfs.values()))
    for n in inp.notes:
        print(f"注意：{n}")
    if args.dev:
        signer = DevKeySigner(client)
    elif args.account:
        signer = KeystoreSigner(args.account)
    else:
        raise ChainError("請加上 --account <keystore 名稱>")
    try:
        return _run(client, signer, args, inp, dep_path, state_path, state)
    finally:
        signer.close()


def _step(title: str) -> None:
    print(f"\n== {title}")


def _skip(title: str) -> None:
    print(f"\n== {title}：已完成，跳過")


def _stop(args, step: str) -> None:
    if args.stop_after == step:
        print(f"\n（--stop-after {step}：停在這裡，再跑一次會從下一步繼續）")
        raise _Stop


def _run(client: Client, signer, args, inp: Inputs, dep_path: Path, state_path: Path, state: dict) -> int:
    net = client.network
    need = needed_wei(client, state, dep_path.exists(), inp.dogfood)
    bal = client.balance(signer.address)
    print(f"帳號 {signer.address}（{to_me1(signer.address)}）餘額 {format_mec(bal)}")
    if bal < need:
        print(f"\n餘額不足。請到水龍頭領取測試幣：{net.faucet or '（這個網路沒有水龍頭）'}")
        print(f"  貼上這個 me1 地址：{to_me1(signer.address)}")
        return 3
    try:
        sess = _contracts(client, signer, args, inp, dep_path, state_path, state)
        _staking(sess, args, inp, state_path, state)
    except _Stop:
        return 0

    _step("5. 寫 EVIDENCE.md")
    args.evidence_md.write_text(evidence_md(sess, state, args.evidence_root), encoding="utf-8")
    print(f"  {args.evidence_md.name} 已更新；重驗：python3 me/me.py verify {state['patched']['deploy'].get('address')}"
          f" --network {net.name} --evidence {_rel(args.evidence_root / 'staking-vault' / 'patched')} --rebuild --replay")
    return 0 if state["patched"]["deploy"].get("status") == "deployed" else 1


# ------------------------------------------------------------------ step 1: contracts and dogfood


def _contracts(client: Client, signer, args, inp: Inputs, dep_path: Path, state_path: Path, state: dict) -> Session:
    net = client.network
    if dep_path.exists():
        d = load_deployment(net.name, dep_path)
        if state.get("registry") not in (None, d["registry"]["address"]):
            raise ChainError(f"{state_path.name} 屬於另一組合約；換一組合約請先把它移走")
        state["registry"] = d["registry"]["address"]
        _skip("1. AuditRegistry 與 AuditEscrow 已部署")
        if inp.dogfood and not (state.get("self") or {}).get("mode"):
            # deployed by an earlier dogfood run (gated, or plain with the reason) or before dogfood existed
            esc = d.get("escrow") or {}
            ours = esc.get("deployedVia") == "deployAudited" or bool(esc.get("reason"))
            state.setdefault("self", {})["mode"] = "fresh" if ours else "legacy"
            if not ours:
                print("  這組合約是在沒有自我稽核時部署的：補上兩個合約的稽核紀錄；AuditEscrow 維持原樣，不重新部署")
        _save(state_path, state)
        sess = Session(client=client, deployment=d, signer=signer)
        if inp.dogfood:
            _self_steps(sess, args, inp, state, state_path, d["registry"]["address"])
        _stop(args, "1e")
        return sess

    c = state.setdefault("contracts", {})
    if not c.get("registry"):
        _step("1a. 部署 AuditRegistry（一般 CREATE：登錄合約不能經由自己部署）")
        if state.get("registry"):
            raise ChainError(f"{state_path.name} 屬於另一組合約；換一組合約請先把它移走")
        c["registry"] = deploy_registry(client, signer)
        state["registry"] = c["registry"]["address"]
        _save(state_path, state)
        print(f"  AuditRegistry {c['registry']['address']}")
    else:
        if client.code_hash(c["registry"]["address"]) != c["registry"]["codehash"]:
            raise ChainError(f"{state_path.name} 記錄的 AuditRegistry {c['registry']['address']} 不在這條鏈上；"
                             "換一條鏈請先把 state 移走")
        _skip("1a. AuditRegistry 已部署")
    _stop(args, "1a")
    registry = c["registry"]["address"]
    sess = Session(client=client, deployment={"registry": c["registry"]}, signer=signer)
    if inp.dogfood:
        state.setdefault("self", {}).setdefault("mode", "fresh")
        _self_steps(sess, args, inp, state, state_path, registry)
        dep = state["self"]["escrow"]["deploy"]
        escrow = {"address": dep["address"], "tx": dep["tx"], "block": dep["block"],
                  "codehash": client.code_hash(dep["address"]), "deployedVia": dep.get("deployedVia", "create")}
        if escrow["deployedVia"] == "deployAudited":
            escrow["record"] = state["self"]["escrow"]["record"]["id"]
        else:
            escrow["reason"] = dep.get("reason")
    else:
        if not c.get("escrow"):
            _step("1e. 部署 AuditEscrow（一般 CREATE；這次不做自我稽核）")
            c["escrow"] = deploy_escrow(client, signer, registry)
            _save(state_path, state)
        else:
            _skip("1e. AuditEscrow 已部署")
        escrow = c["escrow"]
    data = write_deployment(client, signer, c["registry"], escrow, dep_path)
    how = "經由部署閘門" if escrow.get("deployedVia") == "deployAudited" else "一般部署"
    print(f"  部署資訊寫入 {dep_path.name}：AuditRegistry {registry}，AuditEscrow {escrow['address']}（{how}）")
    _stop(args, "1e")
    return Session(client=client, deployment=data, signer=signer)


def _self_steps(sess: Session, args, inp: Inputs, state: dict, state_path: Path, registry: str) -> None:
    s = state["self"]
    legacy = s.get("mode") == "legacy"
    sr, se = s.setdefault("registry", {}), s.setdefault("escrow", {})
    root = args.evidence_root / "self"

    if not sr.get("record"):
        _step("1b. 登錄 AuditRegistry 的稽核紀錄（用 ARBITER Gate 稽核自己的合約）")
        si = inp.selfs["registry"]
        plan = plan_self(si, root / "registry", f"{inp.self_uri}/registry" if inp.self_uri else "", registry)
        sr.update(gate=si.info, input=plan.input, notes=plan.notes)
        sr["record"] = register_once(sess, plan)
        _save(state_path, state)
        v = plan.input["verdict"]
        print(f"  紀錄 #{sr['record']['id']}：判定 {v}（{VERDICT_LABELS[v]}）；gate.json 產生於 {_when(si.info['generatedAt'])}")
    else:
        _skip("1b. AuditRegistry 的稽核紀錄已登錄")
    _stop(args, "1b")

    if not sr.get("link"):
        _step("1c. 宣告 AuditRegistry 本身的位址（linkDeployment → LINK_CLAIMED）")
        sr["link"] = claim(sess, sr["record"]["id"], registry, expected_runtime_hash("AuditRegistry"), "AuditRegistry")
        _save(state_path, state)
        lk = sr["link"]
        print(f"  鏈上 codehash          {lk['codehash']}\n  編譯產物 runtime 雜湊  {lk['expectedCodehash']}"
              f"（{'相同' if lk['codehashMatches'] else '不同'}）")
        print("  " + ("已宣告（LINK_CLAIMED）" if lk["status"] == "claimed" else f"沒有宣告：{lk.get('reason')}"))
    else:
        _skip("1c. AuditRegistry 的位址已宣告")
    _stop(args, "1c")

    if not se.get("record"):
        _step("1d. 登錄 AuditEscrow 的稽核紀錄（initcode = 建立程式碼 + abi.encode(AuditRegistry)）")
        si = inp.selfs["escrow"]
        plan = plan_self(si, root / "escrow", f"{inp.self_uri}/escrow" if inp.self_uri else "", registry)
        se.update(gate=si.info, input=plan.input, notes=plan.notes)
        se["record"] = register_once(sess, plan)
        _save(state_path, state)
        v = plan.input["verdict"]
        print(f"  紀錄 #{se['record']['id']}：判定 {v}（{VERDICT_LABELS[v]}）；gate.json 產生於 {_when(si.info['generatedAt'])}")
    else:
        _skip("1d. AuditEscrow 的稽核紀錄已登錄")
    _stop(args, "1d")

    if not se.get("deploy"):
        rid, v = se["record"]["id"], se["input"]["verdict"]
        existing = (sess.deployment or {}).get("escrow")  # the deployment file names one: never deploy another
        if existing and sess.registry.deployment_of(existing["address"]) == rid:
            _step("1e. AuditEscrow 已經由部署閘門部署（上次的進度沒有存下，從鏈上找回）")
            se["deploy"] = {**deploy_escrow_gated(sess, rid, registry), "deployedVia": "deployAudited"}
        elif existing:
            _step("1e. AuditEscrow 已在較早的執行部署，維持原樣；程式碼是稽核過的版本才宣告它的位址")
            esc = existing["address"]
            link = claim(sess, rid, esc, expected_runtime_hash("AuditEscrow", registry), "AuditEscrow")
            se["deploy"] = {"status": "existing", "deployedVia": "create", "address": esc.lower(), "link": link,
                            "reason": existing.get("reason")
                            or "部署資訊在加入自我稽核之前就存在：AuditEscrow 維持原樣，沒有重新部署"}
            print(f"  AuditEscrow {esc} 維持原樣；"
                  + ("已宣告（LINK_CLAIMED）" if link["status"] == "claimed" else f"沒有宣告：{link.get('reason')}"))
        else:
            _step("1e. AuditEscrow 經由部署閘門部署（deployAudited → LINK_GATED）")
            reason = None
            if v in (1, 2):
                dep = deploy_escrow_gated(sess, rid, registry)
                if dep["status"] == "deployed":
                    se["deploy"] = {**dep, "deployedVia": "deployAudited"}
                    print(f"  登錄合約依紀錄 #{rid} 部署 AuditEscrow：{dep['address']}（事先預測的位址，LINK_GATED）")
                else:
                    reason = f"deployAudited 沒有成功：{dep['reason']}"
            else:
                reason = f"AuditEscrow 的稽核判定是 {v}（{VERDICT_LABELS[v]}），登錄合約不允許經由閘門部署"
            if reason:
                print(f"  {reason}\n  改用一般部署，原因記在 state 與 EVIDENCE.md")
                se["deploy"] = deploy_escrow_plain(sess, registry, reason)
                print(f"  AuditEscrow {se['deploy']['address']}（一般部署）")
        _save(state_path, state)
    else:
        _skip("1e. AuditEscrow 已部署" + ("（維持原樣）" if legacy else ""))


# ------------------------------------------------------------------ steps 2-4: the StakingVault story


def _staking(sess: Session, args, inp: Inputs, state_path: Path, state: dict) -> None:
    signer, client = sess.require_signer(), sess.client
    src_hash = sha256_hex(SOURCE.read_bytes())
    sv = args.evidence_root / "staking-vault"
    uri = inp.staking_uri

    if not state.get("escrow"):
        _step("2. 付費委託：鎖住委託費")
        state["escrow"] = escrow_request(sess, src_hash, signer.address, parse_mec(FEE), 7 * 24 * 3600)
        state["escrow"]["contract"] = sess.escrow.address
        _save(state_path, state)
        print(f"  委託 #{state['escrow']['id']}，{FEE} MEC，AuditEscrow {sess.escrow.address}，交易 {state['escrow']['tx']}")
    else:
        _skip("2. 委託已建立")
    _stop(args, "2")

    if not state.get("blocked"):
        _step("3. 登錄已證實可攻擊的 StakingVault（判定 3），部署被登錄合約拒絕")
        plan = plan_record(inp.gate, SOURCE, out_dir=sv / "original", evidence_uri=f"{uri}/original" if uri else "")
        reg = register_record(sess, plan)
        state["blocked"] = {"record": reg, "gate": gate_info(inp.gate, plan.entry), "input": plan.input}
        _save(state_path, state)
        dep = show_refusal(sess, reg["id"], plan.build, record=True)
        dep["preflight"] = preflight(client, plan.build.deploy_code, signer.address)
        state["blocked"]["deploy"] = dep
        _save(state_path, state)
        settled = escrow_settle(sess, state["escrow"]["id"], reg["id"])
        state["escrow"]["settle"] = settled
        state["blocked"]["sidecars"] = [p.name for p in write_sidecars(sidecar(sess, plan, reg, dep, settled), plan,
                                                                       args.web_dir)]
        _save(state_path, state)
        print(f"  紀錄 #{reg['id']}；拒絕：{dep['reason']}；委託 {settled['status']}")
    else:
        _skip("3. 判定 3 的紀錄已登錄")
    _stop(args, "3")

    if not state.get("patched"):
        _step("4. 登錄修補後的 StakingVault（判定 1，上一版 = 步驟 3），經由登錄合約部署")
        parent = state["blocked"]["record"]["id"]
        plan = plan_record(inp.gate, SOURCE, out_dir=sv / "patched", patched=True, parent_id=parent,
                           evidence_uri=f"{uri}/patched" if uri else "")
        pre = preflight(client, plan.build.deploy_code, signer.address)
        if not pre["ok"]:
            raise ChainError(f"preflight 失敗：{pre['error']}")
        reg = register_record(sess, plan)
        state["patched"] = {"record": reg, "gate": gate_info(inp.gate, plan.entry), "input": plan.input}
        _save(state_path, state)
        dep = deploy_through_registry(sess, reg["id"], plan.build)
        dep["preflight"] = pre
        state["patched"]["deploy"] = dep
        state["patched"]["sidecars"] = [p.name for p in write_sidecars(sidecar(sess, plan, reg, dep, None), plan,
                                                                       args.web_dir)]
        _save(state_path, state)
        print(f"  紀錄 #{reg['id']}；部署 {dep['status']} {dep.get('address')}")
    else:
        _skip("4. 修補後的紀錄已登錄")
    _stop(args, "4")


# ------------------------------------------------------------------ EVIDENCE.md


def _link(text: str | None, url: str | None) -> str:
    if not text:
        return "—"
    return f"[`{text}`]({url})" if url else f"`{text}`"


def _when(generated_at: str | None) -> str:
    """gate.json `generated_at` ("2026-11-21T23:27:52+0800") as UTC+8 wall time."""
    if not generated_at:
        return "未記錄"
    try:
        t = _dt.datetime.strptime(generated_at, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return str(generated_at)
    return t.astimezone(TZ).strftime("%Y-%m-%d %H:%M:%S") + "（UTC+8）"


def _input(sess: Session, slot: dict) -> dict:
    """A demo record's RecordInput: from the state, else from the chain (states of older runs)."""
    return slot.get("input") or sess.registry.record(slot["record"]["id"])


def _gate_facts(bundle: Path, slot: dict) -> dict:
    """gate.json facts of a record: from the state, else from the bundle's own gate.json."""
    if slot.get("gate"):
        return slot["gate"]
    m = load_manifest(bundle)
    gate = load_gate(bundle / "gate.json")
    files = gate.report.get("files") or [{}]
    return gate_info(gate, next((f for f in files if f.get("id") == m.get("fileEntry")), files[0]))


def _commit_cell(info: dict, onchain: str) -> str:
    if info.get("toolCommit"):
        src = f"（{info['toolCommitSource']}）" if info.get("toolCommitSource") else ""
        differs = onchain.removeprefix("0x").lower() != str(info["toolCommit"]).lower()
        return f"`{info['toolCommit']}`{src}" + (f"；鏈上 toolCommit `{onchain}`" if differs else "")
    return f"gate.json 沒有記錄（鏈上 toolCommit 是登錄時的 git HEAD `{onchain[2:14]}…`）"


def evidence_md(sess: Session, state: dict, evidence_root: Path) -> str:
    net, d = sess.net, sess.deployment
    reg_addr, esc = d["registry"]["address"], d["escrow"]

    def tx(t: str | None, cosmos: str | None = None) -> tuple[tuple[int, int], str]:
        """((block, index), two cells): the EVM hash (what RPC tools take) and the explorer link."""
        if not t:
            return (1 << 62, 0), "— | —"
        cosmos = cosmos or sess.client.cosmos_tx_hash(t)
        rcpt = sess.client.receipt(t) or {}
        block = int(str(rcpt.get("blockNumber") or "0x0"), 0)
        index = int(str(rcpt.get("transactionIndex") or "0x0"), 0)
        url = net.tx_url(t, cosmos) if cosmos else None
        return (block, index), f"`{t}`（區塊 {block}） | " + (f"[{cosmos[:10]}…]({url})" if url else "（瀏覽器查不到）")

    ad = lambda a: _link(a, net.address_url(a))  # noqa: E731
    s = state.get("self") or {}
    sr, se = s.get("registry") or {}, s.get("escrow") or {}
    lk, elk = sr.get("link") or {}, (se.get("deploy") or {}).get("link") or {}
    b, p, e = state["blocked"], state["patched"], state["escrow"]
    sv, own = evidence_root / "staking-vault", evidence_root / "self"
    gated = esc.get("deployedVia") == "deployAudited"
    sr_id, se_id = (sr.get("record") or {}).get("id"), (se.get("record") or {}).get("id")
    now = _dt.datetime.now(TZ).strftime("%Y-%m-%d %H:%M")

    rows: list[tuple[tuple[int, int], str, str]] = []

    def add(t: str | None, cosmos: str | None, what: str) -> None:
        key, cells = tx(t, cosmos)
        rows.append((key, cells, what))

    add(d["registry"]["tx"], d["registry"].get("cosmosTx"), "部署 AuditRegistry（paris 編譯；ME 測試網不支援 PUSH0）")
    if gated:
        add(esc["tx"], esc.get("cosmosTx"),
            f"**AuditEscrow 經由部署閘門部署（deployAudited）**：登錄合約依紀錄 #{esc.get('record')} 用 CREATE2 把稽核過的"
            "建立程式碼（含 abi.encode(AuditRegistry 位址)）部署到事先預測的位址（LINK_GATED）。這就是部署 AuditEscrow"
            "（MEC 付費委託，費用不隨判定改變）的交易，後面的委託與結算都用這個 AuditEscrow")
    else:
        why = f"；沒有經由部署閘門：{esc['reason']}" if esc.get("reason") else ""
        add(esc["tx"], esc.get("cosmosTx"), f"部署 AuditEscrow（MEC 付費委託，費用不隨判定改變{why}）")
    if sr.get("record"):
        v = _input(sess, sr)["verdict"]
        add(sr["record"]["tx"], sr["record"].get("cosmosTx"),
            f"**AuditRegistry 的稽核紀錄（用 ARBITER Gate 稽核自己的合約）**：紀錄 #{sr_id}，判定 {v}（{VERDICT_LABELS[v]}）；"
            "sourceHash = AuditRegistry.sol 的 sha256、gateJsonHash = 稽核結果 gate.json 的 sha256、initcodeHash = "
            "部署它的建立程式碼（solc 0.8.24、paris、optimizer 200、無 metadata）")
    if lk.get("tx"):
        add(lk["tx"], lk.get("cosmosTx"),
            f"**宣告 AuditRegistry 本身的位址**：linkDeployment(#{sr_id}, AuditRegistry) → LINK_CLAIMED。登錄合約不可能"
            f"經由自己部署，所以只能由稽核者宣告；鏈上 codehash `{lk['codehash']}` 等於編譯產物 runtime 的 keccak256")
    if se.get("record"):
        v = _input(sess, se)["verdict"]
        why = ("所以只有接上這個 AuditRegistry 的 AuditEscrow 能依這筆紀錄經由閘門部署" if v in (1, 2)
               else f"判定 {v} 的紀錄不能經由閘門部署")
        add(se["record"]["tx"], se["record"].get("cosmosTx"),
            f"**AuditEscrow 的稽核紀錄**：紀錄 #{se_id}，判定 {v}（{VERDICT_LABELS[v]}）；initcodeHash = 建立程式碼 + "
            f"abi.encode(AuditRegistry 位址)，{why}")
    if elk.get("tx"):
        add(elk["tx"], elk.get("cosmosTx"),
            f"宣告既有 AuditEscrow 的位址：linkDeployment(#{se_id}, AuditEscrow) → LINK_CLAIMED（它在加入自我稽核之前"
            f"已用一般方式部署，維持原樣；鏈上 codehash `{elk['codehash']}` 等於稽核過的編譯產物）")
    add(e["tx"], e.get("cosmosTx"),
        f"委託 #{e['id']}：鎖住 {format_mec(int(e['fee_wei']))}，指定稽核者與 StakingVault 原始碼的 sha256")
    add(b["record"]["tx"], b["record"].get("cosmosTx"),
        f"紀錄 #{b['record']['id']}：AI 證實 StakingVault 可被重入攻擊（判定 3），原始碼、gate.json、攻擊程式、修補的雜湊上鏈")
    add(b["deploy"].get("tx"), b["deploy"].get("cosmosTx"),
        f"對紀錄 #{b['record']['id']} 呼叫 deployAudited：合約拒絕部署（{b['deploy'].get('error')}"
        f"({', '.join(map(str, b['deploy'].get('errorArgs') or []))})），交易失敗是預期的")
    add(e["settle"]["settleTx"], e["settle"].get("cosmosTx"),
        f"紀錄 #{b['record']['id']} 結算委託 #{e['id']}：稽核完成，費用付給稽核者（判定是 3 也照付）")
    add(p["record"]["tx"], p["record"].get("cosmosTx"),
        f"紀錄 #{p['record']['id']}：修補後的 StakingVault（判定 1，上一版 #{b['record']['id']}，patchHash 與建議修補相同）")
    add(p["deploy"].get("tx"), p["deploy"].get("cosmosTx"),
        "deployAudited：登錄合約用 CREATE2 把修補後、稽核過的 bytecode 部署到事先預測的地址（LINK_GATED）")
    rows.sort(key=lambda r: r[0])  # chronological (an older run's rows come first)

    reg_role = "稽核紀錄只能新增、不能修改；判定 3（已證實可攻擊）和 0（稽核未完成）不能經由它部署"
    if lk.get("status") == "claimed":
        reg_role += f"。它自己的稽核紀錄是 #{sr_id}，位址由稽核者宣告（LINK_CLAIMED），鏈上 codehash 等於編譯產物的 runtime 雜湊"
    esc_role = "用 MEC 付稽核費；稽核完成就付款，未完成或逾期就退款"
    if gated:
        esc_role += f"。由登錄合約依紀錄 #{esc.get('record')} 部署（LINK_GATED），委託與結算都用這個位址"
    elif elk.get("status") == "claimed":
        esc_role += f"。較早以一般方式部署、維持原樣；紀錄 #{se_id} 宣告這個位址（LINK_CLAIMED）"

    notes = []
    if s.get("mode") == "legacy":
        notes.append("AuditEscrow 在加入自我稽核之前已部署（一般部署，沒有經過部署閘門），這次維持原樣、沒有重新部署；"
                     "兩個合約的稽核紀錄是之後補上的（區塊較晚）。")
    elif esc.get("reason"):
        notes.append(f"AuditEscrow 沒有經由部署閘門部署：{esc['reason']}。")
    if lk and lk.get("status") != "claimed":
        notes.append(f"AuditRegistry 的位址沒有宣告：{lk.get('reason')}。")
    if elk and elk.get("status") != "claimed":
        notes.append(f"既有 AuditEscrow 的位址沒有宣告：{elk.get('reason')}。")
    for slot in (sr, se):
        g = slot.get("gate") or {}
        if g.get("stale"):
            notes.append(f"排練：{g['file']} 稽核的是另一版原始碼（sha256 {g['auditedSha256']}），不是目前的 "
                         f"{g['source']}；正式網路不會登錄這種紀錄。")

    audited = [("StakingVault.sol（示範合約，可重入）", sv / "original", b,
                f"`{_rel(sv / 'original')}`、`{_rel(sv / 'patched')}`")]
    if sr.get("record"):
        audited.append(("AuditRegistry.sol（我們自己的合約）", own / "registry", sr, f"`{_rel(own / 'registry')}`"))
    if se.get("record"):
        audited.append(("AuditEscrow.sol（我們自己的合約）", own / "escrow", se, f"`{_rel(own / 'escrow')}`"))
    gate_rows = []
    for name, bundle, slot, folders in audited:
        info, ri = _gate_facts(bundle, slot), _input(sess, slot)
        if info.get("mode") == "project":
            name = name.replace("）", "，專案模式）", 1)
        same = str(ri["gateJsonHash"]).lower() == str(info["sha256"]).lower()
        gate_rows.append(f"| {name} | `{info.get('gateVerdict')}` → {info['verdict']} {VERDICT_LABELS[info['verdict']]} | "
                         f"{_when(info.get('generatedAt'))} | {_commit_cell(info, str(ri['toolCommit']))} | "
                         f"{info.get('model') or '未記錄'} | `{info['sha256']}`{'' if same else '（和鏈上 gateJsonHash 不同！）'} | "
                         f"{folders} |")

    patched_addr = p["deploy"].get("address")
    verify = [f"python3 me/me.py verify {patched_addr} --network {net.name} --evidence {_rel(sv / 'patched')} --rebuild --replay",
              f"python3 me/me.py verify {b['record']['id']} --network {net.name} --evidence {_rel(sv / 'original')} --replay"]
    if sr.get("record"):
        verify.append(f"python3 me/me.py verify {reg_addr if lk.get('status') == 'claimed' else sr_id} --network {net.name}"
                      f" --evidence {_rel(own / 'registry')} --rebuild")
    if se.get("record"):
        target = esc["address"] if gated or elk.get("status") == "claimed" else se_id
        verify.append(f"python3 me/me.py verify {target} --network {net.name} --evidence {_rel(own / 'escrow')} --rebuild")

    lines = [
        "# ARBITER Gate × ME 測試網：鏈上證據",
        "",
        f"網路 {net.name}（chain {net.chain_id}）｜RPC `{net.rpc}`｜瀏覽器 {net.explorer or '（無）'}｜更新時間 {now}（UTC+8）",
        "",
        "這份文件只是索引。每一項都能用 `python3 me/me.py verify` 直接從鏈上重驗，不需要相信這份文件。",
        "瀏覽器以 Cosmos 交易為索引；連結用的是 EVM 交易所在的 Cosmos 交易雜湊（查不到時才用 EVM 雜湊）。",
        "",
        "## 合約",
        "",
        "| 合約 | 地址 | 展示的功能 |",
        "|---|---|---|",
        f"| AuditRegistry | {ad(reg_addr)} | {reg_role} |",
        f"| AuditEscrow | {ad(esc['address'])} | {esc_role} |",
        f"| StakingVault（修補後） | {ad(patched_addr)} | 由登錄合約部署，鏈上可查它就是紀錄 #{p['record']['id']} 稽核過的 bytecode |",
        "",
        "## 稽核結果（gate.json）",
        "",
        "每筆紀錄的 gateJsonHash 是下表 gate.json 的 sha256，檔案就在證據資料夾裡。產生時間取自 gate.json 的 `generated_at`，"
        "產生結果的程式是 gate.json 的 `tool_commit`（ARBITER Gate 的 git commit）。",
        "",
        "| 稽核對象 | 稽核結果 → 鏈上判定 | 產生時間（generated_at） | 產生結果的程式（tool_commit） | 模型 | gate.json sha256 | 證據資料夾 |",
        "|---|---|---|---|---|---|---|",
        *gate_rows,
        "",
        "## 交易",
        "",
        *[f"- {n}" for n in notes],
        *([""] if notes else []),
        "| # | EVM 交易 | 瀏覽器（Cosmos 交易） | 展示的功能 |",
        "|---|---|---|---|",
        *[f"| {i} | {cells} | {what} |" for i, (_, cells, what) in enumerate(rows, 1)],
        "",
        "## 重驗（任何人都可以跑）",
        "",
        "```bash",
        *verify,
        "```",
        "",
        "- `--evidence`：重算證據資料夾每個檔案的 sha256，和鏈上紀錄比對。",
        "- `--rebuild`：用紀錄的編譯設定（solc 0.8.24、paris、optimizer 200、無 metadata）重新編譯，比對 initcodeHash 與鏈上程式碼"
        "（AuditEscrow import 的 AuditRegistry.sol 也在它的證據資料夾 `imports/` 裡）。",
        "- `--replay`：用 forge 重跑攻擊：在原始碼上攻擊成功，套用修補後攻擊失敗。",
        f"- 瀏覽器打不開時：`cast receipt <EVM 交易> --rpc-url {net.rpc}` 直接向節點查。",
        "",
        "說明：紀錄是稽核者的主張；deployAudited 證明部署的程式碼就是稽核過的 bytecode，linkDeployment 只是稽核者的宣告"
        "（用 `--rebuild` 比對）；判定 1 代表沒有找到可證明的攻擊，判定 2 代表只有靜態工具的提示、沒有證實，兩者都不等於安全。",
        "",
    ]
    return "\n".join(lines)
