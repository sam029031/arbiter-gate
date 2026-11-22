#!/usr/bin/env python3
"""End-to-end probe of the ME layer on a local anvil (no LLM, no funded key).

Uses a real recorded gate result: StakingVault, proven re-entrancy with a verified patch
(arbiter/runs/gate/jobs/20261106-200206-977ff0), and ARBITER Gate's audits of our own two
contracts (me/dogfood/*.gate.json). Scenarios:
  - verdict 3 registered -> deployAudited refused on-chain with NotDeployable(3)
  - the verified patch applied -> child record (verdict 1, parent, patchHash) -> deployed by
    the registry at the predicted address, LINK_GATED
  - verify by address / id / source / tx; evidence re-hash, rebuild, replay (forge)
  - escrow: paid, refunded on verdict 0, refunded after expiry, wrong auditor rejected
  - the morning demo (me.py demo) rehearsed: dogfood records, AuditRegistry claimed
    (LINK_CLAIMED), AuditEscrow deployed through the registry (LINK_GATED) and used for the
    escrow request/settle; interrupted and resumed, rerun, deployments from a run without
    dogfood, an escrow audit that may not be gated, too little MEC; input resolution
  - read-only against the ME testnet RPC: preflight with paris passes, shanghai -> PUSH0
Prints one line per check and "N of M" at the end. --offline skips the ME RPC checks.

    python3 me/scripts/me_registry_probe.py [--port 8720] [--offline] [--keep]
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path

ME = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ME))

import me as me_cli  # noqa: E402
from arbiter_me import abi, demo  # noqa: E402
from arbiter_me.bech32 import to_0x, to_me1  # noqa: E402
from arbiter_me.chain import (ANVIL_DEV_KEYS, ChainError, Client, DevKeySigner, cast, format_mec,  # noqa: E402
                              network, parse_mec)
from arbiter_me.contracts import (Escrow, Registry, creation_code, escrow_ctor_args,  # noqa: E402
                                  expected_runtime_hash)
from arbiter_me.dogfood import TARGETS, load_self  # noqa: E402
from arbiter_me.record import ARBITER_DIR, load_gate, plan_record, sha256_hex, verdict_code  # noqa: E402

JOB = ARBITER_DIR / "runs" / "gate" / "jobs" / "20261106-200206-977ff0"
RID = "be2e752405bb"  # the same result as saved by the web UI
SOURCE = ARBITER_DIR / "examples" / "StakingVault.sol"

results: list[tuple[bool, str]] = []


def check(ok: bool, name: str, detail: str = "") -> bool:
    results.append((bool(ok), name))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not ok else ""))
    return bool(ok)


def cli(*argv: str) -> tuple[int, str]:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = me_cli.main([str(a) for a in argv])
    return code, buf.getvalue()


def cli_json(*argv: str) -> tuple[int, dict]:
    code, out = cli(*argv, "--json")
    try:
        return code, json.loads(out)
    except json.JSONDecodeError:
        return code, {"_raw": out}


def start_anvil(port: int) -> subprocess.Popen:
    from arbiter_me.chain import find_tool
    proc = subprocess.Popen([find_tool("anvil"), "--port", str(port), "--silent"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    client = Client(network("anvil", f"http://127.0.0.1:{port}"))
    for _ in range(50):
        try:
            client.chain_id()
            return proc
        except ChainError:
            time.sleep(0.2)
    proc.kill()
    raise SystemExit(f"anvil did not start on port {port}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8720)
    ap.add_argument("--offline", action="store_true", help="skip the read-only ME testnet checks")
    ap.add_argument("--keep", action="store_true", help="keep the scratch directory")
    args = ap.parse_args()
    if not (JOB / "gate.json").exists():
        raise SystemExit(f"recording missing: {JOB}/gate.json")

    work = Path(tempfile.mkdtemp(prefix="me-registry-probe-"))
    anvil = start_anvil(args.port)
    rpc = f"http://127.0.0.1:{args.port}"
    try:
        run(work, rpc)
        demo_checks(work, rpc)
        if not args.offline:
            me_checks(work)
    finally:
        anvil.kill()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print(f"scratch: {work}")
    passed = sum(ok for ok, _ in results)
    print(f"\nme_registry_probe: {passed} of {len(results)} checks passed")
    return 0 if passed == len(results) else 1


def run(work: Path, rpc: str) -> None:
    client = Client(network("anvil", rpc))
    dep = work / "anvil.json"
    net = ["--network", "anvil", "--rpc", rpc, "--deployments", str(dep)]
    dev0 = cast("wallet", "address", "--private-key", ANVIL_DEV_KEYS[0]).lower()
    dev1 = cast("wallet", "address", "--private-key", ANVIL_DEV_KEYS[1]).lower()

    # ---- units and address forms (pure functions)
    check(format_mec(10**16) == "0.01 MEC" and parse_mec("0.01") == 10**16 and format_mec(0) == "0 MEC"
          and format_mec(2607140000000000) == "0.00260714 MEC", "MEC amounts use 18 decimals")
    check(to_0x(to_me1(dev0)) == dev0, "0x <-> me1 round trip")

    # ---- contracts
    code, out = cli("contracts", "deploy", *net, "--dev")
    d = json.loads(dep.read_text()) if dep.exists() else {}
    reg_addr = (d.get("registry") or {}).get("address")
    check(code == 0 and reg_addr and client.get_code(reg_addr) != "0x" and d.get("auditors") == [dev0],
          "contracts deploy writes registry, escrow and auditors", out)
    code, _ = cli("contracts", "deploy", *net, "--dev")
    check(code != 0, "contracts deploy refuses to overwrite an existing deployment")

    # ---- verdict 3: blocked
    job = work / "job"
    job.mkdir()
    shutil.copyfile(JOB / "gate.json", job / "gate.json")
    web = work / "web"
    web.mkdir()
    shutil.copyfile(ARBITER_DIR / "runs" / "gate" / "web" / f"{RID}.json", web / f"{RID}.json")
    code, r3 = cli_json("deploy", job / "gate.json", "--rid", RID, "--web-dir", web, "--source", SOURCE,
                        "--record-refusal", *net, "--dev")
    rec3 = r3.get("record") or {}
    dp3 = r3.get("deploy") or {}
    check(code == 0 and rec3.get("verdict") == 3 and rec3.get("verdictLabel") == "已證實可攻擊",
          "proven StakingVault registered as verdict 3", str(r3)[:400])
    check(dp3.get("status") == "blocked" and "NotDeployable(3)" in (dp3.get("reason") or ""),
          "deployAudited refused on-chain with NotDeployable(3)", str(dp3))
    rcpt = client.receipt(dp3.get("tx") or "0x" + "00" * 32) if dp3.get("tx") else None
    check(rcpt is not None and rcpt["status"] == "0x0", "--record-refusal sends the reverting deploy (status 0)")
    me_json = job / "me.json"
    side = json.loads(me_json.read_text()) if me_json.exists() else {}
    web_side = web / f"{RID}.me.json"
    check(side.get("schema") == "arbiter-me/0.1" and side.get("chainId") == 31337 and side.get("registry") == reg_addr
          and side["record"]["gateJsonHash"] == sha256_hex((JOB / "gate.json").read_bytes())
          and side["deploy"]["preflight"]["ok"] is True and web_side.exists()
          and json.loads(web_side.read_text())["record"]["id"] == rec3.get("id"),
          "me.json and <rid>.me.json follow BRIEF 4.2", str(side)[:300])
    id3 = rec3.get("id")

    # ---- patched child: deployed through the registry
    code, r1 = cli_json("deploy", job / "gate.json", "--rid", RID, "--web-dir", web, "--source", SOURCE,
                        "--patch", "--parent", id3, *net, "--dev")
    rec1, dp1 = r1.get("record") or {}, r1.get("deploy") or {}
    check(code == 0 and rec1.get("verdict") == 1 and rec1.get("parentId") == id3
          and rec1.get("patchHash") == rec3.get("patchHash") != "0x" + "00" * 32,
          "patched child registered: verdict 1, parent, same patchHash as the suggestion", str(r1)[:400])
    addr = dp1.get("address")
    check(dp1.get("status") == "deployed" and dp1.get("linkKind") == 2 and addr
          and client.code_hash(addr) == dp1.get("runtimeCodeHash"),
          "deployAudited deployed the patched bytecode (LINK_GATED, codehash matches)", str(dp1))
    reg = me_cli.verify.open_session(argparse.Namespace(network="anvil", rpc=rpc, deployments=dep)).registry
    salt = "0x" + int(rec1.get("id") or 0).to_bytes(32, "big").hex()
    check(addr and reg.predict(rec1["id"], dev0, salt).lower() == addr.lower(),
          "deployed at the address predicted before sending")
    side = json.loads(me_json.read_text())
    check(side["record"]["id"] == id3 and side.get("patched", {}).get("record", {}).get("id") == rec1.get("id")
          and side["patched"]["deploy"]["status"] == "deployed",
          "me.json keeps the gate result on top and adds the patched record under 'patched'")

    # ---- verify
    ev_patched, ev_parent = job / "me-evidence-patched", job / "me-evidence"
    code, v = cli_json("verify", addr, "--evidence", ev_patched, "--rebuild", "--replay", *net[:-2],
                       "--deployments", dep)
    rv = (v.get("records") or [{}])[0]
    check(code == 0 and rv.get("codehashMatches") is True and [p["id"] for p in rv.get("parents", [])] == [id3],
          "verify by address: codehash matches, parent chain shown", str(v)[:400])
    check(rv.get("evidence", {}).get("ok") is True, "verify --evidence: every hash matches the chain",
          json.dumps(rv.get("evidence"), ensure_ascii=False)[:500])
    check(rv.get("rebuild", {}).get("ok") is True, "verify --rebuild: recompiled initcode and runtime match",
          json.dumps(rv.get("rebuild"), ensure_ascii=False)[:500])
    check(rv.get("replay", {}).get("ok") is True,
          "verify --replay (patched): attack reproduces on the parent source, fails on the patched source",
          json.dumps(rv.get("replay"), ensure_ascii=False)[:600])
    code, v = cli_json("verify", str(id3), "--evidence", ev_parent, "--replay", *net[:-2], "--deployments", dep)
    rv = (v.get("records") or [{}])[0]
    check(code == 0 and rv.get("replay", {}).get("ok") and [c["id"] for c in rv.get("children", [])] == [rec1["id"]],
          "verify by id (verdict 3): replay applies patch.diff, children listed", str(v)[:400])
    code, v = cli_json("verify", "--source", SOURCE, *net[:-2], "--deployments", dep)
    check(id3 in [r["record"]["id"] for r in v.get("records", [])], "verify --source finds the record by sha256")
    code, v = cli_json("verify", r1["record"]["tx"], *net[:-2], "--deployments", dep)
    check([r["record"]["id"] for r in v.get("records", [])] == [rec1["id"]], "verify by tx hash parses Registered")
    bad = work / "tampered"
    shutil.copytree(ev_parent, bad)
    raw = (bad / "gate.json").read_bytes()
    (bad / "gate.json").write_bytes(raw.replace(b'"exit_code": 1', b'"exit_code": 0', 1))
    code, v = cli_json("verify", str(id3), "--evidence", bad, *net[:-2], "--deployments", dep)
    ev = (v.get("records") or [{}])[0].get("evidence", {})
    check(code == 1 and ev.get("ok") is False
          and any("gate.json" in c["what"] and not c["ok"] for c in ev.get("checks", [])),
          "a tampered gate.json is detected by verify --evidence")

    # ---- determinism of the bundle
    g = load_gate(job / "gate.json")
    m1 = plan_record(g, SOURCE, out_dir=work / "det1").manifest_sha256
    m2 = plan_record(g, SOURCE, out_dir=work / "det2").manifest_sha256
    check(m1 == m2 == json.loads(me_json.read_text())["evidence"]["manifest"],
          "the evidence bundle is deterministic (same manifest hash)")

    # ---- escrow
    src_hash = sha256_hex(SOURCE.read_bytes())
    esc_addr = d["escrow"]["address"]
    code, q = cli_json("escrow", "request", "--source-hash", src_hash, "--auditor", dev0, "--fee", "0.01",
                       *net, "--dev", "--dev-key", "1")
    req_paid = q.get("id")
    check(code == 0 and q.get("status") == "open" and client.balance(esc_addr) == 10**16,
          "escrow request locks 0.01 MEC", str(q))
    code, r = cli_json("register", job / "gate.json", "--source", SOURCE, "--escrow-request", req_paid,
                       "--evidence-out", work / "ev-paid", *net, "--dev")
    er = r.get("escrow_request") or {}
    check(code == 0 and er.get("status") == "paid" and er.get("recipient") == dev0 and er.get("fee_wei") == str(10**16),
          "a finished record (verdict 3) pays the auditor", str(er))

    job0 = work / "job0"
    job0.mkdir()
    g0 = json.loads((JOB / "gate.json").read_text(encoding="utf-8"))
    g0["files"][0].update(verdict="not_executed", label="無法判定（稽核未完成）", findings=[])
    (job0 / "gate.json").write_text(json.dumps(g0, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    code, q = cli_json("escrow", "request", "--source", SOURCE, "--auditor", dev0, "--fee", "0.02",
                       *net, "--dev", "--dev-key", "1")
    code, r = cli_json("register", job0 / "gate.json", "--source", SOURCE, "--escrow-request", q.get("id"),
                       *net, "--dev")
    er = r.get("escrow_request") or {}
    check(code == 0 and r["record"]["verdict"] == 0 and er.get("status") == "refunded" and er.get("recipient") == dev1,
          "a verdict-0 record (audit did not finish) refunds the requester", str(r)[:300])

    code, q = cli_json("escrow", "request", "--source", SOURCE, "--auditor", dev0, "--fee", "0.03", "--ttl", "3600",
                       *net, "--dev", "--dev-key", "1")
    req_exp = q.get("id")
    code, out = cli("escrow", "refund", req_exp, *net, "--dev", "--dev-key", "1")
    check(code != 0 and "NotExpired" in out, "refund before the deadline is rejected (NotExpired)", out)
    client.increase_time(3600 + 3600 + 1)  # ttl + the 1 h settlement grace (v2)
    code, r = cli_json("escrow", "refund", req_exp, *net, "--dev", "--dev-key", "1")
    code2, st = cli_json("escrow", "status", req_exp, *net[:-2], "--deployments", dep)
    check(code == 0 and r.get("status") == "refunded" and st.get("statusName") == "refunded",
          "after expiry the requester gets the fee back", str(r))

    code, q = cli_json("escrow", "request", "--source", SOURCE, "--auditor", dev1, "--fee", "0.01",
                       *net, "--dev", "--dev-key", "1")
    code, r = cli_json("register", job / "gate.json", "--source", SOURCE, "--evidence-out", work / "ev-w",
                       *net, "--dev")
    code, out = cli("escrow", "settle", q.get("id"), r["record"]["id"], *net, "--dev")
    check(code != 0 and "NotAuditor" in out, "only the named auditor may settle (v2)", out)
    code, out = cli("escrow", "settle", q.get("id"), r["record"]["id"], *net, "--dev", "--dev-key", "1")
    check(code != 0 and "WrongAuditor" in out, "settling with another auditor's record is rejected", out)
    check(client.balance(esc_addr) == 10**16, "escrow holds exactly the one open fee")

    # ---- dev key guard
    try:
        DevKeySigner(Client(network("anvil", rpc)), ANVIL_DEV_KEYS[0])
        guard = True
    except ChainError:
        guard = False
    check(guard, "the anvil dev key works on chain 31337")
    check(abi.keccak_hex(b"") == "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
          "pure-Python keccak256 matches the EVM")


SELF_GATES = {key: t.default_gate for key, t in TARGETS.items()}
SELF_ROWS = ("AuditRegistry 的稽核紀錄（用 ARBITER Gate 稽核自己的合約）", "宣告 AuditRegistry 本身的位址",
             "AuditEscrow 的稽核紀錄", "AuditEscrow 經由部署閘門部署（deployAudited）")
STAKING_ROWS = ("部署 AuditRegistry（paris 編譯", "：鎖住 0.001 MEC，指定稽核者與 StakingVault 原始碼的 sha256",
                "AI 證實 StakingVault 可被重入攻擊（判定 3）", "合約拒絕部署（NotDeployable(3)",
                "費用付給稽核者（判定是 3 也照付）", "修補後的 StakingVault（判定 1", "把修補後、稽核過的 bytecode 部署到")


def _scenario(d: Path, tag: str, rpc: str) -> tuple[list, dict]:
    """Files of one demo rehearsal (own deployments, state, job copy, web dir, evidence root)."""
    s = d / tag
    (s / "job").mkdir(parents=True)
    (s / "web").mkdir()
    shutil.copyfile(JOB / "gate.json", s / "job" / "gate.json")
    shutil.copyfile(ARBITER_DIR / "runs" / "gate" / "web" / f"{RID}.json", s / "web" / f"{RID}.json")
    p = {k: s / v for k, v in (("dep", "anvil.json"), ("state", "state.json"), ("md", "EVIDENCE.md"),
                               ("ev", "ev"), ("web", "web"), ("job", "job"))}
    argv = ["demo", "--dev", "--network", "anvil", "--rpc", rpc, "--deployments", p["dep"], "--state", p["state"],
            "--evidence-md", p["md"], "--web-dir", p["web"], "--evidence-root", p["ev"], "--job", p["job"]]
    return argv, p


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def _tx_rows(md_path: Path) -> list[str]:
    md = md_path.read_text(encoding="utf-8") if md_path.exists() else ""
    return [ln for ln in md.splitlines() if ln.startswith("| ") and "0x" in ln and ln.split("|")[1].strip().isdigit()]


def _verdict(gate_path: Path) -> int:
    return verdict_code((json.loads(gate_path.read_text(encoding="utf-8"))["files"][0]).get("verdict"))


@contextlib.contextmanager
def _env(**values: str | None):
    old = {k: os.environ.get(k) for k in values}
    try:
        for k, v in values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def demo_checks(work: Path, rpc: str) -> None:
    """The morning script's flow (me.py demo), rehearsed on anvil. A scenario that crashes is
    reported as a failed check with the reason, and the next scenario still runs."""
    ctx = {"client": Client(network("anvil", rpc)), "d": work / "demo", "work": work, "rpc": rpc,
           "dev0": cast("wallet", "address", "--private-key", ANVIL_DEV_KEYS[0]).lower(),
           "v_reg": _verdict(SELF_GATES["registry"]), "v_esc": _verdict(SELF_GATES["escrow"])}
    # the low-balance scenario empties the dev account, so it runs last
    for name, fn in (("inputs", _demo_inputs), ("stale dogfood", _demo_stale), ("fresh run", _demo_fresh),
                     ("run without dogfood", _demo_legacy), ("unfinished escrow audit", _demo_unfinished),
                     ("low balance", _demo_low_balance)):
        try:
            fn(ctx)
        except Exception as exc:  # noqa: BLE001 - a crash is a failed check, with its reason
            check(False, f"demo scenario '{name}' ran to the end",
                  f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-800:]}")


def _net(ctx: dict, p: dict) -> list:
    return ["--network", "anvil", "--rpc", ctx["rpc"], "--deployments", p["dep"]]


def _demo_inputs(ctx: dict) -> None:
    """--job / ME_DEMO_JOB / evidence root resolution (no chain)."""
    work = ctx["work"]
    with _env(ME_DEMO_JOB=None, ME_EVIDENCE_BASE_ROOT=None, ME_EVIDENCE_BASE_URL=None):
        ok = demo.resolve_job(None) == (demo.JOB, demo.JOB / "gate.json")
        ok &= demo.evidence_urls() == (f"{demo.EVIDENCE_ROOT_URL}/staking-vault", f"{demo.EVIDENCE_ROOT_URL}/self")
    with _env(ME_DEMO_JOB=JOB.name):
        ok &= demo.resolve_job(None) == (JOB, JOB / "gate.json")  # a bare job id
        ok &= demo.resolve_job(str(work)) == (work, work / "gate.json")  # --job wins over the env
        ok &= demo.resolve_job(None, work / "x.json") == (work, work / "x.json")
    with _env(ME_EVIDENCE_BASE_ROOT=None, ME_EVIDENCE_BASE_URL="https://h.example/x/staking-vault/"):
        ok &= demo.evidence_urls() == ("https://h.example/x/staking-vault", "https://h.example/x/self")
    with _env(ME_EVIDENCE_BASE_ROOT="https://r.example/ev/", ME_EVIDENCE_BASE_URL=None):
        ok &= demo.evidence_urls() == ("https://r.example/ev/staking-vault", "https://r.example/ev/self")
    with _env(ME_EVIDENCE_BASE_ROOT=""):
        ok &= demo.evidence_urls() == ("", "")
    check(ok, "demo inputs: --job, ME_DEMO_JOB (path or job id), evidence root -> staking-vault/ and self/ "
              "(ME_EVIDENCE_BASE_URL still works)")


def _demo_stale(ctx: dict) -> None:
    """A dogfood audit of another version of the source is refused outside anvil."""
    work = ctx["work"]
    g = json.loads(SELF_GATES["registry"].read_text(encoding="utf-8"))
    stale, fresh = work / "stale.gate.json", work / "fresh.gate.json"
    g["files"][0]["artifact"]["sha256"] = "00" * 32
    stale.write_text(json.dumps(g, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    g["files"][0]["artifact"]["sha256"] = sha256_hex(TARGETS["registry"].source.read_bytes())[2:]
    fresh.write_text(json.dumps(g, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    try:
        load_self(TARGETS["registry"], stale, rehearsal=False)
        refused = False
    except ChainError as exc:
        refused = "另一版" in str(exc) and "--no-dogfood" in str(exc)
    passed = load_self(TARGETS["registry"], fresh, rehearsal=False).stale is None \
        and load_self(TARGETS["registry"], stale, rehearsal=True).stale == "0x" + "00" * 32
    check(refused and passed, "dogfood: a gate.json that audited another version of the source is refused outside anvil")


def _demo_fresh(ctx: dict) -> None:
    """A fresh run interrupted after 1d, resumed, checked in detail, then rerun."""
    client, dev0, v_reg, v_esc = ctx["client"], ctx["dev0"], ctx["v_reg"], ctx["v_esc"]
    A, a = _scenario(ctx["d"], "a", ctx["rpc"])
    code, out = cli(*A, "--stop-after", "1d")
    st = _load(a["state"])
    s = st.get("self") or {}
    reg_addr = ((st.get("contracts") or {}).get("registry") or {}).get("address")
    reg = Registry(client, reg_addr)
    check(code == 0 and reg.record_count() == 2 and not a["dep"].exists()
          and s.get("registry", {}).get("record", {}).get("id") == 1 and s.get("registry", {}).get("link")
          and s.get("escrow", {}).get("record", {}).get("id") == 2 and not s.get("escrow", {}).get("deploy"),
          "demo: an interrupted run keeps 1a-1d in the state (stopped after 1d, no deployment file yet)", out[-600:])
    code, out = cli(*A)
    st, dep = _load(a["state"]), _load(a["dep"])
    check(code == 0 and out.count("跳過") == 4 and reg.record_count() == 4
          and dep.get("registry", {}).get("address") == reg_addr,
          "demo: the rerun resumes at 1e without repeating 1a-1d (same registry, no duplicate records)", out[-600:])

    rows = _tx_rows(a["md"])
    md = a["md"].read_text(encoding="utf-8")
    side = _load(a["web"] / f"{RID}.me.json")
    # a claim needs a deployable verdict (1/2); a non-deployable escrow audit is deployed plainly
    want = [t for t, on in zip(SELF_ROWS, (True, v_reg in (1, 2), True, v_esc in (1, 2))) if on]
    check(len(rows) == 10 + (v_reg in (1, 2)) and all(any(t in r for r in rows) for t in want + list(STAKING_ROWS))
          and side.get("escrow_request", {}).get("status") == "paid" and side.get("deploy", {}).get("status") == "blocked"
          and side.get("patched", {}).get("deploy", {}).get("status") == "deployed",
          "demo: EVIDENCE.md lists 11 txs (the four dogfood rows and every StakingVault row) and the web sidecar",
          f"{len(rows)} rows")
    ok = True
    for path in (a["job"] / "gate.json", SELF_GATES["registry"], SELF_GATES["escrow"]):
        gj = json.loads(path.read_text(encoding="utf-8"))
        row = next((ln for ln in md.splitlines() if ln.startswith("| ") and sha256_hex(path.read_bytes()) in ln), "")
        ok &= demo._when(gj.get("generated_at")) in row and (gj.get("tool_commit") or "gate.json 沒有記錄") in row
    check(ok, "demo: EVIDENCE.md states when each gate.json was produced (generated_at) and its tool_commit")

    r1 = reg.record(1)
    claimed = r1["linkKind"] == 1 and r1["deployed"] == reg_addr and reg.claims_of(reg_addr) == [1]
    check(r1["sourceHash"] == sha256_hex(TARGETS["registry"].source.read_bytes())
          and r1["gateJsonHash"] == sha256_hex(SELF_GATES["registry"].read_bytes()) and r1["verdict"] == v_reg
          and r1["initcodeHash"] == abi.keccak_hex(creation_code("AuditRegistry"))
          and client.code_hash(reg_addr) == expected_runtime_hash("AuditRegistry") == dep["registry"]["codehash"]
          and (claimed if v_reg in (1, 2) else r1["linkKind"] == 0) and reg.deployment_of(reg_addr) == 0,
          "demo: AuditRegistry's own audit record (sourceHash, gate.json, artifact initcode) claims the registry "
          "(LINK_CLAIMED; on-chain codehash = artifact runtime)", json.dumps(r1)[:400])
    esc = dep["escrow"]["address"]
    r2 = reg.record(2)
    gated = (dep["escrow"].get("deployedVia") == "deployAudited" and dep["escrow"].get("record") == 2
             and reg.deployment_of(esc) == 2 and r2["linkKind"] == 2 and r2["deployed"] == esc
             and reg.predict(2, dev0, "0x" + (2).to_bytes(32, "big").hex()) == esc
             and client.code_hash(esc) == expected_runtime_hash("AuditEscrow", reg_addr))
    check(r2["sourceHash"] == sha256_hex(TARGETS["escrow"].source.read_bytes())
          and r2["gateJsonHash"] == sha256_hex(SELF_GATES["escrow"].read_bytes()) and r2["verdict"] == v_esc
          and r2["initcodeHash"] == abi.keccak_hex(creation_code("AuditEscrow") + escrow_ctor_args(reg_addr)[2:])
          and (gated if v_esc in (1, 2) else dep["escrow"].get("deployedVia") == "create"),
          "demo: AuditEscrow is deployed through the registry (deployAudited, LINK_GATED, predicted address, "
          "initcode includes the registry)", json.dumps(dep.get("escrow"))[:300])
    q = Escrow(client, esc).get(st["escrow"]["id"])
    check(st["escrow"].get("contract") == esc and side.get("escrow") == esc and q["status"] == 2
          and q["recordId"] == st["blocked"]["record"]["id"] and client.balance(esc) == 0,
          "demo: the escrow request is locked and settled (paid) in the gated AuditEscrow", str(q))
    code, v = cli_json("verify", reg_addr, "--evidence", a["ev"] / "self" / "registry", "--rebuild", *_net(ctx, a))
    rv = (v.get("records") or [{}])[0]
    check(code == 0 and rv.get("record", {}).get("id") == 1 and rv.get("evidence", {}).get("ok")
          and rv.get("rebuild", {}).get("ok") and rv.get("codehashMatches") is True,
          "verify: the registry's own address finds its audit (claim); evidence and rebuild match", str(v)[:400])
    code, v = cli_json("verify", esc, "--evidence", a["ev"] / "self" / "escrow", "--rebuild", *_net(ctx, a))
    rv = (v.get("records") or [{}])[0]
    check(code == 0 and rv.get("record", {}).get("id") == 2 and rv.get("evidence", {}).get("ok")
          and rv.get("rebuild", {}).get("ok"),
          "verify: the gated AuditEscrow rebuilds from its bundle (the imported AuditRegistry.sol is in it)",
          str(v)[:400])
    block = client.block_number()
    code, out = cli(*A)
    check(code == 0 and client.block_number() == block and out.count("跳過") == 8,
          "demo: a rerun skips every finished step and sends nothing", out[-400:])
    # the crash window: 1b-1e were mined but their state was never saved (and no deployment file)
    st = _load(a["state"])
    st.pop("self")
    a["state"].write_text(json.dumps(st, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    a["dep"].unlink()
    code, out = cli(*A)
    s2, dep2 = (_load(a["state"]).get("self") or {}), _load(a["dep"])
    check(code == 0 and client.block_number() == block and reg.record_count() == 4
          and s2.get("registry", {}).get("record", {}).get("reused") and s2.get("registry", {}).get("link", {}).get("reused")
          and s2.get("escrow", {}).get("record", {}).get("reused") and s2.get("escrow", {}).get("deploy", {}).get("reused")
          and dep2.get("escrow", {}).get("address") == esc and dep2["escrow"].get("tx") == dep["escrow"]["tx"],
          "demo: dogfood steps mined before an unsaved state are found on chain and not sent again", out[-500:])


def _demo_legacy(ctx: dict) -> None:
    """A run without dogfood first (as before this feature), then the dogfood steps are added."""
    client, v_reg, v_esc = ctx["client"], ctx["v_reg"], ctx["v_esc"]
    B, b = _scenario(ctx["d"], "b", ctx["rpc"])
    code, out = cli(*B, "--no-dogfood")
    old = _load(b["dep"])
    plain = (old.get("escrow") or {}).get("address")
    check(code == 0 and len(_tx_rows(b["md"])) == 8 and plain and "deployedVia" not in old["escrow"],
          "demo --no-dogfood: both contracts deployed plainly, EVIDENCE.md lists the 8 StakingVault-story txs",
          out[-400:])
    code, out = cli(*B)
    dep, st = _load(b["dep"]), _load(b["state"])
    breg = Registry(client, dep["registry"]["address"])
    sb = st.get("self") or {}
    ids = ((sb.get("registry") or {}).get("record", {}).get("id"), (sb.get("escrow") or {}).get("record", {}).get("id"))
    rows = _tx_rows(b["md"])
    md = b["md"].read_text(encoding="utf-8")
    claims = (v_reg in (1, 2), v_esc in (1, 2))
    added = rows[8:]  # chronological: the dogfood rows come after the older run's
    check(code == 0 and sb.get("mode") == "legacy" and dep["escrow"]["address"] == plain and ids == (3, 4)
          and breg.deployment_of(plain) == 0
          and (breg.record(3)["deployed"] == dep["registry"]["address"]) == claims[0]
          and (breg.record(4)["linkKind"] == 1 and breg.record(4)["deployed"] == plain) == claims[1]
          and len(rows) == 10 + sum(claims) and "維持原樣" in md and bool(added) and SELF_ROWS[0] in added[0]
          and any("宣告既有 AuditEscrow 的位址" in r for r in added) == claims[1] and SELF_ROWS[3] not in md,
          "demo: deployments from a run without dogfood get the records as extra steps; the escrow stays "
          "(claimed, not redeployed) and EVIDENCE.md says so", out[-500:])


def _demo_unfinished(ctx: dict) -> None:
    """An escrow audit that may not be deployed through the gate -> plain deployment, reason recorded."""
    client = ctx["client"]
    D, dd = _scenario(ctx["d"], "d", ctx["rpc"])
    g0 = json.loads(SELF_GATES["escrow"].read_text(encoding="utf-8"))
    g0["files"][0].update(verdict="not_executed", label="無法判定（稽核未完成）", findings=[])
    unfinished = ctx["work"] / "escrow-unfinished.gate.json"
    unfinished.write_text(json.dumps(g0, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    code, out = cli(*D, "--self-escrow-gate", unfinished, "--stop-after", "1e")
    dep = _load(dd["dep"])
    e = dep["escrow"]
    dreg = Registry(client, dep["registry"]["address"])
    check(code == 0 and e.get("deployedVia") == "create" and "判定是 0" in (e.get("reason") or "")
          and dreg.record(2)["verdict"] == 0 and dreg.record(2)["linkKind"] == 0 and dreg.deployment_of(e["address"]) == 0
          and client.code_hash(e["address"]) == expected_runtime_hash("AuditEscrow", dep["registry"]["address"]),
          "demo: an escrow audit with verdict 0 is registered as 0 and the escrow is deployed plainly, with the reason",
          out[-500:])


def _demo_low_balance(ctx: dict) -> None:
    E, ee = _scenario(ctx["d"], "e", ctx["rpc"])
    ctx["client"].rpc("anvil_setBalance", [ctx["dev0"], "0x0"])
    code, out = cli(*E)
    check(code == 3 and "水龍頭" in out and "me1" in out and not ee["dep"].exists() and not ee["state"].exists(),
          "demo: with too little MEC it stops before sending and shows the faucet and me1 address", out[-400:])


def me_checks(work: Path) -> None:
    """Read-only calls against the ME testnet RPC (eth_chainId / eth_estimateGas only)."""
    me = ["--network", "me-testnet"]
    code, r = cli_json("preflight", "AuditRegistry", *me)
    check(code == 0 and r.get("ok") and r.get("gas", 0) > 1_000_000, "ME: AuditRegistry (paris) passes preflight",
          str(r))
    code, r = cli_json("preflight", "AuditEscrow", *me)
    check(code == 0 and r.get("ok") and r.get("gas", 0) > 500_000, "ME: AuditEscrow (paris) passes preflight", str(r))
    code, r = cli_json("preflight", SOURCE, *me)
    check(code == 0 and r.get("ok"), "ME: StakingVault compiled for paris passes preflight", str(r))
    code, r = cli_json("preflight", SOURCE, "--evm-version", "shanghai", *me)
    check(code == 1 and r.get("push0") is True and "paris" in (r.get("error") or "") and r.get("push0InBytecode"),
          "ME: StakingVault compiled for shanghai is rejected with a PUSH0 hint", str(r))
    client = Client(network("me-testnet"))
    evm_tx = "0x59ff81116a4dc5574974e562fad35432b14745caedde57c5e65ce0b813c9bb4d"  # a past third-party EVM tx
    cosmos = client.cosmos_tx_hash(evm_tx)
    check(cosmos == "A6B03922FA00284A224A1C4F62E7ED0E24E8F56E266E4BFDD602CE62A29F6E0E"
          and client.network.tx_url(evm_tx, cosmos).endswith(f"/zh-TW/transactions/{cosmos}?netType=hub"),
          "ME: an EVM tx is linked on the explorer through its Cosmos tx hash", str(cosmos))
    try:
        DevKeySigner(Client(network("me-testnet")))
        refused = False
    except ChainError:
        refused = True
    check(refused, "ME: the anvil dev key is refused on chain 400")


if __name__ == "__main__":
    sys.exit(main())
