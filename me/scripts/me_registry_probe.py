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
  - review findings me-tools-1..13 (hardening): the replay sandbox (a bundle's own
    regression.zip with ffi is never run; an anchored exploit cannot use ffi, files, the
    caller's environment or the network; a forged zip is reported; no solc preinstalled), the
    gate.json cross-check (verdict 1 over a proven gate.json), a patched record with an extra
    backdoor, escrow pre-check and resumable deploy/register, verify of a second gated
    deployment, CRLF sources, the escrow help text, a dirty tool commit, the keystore password
    file on SIGTERM/SIGHUP/SIGINT, and logs behind a node that caps eth_getLogs at 10,000 blocks
  - read-only against the ME testnet RPC: preflight with paris passes, shanghai -> PUSH0
Prints one line per check and "N of M" at the end. --offline skips the ME RPC checks.
Ports: anvil on --port, a local listener on --port+5, the capped-log proxy on --port+6.

    python3 me/scripts/me_registry_probe.py [--port 8720] [--offline] [--keep]
"""
from __future__ import annotations

import argparse
import contextlib
import http.server
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request
import zipfile
from pathlib import Path

ME = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ME))

import me as me_cli  # noqa: E402
from arbiter_me import abi, demo  # noqa: E402
from arbiter_me import build as build_mod  # noqa: E402
from arbiter_me import deploy as deploy_mod  # noqa: E402
from arbiter_me import escrow as escrow_mod  # noqa: E402
from arbiter_me.bech32 import to_0x, to_me1  # noqa: E402
from arbiter_me.build import compile_source  # noqa: E402
from arbiter_me.chain import (ANVIL_DEV_KEYS, ZERO32, ChainError, Client, DevKeySigner, cast, format_mec,  # noqa: E402
                              network, parse_mec)
from arbiter_me.contracts import (Escrow, Registry, creation_code, escrow_ctor_args,  # noqa: E402
                                  expected_runtime_hash)
from arbiter_me.dogfood import TARGETS, load_self  # noqa: E402
from arbiter_me.record import ARBITER_DIR, load_gate, plan_record, sha256_hex, verdict_code  # noqa: E402
from arbiter_me.session import open_session  # noqa: E402

JOB = ARBITER_DIR / "runs" / "gate" / "jobs" / "20261106-200206-977ff0"
RID = "be2e752405bb"  # the same result as saved by the web UI
SOURCE = ARBITER_DIR / "examples" / "StakingVault.sol"
TP_SOURCE = Path(__file__).resolve().parent.parent / "examples" / "PrimeYieldVault.sol"  # me.py two-party

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
        ctx = run(work, rpc)
        ctx["port"] = args.port
        hardening_checks(ctx)
        signal_checks()
        demo_checks(work, rpc)
        capped_log_checks(ctx)  # last: mines 12,000 blocks
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
    return {"work": work, "rpc": rpc, "dep": dep, "net": net, "dev0": dev0, "dev1": dev1, "id3": id3,
            "rec3": rec3, "rec1": rec1, "dp1": dp1, "ev_parent": ev_parent, "ev_patched": ev_patched,
            "escrow": esc_addr}


# ------------------------------------------------------------------ hardening (review findings me-tools-*)

# An extra test a malicious bundle can put into its own regression.zip (with ffi = true).
ZZ_SOL = """// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

contract Zz {
    function testZz() public {
        string[] memory c = new string[](3);
        c[0] = "sh";
        c[1] = "-c";
        c[2] = "id > __MARKER__";
        (bool ok, ) = address(uint160(uint256(keccak256("hevm cheat code")))).call(
            abi.encodeWithSignature("ffi(string[])", c));
        ok;
    }
}
"""

# Injected into an exploit that is then registered (anchored by exploitHash): it tries every way
# out of the replay sandbox, each through a low-level call so a refusal does not stop the attack.
# The attack still reproduces only if the caller's environment is invisible.
SANDBOX_ESCAPE = """
        {
            address _cv = address(uint160(uint256(keccak256("hevm cheat code"))));
            string[] memory _cmd = new string[](3);
            _cmd[0] = "sh";
            _cmd[1] = "-c";
            _cmd[2] = "touch __FFI__";
            (bool _a, ) = _cv.call(abi.encodeWithSignature("ffi(string[])", _cmd));
            (bool _b, ) = _cv.call(abi.encodeWithSignature("writeFile(string,string)", "__FS__", "x"));
            (bool _c, bytes memory _env) = _cv.call(
                abi.encodeWithSignature("envOr(string,string)", "ARBITER_PROBE_SECRET", ""));
            require(!_c || bytes(abi.decode(_env, (string))).length == 0, "ARBITER probe: environment visible");
            (bool _d, ) = _cv.call(abi.encodeWithSignature("createSelectFork(string)", "__URL__"));
            _a;
            _b;
            _d;
        }
"""


@contextlib.contextmanager
def scenario(name: str):
    """A scenario that raises (as the unfixed tools do on some inputs) is a FAIL, not a crash."""
    try:
        yield
    except Exception as exc:  # noqa: BLE001
        check(False, f"{name} (scenario raised)", f"{type(exc).__name__}: {exc}"[:400])


def _session(ctx: dict, key: int = 0):
    return open_session(argparse.Namespace(network="anvil", rpc=ctx["rpc"], deployments=ctx["dep"], dev=True,
                                           dev_key=key), need_deployment=True)


def _job(ctx: dict, name: str) -> Path:
    d = ctx["work"] / name
    d.mkdir()
    shutil.copyfile(JOB / "gate.json", d / "gate.json")
    return d


def _refresh_manifest(bundle: Path, record_input: dict | None = None, drop_roles: tuple = ()) -> None:
    """What a forger does after editing a bundle: re-hash the files (the manifest is not on chain)."""
    m = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    m["files"] = [f for f in m["files"] if f["role"] not in drop_roles]
    for f in m["files"]:
        f["sha256"] = sha256_hex((bundle / f["name"]).read_bytes())
    if record_input is not None:
        m["recordInput"] = record_input
    (bundle / "manifest.json").write_text(json.dumps(m, indent=1, sort_keys=True, ensure_ascii=False) + "\n",
                                          encoding="utf-8")


def _rezip(bundle: Path, edit) -> None:
    path = bundle / "regression.zip"
    with zipfile.ZipFile(path) as zf:
        files = {n: zf.read(n) for n in zf.namelist()}
    files = edit(files)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in sorted(files):
            zf.writestr(n, files[n])


def _results_with(ctx: dict, mutate) -> Path:
    """A copy of the run's results.jsonl with the proven PoC's Solidity changed."""
    g = json.loads((JOB / "gate.json").read_text(encoding="utf-8"))
    rows = [json.loads(ln) for ln in (ARBITER_DIR / g["input"]["results"]).read_text(encoding="utf-8").splitlines()
            if ln.strip()]
    for row in rows:
        for p in row["outcome"]["pocs"]:
            if p.get("passed") and p.get("adjudicated") and p.get("solidity"):
                p["solidity"] = mutate(p["solidity"])
    out = ctx["work"] / f"results-{len(list(ctx['work'].glob('results-*.jsonl')))}.jsonl"
    out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return out


def _checks(rv: dict, key: str, text: str) -> list[dict]:
    return [c for c in (rv.get(key) or {}).get("checks", []) if text in c.get("what", "")]


class _Listener:
    """A local HTTP endpoint that counts requests (a sandboxed fork cheatcode must not reach it)."""

    def __init__(self, port: int):
        hits = self.hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                hits.append(self.path)
                self.send_response(500)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def hardening_checks(ctx: dict) -> None:
    for fn in (replay_sandbox_checks, cross_check_checks, escrow_resume_checks, gated_address_checks,
               crlf_help_dirty_checks):
        with scenario(fn.__name__):
            fn(ctx)


def replay_sandbox_checks(ctx: dict) -> None:
    """me-tools-1, -2, -8: what verify --replay executes, and with what."""
    work, net, dep, id3 = ctx["work"], ctx["net"], ctx["dep"], ctx["id3"]
    ro = [*net[:-2], "--deployments", dep]

    # me-tools-1: a bundle whose regression.zip turns ffi on and adds a test that runs a command
    ev = work / "ev-ffi"
    shutil.copytree(ctx["ev_parent"], ev)
    marker = work / "PWNED"

    def ffi_zip(files: dict) -> dict:
        top = next(iter(files)).split("/")[0]
        toml = files[f"{top}/foundry.toml"].decode()
        files[f"{top}/foundry.toml"] = toml.replace("ffi = false", "ffi = true").encode()
        files[f"{top}/test/arbiter/Zz.t.sol"] = ZZ_SOL.replace("__MARKER__", str(marker)).encode()
        return files
    _rezip(ev, ffi_zip)
    code, v = cli_json("verify", id3, "--evidence", ev, "--replay", *ro)
    rv = (v.get("records") or [{}])[0]
    zipc = _checks(rv, "replay", "regression.zip")
    repro = _checks(rv, "replay", "攻擊在原始碼上重現")
    check(not marker.exists() and zipc and not zipc[0]["ok"] and "Zz.t.sol" in str(zipc[0]["actual"])
          and "ffi" in str(zipc[0]["actual"]) and repro and repro[0]["ok"],
          "verify --replay never runs the bundle's regression.zip (its ffi test does not execute; the zip is "
          "reported, the anchored attack still reproduces)",
          f"marker={marker.exists()} " + json.dumps(rv.get("replay"), ensure_ascii=False)[:500])

    # me-tools-1: an anchored exploit (registered, so exploitHash matches) that tries ffi, a file
    # write, the caller's environment and the network from inside the replay
    jd = _job(ctx, "job-mal")
    ffi_m, fs_m = work / "MAL_FFI", work / "MAL_FS"
    listener = _Listener(ctx["port"] + 5)
    url = f"http://127.0.0.1:{ctx['port'] + 5}"
    escape = SANDBOX_ESCAPE.replace("__FFI__", str(ffi_m)).replace("__FS__", str(fs_m)).replace("__URL__", url)
    res = _results_with(ctx, lambda s: s.replace("function arbSetup() external {",
                                                 "function arbSetup() external {" + escape, 1))
    ev = work / "ev-mal"
    code, r = cli_json("register", jd / "gate.json", "--source", SOURCE, "--results", res, "--evidence-out", ev,
                       *net, "--dev")
    mal = (r.get("record") or {}).get("id")
    os.environ["ARBITER_PROBE_SECRET"] = "probe-secret-value"
    try:
        code, v = cli_json("verify", mal, "--evidence", ev, "--replay", *ro)
    finally:
        os.environ.pop("ARBITER_PROBE_SECRET", None)
        listener.close()
    rv = (v.get("records") or [{}])[0]
    repro = _checks(rv, "replay", "攻擊在原始碼上重現")
    check(bool(mal) and not ffi_m.exists() and not fs_m.exists() and bool(repro) and repro[0]["ok"],
          "an anchored exploit cannot use ffi, write files or read the caller's environment during --replay",
          f"ffi={ffi_m.exists()} fs={fs_m.exists()} " + json.dumps(rv.get("replay"), ensure_ascii=False)[:500])
    if (rv.get("replay") or {}).get("networkIsolated"):
        check(not listener.hits, "an anchored exploit cannot reach the network during --replay (unshare)",
              f"{len(listener.hits)} request(s) reached the local listener")
    else:
        print("SKIP  network isolation (unshare -rn is not available here; not counted)")

    # me-tools-2: a forged regression.zip (honest paths removed, manifest re-hashed) is not what runs
    ev = work / "ev-forged"
    shutil.copytree(ctx["ev_parent"], ev)

    def forge_zip(files: dict) -> dict:
        top = next(iter(files)).split("/")[0]
        name = f"{top}/test/arbiter/ArbiterRegression.t.sol"
        text = files[name].decode()
        files[name] = re.sub(r"^\s*function testHonestPath\d+\(\) public \{[^\n]*\}\n", "", text, flags=re.M).encode()
        return files
    _rezip(ev, forge_zip)
    _refresh_manifest(ev)
    code, v = cli_json("verify", id3, "--evidence", ev, "--replay", *ro)
    rv = (v.get("records") or [{}])[0]
    zipc = _checks(rv, "replay", "regression.zip")
    honest = _checks(rv, "replay", "原始碼上沒有攻擊時的誠實路徑")
    check(code == 1 and zipc and not zipc[0]["ok"] and "ArbiterRegression.t.sol" in str(zipc[0]["actual"])
          and honest and honest[0]["ok"] and str(honest[0]["actual"]).startswith("4 個測試"),
          "a forged regression.zip is reported; the replay runs the test rebuilt from the anchored exploit "
          "(4 honest paths from gate.json, none vacuous)", json.dumps(rv.get("replay"), ensure_ascii=False)[:600])

    # me-tools-8: no solc 0.8.20 installed (empty HOME); the tool must provide it, forge stays offline
    real = build_mod.find_solc("0.8.20")
    asked: list[str] = []
    orig_find, orig_home = build_mod.find_solc, os.environ.get("HOME")

    def fake_find(version: str = "0.8.24") -> str:
        asked.append(version)
        return real if version == "0.8.20" else orig_find(version)
    empty = work / "empty-home"
    empty.mkdir()
    build_mod.find_solc = fake_find
    os.environ["HOME"] = str(empty)
    try:
        code, v = cli_json("verify", id3, "--evidence", ctx["ev_parent"], "--replay", *ro)
    finally:
        build_mod.find_solc = orig_find
        os.environ["HOME"] = orig_home or ""
    rv = (v.get("records") or [{}])[0]
    check(code == 0 and (rv.get("replay") or {}).get("ok") and "0.8.20" in asked,
          "verify --replay works without a preinstalled solc: it asks find_solc for 0.8.20, forge stays --offline",
          f"asked={asked} " + str(v)[:400])


def cross_check_checks(ctx: dict) -> None:
    """me-tools-3 (on-chain verdict vs the anchored gate.json) and me-tools-4 (patched source)."""
    work, net, dep, id3 = ctx["work"], ctx["net"], ctx["dep"], ctx["id3"]
    ro = [*net[:-2], "--deployments", dep]
    g = load_gate(_job(ctx, "job-e8") / "gate.json")
    s1 = _session(ctx, 1)

    # verdict 1 registered over a gate.json that says proven_exploitable, deployed through the gate
    ev = work / "ev-e8"
    plan = plan_record(g, SOURCE, out_dir=ev)
    plan.input.update(verdict=1, predicateClass=0, evidenceTier=0, exploitHash=ZERO32)
    _refresh_manifest(ev, plan.input, drop_roles=("exploit",))
    reg = deploy_mod.register_record(s1, plan)
    d = deploy_mod.deploy_through_registry(s1, reg["id"], plan.build)
    code, v = cli_json("verify", d["address"], "--evidence", ev, "--rebuild", "--replay", *ro)
    rv = (v.get("records") or [{}])[0]
    bad = [c for c in (rv.get("evidence") or {}).get("checks", []) if not c["ok"]]
    check(d["status"] == "deployed" and code == 1 and (rv.get("evidence") or {}).get("verdictMismatch") is True
          and any("判定" in c["what"] and str(c["expected"]) == "3" and str(c["actual"]) == "1" for c in bad),
          "verify reports a verdict-1 record whose anchored gate.json says proven_exploitable",
          json.dumps(rv.get("evidence"), ensure_ascii=False)[-700:])

    # same, but the bundle still carries the exploit: replaying it must count against verdict 1
    ev = work / "ev-e8b"
    plan = plan_record(g, SOURCE, out_dir=ev)
    plan.input.update(verdict=1, predicateClass=0, evidenceTier=0, exploitHash=ZERO32)
    _refresh_manifest(ev, plan.input)
    reg = deploy_mod.register_record(s1, plan)
    code, v = cli_json("verify", reg["id"], "--evidence", ev, "--replay", *ro)
    rv = (v.get("records") or [{}])[0]
    contra = [c for c in (rv.get("replay") or {}).get("checks", [])
              if "不能成功" in c["what"] and not c.get("level")]
    check(code == 1 and contra and not contra[0]["ok"] and (rv.get("replay") or {}).get("ok") is False,
          "replaying a bundle's exploit that succeeds against a verdict-1 record is a failure",
          json.dumps(rv.get("replay"), ensure_ascii=False)[:500])

    # me-tools-4: a patched child whose source is the verified patch plus a backdoor
    s0 = _session(ctx, 0)
    ev = work / "ev-e1"
    plan = plan_record(g, SOURCE, out_dir=ev, patched=True, parent_id=id3)
    srcp = ev / "src" / "StakingVault.sol"
    text = srcp.read_text(encoding="utf-8")
    cut = text.rstrip().rfind("}")
    bad_src = text[:cut] + "    function sweep() external { payable(msg.sender).transfer(address(this).balance); }\n}\n"
    srcp.write_text(bad_src, encoding="utf-8")
    b = compile_source(bad_src, "StakingVault.sol", evm_version="paris")
    plan.input.update(sourceHash=sha256_hex(bad_src.encode("utf-8")), initcodeHash=b.initcode_hash)
    plan.build = b
    _refresh_manifest(ev, plan.input)
    reg = deploy_mod.register_record(s0, plan)
    d = deploy_mod.deploy_through_registry(s0, reg["id"], b)
    code, v = cli_json("verify", d["address"], "--evidence", ev, "--rebuild", "--replay", *ro)
    rv = (v.get("records") or [{}])[0]
    deriv = _checks(rv, "evidence", "patch.diff")
    deriv = [c for c in deriv if "上一版原始碼套用" in c["what"]]
    check(d["status"] == "deployed" and code == 1 and deriv and not deriv[0]["ok"],
          "verify flags a patched record whose source is not parent source + patch.diff (extra backdoor)",
          json.dumps(rv.get("evidence"), ensure_ascii=False)[-600:])


def escrow_resume_checks(ctx: dict) -> None:
    """me-tools-7: nothing is sent for a request this record cannot settle; a failing step is
    recorded in me.json and a rerun finishes it without registering again."""
    net, dep, dev0 = ctx["net"], ctx["dep"], ctx["dev0"]
    reg = _session(ctx, 0).registry
    code, q = cli_json("escrow", "request", "--source", SOURCE, "--auditor", dev0, "--fee", "0.01",
                       *net, "--dev", "--dev-key", "1")
    req = q.get("id")
    jd = _job(ctx, "job-e4")
    before = reg.record_count()
    code, out = cli("deploy", jd / "gate.json", "--source", SOURCE, "--patch", "--parent", ctx["id3"],
                    "--escrow-request", req, "--evidence-out", ctx["work"] / "ev-e4p", *net, "--dev")
    check(code != 0 and reg.record_count() == before and "沒有送出任何交易" in out,
          "a request the patched record cannot settle (other source) is refused before anything is sent", out[-400:])

    # the settle transaction fails (a network hiccup): me.json still records the registered record
    orig_settle = escrow_mod.settle

    def broken(*a, **k):
        raise ChainError("simulated network failure")
    escrow_mod.settle = broken
    argv = ["register", jd / "gate.json", "--source", SOURCE, "--escrow-request", req,
            "--evidence-out", ctx["work"] / "ev-e4", *net, "--dev"]
    try:
        code, r = cli_json(*argv)
    finally:
        escrow_mod.settle = orig_settle
    side = json.loads((jd / "me.json").read_text()) if (jd / "me.json").exists() else {}
    er = side.get("escrow_request") or {}
    check(code == 1 and (side.get("record") or {}).get("id") == before + 1 and side.get("pending") == ["settle"]
          and er.get("status") == "open" and "simulated" in str(er.get("settleError")),
          "a failing settle is recorded in me.json (record, pending, error) instead of aborting", str(side)[:400])
    code, r = cli_json(*argv)
    side = json.loads((jd / "me.json").read_text()) if (jd / "me.json").exists() else {}
    check(code == 0 and reg.record_count() == before + 1 and (side.get("escrow_request") or {}).get("status") == "paid"
          and not side.get("pending") and r.get("resumed") is True,
          "rerunning the same command settles with the same record (no duplicate registration)", str(r)[:400])

    # deployAudited fails mid-way: the rerun deploys the record it already registered
    jd = _job(ctx, "job-e4d")
    orig_deploy = deploy_mod.deploy_through_registry

    def broken_deploy(*a, **k):
        raise ChainError("simulated receipt timeout")
    deploy_mod.deploy_through_registry = broken_deploy
    argv = ["deploy", jd / "gate.json", "--source", SOURCE, "--patch", "--parent", ctx["id3"],
            "--evidence-out", ctx["work"] / "ev-e4d", *net, "--dev"]
    before = reg.record_count()
    try:
        code, r = cli_json(*argv)
    finally:
        deploy_mod.deploy_through_registry = orig_deploy
    side_path = next((p for p in (jd / "me.patched.json", jd / "me.json") if p.exists()), None)
    side = json.loads(side_path.read_text()) if side_path else {}
    part = side.get("patched") or side
    check(code == 1 and (part.get("record") or {}).get("id") == before + 1 and part.get("pending") == ["deploy"]
          and (part.get("deploy") or {}).get("status") == "failed",
          "a failing deployAudited leaves me.json with the registered record and 'deploy' pending", str(side)[:400])
    code, r = cli_json(*argv)
    check(code == 0 and reg.record_count() == before + 1 and (r.get("deploy") or {}).get("status") == "deployed"
          and (r.get("record") or {}).get("id") == before + 1,
          "rerunning deploys the record already registered (no duplicate)", str(r)[:400])


def gated_address_checks(ctx: dict) -> None:
    """me-tools-10: a second gated deployment of a record whose first link is a claim."""
    work, net, dep = ctx["work"], ctx["net"], ctx["dep"]
    s0 = _session(ctx, 0)
    g = load_gate(_job(ctx, "job-e9") / "gate.json")
    ev = work / "ev-e9"
    plan = plan_record(g, SOURCE, out_dir=ev, patched=True, parent_id=ctx["id3"])
    reg = deploy_mod.register_record(s0, plan)
    s0.send(s0.registry.address, abi.encode_call("linkDeployment(uint256,address)", reg["id"], ctx["escrow"]))
    d = deploy_mod.deploy_through_registry(s0, reg["id"], plan.build)
    code, v = cli_json("verify", d["address"], "--evidence", ev, "--rebuild", *net[:-2], "--deployments", dep)
    rv = (v.get("records") or [{}])[0]
    check(code == 0 and (rv.get("rebuild") or {}).get("ok") and rv.get("linkKindAtAddress") == 2
          and str((rv.get("firstLink") or {}).get("address", "")).lower() == ctx["escrow"].lower()
          and rv.get("codehashMatches") is True,
          "verify <gated address> compares the address asked about, not the record's first (claimed) link",
          json.dumps({k: rv.get(k) for k in ("rebuild", "firstLink", "linkKindAtAddress")}, ensure_ascii=False)[:500])


def crlf_help_dirty_checks(ctx: dict) -> None:
    """me-tools-11 (CRLF upload), -12 (escrow help), -13 (dirty tool commit)."""
    work, net, dep, dev0 = ctx["work"], ctx["net"], ctx["dep"], ctx["dev0"]
    ro = [*net[:-2], "--deployments", dep]
    lf_hash = sha256_hex(SOURCE.read_bytes())
    crlf = work / "crlf" / "StakingVault.sol"
    crlf.parent.mkdir()
    crlf.write_bytes(SOURCE.read_bytes().replace(b"\n", b"\r\n"))
    jd = _job(ctx, "job-crlf")
    code, r = cli_json("deploy", jd / "gate.json", "--source", crlf, "--dry-run", "--evidence-out", work / "ev-crlf",
                       *net, "--dev")
    check(code == 0 and (r.get("recordInput") or {}).get("sourceHash") == lf_hash
          and any("CRLF" in n for n in r.get("notes") or [])
          and sha256_hex((work / "ev-crlf" / "src" / "StakingVault.sol").read_bytes()) == lf_hash,
          "a CRLF copy of the audited file is accepted: sourceHash and src/ are the LF text the gate audited", str(r)[:300])
    code, v = cli_json("verify", "--source", crlf, *ro)
    check(ctx["id3"] in [x["record"]["id"] for x in v.get("records", [])], "verify --source finds the record from a CRLF copy")
    code, q = cli_json("escrow", "request", "--source", crlf, "--auditor", dev0, "--fee", "0.001", *net, "--dev",
                       "--dev-key", "1")
    code, st = cli_json("escrow", "status", q.get("id"), *ro)
    check(str(st.get("sourceHash", "")).lower() == lf_hash, "escrow request --source hashes the LF text too", str(st))

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        me_cli.main(["escrow", "--help"])
    text = buf.getvalue()
    check("任何人都可以送" not in text and "只有委託指定的稽核者能送" in text and "任何人都能送" in text,
          "escrow --help: only the named auditor settles; anyone may send the refund after the grace period", text[-400:])

    for flag in ("source-text", "flag"):
        jd = _job(ctx, f"job-dirty-{flag}")
        g = json.loads((jd / "gate.json").read_text(encoding="utf-8"))
        g["tool_commit"] = "ab" * 20
        if flag == "flag":
            g.update(tool_commit_source="git HEAD", tool_commit_dirty=True)
        else:
            g["tool_commit_source"] = "git HEAD（有未提交的修改）"
        (jd / "gate.json").write_text(json.dumps(g, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        ev = work / f"ev-dirty-{flag}"
        code, out = cli("deploy", jd / "gate.json", "--source", SOURCE, "--dry-run", "--evidence-out", ev, *net, "--dev")
        code2, r = cli_json("register", jd / "gate.json", "--source", SOURCE, "--evidence-out", ev, *net, "--dev")
        rec = r.get("record") or {}
        man = json.loads((ev / "manifest.json").read_text(encoding="utf-8")) if (ev / "manifest.json").exists() else {}
        code3, vout = cli("verify", rec.get("id", 0), "--evidence", ev, *ro)
        check(code == 0 and "有未提交的修改" in out and code2 == 0 and rec.get("toolCommitDirty") is True
              and man.get("toolCommitDirty") is True and "有未提交的修改" in vout,
              f"a dirty tool commit ({flag}) is marked in the output, the sidecar, the manifest and verify",
              f"{out[-200:]} | {str(rec)[:200]} | {vout[-200:]}")


def signal_checks() -> None:
    """me-tools-9: the keystore password file is removed when the process is stopped."""
    child = ("import sys, time\nsys.path.insert(0, sys.argv[1])\nfrom arbiter_me.chain import KeystoreSigner\n"
             "s = KeystoreSigner('probe-account', address='0x' + '11' * 20)\nprint(s._pwfile, flush=True)\n"
             "time.sleep(60)\n")
    for name in ("SIGTERM", "SIGHUP", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        # A new session has no controlling terminal, so getpass reads the password from stdin.
        p = subprocess.Popen([sys.executable, "-c", child, str(ME)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True, start_new_session=True)
        try:
            p.stdin.write("probe-password\n")
            p.stdin.flush()
            line: list[str] = []
            t = threading.Thread(target=lambda: line.append(p.stdout.readline().strip()), daemon=True)
            t.start()
            t.join(20)
            pw = Path(line[0]) if line and line[0] else None
            existed = bool(pw and pw.exists() and pw.read_text() == "probe-password")
            p.send_signal(sig)
            p.wait(timeout=20)
        finally:
            if p.poll() is None:
                p.kill()
        check(existed and not pw.exists() and not pw.parent.exists(),
              f"the keystore password file is removed when the signer process gets {name}",
              f"existed={existed} left={bool(pw and pw.exists())}")


class _CapProxy(http.server.BaseHTTPRequestHandler):
    """JSON-RPC proxy that refuses eth_getLogs over more than 10,000 blocks, as ME's node does."""
    upstream = ""

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("content-length") or 0))
        req = json.loads(body)
        if req.get("method") == "eth_getLogs":
            f = (req.get("params") or [{}])[0]
            latest = int(self._up({"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []})["result"], 16)

            def num(tag):
                return latest if tag in (None, "latest", "pending", "safe", "finalized") else (
                    0 if tag == "earliest" else int(tag, 16))
            if num(f.get("toBlock")) - num(f.get("fromBlock", "earliest")) > 10_000:
                return self._reply({"jsonrpc": "2.0", "id": req.get("id"),
                                    "error": {"code": -32000, "message": "maximum [from, to] blocks distance: 10000"}})
        return self._reply(self._up(req))

    def _up(self, payload: dict) -> dict:
        r = urllib.request.Request(self.upstream, data=json.dumps(payload).encode(),
                                   headers={"content-type": "application/json"})
        with urllib.request.urlopen(r, timeout=30) as resp:
            return json.loads(resp.read().decode())

    def _reply(self, doc: dict) -> None:
        data = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def capped_log_checks(ctx: dict) -> None:
    """me-tools-5: verify against a node that caps eth_getLogs at 10,000 blocks, long after the
    records were registered."""
    with scenario("capped_log_checks"):
        client = Client(network("anvil", ctx["rpc"]))
        client.rpc("anvil_mine", [hex(12_000), hex(5)])
        _CapProxy.upstream = ctx["rpc"]
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", ctx["port"] + 6), _CapProxy)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        proxy = f"http://127.0.0.1:{ctx['port'] + 6}"
        try:
            dep2 = ctx["work"] / "anvil-noblock.json"
            d = json.loads(Path(ctx["dep"]).read_text())
            d["registry"].pop("block", None)
            dep2.write_text(json.dumps(d))
            for label, depfile in (("", ctx["dep"]), (" (deployment file without a block)", dep2)):
                code, v = cli_json("verify", ctx["id3"], "--network", "anvil", "--rpc", proxy, "--deployments", depfile)
                r3 = (v.get("records") or [{}])[0]
                code2, v2 = cli_json("verify", ctx["dp1"]["address"], "--network", "anvil", "--rpc", proxy,
                                     "--deployments", depfile)
                r1 = (v2.get("records") or [{}])[0]
                check(code == 0 and code2 == 0 and r3.get("registeredTx") == ctx["rec3"]["tx"]
                      and r1.get("registeredTx") == ctx["rec1"]["tx"] and r1.get("linkedTx") == ctx["dp1"]["tx"],
                      f"verify works 12,000 blocks later behind a 10,000-block eth_getLogs cap{label}",
                      f"{str(v)[:200]} | {str(v2)[:200]}")
        finally:
            srv.shutdown()
            srv.server_close()


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
    for name, fn in (("inputs", _demo_inputs), ("stale dogfood", _demo_stale), ("fresh run", _demo_fresh), ("two wallets", _demo_two_party),
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


def _tp_gate(dst: Path, source: Path) -> Path:
    """A verdict-1 gate.json for `source`, made from the recording (anvil rehearsal only)."""
    g = json.loads((JOB / "gate.json").read_text(encoding="utf-8"))
    f = dict(g["files"][0])
    f.update(id=f"file::{source.stem}", path=source.name,
             artifact={"uri": source.name, "sha256": sha256_hex(source.read_bytes())[2:]},
             verdict="no_provable_attack", label="未發現可證明攻擊（不等於安全）", reason="no_finding",
             findings=[], static_hints=[])
    g["files"] = [f]
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "gate.json").write_text(json.dumps(g, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return dst / "gate.json"


def _demo_two_party(ctx: dict) -> None:
    """me.py two-party on the fresh run's deployment: a second account requests, the auditor settles,
    the requester deploys through the gate, the request nobody settles is refunded after expiry."""
    client, dev0 = ctx["client"], ctx["dev0"]
    dev1 = cast("wallet", "address", "--private-key", ANVIL_DEV_KEYS[1]).lower()
    s = ctx["d"] / "a"
    dep_path, md, ev, st_path = s / "anvil.json", s / "EVIDENCE.md", s / "ev", s / "two-party.json"
    dep = _load(dep_path)
    reg, esc = Registry(client, dep["registry"]["address"]), Escrow(client, dep["escrow"]["address"])
    net = ["--network", "anvil", "--rpc", ctx["rpc"], "--deployments", dep_path, "--state", st_path,
           "--demo-state", s / "state.json", "--evidence-md", md, "--evidence-root", ev]
    rows_before = len(_tx_rows(md))
    gate = _tp_gate(s / "tp-job", TP_SOURCE)

    def tp(*a):
        return cli("two-party", *a, *net)

    code, out = tp("request", "--source", TP_SOURCE, "--dev")
    check(code != 0 and "同一個地址" in out, "two-party: the auditor's own account cannot be the requester", out[-300:])
    code, out = tp("settle", "--gate", gate, "--dev")
    check(code != 0 and "還沒有委託" in out, "two-party: settle before any request is refused", out[-300:])

    n0, bal0 = esc.request_count(), client.balance(esc.address)
    code, out = tp("request", "--source", TP_SOURCE, "--note", "probe note", "--dev", "--dev-key", "1")
    st = _load(st_path)
    rq = st.get("requests") or {}
    span = lambda k: (lambda q: q["deadline"] - q["createdAt"])(esc.get(rq[k]["id"])) if k in rq else None  # noqa: E731
    check(code == 0 and esc.request_count() == n0 + 2 and st.get("requester") == dev1 and st.get("auditor") == dev0
          and client.balance(esc.address) == bal0 + 2 * 10**15 and span("paid") == 7 * 24 * 3600 and span("expire") == 3600,
          "two-party: the second account locks two fees naming the auditor (7 days and 1 hour)", out[-400:])
    code, out = tp("request", "--source", TP_SOURCE, "--dev", "--dev-key", "1")
    check(code == 0 and esc.request_count() == n0 + 2, "two-party: rerunning request sends nothing", out[-300:])

    code, out = tp("settle", "--gate", gate, "--dev", "--dev-key", "1")
    check(code != 0 and "稽核者" in out, "two-party: only the named auditor's account may settle", out[-300:])
    code, out = tp("deploy", "--dev", "--dev-key", "1")
    check(code != 0 and "還沒有稽核紀錄" in out, "two-party: deploy before the record is refused", out[-300:])

    code, out = tp("settle", "--gate", gate, "--dev")
    st = _load(st_path)
    rec, stl = st.get("record") or {}, st.get("settle") or {}
    rid = rec.get("id")
    check(code == 0 and rec.get("verdict") == 1 and rid and reg.record(rid)["auditor"].lower() == dev0
          and stl.get("status") == "paid" and str(stl.get("recipient")).lower() == dev0
          and client.balance(esc.address) == bal0 + 10**15,
          "two-party: the auditor registers its record and the escrow pays it", out[-400:])
    code, out = tp("settle", "--gate", gate, "--dev")
    check(code == 0 and "跳過" in out and reg.record_count() == rid, "two-party: rerunning settle sends nothing", out[-300:])

    code, out = tp("deploy", "--dev")
    check(code != 0 and "委託人" in out, "two-party: the deploy step belongs to the requester", out[-300:])
    code, out = tp("deploy", "--dev", "--dev-key", "1")
    st = _load(st_path)
    d = st.get("deploy") or {}
    want = reg.predict(rid, dev1, deploy_mod.salt_for(rid)).lower() if rid else None
    check(code == 0 and d.get("status") == "deployed" and d.get("address") == want and reg.deployment_of(want) == rid
          and want != reg.predict(rid, dev0, deploy_mod.salt_for(rid)).lower() and d.get("deployer") == dev1,
          "two-party: the requester deploys the audited bytecode at the address bound to it (LINK_GATED)", out[-400:])

    code, out = tp("refund", "--dev", "--dev-key", "1")
    check(code != 0 and "還不能退款" in out, "two-party: refund waits for the deadline plus the grace", out[-300:])
    client.increase_time(3600 + 3600 + 1)
    code, out = tp("refund", "--dev", "--dev-key", "1")
    st = _load(st_path)
    rf = st.get("refund") or {}
    check(code == 0 and rf.get("status") == "refunded" and str(rf.get("recipient")).lower() == dev1
          and client.balance(esc.address) == bal0 and esc.get(rq["expire"]["id"])["status"] == 3,
          "two-party: after the deadline plus the grace the requester gets its fee back", out[-400:])

    rows, text = _tx_rows(md), md.read_text(encoding="utf-8")
    check("## 兩個錢包的託管示範" in text and "probe note" in text and len(rows) == rows_before + 6
          and rows[rows_before].startswith(f"| {rows_before + 1} |")
          and text.count("| 委託人 |") == 4 and text.count("| 稽核者 |") == 2 and "（委託人部署）" in text,
          "two-party: EVIDENCE.md lists the six transactions after the first table, with who sent each", text[-700:])
    code, out = tp("status")
    check(code == 0 and "全部完成" in out, "two-party: status says every step is done", out[-300:])
    code, out = cli("verify", d.get("address"), "--network", "anvil", "--rpc", ctx["rpc"], "--deployments", dep_path,
                    "--evidence", ev / "two-party", "--rebuild")
    check(code == 0, "two-party: me.py verify rebuilds the requester's deployment from the bundle", out[-500:])
    code, out = cli("deploy", "--record", rid, "--source", TP_SOURCE, "--network", "anvil", "--rpc", ctx["rpc"],
                    "--deployments", dep_path, "--dev", "--dev-key", "1")
    check(code == 0 and "先前的執行已經部署" in out, "deploy --record: a deployed record is not deployed twice", out[-300:])


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
