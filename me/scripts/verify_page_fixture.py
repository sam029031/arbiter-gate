#!/usr/bin/env python3
"""Test data for the static verify page (me/web/verify/), standard library + Foundry only.

AuditRegistry v2 accepts only empty or https:// evidence URIs, so the fixture is served over
TLS with a throwaway self-signed certificate:

    anvil --port 8741 &
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=127.0.0.1 \
        -addext subjectAltName=IP:127.0.0.1 -keyout /tmp/vp_key.pem -out /tmp/vp_cert.pem
    python3 me/scripts/verify_page_fixture.py --rpc http://127.0.0.1:8741 --root /tmp/vp_root \
        --evidence-url https://127.0.0.1:8751/evidence
    python3 me/scripts/verify_page_fixture.py --serve 8751 --root /tmp/vp_root \
        --cert /tmp/vp_cert.pem --key /tmp/vp_key.pem &
    # open https://127.0.0.1:8751/me/web/verify/?rpc=http%3A%2F%2F127.0.0.1%3A8741&record=1

It deploys AuditRegistry + AuditEscrow (contract v2) and writes, under --root:
  me/deployments/anvil.json  the deployment file the page reads, plus the optional keys
                             "auditors" (account A only) and "publicToolCommits"
  me/web -> <repo>/me/web    a symlink, so the page is served at /me/web/verify/
  evidence/r1..r3/           evidence bundles. r1 uses the first manifest format
                             ("arbiter-evidence/0.1", role gateJson); r2 the one
                             me/arbiter_me/record.py writes ("arbiter-me-evidence/0.1", role
                             gate_json, parent_src/, regression.zip, compiler.json); r3's
                             gate.json is altered after registration, so the page must show a mismatch
  fixture.json               record ids, tx hashes and addresses for the checks

Accounts: A = anvil dev account 0 (the listed auditor), B = dev account 1 (not listed).
Records (all marked as test data inside their gate.json):
  1  A, verdict 3 (strict predicate, evidence tier 3) for DemoVault.sol; escrow request 1
     (B pays, A audits) is settled by A with it (paid); deployAudited(1) reverts NotDeployable.
     Then --log-gap empty blocks are mined, so a node that caps eth_getLogs at 10,000 blocks
     (like ME) cannot answer a whole-range query (the browser check's capped proxy).
  2  A, verdict 1, parent 1 with patchHash: the patched DemoVault.sol, deployed through
     deployAudited twice, by A and by B (two addresses, each at its predicted address).
  3  A, verdict 0 for DemoToken.sol; escrow request 2 (B pays) is settled by A with it (refunded).
  4  B, verdict 2 for DemoCounter.sol, deployed outside the registry and claimed by B
     (linkDeployment); no evidence URI; its tool commit is listed as public.
  5  B, verdict 3 for the patched DemoVault bytecode: another account disputes record 2.
  6  A, verdict 1 for the original DemoVault.sol (same bytecode A proved exploitable in record 1):
     deployAudited(6) reverts ContradictsProvenRecord, and record 1 has a newer record by A.

    python3 me/scripts/verify_page_fixture.py --vectors me/web/verify/test/vectors.json

writes ABI test vectors encoded by `cast` for the page's decoder unit tests (no chain needed).
"""
from __future__ import annotations

import argparse
import difflib
import functools
import hashlib
import http.server
import io
import json
import os
import ssl
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ME_DIR = Path(__file__).resolve().parent.parent
REPO = ME_DIR.parent
sys.path.insert(0, str(ME_DIR))

from arbiter_me import bech32, chain, contracts  # noqa: E402
from arbiter_me.chain import ANVIL_DEV_KEYS, ChainError, Client, DevKeySigner, Network  # noqa: E402

ZERO32 = "0x" + "00" * 32
# sam029031/arbiter-gate main (public). The fixture's deployment file lists it in
# "publicToolCommits", so the page links record 4's commit and shows the others as plain text.
PUBLIC_COMMIT = "eb3af189e9abcb2e3e8617233575b7370210286b"
FEE_WEI = 10**16  # 0.01 of the native coin per escrow request
SALT = "0x" + "00" * 31 + "01"

NOTE = "verify page 測試資料（本機 anvil），不是真的稽核結果"

VAULT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Test data for the ARBITER Gate verify page. Local chains only.
contract DemoVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
    }
}
"""
VAULT_PATCHED = VAULT.replace(
    """        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] = 0;
""",
    """        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
""",
)
EXPLOIT = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Test data: the shape of an exploit file in an evidence bundle (not compiled here).
import {Test} from "forge-std/Test.sol";
import {DemoVault} from "../src/DemoVault.sol";

contract Reenter {
    DemoVault immutable vault;
    constructor(DemoVault v) payable { vault = v; }
    function go() external { vault.deposit{value: 1 ether}(); vault.withdraw(); }
    receive() external payable { if (address(vault).balance >= 1 ether) vault.withdraw(); }
}

contract DemoVaultExploit is Test {
    function test_drain() public {
        DemoVault vault = new DemoVault();
        vm.deal(address(this), 10 ether);
        vault.deposit{value: 9 ether}();
        Reenter r = new Reenter{value: 1 ether}(vault);
        r.go();
        assertEq(address(vault).balance, 0);
    }
}
"""
# record 5: what another account says breaks the patched vault (test data, not a real exploit)
DISPUTE = EXPLOIT.replace("contract DemoVaultExploit", "contract DemoVaultPatchedClaim")
TOKEN = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Test data for the ARBITER Gate verify page.
contract DemoToken {
    mapping(address => uint256) public balanceOf;
    function mint(uint256 amount) external { balanceOf[msg.sender] += amount; }
}
"""
COUNTER = """// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

// Test data for the ARBITER Gate verify page.
contract DemoCounter {
    address public owner = tx.origin;
    uint256 public count;
    function bump() external { count += 1; }
    function reset() external { require(tx.origin == owner, "owner"); count = 0; }
}
"""

FOUNDRY_TOML = """[profile.default]
src = "src"
out = "out"
solc_version = "0.8.24"
evm_version = "paris"
optimizer = true
optimizer_runs = 200
bytecode_hash = "none"
cbor_metadata = false
"""


def sha256_hex(data: str | bytes) -> str:
    raw = data.encode() if isinstance(data, str) else data
    return "0x" + hashlib.sha256(raw).hexdigest()


def gate_json(obj: dict) -> str:
    """Serialised the way web.py serves gate.json, so the hash convention is the same."""
    return json.dumps(obj, ensure_ascii=False, indent=1) + "\n"


def compile_initcode(name: str, source: str) -> str:
    """Creation bytecode of contract `name`, built with the registry's compiler settings."""
    with tempfile.TemporaryDirectory(prefix="vp-build-") as tmp:
        root = Path(tmp)
        (root / "src").mkdir()
        (root / "src" / f"{name}.sol").write_text(source)
        (root / "foundry.toml").write_text(FOUNDRY_TOML)
        proc = subprocess.run([chain.find_tool("forge"), "build", "--root", str(root)],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            raise ChainError(f"forge build {name} failed:\n{proc.stdout[-1500:]}{proc.stderr[-1500:]}")
        art = json.loads((root / "out" / f"{name}.sol" / f"{name}.json").read_text())
        return art["bytecode"]["object"]


def deterministic_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            zf.writestr(info, files[name])
    return buf.getvalue()


def topic(signature: str) -> str:
    return chain.cast("keccak", signature)


def event_topics(receipt: dict, address: str, signature: str) -> list[str]:
    want = topic(signature)
    for log in receipt.get("logs") or []:
        if log["address"].lower() == address.lower() and log["topics"][0] == want:
            return log["topics"]
    raise ChainError(f"no {signature} log in {receipt.get('transactionHash')}")


def write_bundle(root: Path, name: str, files: dict[str, tuple[str, str | bytes]], schema: str) -> None:
    """files: path inside the bundle -> (role, content). Writes the files and manifest.json."""
    d = root / "evidence" / name
    listed = []
    for fname, (role, content) in files.items():
        raw = content.encode() if isinstance(content, str) else content
        (d / fname).parent.mkdir(parents=True, exist_ok=True)
        (d / fname).write_bytes(raw)
        listed.append({"name": fname, "role": role, "sha256": sha256_hex(raw)})
    manifest = {"schema": schema, "note": NOTE, "files": listed}
    (d / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=1) + "\n")


def expect_revert(client: Client, to: str, data: str, sender: str, error: str) -> None:
    ok, _, err = contracts.simulate(client, to, data, sender=sender)
    if ok or not err or err[0] != error:
        raise ChainError(f"expected {error}, got {'success' if ok else err}")


class Fixture:
    """One account sending fixture transactions to the registry and the escrow."""

    def __init__(self, client: Client, signer: DevKeySigner, registry: str, escrow: str):
        self.client, self.signer, self.registry, self.escrow = client, signer, registry, escrow
        self.address = signer.address

    def send(self, to: str | None, data: str, value: int = 0) -> dict:
        return self.signer.send(self.client, to, data, value=value)

    def register(self, *, source: str, verdict: int, gate: str, commit: str, initcode: str = "",
                 exploit: str = "", patch: str = "", parent: int = 0, pred: int = 0, tier: int = 0,
                 model: str = "arbiter-gpt", uri: str = "") -> tuple[int, str]:
        fields = [
            sha256_hex(source),
            chain.keccak(initcode) if initcode else ZERO32,
            str(verdict), str(pred), str(tier),
            sha256_hex(gate),
            sha256_hex(exploit) if exploit else ZERO32,
            sha256_hex(patch) if patch else ZERO32,
            str(parent),
            "0x" + commit[:40],
            model,
            uri or '""',
        ]
        data = chain.calldata(contracts.SIG["register"], "(" + ",".join(fields) + ")")
        receipt = self.send(self.registry, data)
        topics = event_topics(receipt, self.registry, contracts.EVENT_REGISTERED)
        return int(topics[1], 16), receipt["transactionHash"]

    def deploy(self, rid: int, initcode: str) -> tuple[str, str]:
        """deployAudited from this account; checks the address predictAddress gave beforehand."""
        reg = contracts.Registry(self.client, self.registry)
        predicted = reg.predict(rid, self.address, SALT)
        receipt = self.send(self.registry, contracts.Registry.deploy_data(rid, initcode, SALT))
        linked = event_topics(receipt, self.registry, contracts.EVENT_LINKED)
        addr = chain.cast("to-check-sum-address", "0x" + linked[2][-40:])
        if addr.lower() != predicted.lower():
            raise ChainError(f"deployAudited({rid}) by {self.address} went to {addr}, predicted {predicted}")
        return addr, receipt["transactionHash"]

    def link(self, rid: int, address: str) -> str:
        return self.send(self.registry, chain.calldata(contracts.SIG["linkDeployment"], str(rid), address))[
            "transactionHash"]

    def request(self, source: str, auditor: str) -> tuple[int, str]:
        data = chain.calldata(contracts.SIG["escrow.request"], sha256_hex(source), auditor, "3600")
        receipt = self.send(self.escrow, data, value=FEE_WEI)
        topics = event_topics(receipt, self.escrow, contracts.EVENT_REQUESTED)
        return int(topics[1], 16), receipt["transactionHash"]

    def settle(self, request_id: int, record_id: int) -> str:
        data = chain.calldata(contracts.SIG["escrow.settle"], str(request_id), str(record_id))
        return self.send(self.escrow, data)["transactionHash"]


def build_chain(args: argparse.Namespace) -> dict:
    root = Path(args.root).resolve()
    client = Client(Network(name="anvil", rpc=args.rpc, chain_id=31337))
    signer_a = DevKeySigner(client, ANVIL_DEV_KEYS[0])  # both refuse any chain id other than 31337
    signer_b = DevKeySigner(client, ANVIL_DEV_KEYS[1])
    dep_path = root / "me" / "deployments" / "anvil.json"
    dep = contracts.deploy_contracts(client, signer_a, out_path=dep_path)
    dep["auditors"] = [{"address": signer_a.address, "name": "示範稽核者（anvil 測試帳號）"}]
    dep["publicToolCommits"] = [PUBLIC_COMMIT]
    dep_path.write_text(json.dumps(dep, ensure_ascii=False, indent=2) + "\n")

    web_link = root / "me" / "web"
    if web_link.is_symlink() or web_link.exists():
        web_link.unlink()
    web_link.symlink_to(REPO / "me" / "web", target_is_directory=True)

    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()
    registry, escrow = dep["registry"]["address"], dep["escrow"]["address"]
    a = Fixture(client, signer_a, registry, escrow)
    b = Fixture(client, signer_b, registry, escrow)
    base = args.evidence_url.rstrip("/")
    vault_init = compile_initcode("DemoVault", VAULT)
    patched_init = compile_initcode("DemoVault", VAULT_PATCHED)
    counter_init = compile_initcode("DemoCounter", COUNTER)
    patch = "".join(difflib.unified_diff(VAULT.splitlines(True), VAULT_PATCHED.splitlines(True),
                                         "a/src/DemoVault.sol", "b/src/DemoVault.sol"))
    gate_base = {"schema": "arbiter-gate/0.1", "fixture": NOTE, "models": ["arbiter-gpt"]}

    # 1: proven exploit; B paid A through escrow request 1, A settles it with this record
    gate1 = gate_json({**gate_base, "exit_code": 1,
                       "files": [{"path": "DemoVault.sol", "verdict": "proven_exploitable",
                                  "label": "已證實可攻擊（擋部署）",
                                  "findings": [{"vuln_class": "reentrancy", "predicate": "victim_loss",
                                                "evidence": {"reached": 3}, "patch": {"status": "verified"}}]}]})
    write_bundle(root, "r1", {"gate.json": ("gateJson", gate1), "DemoVault.sol": ("source", VAULT),
                              "DemoVaultExploit.t.sol": ("exploit", EXPLOIT), "patch.diff": ("patch", patch)},
                 schema="arbiter-evidence/0.1")
    req1, req1_tx = b.request(VAULT, a.address)
    r1, r1_tx = a.register(source=VAULT, verdict=3, pred=2, tier=3, gate=gate1, exploit=EXPLOIT, patch=patch,
                           initcode=vault_init, commit=head, uri=f"{base}/r1/")
    settle1_tx = a.settle(req1, r1)
    expect_revert(client, registry, contracts.Registry.deploy_data(r1, vault_init, SALT), a.address, "NotDeployable")

    # older than the node's eth_getLogs window from here on (anvil_mine: count, seconds apart)
    if args.log_gap:
        client.rpc("anvil_mine", [hex(args.log_gap), "0x1"])

    # 2: the patched source, re-audited by the same auditor, deployed through the registry by A and by B
    gate2 = gate_json({**gate_base, "exit_code": 0,
                       "files": [{"path": "DemoVault.sol", "verdict": "no_provable_attack",
                                  "label": "未發現可證明攻擊（不等於安全）", "findings": []}]})
    compiler = json.dumps({"compiler": "solc 0.8.24", "settings": {"evmVersion": "paris", "optimizer":
                                                                   {"enabled": True, "runs": 200},
                                                                   "metadata": {"bytecodeHash": "none"}},
                           "file": "DemoVault.sol", "contract": "DemoVault", "constructorArgs": "0x"},
                          indent=1, sort_keys=True) + "\n"
    regression = deterministic_zip({"arbiter-regression-DemoVault/foundry.toml": FOUNDRY_TOML,
                                    "arbiter-regression-DemoVault/src/DemoVault.sol": VAULT,
                                    "arbiter-regression-DemoVault/test/DemoVaultExploit.t.sol": EXPLOIT})
    write_bundle(root, "r2", {"compiler.json": ("compiler", compiler),
                              "exploit/DemoVaultExploit.t.sol": ("exploit", EXPLOIT),
                              "gate.json": ("gate_json", gate2),
                              "parent_src/DemoVault.sol": ("parent_source", VAULT),
                              "patch.diff": ("patch", patch),
                              "regression.zip": ("regression", regression),
                              "src/DemoVault.sol": ("source", VAULT_PATCHED)},
                 schema="arbiter-me-evidence/0.1")
    r2, r2_tx = a.register(source=VAULT_PATCHED, verdict=1, gate=gate2, patch=patch, parent=r1,
                           initcode=patched_init, commit=head, uri=f"{base}/r2/")
    deployed2a, deploy2a_tx = a.deploy(r2, patched_init)
    deployed2b, deploy2b_tx = b.deploy(r2, patched_init)

    # 3: unfinished audit; B paid A through escrow request 2, refunded; gate.json altered afterwards
    gate3 = gate_json({**gate_base, "exit_code": 2,
                       "files": [{"path": "DemoToken.sol", "verdict": "not_executed",
                                  "label": "無法判定（稽核未完成）", "reason": "context_unbuildable"}]})
    req2, req2_tx = b.request(TOKEN, a.address)
    r3, r3_tx = a.register(source=TOKEN, verdict=0, gate=gate3, commit=head, uri=f"{base}/r3/")
    settle2_tx = a.settle(req2, r3)
    write_bundle(root, "r3", {"gate.json": ("gateJson", gate3), "DemoToken.sol": ("source", TOKEN)},
                 schema="arbiter-evidence/0.1")
    tampered = gate3.replace('"exit_code": 2', '"exit_code": 0')
    (root / "evidence" / "r3" / "gate.json").write_text(tampered)  # manifest keeps the original hash

    # 4: B's static hint, deployed by B outside the registry and claimed by B, no evidence URI
    gate4 = gate_json({**gate_base, "exit_code": 0,
                       "files": [{"path": "DemoCounter.sol", "verdict": "static_hint_unproven",
                                  "label": "靜態工具提示但未證實", "static_hints": [{"check": "tx-origin"}]}]})
    r4, r4_tx = b.register(source=COUNTER, verdict=2, gate=gate4, initcode=counter_init, commit=PUBLIC_COMMIT)
    deployed4 = b.send(None, counter_init)["contractAddress"]
    link4_tx = b.link(r4, deployed4)

    # 5: B says the patched bytecode is exploitable (does not block A's record: another auditor)
    gate5 = gate_json({**gate_base, "exit_code": 1,
                       "files": [{"path": "DemoVault.sol", "verdict": "proven_exploitable",
                                  "label": "已證實可攻擊（擋部署）"}]})
    r5, r5_tx = b.register(source=VAULT_PATCHED, verdict=3, pred=1, tier=1, gate=gate5, exploit=DISPUTE,
                           initcode=patched_init, commit=head)

    # 6: A later records "no provable attack" for the bytecode A itself proved exploitable
    gate6 = gate_json({**gate_base, "exit_code": 0,
                       "files": [{"path": "DemoVault.sol", "verdict": "no_provable_attack",
                                  "label": "未發現可證明攻擊（不等於安全）", "findings": []}]})
    r6, r6_tx = a.register(source=VAULT, verdict=1, gate=gate6, initcode=vault_init, commit=head)
    expect_revert(client, registry, contracts.Registry.deploy_data(r6, vault_init, SALT), a.address,
                  "ContradictsProvenRecord")
    reg = contracts.Registry(client, registry)
    if reg.latest_record(a.address, sha256_hex(VAULT)) != r6:
        raise ChainError("latestRecord(A, DemoVault.sol) is not record 6")

    sources = root / "sources"
    sources.mkdir(exist_ok=True)
    for fname, text in (("DemoVault.sol", VAULT), ("DemoVault.patched.sol", VAULT_PATCHED),
                        ("DemoToken.sol", TOKEN), ("DemoCounter.sol", COUNTER)):
        (sources / fname).write_text(text)

    out = {
        "rpc": args.rpc, "chainId": 31337, "registry": registry, "escrow": escrow,
        "accounts": {"auditor": a.address, "other": b.address},
        "records": {"proven": r1, "patched": r2, "undetermined": r3, "hint_claimed": r4, "dispute": r5,
                    "reaudit": r6},
        "tx": {"register1": r1_tx, "register2": r2_tx, "deploy2a": deploy2a_tx, "deploy2b": deploy2b_tx,
               "register3": r3_tx, "register4": r4_tx, "link4": link4_tx, "register5": r5_tx,
               "register6": r6_tx, "request1": req1_tx, "settle1": settle1_tx, "request2": req2_tx,
               "settle2": settle2_tx},
        "requests": {"paid": req1, "refunded": req2},
        "deployed": {"gatedA": deployed2a, "gatedB": deployed2b, "claimed": deployed4},
        "sourceHashes": {"DemoVault.sol": sha256_hex(VAULT), "DemoVault.patched.sol": sha256_hex(VAULT_PATCHED),
                         "DemoToken.sol": sha256_hex(TOKEN)},
        "logGap": args.log_gap,
    }
    (root / "fixture.json").write_text(json.dumps(out, indent=2) + "\n")
    return out


# ---------------------------------------------------------------------------- serving


def serve(root: Path, port: int, cert: str | None, key: str | None) -> None:
    """Serve `root` on 127.0.0.1 (https with --cert/--key; the evidence URIs are https)."""

    class Handler(http.server.SimpleHTTPRequestHandler):
        def end_headers(self):
            self.send_header("Cache-Control", "no-store")
            super().end_headers()

        def log_message(self, fmt, *a):  # quiet
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), functools.partial(Handler, directory=str(root)))
    scheme = "http"
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"
    print(f"serving {root} at {scheme}://127.0.0.1:{port}/", flush=True)
    httpd.serve_forever()


# ---------------------------------------------------------------------------- ABI vectors

RECORD_SIG = f"f({contracts.RECORD_TUPLE})"
# every function the page calls (me/web/verify/verify-lib.js FUNC_SIGS); the unit test checks both lists
SELECTOR_SIGS = {
    "recordCount": "recordCount()", "getRecord": "getRecord(uint256)",
    "recordsBySourceCount": "recordsBySourceCount(bytes32)",
    "recordsBySourcePage": "recordsBySourcePage(bytes32,uint256,uint256)",
    "recordsByInitcodeCount": "recordsByInitcodeCount(bytes32)",
    "recordsByInitcodePage": "recordsByInitcodePage(bytes32,uint256,uint256)",
    "recordsByCodehash": "recordsByCodehash(bytes32)", "childrenOf": "childrenOf(uint256)",
    "deploymentOf": "deploymentOf(address)", "deploymentsOf": "deploymentsOf(uint256)", "claimsOf": "claimsOf(address)",
    "latestRecord": "latestRecord(address,bytes32)", "isLinkCurrent": "isLinkCurrent(uint256)",
    "settledBy": "settledBy(uint256)", "getRequest": "getRequest(uint256)", "requestCount": "requestCount()",
    "registry": "registry()",
}
EVENT_SIGS = {
    "Registered": contracts.EVENT_REGISTERED, "Linked": contracts.EVENT_LINKED,
    "Requested": contracts.EVENT_REQUESTED, "Settled": contracts.EVENT_SETTLED,
}


def _record_vector(inp: dict, auditor: str, ts: int, deployed: str, code_hash: str, link: int) -> dict:
    keys = ["sourceHash", "initcodeHash", "verdict", "predicateClass", "evidenceTier", "gateJsonHash",
            "exploitHash", "patchHash", "parentId", "toolCommit", "model", "evidenceURI"]
    inner = ",".join(str(inp[k]) if inp[k] != "" else '""' for k in keys)
    hexdata = chain.cast("abi-encode", RECORD_SIG, f"(({inner}),{auditor},{ts},{deployed},{code_hash},{link})")
    expect = {"input": inp, "auditor": auditor, "timestamp": ts, "deployed": deployed,
              "runtimeCodeHash": code_hash, "linkKind": link}
    return {"hex": hexdata, "expect": expect}


def write_vectors(path: Path) -> None:
    a1 = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
    a2 = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
    h = lambda b: "0x" + b * 32  # noqa: E731
    records = [
        _record_vector({"sourceHash": h("11"), "initcodeHash": h("22"), "verdict": 3, "predicateClass": 2,
                        "evidenceTier": 3, "gateJsonHash": h("33"), "exploitHash": h("44"), "patchHash": h("55"),
                        "parentId": 7, "toolCommit": "0x" + "ab" * 20, "model": "arbiter-gpt",
                        "evidenceURI": "https://example.org/證據/r1/"}, a1, 1763740800, a2, h("66"), 2),
        _record_vector({"sourceHash": h("aa"), "initcodeHash": ZERO32, "verdict": 1, "predicateClass": 0,
                        "evidenceTier": 0, "gateJsonHash": h("bb"), "exploitHash": ZERO32, "patchHash": ZERO32,
                        "parentId": 0, "toolCommit": "0x" + "00" * 20, "model": "", "evidenceURI": ""},
                       a2, 1, "0x" + "00" * 20, ZERO32, 0),
    ]
    # AuditEscrow v2 Request: (requester, auditor, sourceHash, fee, createdAt, deadline, status, minRecordId, recordId)
    req = [a1, a2, h("77"), str(FEE_WEI), "1763740800", "1763744400", "2", "4", "5"]
    requests = [{"hex": chain.cast("abi-encode", f"f({contracts.REQUEST_TUPLE})", "(" + ",".join(req) + ")"),
                 "expect": {"requester": a1, "auditor": a2, "sourceHash": h("77"), "fee": str(FEE_WEI),
                            "createdAt": 1763740800, "deadline": 1763744400, "status": 2, "minRecordId": 4,
                            "recordId": 5}}]
    arrays = [{"hex": chain.cast("abi-encode", "f(uint256[])", v), "expect": e}
              for v, e in (("[1,2,5]", [1, 2, 5]), ("[]", []))]
    address_arrays = [{"hex": chain.cast("abi-encode", "f(address[])", v), "expect": e}
                      for v, e in ((f"[{a1},{a2}]", [a1, a2]), ("[]", []))]
    bools = [{"hex": chain.cast("abi-encode", "f(bool)", v), "expect": v == "true"} for v in ("true", "false")]
    calls = [
        {"fn": "getRecord", "args": ["7"], "hex": chain.calldata("getRecord(uint256)", "7")},
        {"fn": "deploymentOf", "args": [a2], "hex": chain.calldata("deploymentOf(address)", a2)},
        {"fn": "claimsOf", "args": [a2], "hex": chain.calldata("claimsOf(address)", a2)},
        {"fn": "deploymentsOf", "args": ["7"], "hex": chain.calldata("deploymentsOf(uint256)", "7")},
        {"fn": "isLinkCurrent", "args": ["3"], "hex": chain.calldata("isLinkCurrent(uint256)", "3")},
        {"fn": "latestRecord", "args": [a1, h("11")],
         "hex": chain.calldata("latestRecord(address,bytes32)", a1, h("11"))},
        {"fn": "recordsBySourcePage", "args": [h("11"), "0", "30"],
         "hex": chain.calldata("recordsBySourcePage(bytes32,uint256,uint256)", h("11"), "0", "30")},
        {"fn": "recordsByInitcodeCount", "args": [h("22")],
         "hex": chain.calldata("recordsByInitcodeCount(bytes32)", h("22"))},
        {"fn": "recordCount", "args": [], "hex": chain.calldata("recordCount()")},
    ]
    topics = {k: topic(v) for k, v in EVENT_SIGS.items()}
    word = lambda n: "0x" + format(n, "064x")  # noqa: E731
    logs = [
        {"topics": [topics["Registered"], word(3), h("11"), "0x" + "00" * 12 + a1[2:].lower()],
         "data": chain.cast("abi-encode", "f(uint8,uint256)", "3", "1"),
         "expect": {"event": "Registered", "id": 3, "sourceHash": h("11"), "auditor": a1, "verdict": 3,
                    "parentId": 1}},
        {"topics": [topics["Linked"], word(2), "0x" + "00" * 12 + a2[2:].lower()],
         "data": chain.cast("abi-encode", "f(bytes32,uint8)", h("66"), "2"),
         "expect": {"event": "Linked", "id": 2, "deployed": a2, "runtimeCodeHash": h("66"), "linkKind": 2}},
        {"topics": [topics["Settled"], word(1), word(3), "0x" + "00" * 12 + a1[2:].lower()],
         "data": chain.cast("abi-encode", "f(uint256,bool)", str(FEE_WEI), "true"),
         "expect": {"event": "Settled", "requestId": 1, "recordId": 3, "recipient": a1, "amount": str(FEE_WEI),
                    "refunded": True}},
    ]
    texts = ["abc", "ARBITER Gate 證據\n", ""]
    me_addresses = [{"hex": a, "me": bech32.bech32_encode(bech32.HRP, bytes.fromhex(a[2:]))} for a in (a1, a2)]
    vectors = {
        "generatedBy": "python3 me/scripts/verify_page_fixture.py --vectors <path> (encoded by Foundry cast)",
        "selectors": {k: chain.cast("sig", v) for k, v in SELECTOR_SIGS.items()},
        "topics": topics,
        "records": records, "requests": requests, "uintArrays": arrays, "addressArrays": address_arrays,
        "bools": bools, "calls": calls, "logs": logs,
        "sha256": [{"text": t, "hex": sha256_hex(t)} for t in texts],
        "meAddresses": me_addresses,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(vectors, ensure_ascii=False, indent=1) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--rpc", default=os.environ.get("ANVIL_RPC_URL", "http://127.0.0.1:8741"))
    ap.add_argument("--root", default="/tmp/vp_root", help="directory the page and the evidence are served from")
    ap.add_argument("--evidence-url", default="https://127.0.0.1:8751/evidence",
                    help="https URL under which <root>/evidence is served")
    ap.add_argument("--log-gap", type=int, default=12000,
                    help="empty blocks mined after record 1 (0 = none), beyond a 10,000-block eth_getLogs cap")
    ap.add_argument("--vectors", metavar="PATH", help="only write ABI test vectors to PATH")
    ap.add_argument("--serve", type=int, metavar="PORT", help="only serve --root on 127.0.0.1:PORT")
    ap.add_argument("--cert", help="PEM certificate for --serve (https)")
    ap.add_argument("--key", help="PEM private key for --serve")
    args = ap.parse_args()
    if args.vectors:
        write_vectors(Path(args.vectors))
        print(f"vectors written to {args.vectors}")
        return 0
    if args.serve:
        serve(Path(args.root).resolve(), args.serve, args.cert, args.key)
        return 0
    out = build_chain(args)
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
