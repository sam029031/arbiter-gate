"""Look up and re-check an audit record from the chain: 「經得起追問」.

Lookup by a deployed address, a record id, a source file (sha256 -> recordsBySource) or a
transaction hash (its Registered/Linked logs). For each record it shows what the chain
says (verdict, auditor, parent chain, children, link kind, recorded vs current codehash),
then, on request, re-checks it independently of whoever registered it:

    --evidence DIR   re-hash the evidence bundle and compare with the on-chain hashes; derive
                     verdict / predicateClass / evidenceTier / patchHash / model again from the
                     gate.json the chain anchors and compare; for a patched record, check that
                     its source is the parent's source with patch.diff applied
    --rebuild        compile the source with the recorded recipe; compare initcode/runtime
    --replay         re-run the anchored attack: it must succeed on the original and fail on the
                     patched source. The Foundry project is built here, from scratch: only files
                     whose sha256 the chain records go in (source, exploit, parent source, patch),
                     the test is generated from them and from the anchored gate.json, and forge
                     runs with this tool's own foundry.toml (no ffi, no file access, offline), a
                     clean environment and, where Linux allows it, no network. The bundle's
                     regression.zip is never executed; it is only compared with the rebuilt test.

Logs are read in windows of at most 10,000 blocks (ME's eth_getLogs cap), starting at the
block where the record was registered (found from its timestamp).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from . import abi, build
from .build import compile_source
from .chain import ZERO32, ChainError, find_tool
from .contracts import EVENT_LINKED, EVENT_REGISTERED, LINK_LABELS, PRED_LABELS, RECORD_FIELDS, VERDICT_LABELS
from .deploy import TZ
from .record import (DIRTY_MARK, _arbiter, apply_download_patch, gate_fields, load_manifest, normalize_source,
                     proven_finding, sha256_hex, source_hashes, tool_commit_dirty)
from .session import Session, add_network_args, open_session

_HEX = re.compile(r"^0x[0-9a-fA-F]*$")
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_SAFE_SOL = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\.sol$")
REPLAY_TIMEOUT = 900  # seconds per forge run
REGISTERED_WINDOWS = 3  # the Registered log is in the block stamped with the record's timestamp
LINKED_WINDOWS = 100  # a link up to 1,000,000 blocks after registration (about 8 weeks on ME)


# ------------------------------------------------------------------ lookup


def lookup(sess: Session, target: str | None, source: Path | None = None) -> tuple[str, list[int], str | None]:
    """(description, record ids, the deployed address asked about or None)."""
    reg = sess.registry
    if source:
        hashes = source_hashes(Path(source).read_bytes())
        ids: list[int] = []
        for h in hashes:
            ids += [i for i in reg.records_by_source(h) if i not in ids]
        what = f"原始碼 sha256 {hashes[0]}"
        if len(hashes) > 1:
            what += f"（換行統一成 LF 的 UTF-8 文字；檔案本身的 sha256 是 {hashes[1]}）"
        return what, ids, None
    t = (target or "").strip()
    if t.isdigit():
        return f"紀錄 #{t}", [int(t)], None
    if _HEX.match(t) and len(t) == 42:
        if t.lower() == reg.address.lower():
            # the registry cannot deploy itself; its own audit can only be linked as a claim
            claims = reg.claims_of(t)
            if claims:
                return f"AuditRegistry 本身 {t}（稽核者自行宣告的位址，未經閘門）", list(claims), t.lower()
            raise ChainError("這是 AuditRegistry 本身的地址，沒有任何紀錄宣告它；請給部署出來的合約地址或紀錄編號")
        rid = reg.deployment_of(t)
        if rid:
            return f"地址 {t}（由登錄合約依稽核過的 bytecode 部署）", [rid], t.lower()
        claims = reg.claims_of(t)
        if claims:
            return f"地址 {t}（稽核者自行宣告的部署，未經閘門）", list(claims), t.lower()
        ch = sess.client.code_hash(t)
        if ch == ZERO32:
            return f"地址 {t}（沒有程式碼）", [], None
        return f"地址 {t}（沒有連結；以 runtime codehash {ch} 查同一份程式碼）", reg.records_by_codehash(ch), None
    if _HEX.match(t) and len(t) == 66:
        receipt = sess.client.receipt(t)
        if receipt:
            ids = [e["id"] for e in reg.registered(receipt)] + [e["id"] for e in reg.linked(receipt)]
            return f"交易 {t}", sorted(set(ids)), None
        return f"雜湊 {t}（當作原始碼 sha256 查）", reg.records_by_source(t.lower()), None
    raise ChainError("請給 0x 地址、紀錄編號、交易雜湊，或用 --source 指定原始碼檔案")


# ------------------------------------------------------------------ logs (ME caps eth_getLogs at 10,000 blocks)


def _id_topic(rid: int) -> str:
    return "0x" + int(rid).to_bytes(32, "big").hex()


def _addr_topic(address: str) -> str:
    return "0x" + "00" * 12 + address.lower().removeprefix("0x")


def _record_start_block(sess: Session, rec: dict) -> int:
    """The first block that can hold the record's Registered log: the first block stamped with
    the record's timestamp or later, searched from the registry's deployment block."""
    lo = int(((sess.deployment or {}).get("registry") or {}).get("block") or 0)
    return sess.client.block_at_timestamp(int(rec["timestamp"]), lo)


def _event_log(sess: Session, event: str, topics: list[str], start: int, windows: int) -> dict | None:
    logs = sess.client.find_logs(sess.registry.address, [abi.topic(event), *topics], start, max_windows=windows)
    return logs[0] if logs else None


# ------------------------------------------------------------------ describe


def describe(sess: Session, rid: int, address: str | None = None) -> dict:
    reg = sess.registry
    rec = reg.record(rid)
    chain, cur, seen = [], rec, {rid}
    while cur["parentId"] and cur["parentId"] not in seen:
        seen.add(cur["parentId"])
        cur = reg.record(cur["parentId"])
        chain.append({"id": cur["id"], "verdict": cur["verdict"], "sourceHash": cur["sourceHash"]})
    kids = [{"id": k, "verdict": reg.record(k)["verdict"]} for k in reg.children(rid)]
    out = {"record": rec, "verdictLabel": VERDICT_LABELS.get(rec["verdict"], "?"), "parents": chain,
           "children": kids}
    auditors = [a.lower() for a in (sess.deployment or {}).get("auditors") or []]
    out["auditorListed"] = rec["auditor"].lower() in auditors if auditors else None

    # Transactions are informational: a failed log lookup is reported, never fatal.
    start = None
    out["registeredTx"] = out["registeredBlock"] = None
    try:
        start = _record_start_block(sess, rec)
        lg = _event_log(sess, EVENT_REGISTERED, [_id_topic(rid)], start, REGISTERED_WINDOWS)
        if lg:
            out["registeredTx"] = lg["transactionHash"]
            out["registeredBlock"] = int(str(lg["blockNumber"]), 0)
    except ChainError as exc:
        out["logError"] = str(exc)

    target = (address or rec["deployed"] or "").lower() or None
    if target:
        first = (rec["deployed"] or "").lower()
        out["address"] = target
        out["addressQueried"] = bool(address)
        now = sess.client.code_hash(target)
        out["currentCodehash"] = now
        recorded, lg = None, None
        if start is not None:
            try:
                lg = _event_log(sess, EVENT_LINKED, [_id_topic(rid), _addr_topic(target)],
                                out["registeredBlock"] or start, LINKED_WINDOWS)
            except ChainError as exc:
                out["logError"] = str(exc)
        out["linkedTx"] = lg["transactionHash"] if lg else None
        if target == first:
            kind, recorded = rec["linkKind"], rec["runtimeCodeHash"]
        else:
            kind = 2 if reg.deployment_of(target) == rid else (1 if rid in reg.claims_of(target) else 0)
            if lg:
                recorded, _ = abi.decode(["bytes32", "uint8"], lg["data"])
            out["firstLink"] = {"address": rec["deployed"], "linkKind": rec["linkKind"],
                                "runtimeCodeHash": rec["runtimeCodeHash"]} if rec["deployed"] else None
        out["linkKindAtAddress"] = kind
        out["recordedCodehash"] = recorded
        # None = the link-time codehash could not be read (log lookup failed): unknown, not a mismatch
        out["codehashMatches"] = (now == recorded) if recorded else None
    try:
        gated = [a.lower() for a in reg.deployments_of(rid)]
    except ChainError:
        gated = []
    out["gatedDeployments"] = gated
    esc = sess.escrow
    if esc:
        try:
            q = esc.settled_by(rid)
            out["settledRequest"] = q or None
        except ChainError:
            out["settledRequest"] = None
    return out


# ------------------------------------------------------------------ evidence bundle access


def _role(manifest: dict, role: str) -> dict | None:
    return next((f for f in manifest.get("files", []) if f.get("role") == role), None)


def _safe_rel(name: str) -> bool:
    """A bundle-relative path that stays inside the bundle."""
    s = str(name)
    return bool(s) and "\\" not in s and not Path(s).is_absolute() and ".." not in Path(s).parts
def _bundle_file(bundle: Path, name: str | None) -> Path | None:
    """A file inside the bundle (a manifest name cannot point outside it)."""
    if not name:
        return None
    root = Path(bundle).resolve()
    p = (root / name).resolve()
    if not p.is_relative_to(root) or not p.is_file():
        return None
    return p


def _anchored(bundle: Path, manifest: dict, role: str, want: str) -> Path | None:
    """The bundle's file for `role`, only if its sha256 is the on-chain hash `want`."""
    if not want or want == ZERO32:
        return None
    p = _bundle_file(bundle, (_role(manifest, role) or {}).get("name"))
    return p if p and sha256_hex(p.read_bytes()) == want.lower() else None


def _gate_entry(report: dict, source_hash: str) -> dict | None:
    want = source_hash.lower().removeprefix("0x")
    return next((e for e in report.get("files") or []
                 if str((e.get("artifact") or {}).get("sha256") or "").lower() == want), None)


def _check(what: str, expected, actual, ok: bool, level: str | None = None) -> dict:
    c = {"what": what, "expected": expected, "actual": actual, "ok": bool(ok)}
    if level:
        c["level"] = level  # "info" / "warn": shown, never counted as a failure
        c["ok"] = True
    return c


# ------------------------------------------------------------------ --evidence


def check_evidence(sess: Session, rec: dict, bundle: Path) -> dict:
    """Re-hash every file of the bundle and compare with the manifest and with the chain; derive
    the record's fields from the anchored gate.json; check a patched record's derivation."""
    m = load_manifest(bundle)
    checks = []
    for f in m.get("files", []):
        p = _bundle_file(bundle, f["name"])
        actual = sha256_hex(p.read_bytes()) if p else None
        checks.append(_check(f"檔案 {f['name']} 與 manifest", f["sha256"], actual, actual == f["sha256"]))
    parent = sess.registry.record(rec["parentId"]) if rec["parentId"] else None
    exploit_expect = rec["exploitHash"]
    if parent and exploit_expect == ZERO32:  # patched child: the exploit is the parent's
        exploit_expect = parent["exploitHash"]
    pairs = [("gate_json", "gate.json", rec["gateJsonHash"]), ("source", "原始碼", rec["sourceHash"]),
             ("exploit", "攻擊程式", exploit_expect), ("patch", "修補", rec["patchHash"])]
    for role, word, onchain in pairs:
        f = _role(m, role)
        if f is None and onchain == ZERO32:
            continue
        p = _bundle_file(bundle, f["name"]) if f else None
        actual = sha256_hex(p.read_bytes()) if p else None
        checks.append(_check(f"{word}的 sha256 與鏈上紀錄", onchain, actual, actual == onchain))
    if parent:
        f = _role(m, "parent_source")
        if f:
            p = _bundle_file(bundle, f["name"])
            actual = sha256_hex(p.read_bytes()) if p else None
            checks.append(_check("上一版原始碼與上一版紀錄", parent["sourceHash"], actual,
                                 actual == parent["sourceHash"]))
    mi = m.get("recordInput") or {}
    diff = [k for k in RECORD_FIELDS if str(mi.get(k)).lower() != str(rec[k]).lower()]
    checks.append(_check("manifest 的紀錄內容與鏈上紀錄", "全部欄位相同", "相同" if not diff else f"不同：{', '.join(diff)}",
                         not diff))
    gate_checks, info = _gate_checks(rec, parent, bundle, m)
    checks += gate_checks
    if parent:
        checks.append(_derivation_check(rec, parent, bundle, m))
    return {"ok": all(c["ok"] for c in checks), "checks": checks, **info}


def _gate_checks(rec: dict, parent: dict | None, bundle: Path, m: dict) -> tuple[list[dict], dict]:
    """The fields gate.json fixes, derived again with record.gate_fields (the function that
    registered them) from the gate.json whose sha256 the chain anchors."""
    gpath = _anchored(bundle, m, "gate_json", rec["gateJsonHash"])
    if gpath is None:
        return [_check("用鏈上錨定的 gate.json 重新推導判定", "sha256 等於 gateJsonHash 的 gate.json",
                       "證據裡沒有相符的 gate.json，無法比對判定", False)], {}
    report = json.loads(gpath.read_bytes().decode("utf-8"))
    orig_hash = (parent or rec)["sourceHash"]
    entry = _gate_entry(report, orig_hash)
    if entry is None:
        return [_check("gate.json 裡有這份原始碼的稽核結果", f"artifact.sha256 = {orig_hash}", "沒有", False)], {}
    finding = proven_finding(entry)
    src = _role(m, "parent_source" if parent else "source")
    file_name = Path(src["name"]).name if src else Path(str((entry.get("artifact") or {}).get("uri") or "")).name
    exp = gate_fields(report, entry, finding, file_name, patched=bool(parent))
    checks = []
    for key, word in (("verdict", "判定"), ("predicateClass", "證明條件（predicateClass）"),
                      ("evidenceTier", "證據層級（evidenceTier）"), ("patchHash", "修補 sha256（patchHash）"),
                      ("model", "模型")):
        same = str(exp[key]).lower() == str(rec[key]).lower()
        checks.append(_check(f"鏈上的{word}與 gate.json 推導出的值", exp[key], rec[key], same))
    has_exploit = rec["exploitHash"] != ZERO32
    checks.append(_check("exploitHash 與 gate.json 的判定一致（只有已證實可攻擊的紀錄帶攻擊程式）",
                         "有" if exp["verdict"] == 3 else "無", "有" if has_exploit else "無",
                         has_exploit == (exp["verdict"] == 3)))
    anchor = rec["exploitHash"] if has_exploit else ((parent or {}).get("exploitHash") or ZERO32)
    poc = (finding or {}).get("poc_name")
    if anchor != ZERO32 and poc:
        ex = _anchored(bundle, m, "exploit", anchor)
        checks.append(_check("錨定的攻擊程式就是 gate.json 這個漏洞的 PoC（檔名）", f"exploit/{poc}.t.sol",
                             (Path(ex).relative_to(Path(bundle).resolve()).as_posix() if ex else "沒有相符的檔案"),
                             bool(ex) and ex.name == f"{poc}.t.sol"))
    info = {"gateVerdict": entry.get("verdict"), "derivedVerdict": exp["verdict"],
            "verdictMismatch": exp["verdict"] != rec["verdict"]}
    tc = str(report.get("tool_commit") or "").lower().removeprefix("0x")
    if tc:
        same = "0x" + tc == str(rec["toolCommit"]).lower()
        checks.append(_check("工具 commit 與 gate.json 記錄的 commit" + ("" if same else
                             "（不同：登錄時用 --tool-commit 指定的才會這樣）"), "0x" + tc, rec["toolCommit"],
                             True, "info" if same else "warn"))
    if tool_commit_dirty(report):
        info["toolCommitDirty"] = True
        info["toolCommitSource"] = report.get("tool_commit_source")
        checks.append(_check(f"gate.json 記錄產生結果的程式{DIRTY_MARK}：toolCommit 不完全等於執行的程式碼",
                             "乾淨的 commit", report.get("tool_commit_source") or "tool_commit_dirty", True, "warn"))
    return checks, info


def _derivation_check(rec: dict, parent: dict, bundle: Path, m: dict) -> dict:
    what = "這一版的原始碼 = 上一版原始碼套用 patch.diff"
    parent_src = _anchored(bundle, m, "parent_source", parent["sourceHash"])
    patch = _anchored(bundle, m, "patch", rec["patchHash"])
    if parent_src is None or patch is None:
        return _check(what, rec["sourceHash"], "缺少雜湊和鏈上相同的上一版原始碼或 patch.diff", False)
    new, err = apply_download_patch(parent_src.read_bytes(), patch.read_bytes(), parent_src.name)
    actual = sha256_hex(new) if new is not None else f"patch.diff 套用失敗：{err}"
    return _check(what, rec["sourceHash"], actual, new is not None and actual == rec["sourceHash"])


# ------------------------------------------------------------------ --rebuild


def rebuild(sess: Session, rec: dict, bundle: Path | None, source: Path | None, address: str | None = None) -> dict:
    """Compile with the recorded recipe and compare with initcodeHash and the code at `address`
    (the deployment asked about; default the record's first link)."""
    recipe = {}
    if bundle and (Path(bundle) / "compiler.json").exists():
        recipe = json.loads((Path(bundle) / "compiler.json").read_text())
    src_path = source
    if not src_path and bundle:
        f = _role(load_manifest(bundle), "source")
        src_path = _bundle_file(bundle, f["name"]) if f else None
    if not src_path:
        raise ChainError("--rebuild 需要 --evidence 資料夾或 --source 原始碼")
    raw = Path(src_path).read_bytes()
    text = raw if sha256_hex(raw) == rec["sourceHash"] else normalize_source(raw)
    if sha256_hex(text) != rec["sourceHash"]:
        return {"ok": False, "checks": [_check("原始碼 sha256 與鏈上紀錄", rec["sourceHash"], sha256_hex(raw), False)]}
    imports = {}
    for unit, rel in (recipe.get("imports") or {}).items():
        if not (bundle and _safe_rel(unit) and _safe_rel(rel)):
            raise ChainError(f"compiler.json 的 imports 不能用：{unit} → {rel}")
        p = Path(bundle) / rel
        if not p.is_file():
            raise ChainError(f"證據資料夾缺少 {rel}（編譯時 import 的檔案）")
        imports[unit] = p.read_text(encoding="utf-8")
    b = compile_source(text.decode("utf-8"), recipe.get("file") or Path(src_path).name, recipe.get("contract"),
                       evm_version=(recipe.get("settings") or {}).get("evmVersion", "paris"),
                       ctor_args=recipe.get("constructorArgs", "0x"), imports=imports or None)
    checks = [_check(f"用 {b.solc}（{b.evm_version}）重新編譯的 initcode 與鏈上 initcodeHash",
                     rec["initcodeHash"], b.initcode_hash, b.initcode_hash == rec["initcodeHash"])]
    target = address or rec["deployed"]
    if target:
        live = sess.client.code_hash(target)
        if b.has_immutables:
            checks.append(_check("runtime 程式碼（合約有 immutable，部署時才寫入，只比對 initcode）", live, "略過", True))
        else:
            checks.append(_check(f"重新編譯的 runtime 與部署地址 {target} 的程式碼", live, b.runtime_hash,
                                 live == b.runtime_hash))
    return {"ok": all(c["ok"] for c in checks), "checks": checks, "contract": b.contract}


# ------------------------------------------------------------------ --replay (sandboxed)

HERMETIC_IMPORT = "../src/Target.sol"
_IMPORT_ANY = re.compile(r"^[ \t]*import\b[^\n]*$", re.M)
_IMPORT_PLAIN = re.compile(r'^[ \t]*import[ \t]+"([^"\n]+)"[ \t]*;[ \t]*$', re.M)
SANDBOX_TOML = """# Written by `me.py verify --replay`. Nothing in the evidence bundle configures this run.
[profile.default]
src = "src"
test = "test"
out = "out"
libs = []
remappings = []
auto_detect_remappings = false
auto_detect_solc = false
optimizer = false
via_ir = false
ffi = false
fs_permissions = []
offline = true
"""
_TOML_DANGER = (("ffi = true", re.compile(r"^\s*ffi\s*=\s*true", re.M)),
                ("fs_permissions", re.compile(r"^\s*fs_permissions\s*=\s*\[\s*[^\]\s]", re.M)),
                ("remappings", re.compile(r"^\s*remappings\s*=\s*\[\s*[^\]\s]", re.M)),
                ("rpc / fork", re.compile(r"^\s*(eth_rpc_url|fork_url|\[rpc_endpoints\])", re.M)),
                ("allow_paths / include_paths", re.compile(r"^\s*(allow_paths|include_paths)\s*=\s*\[\s*[^\]\s]", re.M)))
_netns: list[str] | None = None


def _no_network_prefix() -> list[str]:
    """`unshare -rn` (a new user + network namespace: no interface but a downed loopback) when
    this Linux allows it, so a cheatcode cannot reach any host (vm.createFork / vm.rpc)."""
    global _netns
    if _netns is None:
        _netns = []
        exe = shutil.which("unshare")
        if exe and sys.platform.startswith("linux"):
            try:
                if subprocess.run([exe, "-rn", "true"], capture_output=True, timeout=20).returncode == 0:
                    _netns = [exe, "-rn"]
            except (OSError, subprocess.SubprocessError):
                pass
    return _netns


def _sandbox_env(home: Path) -> dict[str, str]:
    """A clean environment: no FOUNDRY_* / ETH_* / API keys from the caller, an empty HOME (so no
    global foundry.toml either), ffi and network installs off."""
    env = {"PATH": os.environ.get("PATH") or os.defpath, "HOME": str(home), "TMPDIR": str(home),
           "LANG": "C.UTF-8", "NO_COLOR": "1", "FOUNDRY_FFI": "false", "FOUNDRY_OFFLINE": "true"}
    for k in ("SYSTEMROOT", "SystemRoot", "COMSPEC"):  # needed to start a process on Windows
        if k in os.environ:
            env[k] = os.environ[k]
    return env


def _forge_test(proj: Path, solc: str, home: Path) -> tuple[dict[str, bool] | None, str]:
    cmd = [*_no_network_prefix(), find_tool("forge"), "test", "--root", str(proj), "--json", "--offline",
           "--use", solc, "--match-contract", "^TestArbiterRegression$"]
    try:
        proc = subprocess.run(cmd, cwd=proj, env=_sandbox_env(home), stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=REPLAY_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, f"forge test 超過 {REPLAY_TIMEOUT} 秒沒有結束"
    start = proc.stdout.find("{")
    try:
        data = json.loads(proc.stdout[start:]) if start >= 0 else {}
    except json.JSONDecodeError:
        data = {}
    out: dict[str, bool] = {}
    for suite_name, suite in (data.items() if isinstance(data, dict) else []):
        if not str(suite_name).endswith(":TestArbiterRegression"):
            continue
        for name, r in (suite.get("test_results") or {}).items():
            out[name.split("(")[0]] = r.get("status") == "Success"
    if not out:
        return None, ((proc.stderr or "") + (proc.stdout or "")).strip()[-800:] or "forge 沒有輸出"
    return out, ""


def hermetic_exploit(text: str, file_name: str) -> str:
    """The anchored exploit pointed at src/Target.sol, as arbiter.patch.hermetic_exploit does
    for the gate (which knows the import from the run; here it is read from the file). Only a
    single-file target is accepted: exactly one plain import of the audited file, plus ./Vm.sol."""
    plain = list(_IMPORT_PLAIN.finditer(text))
    if len(plain) != len(_IMPORT_ANY.findall(text)):
        raise ValueError("攻擊程式有不是 `import \"路徑\";` 形式的 import；沙箱只重建單一合約檔的專案")
    targets = [mm for mm in plain if mm.group(1) != "./Vm.sol"]
    if len(targets) != 1:
        raise ValueError(f"攻擊程式要剛好 import 被稽核的合約一次（另外只能有 ./Vm.sol），實際："
                         f"{[mm.group(1) for mm in targets]}")
    mm = targets[0]
    if mm.group(1) != HERMETIC_IMPORT and Path(mm.group(1)).name != file_name:
        raise ValueError(f"攻擊程式 import 的是 {mm.group(1)}，不是被稽核的 {file_name}")
    return text[:mm.start()] + f'import "{HERMETIC_IMPORT}";' + text[mm.end():]


def _zip_members(zf: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if any(i.file_size > 5_000_000 for i in infos):
        raise ValueError("有超過 5 MB 的檔案")
    tops = {i.filename.split("/", 1)[0] for i in infos}
    members = {i.filename.split("/", 1)[1]: i for i in infos if "/" in i.filename}
    if len(tops) != 1 or len(members) != len(infos):
        raise ValueError("不是單一資料夾的專案")
    return members


def _zip_solc(zip_path: Path | None) -> str | None:
    """Only the solc version string of the zip's foundry.toml (never the file itself)."""
    if not zip_path:
        return None
    try:
        with zipfile.ZipFile(zip_path) as zf:
            members = _zip_members(zf)
            text = zf.read(members["foundry.toml"]).decode("utf-8") if "foundry.toml" in members else ""
    except (zipfile.BadZipFile, ValueError, KeyError, UnicodeDecodeError, OSError):
        return None
    mm = re.search(r'^\s*solc\s*=\s*"(\d+\.\d+\.\d+)"\s*$', text, re.M)
    return mm.group(1) if mm else None


def _replay_solc(entry: dict, zip_path: Path | None, source: str) -> tuple[str, str]:
    v = str(((entry or {}).get("static_analysis") or {}).get("solc") or "")
    if _VERSION.match(v):
        return v, "gate.json 的 static_analysis.solc"
    v = _zip_solc(zip_path) or ""
    if _VERSION.match(v):
        return v, "regression.zip 的 foundry.toml（只取版本號）"
    mm = re.search(r"pragma\s+solidity\s+=?\s*(\d+\.\d+\.\d+)\s*;", source)
    if mm:
        return mm.group(1), "原始碼的 pragma"
    return build.SOLC_VERSION, "工具預設"


def _zip_check(zip_path: Path, file_name: str, source: bytes, exploit_h: str, envs: list, finding: dict,
               report: dict) -> dict:
    """Extra check: is the bundle's downloadable regression project exactly what the anchored
    files regenerate (arbiter.dump.write_regression, as record.py built it)? Compared, never run."""
    _arbiter()
    from arbiter.dump import write_regression
    what = "額外檢查：證據的 regression.zip 和用鏈上錨定的檔案重建的回歸專案相同（zip 只比對，從不執行）"
    try:
        with zipfile.ZipFile(zip_path) as zf:
            members = _zip_members(zf)
            got = {k: zf.read(i) for k, i in members.items()}
    except (zipfile.BadZipFile, ValueError, OSError) as exc:
        return _check(what, "相同", f"無法讀取 regression.zip：{exc}", False)
    toml = got.get("foundry.toml", b"").decode("utf-8", errors="replace")
    mm = re.search(r'^\s*solc\s*=\s*"(\d+\.\d+\.\d+)"\s*$', toml, re.M)
    meta = {"models": report.get("models"), "run_id": (report.get("input") or {}).get("run_id"),
            "generated_at": report.get("generated_at")}
    with tempfile.TemporaryDirectory(prefix="arbiter-me-regen-") as tmp:
        write_regression(Path(tmp), source=source.decode("utf-8"), contract_file=file_name,
                         exploit_solidity=exploit_h, environments=envs, finding=finding or {},
                         solc=mm.group(1) if mm else "", meta=meta)
        want = {p.relative_to(tmp).as_posix(): p.read_bytes() for p in Path(tmp).rglob("*") if p.is_file()}
    differ = [k for k in sorted(want) if k != "README.md" and got.get(k) != want[k]]
    extra = sorted(set(got) - set(want))
    danger = [name for name, rx in _TOML_DANGER if rx.search(toml)]
    parts = []
    if differ:
        parts.append(f"內容不同：{', '.join(differ)}")
    if extra:
        parts.append(f"多出檔案：{', '.join(extra)}")
    if danger:
        parts.append(f"foundry.toml 打開了危險的設定（{', '.join(danger)}）：不要在這個 zip 裡直接跑 forge")
    if not parts and got.get("README.md") != want.get("README.md"):
        return _check(what, "相同", "測試與設定相同；README.md 的說明文字不同", True, "warn")
    return _check(what, "相同", "；".join(parts) or "相同", not parts)


def replay(sess: Session, rec: dict, bundle: Path) -> dict:
    """Re-run the anchored attack in a sandbox built here: it must succeed on the original and
    fail (with the honest paths still passing) on the patched source."""
    m = load_manifest(bundle)
    parent = sess.registry.record(rec["parentId"]) if rec["parentId"] else None
    checks: list[dict] = []

    def stop(what: str, expected, actual) -> dict:
        checks.append(_check(what, expected, actual, False))
        return {"ok": False, "checks": checks}

    def cannot(what: str, expected, actual) -> dict:
        """Only anchored evidence has to replay; an extra, unanchored exploit that cannot is noted."""
        if anchored:
            return stop(what, expected, actual)
        checks.append(_check(f"未錨定的攻擊程式無法重跑：{what}（{actual}）", "—", "—", True, "info"))
        return {"ok": True, "checks": checks}

    anchored = True
    orig_hash = (parent or rec)["sourceHash"]
    orig = _anchored(bundle, m, "parent_source" if parent else "source", orig_hash)
    if orig is None:
        return stop("重跑用的原始碼（sha256 必須等於鏈上紀錄）", orig_hash, "證據裡沒有相符的檔案")
    file_name = orig.name
    if not _SAFE_SOL.match(file_name):
        return stop("原始碼檔名", "一般的 .sol 檔名", file_name)
    exploit_hash = rec["exploitHash"] if rec["exploitHash"] != ZERO32 else (parent or {}).get("exploitHash") or ZERO32
    anchored = exploit_hash != ZERO32
    if anchored:
        exploit = _anchored(bundle, m, "exploit", exploit_hash)
        if exploit is None:
            return stop("攻擊程式（sha256 必須等於鏈上 exploitHash）", exploit_hash, "證據裡沒有相符的檔案")
    else:
        exploit = _bundle_file(bundle, (_role(m, "exploit") or {}).get("name"))
        if exploit is None:
            checks.append(_check(f"這筆紀錄（判定 {rec['verdict']}）沒有鏈上錨定的攻擊程式，證據裡也沒有：沒有可以重跑的攻擊",
                                 "—", "—", True, "info"))
            return {"ok": True, "checks": checks}
        checks.append(_check(f"這筆紀錄（判定 {rec['verdict']}）沒有 exploitHash；證據裡的 {exploit.name} 沒有上鏈錨定，"
                             "只用來確認它在這份原始碼上不能成功", "—", "—", True, "info"))
    gpath = _anchored(bundle, m, "gate_json", rec["gateJsonHash"])
    if gpath is None:
        return cannot("gate.json（sha256 必須等於 gateJsonHash；重跑的環境與誠實路徑的基準來自它）",
                      rec["gateJsonHash"], "證據裡沒有相符的 gate.json")
    report = json.loads(gpath.read_bytes().decode("utf-8"))
    entry = _gate_entry(report, orig_hash)
    if entry is None:
        return cannot("gate.json 裡有這份原始碼的稽核結果", f"artifact.sha256 = {orig_hash}", "沒有")
    finding = proven_finding(entry) or {}
    envs = ((finding.get("abg") or {}).get("environments")) or []
    want_honest = ([f"testHonestPath{e['env']}" for e in envs if e.get("A")]
                   + [f"testOwnerClaim{e['env']}" for e in envs if e.get("TA")])
    original = orig.read_bytes()
    try:
        if not any(e.get("A") for e in envs):
            raise ValueError("gate.json 記錄的環境裡沒有原合約讓使用者取回的金額（A > 0），誠實路徑沒有基準")
        exploit_h = hermetic_exploit(exploit.read_bytes().decode("utf-8"), file_name)
        _arbiter()
        from arbiter.dump import regression_solidity
        from arbiter.workspace import VM_SOL
        test_sol = regression_solidity(exploit_h, file_name, envs)
    except (ValueError, UnicodeDecodeError) as exc:
        why = str(exc)
        if "victim_loss" in why:
            why = f"目前只有 victim_loss（受害者少拿回錢）的證明能重建成重跑用的測試（{why}）"
        return cannot("把攻擊程式和 gate.json 轉成重跑用的測試", "可以轉換", why)

    patched, how = None, None
    if parent:
        p = _anchored(bundle, m, "source", rec["sourceHash"])
        if p is None:
            return stop("修補後的原始碼（sha256 必須等於鏈上 sourceHash）", rec["sourceHash"], "證據裡沒有相符的檔案")
        patched, how = p.read_bytes(), "這筆紀錄的原始碼（修補後）上"
    elif anchored and rec["patchHash"] != ZERO32:
        pf = _anchored(bundle, m, "patch", rec["patchHash"])
        if pf is None:
            checks.append(_check("patch.diff（sha256 必須等於鏈上 patchHash）", rec["patchHash"], "證據裡沒有相符的檔案", False))
        else:
            patched, err = apply_download_patch(original, pf.read_bytes(), file_name)
            if patched is None:
                checks.append(_check("patch.diff 套用到原始碼", "可以套用", err, False))
            how = "原始碼套用 patch.diff 之後"

    zip_path = _bundle_file(bundle, (_role(m, "regression") or {}).get("name"))
    version, origin = _replay_solc(entry, zip_path, original.decode("utf-8", errors="replace"))
    try:
        solc = build.find_solc(version)
    except ChainError as exc:
        return stop(f"取得 solc {version}（{origin}）", "已安裝或可下載", str(exc))
    netns = bool(_no_network_prefix())
    checks.append(_check(f"沙箱：在暫存資料夾重建 Foundry 專案，只放入雜湊和鏈上相同的原始碼與攻擊程式，測試由它們和 gate.json "
                         f"重新產生；用這個工具自己的 foundry.toml（ffi 關閉、沒有檔案權限、離線）、乾淨的環境變數、"
                         f"solc {version}（{origin}）；" + ("網路隔離（unshare）" if netns else "沒有網路隔離（這台機器沒有可用的 unshare）"),
                         "—", "—", True, "info"))

    with tempfile.TemporaryDirectory(prefix="arbiter-me-replay-") as tmp:
        proj, home = Path(tmp) / "proj", Path(tmp) / "home"
        (proj / "src").mkdir(parents=True)
        (proj / "test" / "arbiter").mkdir(parents=True)
        home.mkdir()
        (proj / "foundry.toml").write_text(SANDBOX_TOML, encoding="utf-8")
        (proj / "src" / file_name).write_bytes(original)
        (proj / "test" / "arbiter" / "ArbiterRegression.t.sol").write_bytes(test_sol.encode("utf-8"))
        (proj / "test" / "arbiter" / "Vm.sol").write_bytes(VM_SOL.replace("__PRAGMA__", ">=0.8.0").encode("utf-8"))

        def honest(res: dict[str, bool], where: str) -> dict:
            present = sorted(k for k in res if k.startswith(("testHonestPath", "testOwnerClaim")))
            passed = sum(bool(res.get(k)) for k in want_honest)
            return _check(f"{where}沒有攻擊時的誠實路徑（數量等於 gate.json 裡 A > 0 的環境）", f"{len(want_honest)} 個通過",
                          f"{len(present)} 個測試、{passed} 個通過",
                          present == sorted(want_honest) and passed == len(want_honest))

        before, err = _forge_test(proj, solc, home)
        if before is None:
            return stop("在原始碼上執行重跑測試", "forge test 有結果", err)
        reproduced = before.get("testExploitBlocked") is False
        if anchored:
            checks.append(_check("攻擊在原始碼上重現（testExploitBlocked 失敗 = 攻擊成功）", "重現",
                                 "重現" if reproduced else "沒有重現", reproduced))
        else:
            checks.append(_check(f"攻擊在判定 {rec['verdict']} 的原始碼上不能成功（成功就和鏈上的判定矛盾）", "沒有重現",
                                 "重現" if reproduced else "沒有重現", not reproduced))
        checks.append(honest(before, "原始碼上"))
        if patched is not None:
            (proj / "src" / file_name).write_bytes(patched)
            after, err = _forge_test(proj, solc, home)
            if after is None:
                checks.append(_check(f"在{how}執行重跑測試", "forge test 有結果", err, False))
            else:
                blocked = after.get("testExploitBlocked") is True
                checks.append(_check(f"{how}攻擊失敗（testExploitBlocked 通過）", "攻擊失敗",
                                     "攻擊失敗" if blocked else "攻擊仍然成功", blocked))
                checks.append(honest(after, how))
    if zip_path:
        checks.append(_zip_check(zip_path, file_name, original, exploit_h, envs, finding, report))
    return {"ok": all(c["ok"] for c in checks), "checks": checks, "solc": version, "networkIsolated": netns}


# ------------------------------------------------------------------ CLI


def _fmt_checks(title: str, res: dict) -> list[str]:
    counted = [c for c in res["checks"] if not c.get("level")]
    head = "全部符合" if res["ok"] else "有不符合"
    if not counted:
        head = "沒有可以比對的項目"
    lines = [f"  {title}：{head}"]
    for c in res["checks"]:
        level = c.get("level")
        mark = {"info": "說明", "warn": "提醒"}.get(level) or ("符合" if c["ok"] else "不符")
        detail = ""
        if level == "warn" or not c["ok"]:
            detail = f"\n           預期 {c['expected']}\n           實際 {c['actual']}"
        lines.append(f"    [{mark}] {c['what']}" + detail)
    return lines


def _text(sess: Session, d: dict) -> str:
    net, r = sess.net, d["record"]
    ev = d.get("evidence") or {}
    lines = [f"紀錄 #{r['id']}  判定 {r['verdict']}：{d['verdictLabel']}"]
    if ev.get("verdictMismatch"):
        lines.append(f"  ！！ 鏈上判定 {r['verdict']} 和它錨定的 gate.json 矛盾：gate.json 是 {ev.get('gateVerdict')}"
                     f"（應登錄為判定 {ev.get('derivedVerdict')}）")
    if r["verdict"] == 3:
        lines.append(f"  證明條件  {PRED_LABELS.get(r['predicateClass'])}；證據層級 {r['evidenceTier']}")
    lines += [f"  原始碼    sha256 {r['sourceHash']}", f"  initcode  keccak256 {r['initcodeHash']}",
              f"  gate.json sha256 {r['gateJsonHash']}"]
    if r["exploitHash"] != ZERO32:
        lines.append(f"  攻擊程式  sha256 {r['exploitHash']}")
    if r["patchHash"] != ZERO32:
        lines.append(f"  修補      sha256 {r['patchHash']}")
    listed = {True: "（在部署資訊的稽核者名單內）", False: "（不在部署資訊的稽核者名單內）", None: ""}[d["auditorListed"]]
    dirty = f"（gate.json：產生結果的程式{DIRTY_MARK}）" if ev.get("toolCommitDirty") else ""
    lines += [f"  稽核者    {r['auditor']}{listed}",
              f"  模型      {r['model'] or '未記錄'}；工具 commit {r['toolCommit'][2:12]}{dirty}",
              f"  登錄時間  {_dt.datetime.fromtimestamp(r['timestamp'], TZ):%Y-%m-%d %H:%M:%S}（UTC+8，區塊時間）"]
    if d.get("registeredTx"):
        lines.append(f"  登錄交易  {d['registeredTx']}（區塊 {d.get('registeredBlock')}）")
    elif d.get("logError"):
        lines.append(f"  登錄交易  查不到（節點的 eth_getLogs 回應：{d['logError']}）")
    if d["parents"]:
        lines.append("  上一版    " + " ← ".join(f"#{p['id']}（判定 {p['verdict']}）" for p in d["parents"]))
    if d["children"]:
        lines.append("  後續版本  " + "、".join(f"#{c['id']}（判定 {c['verdict']}）" for c in d["children"]))
    if d.get("address"):
        kind = d.get("linkKindAtAddress", r["linkKind"])
        lines.append(f"  部署      {LINK_LABELS.get(kind)}")
        lines.append(f"            地址 {d['address']}" + ("（查詢的地址）" if d.get("addressQueried") else ""))
        if url := net.address_url(d["address"]):
            lines.append(f"            {url}")
        rec_hash = d.get("recordedCodehash")
        lines.append(f"            連結時的 codehash {rec_hash or '查不到（連結紀錄讀不到）'}")
        same = {True: "相同", False: "不同！", None: "無法比對"}[d.get("codehashMatches")]
        lines.append(f"            目前的 codehash {d['currentCodehash']}（{same}）")
        if d.get("linkedTx"):
            lines.append(f"            連結交易 {d['linkedTx']}")
        if d.get("firstLink"):
            fl = d["firstLink"]
            lines.append(f"            紀錄的第一個連結是另一個地址：{fl['address']}（{LINK_LABELS.get(fl['linkKind'])}）")
    else:
        lines.append(f"  部署      {LINK_LABELS.get(r['linkKind'])}")
    others = [a for a in d.get("gatedDeployments") or [] if a != (d.get("address") or "")]
    if others:
        lines.append(f"  其他經由登錄合約的部署  {'、'.join(others)}")
    if d.get("settledRequest"):
        lines.append(f"  委託      這筆紀錄結算了委託 #{d['settledRequest']}")
    for key, title in (("evidence", "證據檔案"), ("rebuild", "重新編譯"), ("replay", "重跑攻擊")):
        if key in d:
            lines += _fmt_checks(title, d[key])
    lines.append("  說明：紀錄是稽核者的主張；判定 1 代表沒有找到可證明的攻擊，不等於安全。")
    return "\n".join(lines)


def add_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("target", nargs="?", help="部署地址（0x…）、紀錄編號、交易雜湊或原始碼 sha256")
    ap.add_argument("--source", type=Path, help="用原始碼檔案查（sha256 → recordsBySource）")
    ap.add_argument("--evidence", type=Path, help="證據資料夾：重算雜湊、用 gate.json 重新推導判定，和鏈上比對")
    ap.add_argument("--rebuild", action="store_true", help="用紀錄的編譯設定重新編譯並比對")
    ap.add_argument("--replay", action="store_true",
                    help="在沙箱裡用 forge 重跑鏈上錨定的攻擊（需要 --evidence；不會執行證據裡的 regression.zip）")
    ap.add_argument("--json", action="store_true", help="輸出 JSON")
    add_network_args(ap, signer=False)


def run(args: argparse.Namespace) -> int:
    if not args.target and not args.source:
        raise ChainError("請給要查的地址 / 紀錄編號 / 交易雜湊，或 --source")
    if args.replay and not args.evidence:
        raise ChainError("--replay 需要 --evidence 證據資料夾")
    sess = open_session(args, need_deployment=True)
    what, ids, address = lookup(sess, args.target, args.source)
    results = []
    for rid in ids:
        d = describe(sess, rid, address)
        rec = d["record"]
        if args.evidence:
            d["evidence"] = check_evidence(sess, rec, args.evidence)
        if args.rebuild:
            d["rebuild"] = rebuild(sess, rec, args.evidence, args.source, d.get("address"))
        if args.replay:
            d["replay"] = replay(sess, rec, args.evidence)
        results.append(d)
    ok = bool(results) and all(all(d[k]["ok"] for k in ("evidence", "rebuild", "replay") if k in d)
                               and d.get("codehashMatches") is not False for d in results)
    if args.json:
        print(json.dumps({"query": what, "network": sess.net.name, "registry": sess.registry.address,
                          "records": results, "ok": ok}, ensure_ascii=False, indent=1))
    else:
        print(f"查詢：{what}  網路 {sess.net.name}  登錄合約 {sess.registry.address}")
        if not results:
            print("  鏈上沒有相符的紀錄。")
        for d in results:
            print(_text(sess, d))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="me_verify.py", description="從 ME 鏈上查詢並獨立重驗 ARBITER Gate 稽核紀錄。")
    add_args(ap)
    args = ap.parse_args(argv)
    try:
        return run(args)
    except ChainError as exc:
        print(f"錯誤：{exc}")
        return 2
