"""Turn an ARBITER Gate result into an AuditRegistry record and its evidence bundle.

Inputs: a gate.json (exact bytes; or a web result id, hashed as the bytes the web page
serves), the audited source file, and the run's results row (found through gate.json
`input.results`) for the exploit. Output: the RecordInput the registry takes and a directory
anyone can re-check against the chain:

    gate.json            exact bytes whose sha256 is gateJsonHash
    src/<File>.sol       the source this record is about (sourceHash)
    parent_src/<File>    patched records only: the original the patch applies to
    exploit/<poc>.t.sol  the proven exploit as the run recorded it (exploitHash)
    patch.diff           the verified patch, headers naming src/<File> (patchHash)
    regression.zip       Foundry project: the attack as a regression test (if available)
    compiler.json        the exact compiler recipe behind initcodeHash
    manifest.json        every file above with its sha256, plus the RecordInput

Everything is a pure function of the inputs (no timestamps), so the same gate result always
produces the same bundle and the same hashes.
"""
from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .build import Build, compile_source
from .chain import ZERO32, ChainError
from .contracts import ME_DIR, RECORD_FIELDS

ARBITER_DIR = ME_DIR.parent / "arbiter"  # the gate's own directory (paths in gate.json are relative to it)
WEB_DIR = ARBITER_DIR / "runs" / "gate" / "web"

# BRIEF 4.3: gate verdict -> registry uint8
VERDICT_CODES = {"proven_exploitable": 3, "static_hint_unproven": 2, "no_provable_attack": 1, "not_executed": 0}
STRICT_PREDICATES = {"victim_loss", "liveness_broken"}
LOOSE_PREDICATES = {"eth_profit", "token_profit", "state_change"}
# check-5 statuses that mean "the patched code was attacked again and nothing was proven"
REATTACK_DONE = {"pass", "not_diverse"}


def _arbiter():
    """Import the gate's own modules (gate.public_report etc.), standard library only."""
    if str(ARBITER_DIR) not in sys.path:
        sys.path.insert(0, str(ARBITER_DIR))


def sha256_hex(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def verdict_code(gate_verdict: str | None) -> int:
    return VERDICT_CODES.get(str(gate_verdict or ""), 0)


def predicate_class(finding: dict) -> int:
    p = finding.get("predicate")
    if p in STRICT_PREDICATES:
        return 2
    if p in LOOSE_PREDICATES:
        return 1
    if finding.get("predicate_strict") is not None:
        return 2 if finding["predicate_strict"] else 1
    return 0


# ------------------------------------------------------------------ gate.json input


@dataclass
class GateInput:
    raw: bytes  # the bytes gateJsonHash covers
    report: dict
    path: Path | None = None
    rid: str | None = None

    @property
    def sha256(self) -> str:
        return sha256_hex(self.raw)


def web_gate_bytes(saved: dict) -> bytes:
    """What /result/<rid>/gate.json serves (web.download kind 'gate')."""
    _arbiter()
    from arbiter.gate import public_report
    return (json.dumps(public_report(saved["report"]), ensure_ascii=False, indent=1) + "\n").encode("utf-8")


def load_gate(gate_path: Path | None = None, rid: str | None = None, web_dir: Path | None = None) -> GateInput:
    if not gate_path and not rid:
        raise ChainError("需要 gate.json 路徑或 --rid")
    raw = None
    if rid:
        saved_path = (web_dir or WEB_DIR) / f"{rid}.json"
        if not saved_path.exists():
            raise ChainError(f"找不到網頁結果 {rid}")
        raw = web_gate_bytes(json.loads(saved_path.read_text(encoding="utf-8")))
    if gate_path:
        file_raw = Path(gate_path).read_bytes()
        if raw is not None and file_raw != raw:
            raise ChainError("gate.json 和 --rid 的網頁結果內容不同；請只給其中一個")
        raw = file_raw
    return GateInput(raw=raw, report=json.loads(raw.decode("utf-8")),
                     path=Path(gate_path) if gate_path else None, rid=rid)


def pick_entry(report: dict, source_sha: str | None = None, file_id: str | None = None) -> dict:
    files = report.get("files") or []
    if not files:
        raise ChainError("gate.json 沒有任何檔案結果")
    if file_id is not None:
        for i, e in enumerate(files):
            if str(i) == str(file_id) or e.get("id") == file_id:
                return e
        raise ChainError(f"gate.json 裡沒有檔案 {file_id}（有：{', '.join(e.get('id', '?') for e in files)}）")
    if source_sha:
        hits = [e for e in files if (e.get("artifact") or {}).get("sha256") == source_sha.removeprefix("0x")]
        if len(hits) == 1:
            return hits[0]
    if len(files) == 1:
        return files[0]
    raise ChainError("gate.json 有多個檔案；用 --file 指定（id 或索引）")


def results_row(report: dict, sample_id: str, results: Path | None = None) -> dict | None:
    raw = str(results) if results else (report.get("input") or {}).get("results")
    if not raw:
        return None
    path = Path(raw) if Path(raw).is_absolute() else ARBITER_DIR / raw
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and (row := json.loads(line)).get("sample_id") == sample_id:
            return row
    return None


def proven_finding(entry: dict) -> dict | None:
    for f in entry.get("findings") or []:
        if f.get("poc_name"):
            return f
    return (entry.get("findings") or [None])[0]


def exploit_solidity(row: dict | None, poc_name: str | None) -> str | None:
    for p in ((row or {}).get("outcome") or {}).get("pocs") or []:
        if p.get("passed") and p.get("adjudicated") and p.get("name") == poc_name and p.get("solidity"):
            return p["solidity"]
    return None


def tool_commit(report: dict, override: str | None = None) -> tuple[str, str]:
    """(bytes20 hex, where it came from). gate.json records `tool_commit` since the gate
    started writing it; for older reports the checkout running this tool is the fallback (and
    the note says so); --tool-commit sets it explicitly."""
    commit = override or report.get("tool_commit")
    source = "--tool-commit" if override else "gate.json"
    if not commit:
        proc = subprocess.run(["git", "-C", str(ME_DIR), "rev-parse", "HEAD"], capture_output=True, text=True)
        commit, source = proc.stdout.strip(), "目前的 git HEAD（gate.json 沒有記錄 commit）"
    commit = commit.removeprefix("0x").lower()
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise ChainError(f"tool commit 必須是 40 位十六進位：{commit!r}")
    return "0x" + commit, source


def model_name(report: dict) -> str:
    models = report.get("models") or []
    return str(models[0]).removesuffix(":latest")[:64] if models else ""


def gate_info(gate: GateInput, entry: dict) -> dict:
    """What a reader needs to know about a gate.json besides its hash: when it was produced,
    by which ARBITER Gate code and model, and what it concluded for this file."""
    r = gate.report
    art = (entry.get("artifact") or {}).get("sha256")
    return {"file": gate.path.name if gate.path else (f"{gate.rid}.gate.json" if gate.rid else "gate.json"),
            "sha256": gate.sha256, "generatedAt": r.get("generated_at"),
            "toolCommit": r.get("tool_commit"), "toolCommitSource": r.get("tool_commit_source"),
            "model": model_name(r), "mode": (r.get("input") or {}).get("mode"),
            "entry": entry.get("id"), "gateVerdict": entry.get("verdict"),
            "verdict": verdict_code(entry.get("verdict")), "auditedSha256": "0x" + art if art else None}


def deterministic_zip(root: Path, top: str) -> bytes:
    """Zip `root` as `top/...` with fixed timestamps and order, so the bytes are reproducible."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fp in sorted(p for p in root.rglob("*") if p.is_file()):
            info = zipfile.ZipInfo(f"{top}/{fp.relative_to(root).as_posix()}", date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, fp.read_bytes())
    return buf.getvalue()


# ------------------------------------------------------------------ the record


@dataclass
class RecordPlan:
    input: dict  # RecordInput, keys = contracts.RECORD_FIELDS
    build: Build | None
    bundle: Path
    files: list[dict]  # [{"name", "role", "sha256"}]
    manifest_sha256: str
    gate: GateInput
    entry: dict
    finding: dict | None
    patched: bool
    notes: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> int:
        return self.input["verdict"]


def _write(bundle: Path, rel: str, data: bytes, role: str, files: list[dict]) -> None:
    p = bundle / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    files.append({"name": rel, "role": role, "sha256": sha256_hex(data)})


def stale_source(entry: dict, source_sha: str) -> str | None:
    """The sha256 gate.json says it audited, when that is not `source_sha` (else None)."""
    art_sha = (entry.get("artifact") or {}).get("sha256")
    return "0x" + art_sha if art_sha and "0x" + art_sha != source_sha else None


def plan_record(gate: GateInput, source_path: Path, *, out_dir: Path, file_id: str | None = None,
                results: Path | None = None, patched: bool = False, parent_id: int = 0,
                contract: str | None = None, ctor_args: str = "0x", evidence_uri: str = "",
                tool_commit_override: str | None = None, evm_version: str = "paris",
                imports: dict[str, Path] | None = None, stale_ok: bool = False) -> RecordPlan:
    """Build the RecordInput and write the evidence bundle to `out_dir`.

    patched=False: the record is the gate result for `source_path` (which must be the audited
    file). patched=True: `source_path` is still the audited original; the verified patch from
    gate.json is applied to it and the record is about the patched source, child of
    `parent_id`. `imports` (source unit name -> file) are the files `source_path` imports; they
    go into the bundle as imports/<unit> and compiler.json names them, so the initcode can be
    rebuilt from the bundle alone. `stale_ok` is for anvil rehearsals only: it lets a gate.json
    that audited another version of the file through, with a note."""
    notes: list[str] = []
    report = gate.report
    original = Path(source_path).read_bytes()
    orig_sha = sha256_hex(original)
    entry = pick_entry(report, orig_sha, file_id)
    if stale := stale_source(entry, orig_sha):
        msg = (f"{Path(source_path).name} 的 sha256 ({orig_sha[:18]}…) 和 gate.json 稽核的檔案"
               f"（{stale[:18]}…）不同")
        if not stale_ok:
            raise ChainError(msg + "：紀錄必須指向被稽核的那份原始碼")
        notes.append(msg + "（排練：gate.json 稽核的是另一版原始碼，正式網路不會登錄）")
    file_name = Path(source_path).name
    finding = proven_finding(entry)
    row = results_row(report, entry.get("id", ""), results)
    gate_verdict = verdict_code(entry.get("verdict"))
    p = (finding or {}).get("patch") or {}
    diff = p.get("diff") if p.get("status") == "verified" else None

    _arbiter()
    from arbiter.gate import build_regression, patch_for_download

    files: list[dict] = []
    bundle = Path(out_dir)
    bundle.mkdir(parents=True, exist_ok=True)
    _write(bundle, "gate.json", gate.raw, "gate_json", files)

    patch_bytes = patch_for_download(diff, file_name).encode("utf-8") if diff else None
    if patched:
        if not parent_id:
            raise ChainError("修補後的紀錄需要 --parent（原始紀錄的編號）")
        if not diff:
            raise ChainError("gate.json 裡這個漏洞沒有通過驗證的修補，無法建立修補後的紀錄")
        from arbiter.patch import apply_diff
        new_text, err = apply_diff(original.decode("utf-8"), diff)
        if new_text is None:
            raise ChainError(f"修補套用失敗：{err}")
        source = new_text.encode("utf-8")
        c5 = (p.get("gate_checks") or {}).get("5")
        verdict = 1 if c5 in REATTACK_DONE else 0
        if c5 == "not_diverse":
            notes.append("修補後再攻擊沒有換手法（check 5 = not_diverse）；判定 1 只代表沒有證實新的攻擊")
        elif verdict == 0:
            notes.append(f"修補後沒有再攻擊（check 5 = {c5 or '未記錄'}），修補後的程式碼沒有被重新稽核，判定 0")
        _write(bundle, f"parent_src/{file_name}", original, "parent_source", files)
    else:
        source = original
        verdict = gate_verdict

    _write(bundle, f"src/{file_name}", source, "source", files)

    exploit_hash, pred, tier = ZERO32, 0, 0
    poc = (finding or {}).get("poc_name")
    sol = exploit_solidity(row, poc) if gate_verdict == 3 else None
    if sol:
        _write(bundle, f"exploit/{poc}.t.sol", sol.encode("utf-8"), "exploit", files)
    if verdict == 3:
        if not sol:
            raise ChainError("判定為已證實可攻擊，但找不到攻擊程式（results.jsonl）；用 --results 指定")
        exploit_hash = sha256_hex(sol.encode("utf-8"))
        pred = predicate_class(finding) or 1
        tier = int(((finding.get("evidence") or {}).get("reached")) or 1)
        tier = min(max(tier, 1), 3)
    if patch_bytes:
        _write(bundle, "patch.diff", patch_bytes, "patch", files)
    elif patched:
        raise ChainError("internal: patched record without patch bytes")

    if row and finding and (finding.get("regression") or {}).get("status") == "available":
        meta = {"models": report.get("models"), "run_id": (report.get("input") or {}).get("run_id"),
                "generated_at": report.get("generated_at")}
        stem = Path(file_name).stem
        with tempfile.TemporaryDirectory(prefix="arbiter-me-reg-") as tmp:
            proj = Path(tmp) / "proj"
            try:
                build_regression(row, finding, proj, meta, file_name)
                _write(bundle, "regression.zip", deterministic_zip(proj, f"arbiter-regression-{stem}"),
                       "regression", files)
            except (ValueError, KeyError) as exc:
                notes.append(f"回歸測試專案無法產生：{exc}")

    import_texts: dict[str, str] = {}
    for unit, path in (imports or {}).items():
        data = Path(path).read_bytes()
        # role "compiler": an input of the compile recipe, checked against the manifest only
        _write(bundle, f"imports/{unit}", data, "compiler", files)
        import_texts[unit] = data.decode("utf-8")

    build = None
    try:
        build = compile_source(source.decode("utf-8"), file_name, contract, evm_version=evm_version,
                               ctor_args=ctor_args, imports=import_texts or None)
        initcode_hash = build.initcode_hash
        recipe = build.compiler_json()
        if import_texts:
            recipe["imports"] = {unit: f"imports/{unit}" for unit in import_texts}
        cj = json.dumps(recipe, indent=1, sort_keys=True) + "\n"
        _write(bundle, "compiler.json", cj.encode("utf-8"), "compiler", files)
    except ChainError as exc:
        if verdict in (1, 2):
            raise
        initcode_hash = ZERO32
        notes.append(f"無法編譯，initcodeHash 記為 0（這筆紀錄本來就不能部署）：{exc}")

    commit, commit_src = tool_commit(report, tool_commit_override)
    notes.append(f"toolCommit 來源：{commit_src}")
    inp = {
        "sourceHash": sha256_hex(source),
        "initcodeHash": initcode_hash,
        "verdict": verdict,
        "predicateClass": pred,
        "evidenceTier": tier,
        "gateJsonHash": gate.sha256,
        "exploitHash": exploit_hash,
        "patchHash": sha256_hex(patch_bytes) if patch_bytes else ZERO32,
        "parentId": int(parent_id or 0),
        "toolCommit": commit,
        "model": model_name(report),
        "evidenceURI": evidence_uri,
    }
    assert set(inp) == set(RECORD_FIELDS)
    files.sort(key=lambda f: f["name"])
    manifest = {"schema": "arbiter-me-evidence/0.1", "recordInput": inp, "files": files,
                "fileEntry": entry.get("id"), "gateVerdict": entry.get("verdict"), "patched": patched}
    mbytes = (json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
    (bundle / "manifest.json").write_bytes(mbytes)
    return RecordPlan(input=inp, build=build, bundle=bundle, files=files, manifest_sha256=sha256_hex(mbytes),
                      gate=gate, entry=entry, finding=finding, patched=patched, notes=notes)


def load_manifest(bundle: Path) -> dict:
    path = Path(bundle) / "manifest.json"
    if not path.exists():
        raise ChainError(f"{bundle} 不是證據資料夾（沒有 manifest.json）")
    return json.loads(path.read_text(encoding="utf-8"))
