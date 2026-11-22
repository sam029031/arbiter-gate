"""Compile an audited contract to the exact creation bytecode a record commits to.

One fixed recipe, so anyone can rebuild the same bytes: solc 0.8.24, optimizer on with 200
runs, evm_version paris (ME testnet rejects PUSH0, which every target newer than paris
emits), no metadata hash and no CBOR trailer (the bytecode then does not depend on file
paths or comments). The settings go into the evidence bundle as compiler.json.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import abi
from .chain import ChainError, find_tool

SOLC_VERSION = "0.8.24"
DEFAULT_EVM = "paris"


def settings(evm_version: str = DEFAULT_EVM) -> dict:
    return {
        "optimizer": {"enabled": True, "runs": 200},
        "evmVersion": evm_version,
        "metadata": {"bytecodeHash": "none", "appendCBOR": False},
        "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object", "evm.deployedBytecode.object",
                                        "evm.deployedBytecode.immutableReferences"]}},
    }


@dataclass
class Build:
    contract: str
    file_name: str
    initcode: str  # creation bytecode, 0x-hex, without constructor arguments
    runtime: str  # deployedBytecode, 0x-hex
    abi: list
    has_immutables: bool
    solc: str  # long version, e.g. 0.8.24+commit.e11b9ed9
    evm_version: str
    ctor_args: str = "0x"

    @property
    def deploy_code(self) -> str:
        """Creation bytecode plus ABI-encoded constructor arguments: what CREATE2 runs."""
        return self.initcode + self.ctor_args[2:]

    @property
    def initcode_hash(self) -> str:
        return abi.keccak_hex(self.deploy_code)

    @property
    def runtime_hash(self) -> str:
        return abi.keccak_hex(self.runtime)

    def compiler_json(self) -> dict:
        s = settings(self.evm_version)
        del s["outputSelection"]
        return {"solc": self.solc, "language": "Solidity", "settings": s, "file": self.file_name,
                "contract": self.contract, "constructorArgs": self.ctor_args}


def _svm_paths(version: str) -> list[Path]:
    """Where svm (Foundry's solc manager) keeps solc: ~/.svm, or the XDG data dir when ~/.svm
    does not exist (newer svm releases)."""
    xdg = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return [d / version / f"solc-{version}" for d in (Path.home() / ".svm", xdg / "svm")]


def find_solc(version: str = SOLC_VERSION) -> str:
    """svm's install location first (Foundry puts solc there), then PATH; otherwise let forge
    download it once (the only network access the tools make for compiling)."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", version or ""):
        raise ChainError(f"solc 版本格式不對：{version!r}")
    cand = [*_svm_paths(version), shutil.which(f"solc-{version}"), shutil.which("solc")]
    for c in cand:
        if c and Path(c).exists():
            out = subprocess.run([str(c), "--version"], capture_output=True, text=True).stdout
            if f"Version: {version}+" in out:
                return str(c)
    # Let forge download it once (it caches solc in ~/.svm). The project is this throwaway one.
    with tempfile.TemporaryDirectory(prefix="arbiter-solc-") as tmp:
        (Path(tmp) / "src").mkdir()
        (Path(tmp) / "src" / "A.sol").write_text(f"pragma solidity {version};\ncontract A {{}}\n")
        subprocess.run([find_tool("forge"), "build", "--use", version, "--root", tmp],
                       capture_output=True, text=True, timeout=600)
    for p in _svm_paths(version):
        if p.exists():
            return str(p)
    raise ChainError(f"找不到 solc {version}；請先執行 `forge build --use {version}` 讓 Foundry 下載")


def solc_long_version(solc: str) -> str:
    out = subprocess.run([solc, "--version"], capture_output=True, text=True).stdout
    m = re.search(r"Version: (\S+)", out)
    return (m.group(1) if m else SOLC_VERSION).removesuffix(".Linux.g++").split(".Linux")[0]


_IMPORT_RE = re.compile(r"^\s*import\s", re.M)


def compile_source(source: str, file_name: str, contract: str | None = None, *,
                   evm_version: str = DEFAULT_EVM, ctor_args: str = "0x",
                   version: str = SOLC_VERSION, imports: dict[str, str] | None = None) -> Build:
    """Compile one Solidity file and pick `contract` (default: the contract named like the
    file, else the last contract with bytecode). A file with imports needs `imports`: the
    content of every imported file by its source unit name (a relative import resolves
    against `file_name`: "./AuditRegistry.sol" imported by "AuditEscrow.sol" is the unit
    "AuditRegistry.sol"). Without metadata the bytecode does not depend on unit names."""
    if _IMPORT_RE.search(source) and not imports:
        raise ChainError(f"{file_name} 有 import；目前只支援單一檔案（請先 flatten：forge flatten）")
    solc = find_solc(version)
    sources = {name: {"content": text} for name, text in (imports or {}).items()}
    sources[file_name] = {"content": source}
    std_in = {"language": "Solidity", "sources": sources, "settings": settings(evm_version)}
    proc = subprocess.run([solc, "--standard-json"], input=json.dumps(std_in), capture_output=True, text=True,
                          timeout=300)
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise ChainError(f"solc 輸出無法解析：{proc.stderr[-500:]}") from exc
    errors = [e for e in out.get("errors", []) if e.get("severity") == "error"]
    if errors:
        raise ChainError("編譯失敗：\n" + "\n".join(e.get("formattedMessage", e.get("message", "")) for e in errors))
    found = out.get("contracts", {}).get(file_name, {})
    deployable = {n: c for n, c in found.items() if c["evm"]["bytecode"]["object"]}
    if contract is None:
        stem = Path(file_name).stem
        contract = stem if stem in deployable else (list(deployable)[-1] if deployable else None)
    if contract not in deployable:
        raise ChainError(f"{file_name} 裡沒有可部署的合約 {contract!r}（有：{', '.join(deployable) or '無'}）")
    c = deployable[contract]
    ctor = ctor_args if ctor_args.startswith("0x") else "0x" + ctor_args
    return Build(
        contract=contract, file_name=file_name,
        initcode="0x" + c["evm"]["bytecode"]["object"],
        runtime="0x" + c["evm"]["deployedBytecode"]["object"],
        abi=c.get("abi", []),
        has_immutables=bool(c["evm"]["deployedBytecode"].get("immutableReferences")),
        solc=solc_long_version(solc), evm_version=evm_version, ctor_args=ctor.lower(),
    )


def uses_push0(bytecode_hex: str) -> bool:
    """True when the bytecode executes PUSH0 (0x5f) as an opcode (push data skipped)."""
    code = abi.hexbytes(bytecode_hex)
    i = 0
    while i < len(code):
        op = code[i]
        if op == 0x5F:
            return True
        i += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
    return False
