"""Which solc versions an audit can use here, and a zh-TW reason when a contract needs another.

The sandbox (sandbox.py) runs with --network none and a read-only root, so forge cannot
install a compiler at audit time: it can use only what the image carries in /opt/svm
(service/sandbox/solc.lock). When a pragma needs another version, forge says

    Failed to install solc 0.5.17: Read-only file system (os error 30)
    Error: Read-only file system (os error 30)              (a version pinned in foundry.toml)
    No compiler version exists that matches the version requirement: =0.8.38
    Error: Found incompatible versions:                     (no version fits contract AND harness)

none of which tells the person who uploaded the contract what happened, and the contract
may be perfectly fine. explain_missing() (from forge's output) and explain_pragma() (from
the contract's own pragma) turn these into
「沙箱裡沒有 solc 0.5.17（目前支援 0.7.6、0.8.0～0.8.37）」.

"Supported" means usable by the audit, not merely present: the harness's test files
declare a file-level constant and free functions (workspace.py VM_SOL), which solc
accepts from 0.7.4 on, so the image's 0.6.12 compiles a 0.6 contract on its own but not
the audit around it. A contract that only accepts versions below 0.7.4 is told exactly
that. The list is read from the running job's container (or ~/.svm outside the sandbox),
so it is right for whichever image actually ran.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

HARNESS_MIN = (0, 7, 4)
_INSTALL = re.compile(r"Failed to install solc (\d+\.\d+\.\d+)")
_NO_MATCH = re.compile(r"No compiler version exists that matches the version requirement: ([^\n]+)")
_ROFS = "Read-only file system (os error 30)"
_VERSION = re.compile(r"\d+\.\d+\.\d+")
_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")
_COMMENTS = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_COMPARATOR = re.compile(r"(\^|~|>=|<=|>|<|=)?\s*v?(\d+(?:\.(?:\d+|[xX*])){0,2})")
# Recognises one of these explanations in a stored reason/detail (webui picks its advice by it).
MISSING_RE = re.compile(r"^(?:context_unbuildable: )?(?:(?:沙箱裡|這台機器)沒有 (?:solc |符合 )"
                        r"|ARBITER 的測試程式需要 solc )")


def _key(v: str) -> tuple[int, int, int]:
    a, b, c = (int(x) for x in v.split("."))
    return a, b, c


def installed() -> list[str]:
    """The solc versions forge can use without downloading, oldest first."""
    container = os.environ.get("ARBITER_SANDBOX_CONTAINER")
    names: list[str] = []
    if container:
        try:
            out = subprocess.run(["docker", "exec", container, "ls", "/opt/svm"],
                                 capture_output=True, text=True, timeout=30)
            names = out.stdout.split() if out.returncode == 0 else []
        except (subprocess.TimeoutExpired, OSError):
            names = []
    else:
        svm = Path.home() / ".svm"
        if svm.is_dir():
            names = [p.name for p in svm.iterdir() if (p / f"solc-{p.name}").is_file()]
    return sorted({n for n in names if _VERSION.fullmatch(n)}, key=_key)


def auditable(versions: list[str]) -> list[str]:
    """The versions the audit's own test files compile with (HARNESS_MIN and up)."""
    return [v for v in versions if _key(v) >= HARNESS_MIN]


def summarize(versions: list[str]) -> str:
    """'0.7.6、0.8.0～0.8.37': runs of three or more consecutive patches collapse."""
    parts: list[str] = []
    run: list[str] = []

    def flush() -> None:
        parts.extend([f"{run[0]}～{run[-1]}"] if len(run) >= 3 else run)
        run.clear()

    for v in sorted(set(versions), key=_key):
        if run:
            a, b = _key(run[-1]), _key(v)
            if not (a[:2] == b[:2] and b[2] == a[2] + 1):
                flush()
        run.append(v)
    flush()
    return "、".join(parts)


def _comparator_ok(op: str, ver: str, v: tuple[int, int, int]) -> bool:
    nums = [int(x) for x in ver.split(".") if x.isdigit()]
    n = len(nums)
    base = tuple(nums + [0] * (3 - n))
    if op in ("", "="):
        return v[:n] == tuple(nums)
    if op == "^":
        if base[0] > 0 or n == 1:
            hi = (base[0] + 1, 0, 0)
        elif base[1] > 0 or n == 2:
            hi = (0, base[1] + 1, 0)
        else:
            hi = (0, 0, base[2] + 1)
        return base <= v < hi
    if op == "~":
        hi = (base[0] + 1, 0, 0) if n == 1 else (base[0], base[1] + 1, 0)
        return base <= v < hi
    if op == ">=":
        return v >= base
    if op == "<":
        return v < base
    if op == ">":
        return v[:n] > tuple(nums)
    return v[:n] <= tuple(nums)  # "<="


def satisfies(version: str, requirement: str) -> bool | None:
    """Does `version` meet a pragma expression? None if the expression is not understood."""
    v = _key(version)
    any_alt = False
    for alt in requirement.split("||"):
        alt = re.sub(r"(\d)\s+-\s+(\d)", r"\1 HYPHEN \2", alt.strip())
        if "HYPHEN" in alt:  # "0.8.0 - 0.8.10"
            lo, hi = (s.strip() for s in alt.split("HYPHEN"))
            alt = f">={lo} <={hi}"
        comps = _COMPARATOR.findall(alt)
        if not comps or _COMPARATOR.sub("", alt).strip():
            return None
        any_alt = True
        if all(_comparator_ok(op, ver, v) for op, ver in comps):
            return True
    return False if any_alt else None


def pragmas(code: str) -> list[str]:
    return [p.strip() for p in _PRAGMA.findall(_COMMENTS.sub("", code))]


def _where(need: str, listed: str) -> str:
    if os.environ.get("ARBITER_SANDBOX_CONTAINER"):
        return f"沙箱裡沒有 {need}" + (f"（目前支援 {listed}）" if listed else "")
    return f"這台機器沒有 {need}，也沒能下載" + (f"（目前有 {listed}）" if listed else "")


def explain_missing(output: str, pinned: str = "") -> str | None:
    """A zh-TW reason if `output` (forge's) is a compiler it could not get, else None.

    `pinned` is the version foundry.toml pinned, if any: forge's bare "Read-only file
    system" error after a pinned build names no version, so it is only explained when
    the pinned version really is absent."""
    need = ""
    if m := _INSTALL.search(output):
        need = f"solc {m.group(1)}"
    elif m := _NO_MATCH.search(output):
        req = m.group(1).strip()
        need = f"solc {req[1:]}" if re.fullmatch(r"=\d+\.\d+\.\d+", req) else f"符合 {req} 的 solc 版本"
    elif _ROFS not in output or not pinned:
        return None
    have = installed()
    if not need:
        if pinned in have:
            return None
        need = f"solc {pinned}"
    return _where(need, summarize(auditable(have)))


def explain_pragma(code: str) -> str | None:
    """A zh-TW reason if no compiler here can build `code` inside an audit, else None.

    Read from the contract's own pragma(s); None when there is none, when one is not
    understood, or when some available version fits (the failure is then something
    else, and the compiler's own message is the one to show)."""
    reqs = pragmas(code)
    if not reqs:
        return None

    def fits(v: str) -> bool | None:
        oks = [satisfies(v, r) for r in reqs]
        return None if None in oks else all(oks)

    # Every version a pragma could plausibly name, released or not: enough to tell
    # "accepts only compilers older than the harness needs" from "accepts something".
    every = ([f"0.{m}.{p}" for m in (4, 5, 6, 7) for p in range(30)]
             + [f"0.8.{p}" for p in range(100)] + ["0.9.0", "0.10.0", "1.0.0"])
    verdicts = {v: fits(v) for v in every}
    if None in verdicts.values():
        return None
    sandboxed = bool(os.environ.get("ARBITER_SANDBOX_CONTAINER"))
    have = installed() if sandboxed else []
    shown = "、".join(reqs)
    exact = re.fullmatch(r"=?\s*(\d+\.\d+\.\d+)", reqs[0]) if len(reqs) == 1 else None
    need = f"solc {exact.group(1)}" if exact else f"符合 pragma（{shown}）的 solc 版本"
    floor = ".".join(map(str, HARNESS_MIN))
    if any(verdicts.values()) and not any(ok for v, ok in verdicts.items() if _key(v) >= HARNESS_MIN):
        # Accepts only compilers older than the harness needs. Said even when the sandbox
        # lacks that compiler too, because adding it would not make the audit possible.
        if have and not any(fits(v) for v in have):
            return (f"沙箱裡沒有 {need}（目前支援 {summarize(auditable(have))}；"
                    f"ARBITER 的測試程式需要 solc {floor} 以上）")
        return (f"ARBITER 的測試程式需要 solc {floor} 以上，"
                f"這份合約的 pragma（{shown}）只接受更舊的版本，所以目前沒辦法稽核"
                + (f"（沙箱裡可用 {summarize(auditable(have))}）" if have else ""))
    # Outside the sandbox forge downloads what it lacks; only the sandbox can be short.
    if not sandboxed or not have or any(fits(v) for v in auditable(have)):
        return None
    return _where(need, summarize(auditable(have)))
