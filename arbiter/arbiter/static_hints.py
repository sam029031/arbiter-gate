"""Slither as the gate's second level: a hint, never evidence.

    hints = run_slither(code, "StakingVault.sol", work_dir)    # -> SlitherRun

The gate's verdicts stay execution-first (plan 7.6): a proven exploit is level one, an
unfinished audit is "not executed", and only when nothing was proven does a Slither
finding at impact >= Medium and confidence >= Medium raise the file to
static_hint_unproven -- shown as "this is an automated scanner's hint; the system did not
prove it can be attacked". That threshold is the best operating point on v3
(runs/slither.json) and was chosen with the answers in hand, so it is a display
threshold and nothing more: on v3 it flags 10 of the 20 patched contracts.

Slither is an external tool (pip, not the standard library), so it is only ever run as a
subprocess. Where to find it: $ARBITER_SLITHER, then PATH, then the tools venv that
sits next to the repository checkout (<checkout>/../venv-tools/bin/slither). The compiler
is forge's own download under ~/.svm, picked from the contract's pragma, because the
solc-select inside that venv has none installed. Any failure -- not installed, timeout,
compile error, bad JSON -- comes back as status "not_run" with a reason, and the caller
keeps its verdict.

scripts/slither_arm.py (the v3 control arm) uses run_slither too.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

IMPACTS = ["High", "Medium", "Low", "Informational", "Optimization"]
CONFIDENCES = ["High", "Medium", "Low"]
THRESHOLD = ("Medium", "Medium")
THRESHOLD_TEXT = "impact ≥ Medium 且 confidence ≥ Medium"
HINT_NOTE = "這是自動掃描工具的提示，系統沒有證實它真的能被攻擊。"
NOT_RUN_LABEL = "靜態分析未執行"
_RIG = Path(__file__).resolve().parent.parent          # the arbiter/ directory


@dataclass
class SlitherRun:
    status: str                       # "ran" | "not_run"
    reason: str = ""
    version: str = ""
    solc: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)

    def hints(self, functions: set[str] | None = None) -> list[dict[str, Any]]:
        """Findings at or above the display threshold; `functions` limits them to those
        whose first element sits in one of these functions (PR mode, P5)."""
        mi, mc = IMPACTS.index(THRESHOLD[0]), CONFIDENCES.index(THRESHOLD[1])
        out = [f for f in self.findings
               if IMPACTS.index(f.get("impact", "Optimization")) <= mi
               and CONFIDENCES.index(f.get("confidence", "Low")) <= mc]
        if functions is not None:
            out = [f for f in out if f.get("function") in functions]
        return out

    def as_dict(self, functions: set[str] | None = None) -> dict[str, Any]:
        hints = self.hints(functions) if self.status == "ran" else []
        return {"status": self.status, "label": "" if self.status == "ran" else NOT_RUN_LABEL,
                "reason": self.reason, "tool": f"slither {self.version}".strip(),
                "solc": self.solc, "threshold": THRESHOLD_TEXT,
                "findings_total": len(self.findings), "hints": hints}


def find_slither() -> str | None:
    """$ARBITER_SLITHER when set (an invalid one means "not installed", no fallback),
    else PATH, else the tools venv beside the checkout."""
    if "ARBITER_SLITHER" in os.environ:
        cand = os.environ["ARBITER_SLITHER"]
        return cand if cand and Path(cand).is_file() and os.access(cand, os.X_OK) else None
    for cand in (shutil.which("slither"),
                 str(_RIG.parent.parent / "venv-tools" / "bin" / "slither")):
        if cand and Path(cand).is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _ver(text: str) -> tuple[int, ...]:
    return tuple(int(x) for x in text.split("."))


def _satisfies(v: tuple[int, ...], spec: str) -> bool:
    for op, raw in re.findall(r"(\^|~|>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+)", spec):
        w = _ver(raw)
        ok = {"^": w <= v < (w[0], w[1] + 1, 0) if w[0] == 0 else w <= v < (w[0] + 1, 0, 0),
              "~": w <= v < (w[0], w[1] + 1, 0), ">=": v >= w, "<=": v <= w,
              ">": v > w, "<": v < w, "=": v == w, "": v == w}[op]
        if not ok:
            return False
    return True


def pick_solc(code: str, prefer: str = "") -> str | None:
    """forge's solc for this pragma: `prefer` if installed and allowed, else the newest
    installed one that satisfies it (what forge's auto-detect picks)."""
    svm = Path.home() / ".svm"
    installed = sorted((_ver(p.name), p / f"solc-{p.name}") for p in svm.glob("0.*")
                       if (p / f"solc-{p.name}").is_file())
    m = re.search(r"pragma\s+solidity\s+([^;]+);", code)
    spec = m.group(1) if m else ""
    allowed = [(v, b) for v, b in installed if _satisfies(v, spec)]
    for v, b in allowed:
        if prefer and v == _ver(prefer):
            return str(b)
    return str(allowed[-1][1]) if allowed else None


def _finding(d: dict[str, Any]) -> dict[str, Any]:
    els = d.get("elements") or []
    first = els[0] if els else {}
    lines = (first.get("source_mapping") or {}).get("lines") or []
    func = ""
    for e in els:
        if e.get("type") == "function":
            func = e.get("name", "")
            break
        parent = (e.get("type_specific_fields") or {}).get("parent") or {}
        if parent.get("type") == "function":
            func = parent.get("name", "")
            break
    desc = (d.get("description") or "").strip().splitlines()
    return {"check": d.get("check"), "impact": d.get("impact"),
            "confidence": d.get("confidence"),
            "line": lines[0] if lines else None, "end_line": lines[-1] if lines else None,
            "function": func,
            # The first line names the place; Slither appends (file#lines) with the
            # relative path we gave it, so no host path is carried.
            "message": desc[0][:300] if desc else d.get("check")}


def run_slither(code: str, filename: str, work_dir: Path, *, timeout: int = 180,
                slither: str | None = None, solc: str | None = None,
                prefer_solc: str = "") -> SlitherRun:
    """Slither on one self-contained file, inside `work_dir` (created; caller owns it)."""
    slither = slither or find_slither()
    if not slither:
        return SlitherRun("not_run", "slither 沒有安裝（或找不到）")
    solc = solc or pick_solc(code, prefer_solc)
    if not solc:
        return SlitherRun("not_run", "找不到符合 pragma 的 solc（~/.svm）")
    work_dir.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(filename).name) or "Target.sol"
    (work_dir / name).write_text(code, encoding="utf-8")
    out = work_dir / "slither.json"
    out.unlink(missing_ok=True)
    try:
        version = subprocess.run([slither, "--version"], capture_output=True, text=True,
                                 timeout=60).stdout.strip()
        proc = subprocess.run(  # noqa: S603
            [slither, name, "--solc", solc, "--json", out.name],
            cwd=work_dir, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return SlitherRun("not_run", f"slither 超過 {timeout} 秒未完成")
    except OSError as exc:
        return SlitherRun("not_run", f"slither 無法執行：{type(exc).__name__}")
    solc_ver = Path(solc).name.removeprefix("solc-")
    if not out.is_file():
        tail = (proc.stderr or proc.stdout).strip().splitlines()
        return SlitherRun("not_run", "slither 沒有產生結果：" + (tail[-1][:150] if tail else "?"),
                          version, solc_ver)
    try:
        data = json.loads(out.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return SlitherRun("not_run", f"slither 輸出不是 JSON：{exc}", version, solc_ver)
    if not data.get("success", True) and not (data.get("results") or {}).get("detectors"):
        return SlitherRun("not_run", "slither 分析失敗：" + str(data.get("error") or "")[:150],
                          version, solc_ver)
    raw = (data.get("results") or {}).get("detectors") or []
    return SlitherRun("ran", "", version, solc_ver, [_finding(d) for d in raw])
