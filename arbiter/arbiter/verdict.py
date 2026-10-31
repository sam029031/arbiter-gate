"""Map one results row to the four display verdicts.

`outcome.verdict` is a scoring label: everything that is not "vulnerable" collapses to
"safe" downstream, which is how a run with a dead gateway, zero requests, used to print
CLEAR. A verdict shown to a person has to say whether anything was measured, so the
mapping below is checked top to bottom and the first match wins:

    proven_exploitable    outcome.proven -- a passed, harness-adjudicated exploit
    not_executed          no compilable context, no toolchain, an exception (a gateway
                          failure lands here), or not one completed agent turn
    static_hint_unproven  not proven, but Slither flags impact >= Medium and confidence
                          >= Medium (with_static_hints, applied by gate.py; a hint, never
                          evidence)
    no_provable_attack    everything else, conclude_safe and turn_budget_exhausted
                          included -- a search that found nothing, not a clean bill

No label here says "safe". `no_provable_attack` is deliberately worded as an absence of
evidence, and `not_executed` is never folded into it.
"""

from __future__ import annotations

from typing import Any

PROVEN = "proven_exploitable"
STATIC_HINT = "static_hint_unproven"
NO_PROVABLE = "no_provable_attack"
NOT_EXECUTED = "not_executed"

LABELS = {
    PROVEN: "已證實可攻擊（擋部署）",
    STATIC_HINT: "靜態工具提示但未證實",
    NO_PROVABLE: "未發現可證明攻擊（不等於安全）",
    NOT_EXECUTED: "無法判定（稽核未完成）",
}

# Exit codes for a gate: 1 blocks deployment, 2 is "did not run" and must not read as a
# pass either, 0 is the only success.
EXIT_CODES = {PROVEN: 1, NOT_EXECUTED: 2, STATIC_HINT: 0, NO_PROVABLE: 0}

_NOT_RUN_STOPS = ("context_unbuildable", "toolchain_unavailable")


def classify(row: dict[str, Any]) -> tuple[str, str]:
    """Return (verdict, reason) for one row of `<run_id>.results.jsonl`."""
    o = row.get("outcome") or {}
    stop = str(o.get("stop_reason") or "")
    if o.get("proven"):
        return PROVEN, stop
    if not (row.get("context") or {}).get("ok", True):
        return NOT_EXECUTED, "context_unbuildable"
    if stop in _NOT_RUN_STOPS or stop.startswith("error"):
        return NOT_EXECUTED, row.get("error") or stop
    # A row with no completed turn never reached the model: zero requests answered.
    turns = sum(int(a.get("turns") or 0) for a in row.get("attempts") or [])
    if turns == 0 and not o.get("turns"):
        return NOT_EXECUTED, f"zero completed turns ({stop or 'no stop_reason'})"
    return NO_PROVABLE, stop


def worst_exit(verdicts: list[str]) -> int:
    """Gate exit code over many files: any proven blocks (1), else any unrun is 2."""
    if PROVEN in verdicts:
        return 1
    if NOT_EXECUTED in verdicts:
        return 2
    return 0


def with_static_hints(verdict: str, hints: list[Any]) -> str:
    """Raise no_provable_attack to static_hint_unproven when a static tool flagged
    something at the display threshold. Proven and not-executed stay what they are: a
    hint is never evidence, and it cannot stand in for an audit that did not finish."""
    return STATIC_HINT if verdict == NO_PROVABLE and hints else verdict
