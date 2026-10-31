"""Turn Bastet's discarded detector hits into a hypothesis queue.

The instrument audit showed Bastet's *verdict* is worthless: a 53-way OR that fires on
every sample, specificity 0.000, MCC exactly 0.000. But the verdict is an aggregation,
and the aggregation is what destroys the signal. The individual hits underneath it are a
different object, and measurement says they carry information the verdict does not: of
the 11 vulnerable samples ARBITER failed to prove, 8 had a detector fire whose name
matches the real defect -- `avoidTx-origin` on the tx.origin sample, `Unbounded-loop` on
the denial-of-service one, `ERC4626-Rounding` on the rounding one, `FoTTokens` on
fee-on-transfer. Every one of those is a hypothesis the agent never formed.

So the two systems fail in complementary ways. Bastet proposes everything and decides
nothing; ARBITER decides well and proposes badly. This module is the join: Bastet's hits
become the hypothesis queue, and the execution gate still refuses anything that cannot be
proven, so a wrong proposal costs turns rather than precision.

Ranking is by corpus-wide rarity, computed from the detector rows alone and never from
labels. A detector that fires on nearly every sample carries almost no information about
any particular one; a detector that fires rarely and fires *here* is worth trying first.
That ordering is unsupervised, so it introduces no leakage from the evaluation labels.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path


def load_hits(jobs_path: Path) -> dict[str, list[str]]:
    """sample id -> detector names that returned a non-empty finding list."""
    fired: dict[str, list[str]] = defaultdict(list)
    for line in jobs_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("n_findings"):
            fired[row["sample"]].append(row["detector"])
    return {k: sorted(set(v)) for k, v in fired.items()}


def rarity(jobs_path: Path) -> dict[str, float]:
    """detector -> share of samples it fires on. Lower is more informative."""
    fired_on: dict[str, set[str]] = defaultdict(set)
    samples: set[str] = set()
    for line in jobs_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        samples.add(row["sample"])
        if row.get("n_findings"):
            fired_on[row["detector"]].add(row["sample"])
    n = len(samples) or 1
    return {d: len(s) / n for d, s in fired_on.items()}


def humanise(detector: str) -> str:
    """Make an n8n node name readable as a hypothesis.

    Names arrive as `SC10-2025-Denial-Of-Service`, `4naly3er-M-avoidTx-origin`,
    `Chainlink-Not-Checking-For-Stale-Price`. Stripping the taxonomy prefixes and the
    separators leaves the part that actually names a vulnerability class.
    """
    text = detector
    text = re.sub(r"^(SC\d+[-:]?\d*|4naly3er)[-_ ]*", "", text)
    text = re.sub(r"^[MHL][-_ ]", "", text)
    text = re.sub(r"[-_]+", " ", text).strip()
    return text or detector


def proposal_block(
    hits: list[str], rare: dict[str, float], limit: int = 14
) -> str:
    """Render the hypothesis queue that goes into the agent's task prompt."""
    if not hits:
        return ""
    ordered = sorted(hits, key=lambda d: (rare.get(d, 1.0), d))[:limit]
    lines = "\n".join(
        f"  - {humanise(d)}  (this detector fires on "
        f"{rare.get(d, 1.0):.0%} of contracts)"
        for d in ordered
    )
    dropped = len(hits) - len(ordered)
    tail = f"\n  ... and {dropped} more, omitted as too common to be informative." if dropped > 0 else ""
    return (
        "\n\nA cheap pattern-matching scanner was run over this contract first. It is "
        "NOT reliable: it flags almost every contract it sees, its true-negative rate is "
        "zero, and its overall verdict carries no information at all. Do not treat any "
        "of this as evidence.\n\n"
        "What it is good for is naming classes you might not otherwise consider. These "
        "are the classes it flagged here, rarest first -- a detector that fires on most "
        "contracts is telling you almost nothing, one that fires rarely and fired here "
        "is worth a look:\n\n"
        f"{lines}{tail}\n\n"
        "Treat these as a queue of hypotheses to test and discard, not as findings. Most "
        "will be wrong. Work through the plausible ones with run_exploit; the harness "
        "will refuse anything you cannot actually demonstrate, so a wrong suggestion "
        "costs you turns and nothing else. If none of them survives contact with the "
        "code, say so with conclude_safe -- following a bad suggestion into a finding "
        "you cannot prove is the one outcome worse than missing the bug."
    )


# -- Slither as the proposal source (plan Step 4), OFF by default ------------------------
#
# Three gaps had to close before Slither could feed this queue, and all three are closed
# here without touching the Bastet path above:
#   1. format: Slither's JSON becomes jobs.jsonl rows (`slither_jobs`), one per check,
#      with an n_findings 0 row for every corpus check that did not fire, so `load_hits`
#      and the denominators see the sample even when nothing fired;
#   2. wording: `proposal_block` describes Bastet ("true-negative rate is zero"), which is
#      false of Slither; `slither_proposal_block` states Slither's own measured numbers;
#   3. rarity: on a single contract `rarity()` divides by 1 and every check reads 100%, so
#      `slither_rarity` uses the 40-contract reference corpus (runs/slither.json).
# Whether it should ever be on is the pre-registered A/B's call (plan 9.3), and that A/B
# has not run, so the gate only uses it behind --slither-proposals.

SLITHER_EXCLUDED_IMPACTS = ("Informational", "Optimization")


def _slither_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = defaultdict(int)
    for f in findings:
        if f.get("impact") not in SLITHER_EXCLUDED_IMPACTS and f.get("check"):
            counts[f["check"]] += 1
    return counts


def slither_rarity(corpus_path: Path) -> dict[str, float]:
    """check -> share of the reference corpus's contracts it fires on (Informational and
    Optimization excluded: `solc-version` alone fires on all 40 v3 contracts)."""
    rows = json.loads(corpus_path.read_text(encoding="utf-8")).get("rows") or []
    fired_on: dict[str, int] = defaultdict(int)
    for r in rows:
        for check in _slither_counts(r.get("findings") or []):
            fired_on[check] += 1
    n = len(rows) or 1
    return {c: k / n for c, k in fired_on.items()}


def slither_jobs(sample_id: str, findings: list[dict],
                 corpus_checks: list[str] | None = None) -> list[dict]:
    """jobs.jsonl rows for one audited item (`sample` must be the run's item id)."""
    counts = _slither_counts(findings)
    checks = sorted(set(counts) | set(corpus_checks or []))
    return [{"sample": sample_id, "detector": c, "n_findings": counts.get(c, 0),
             "source": "slither"} for c in checks] or [
        {"sample": sample_id, "detector": "slither:none", "n_findings": 0, "source": "slither"}]


def slither_proposal_block(hits: list[str], rare: dict[str, float], limit: int = 14) -> str:
    """The queue text for Slither hits, with Slither's own measured reliability."""
    if not hits:
        return ""
    ordered = sorted(hits, key=lambda d: (rare.get(d, 1.0), d))[:limit]
    lines = "\n".join(
        f"  - {d.replace('-', ' ')}  (fires on {rare.get(d, 1.0):.0%} of a 40-contract "
        "reference set)" for d in ordered)
    return (
        "\n\nSlither, a static analyser, was run over this contract first. It is a pattern "
        "matcher, not evidence: on a reference set of 20 vulnerable contracts and their 20 "
        "patched twins it flagged half of the patched ones at medium severity "
        "(specificity 0.50), so most of what it says about any one contract is noise.\n\n"
        "It is useful only for naming classes you might not otherwise consider. These are "
        "the checks it raised here, rarest first:\n\n"
        f"{lines}\n\n"
        "Treat them as hypotheses to test and discard, not as findings. Work through the "
        "plausible ones with run_exploit; the harness refuses anything you cannot "
        "demonstrate. If none survives contact with the code, say so with conclude_safe."
    )
