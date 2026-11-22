"""Run ARBITER over an evaluation set: concurrent, resumable, fully recorded.

Concurrency here buys latency hiding, not throughput -- the gateway's 120 rpm cap is per
key, so the rate limiter in ``gateway`` is what actually shapes the run. Workers exist
because each audit spends real wall-clock inside ``forge`` with no request outstanding,
and that time is free to overlap.

Every audit writes one JSONL row containing the verdict, the PoCs the agent wrote, the
compiler and EVM output, and the full turn trace. A run is therefore auditable after the
fact by someone who does not trust the summary, which is the point.
"""

from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from .agent import audit, outcome_to_label
from .gateway import Gateway, RateLimiter
from .proposals import load_hits, proposal_block, rarity
from .repo import plan_for
from .tools import STRICT_PREDICATES, AgentOutcome, PocRecord
from .workspace import BuildUnavailable, Workspace


def load_evalset(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("meta", {}), data["items"]


def _root_of(item: dict[str, Any]) -> Path | None:
    root = item.get("repo_root")
    return Path(root) if root else None


def truth_map(items: list[dict[str, Any]]) -> dict[str, str]:
    return {item["id"]: item["label"] for item in items}


def run_arbiter(
    *,
    evalset: Path,
    model: str,
    run_id: str,
    out_dir: Path,
    repeats: int = 1,
    attempts: int = 1,
    concurrency: int = 8,
    max_turns: int = 26,
    max_tokens: int = 4096,
    rpm: int = 45,
    workspace_root: Path | None = None,
    proposals_path: Path | None = None,
    carry_ruled_out: bool = False,
    api_key: str | None = None,
    predicates: tuple[str, ...] | None = None,
    proposal_renderer: Any = None,
    on_turn: Any = None,
    on_row: Any = None,
    on_request: Any = None,
    strict_retry: bool = False,
) -> dict[str, Any]:
    """`proposal_renderer(hits, rarity) -> str` replaces proposal_block (whose wording
    describes Bastet) for another proposal source; None keeps proposal_block.

    Progress hooks, all optional and off by default (plan Step 3; agent.py unchanged):
    `on_turn(event)` fires as each agent turn lands in the trace -- the model has chosen
    its tools, they have not run yet -- with sample, attempt, turn, the turn budget and
    the tool calls; `on_row(row)` after a sample's row is written; `on_request(messages,
    tag)` is handed to the gateway and fires before every model request, so the previous
    tool results are visible to whoever listens. A hook that raises is ignored.

    `strict_retry` (off by default, so earlier runs stay reproducible): when the final
    outcome is proven only under a loose predicate, one more audit runs, restricted to
    the strict predicates and briefed with the loose proof (see run_strict_retry). The
    row carries `strict_retry`; the turn events of that audit carry strict_retry=True."""
    meta, items = load_evalset(evalset)
    render = proposal_renderer or proposal_block
    out_dir.mkdir(parents=True, exist_ok=True)

    # Cascade mode: a cheap detector proposes classes, the execution gate adjudicates.
    hits: dict = {}
    rare: dict = {}
    if proposals_path is not None:
        hits = load_hits(proposals_path)
        rare = rarity(proposals_path)
        print(f"cascade: hypothesis proposals loaded for {len(hits)} samples", flush=True)
    ws_root = workspace_root or Path("/tmp/arbiter-ws") / run_id

    limiter = RateLimiter(rpm)
    gateway = Gateway(
        model=model,
        api_key=api_key,
        limiter=limiter,
        ledger_path=out_dir / f"{run_id}.ledger.jsonl",
    )
    if on_request is not None:
        gateway.on_request = on_request

    results_path = out_dir / f"{run_id}.results.jsonl"
    done: set[str] = set()
    if results_path.exists():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            done.add(f"{row['repeat']}::{row['sample_id']}")

    write_lock = threading.Lock()
    started = time.monotonic()

    def _row(
        repeat: int,
        item: dict[str, Any],
        outcome: Any,
        tried: list[dict[str, Any]],
        trace: list[dict[str, Any]],
        error: str,
        t0: float,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "repeat": repeat,
            "sample_id": item["id"],
            # The repository the contract came from. Absent, repo-level scoring -- the
            # unit OneSavie's own evaluation uses -- collapses every row into "?".
            "repo": item.get("repo", ""),
            "path": item.get("path", ""),
            "truth": item["label"],
            "predicted": outcome_to_label(outcome),
            # The contract under audit travels with the record. Without it a dumped
            # exploit has nothing to run against, and evidence that cannot be replayed
            # is an assertion with extra steps.
            "source": item["code"],
            # Whether the harness could compile the contract at all, and how. A verdict
            # of "safe" means something entirely different when this is false.
            "context": context,
            "attempts_used": len(tried),
            "attempts": tried,
            "elapsed_s": round(time.monotonic() - t0, 2),
            "error": error,
            "outcome": outcome.as_dict(),
            "trace": trace,
        }

    def _emit(row: dict[str, Any], outcome: Any) -> None:
        with write_lock:
            with results_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        _safe_call(on_row, row)
        hit = "OK " if row["predicted"] == row["truth"] else "MISS"
        proven = "proven" if outcome.proven else outcome.stop_reason
        print(
            f"  [{hit}] r{row['repeat']} {row['sample_id'][:44]:46s} "
            f"-> {row['predicted']:5s} ({proven}, "
            f"{row['attempts_used']}x{outcome.turns}t, {row['elapsed_s']}s)",
            flush=True,
        )

    def one(repeat: int, item: dict[str, Any]) -> dict[str, Any] | None:
        key = f"{repeat}::{item['id']}"
        if key in done:
            return None
        t0 = time.monotonic()
        trace: list[dict[str, Any]] = []
        error = ""
        outcome = None
        tried: list[dict[str, Any]] = []

        # A contract that lives in a repository is compiled in that repository's context.
        # Built once per sample, not per attempt: indexing a 400-file repo is not free,
        # and the remappings the repair loop discovers are worth carrying forward.
        plan = None
        context: dict[str, Any] = {"ok": True, "mode": "hermetic"}
        if item.get("path"):
            try:
                plan = plan_for(Path(item["path"]), repo_root=_root_of(item))
                probe = Workspace(
                    ws_root / "ctx", f"{item['id']}__ctx", item["code"], plan=plan
                )
                try:
                    context = probe.prepare_context()
                finally:
                    probe.cleanup()
                # Enough to rebuild the compilation environment outside this process.
                # Without it a dumped exploit imports paths that only existed inside a
                # scratch workspace, which is evidence nobody else can replay.
                context["plan"] = {
                    "repo_root": plan.repo_root.as_posix(),
                    "target": plan.target.as_posix(),
                    "target_import": plan.target_import,
                    "pragma": plan.test_pragma,
                    "chosen_src": plan.chosen_src,
                    "remappings": list(plan.remappings),
                }
            except Exception as exc:  # noqa: BLE001
                context = {"ok": False, "mode": "error",
                           "error": f"{type(exc).__name__}: {exc}"[:200]}

        # No compilable context means no execution, and no execution means this run has
        # no evidence either way. Spending 26 turns of a rationed gateway to arrive at a
        # verdict the harness could never have backed is waste; the sample is recorded as
        # unbuildable and the summary reports how many there were, so a low recall caused
        # by a toolchain gap is never presented as a clean bill of health.
        if not context.get("ok"):
            from .tools import AgentOutcome

            outcome = AgentOutcome(stop_reason="context_unbuildable")
            row = _row(repeat, item, outcome, [], [], "", t0, context)
            _emit(row, outcome)
            return row

        # Independent attempts, unioned: the sample is vulnerable if ANY attempt
        # produced a harness-adjudicated exploit. Unioning is safe here in a way it is
        # not for Bastet. Bastet unions 53 detectors and each one can only add false
        # positives, because nothing checks them -- with 53 draws at even a 5% error
        # rate it flags 93% of safe code. Every ARBITER attempt has to clear the same
        # execution predicate, so extra attempts can raise recall but cannot manufacture
        # a false positive. Attempts stop as soon as one succeeds, so the cost is paid
        # only on samples we are failing to crack.
        ruled_out: list[str] = []
        for attempt in range(attempts):
            attempt_trace: list[dict[str, Any]] = (
                _TurnSink(on_turn, {"sample_id": item["id"], "repeat": repeat,
                                    "attempt": attempt, "attempts": attempts,
                                    "max_turns": max_turns})
                if on_turn is not None else [])
            ws = None
            try:
                # Workspace construction is inside the try. It was outside, and it
                # touches the filesystem and shells out to forge, so a single sample
                # hitting a transient disk or toolchain error propagated out of the
                # worker, through future.result(), and killed the entire run.
                ws = Workspace(
                    ws_root / f"r{repeat}a{attempt}", item["id"], item["code"],
                    plan=plan,
                )
                outcome = audit(
                    gateway,
                    ws,
                    max_turns=max_turns,
                    max_tokens=max_tokens,
                    trace_sink=attempt_trace,
                    ruled_out=ruled_out if carry_ruled_out else None,
                    proposals=render(hits.get(item['id'], []), rare) if hits else "",
                    predicates=predicates,
                )
            except BuildUnavailable as exc:
                # Kept out of the generic handler on purpose. Every non-vulnerable
                # outcome maps to "safe" downstream, so a missing compiler used to be
                # reported as CLEAR: measured on a real contract with forge off PATH,
                # the audit printed "0/1 reported vulnerable, each backed by an executed
                # exploit" after 0.01s and zero requests. That is an unmeasured clean
                # answer, which is the one thing this project exists to stop producing.
                from .tools import AgentOutcome

                outcome = AgentOutcome(stop_reason="toolchain_unavailable")
                error = f"toolchain_unavailable: {exc}"
            except Exception as exc:  # noqa: BLE001
                from .tools import AgentOutcome

                outcome = AgentOutcome(stop_reason=f"error: {type(exc).__name__}: {exc}")
                error = f"{type(exc).__name__}: {exc}"
            finally:
                if ws is not None:
                    ws.cleanup()
            tried.append(
                {
                    "attempt": attempt,
                    "verdict": outcome.verdict,
                    "proven": outcome.proven,
                    "turns": outcome.turns,
                    "stop_reason": outcome.stop_reason,
                }
            )
            trace = attempt_trace
            if outcome.proven:
                break
            # Dead ends carried into the next attempt. OFF by default: measured, this
            # halved recall (0.450 -> 0.200) because an exploit that fails does not tell
            # you whether the hypothesis was wrong or merely badly built, so banning it
            # bans correct answers too. Kept behind the flag as a recorded negative.
            for poc in outcome.pocs:
                if not poc.adjudicated or poc.passed:
                    continue
                text = " ".join(poc.hypothesis.split())[:140]
                if text and not any(
                    text[:60].lower() == seen[:60].lower() for seen in ruled_out
                ):
                    ruled_out.append(text)

        retry_rec: dict[str, Any] | None = None
        if strict_retry and loose_proof(outcome) is not None:
            retry_trace: list[dict[str, Any]] = (
                _TurnSink(on_turn, {"sample_id": item["id"], "repeat": repeat,
                                    "attempt": attempts, "attempts": attempts + 1,
                                    "max_turns": max_turns, "strict_retry": True})
                if on_turn is not None else [])
            outcome, retry_rec = run_strict_retry(
                gateway, outcome,
                lambda: Workspace(ws_root / f"r{repeat}strict", item["id"], item["code"],
                                  plan=plan),
                max_turns=max_turns, max_tokens=max_tokens, trace_sink=retry_trace)
            retry_rec["trace"] = list(retry_trace)

        row = _row(repeat, item, outcome, tried, trace, error, t0, context)
        if retry_rec is not None:
            row["strict_retry"] = retry_rec
        _emit(row, outcome)
        return row

    jobs = [(r, item) for r in range(repeats) for item in items]
    print(
        f"ARBITER  model={model}  samples={len(items)}  repeats={repeats}  "
        f"max_turns={max_turns}  workers={concurrency}  rpm={rpm}",
        flush=True,
    )

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(one, r, item) for r, item in jobs]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as exc:  # noqa: BLE001
                # One sample must never take the run with it. A 70-sample run that
                # dies on sample 3 costs an hour and produces nothing; a run that
                # loses sample 3 costs one row and says so in the summary.
                print(f"  [ERR ] worker raised {type(exc).__name__}: {exc}", flush=True)

    rows = [
        json.loads(line)
        for line in results_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    summary = {
        "arm": "arbiter_cascade" if proposals_path else "arbiter",
        "run_id": run_id,
        "model": model,
        "evalset": str(evalset),
        "evalset_meta": meta,
        "repeats": repeats,
        "attempts_per_sample": attempts,
        "proposals_from": str(proposals_path) if proposals_path else None,
        "carry_ruled_out": carry_ruled_out,
        "predicates": list(predicates) if predicates else None,
        "strict_retry": _strict_retry_stats(rows) if strict_retry else None,
        "max_turns": max_turns,
        "max_tokens": max_tokens,
        "wall_clock_s": round(time.monotonic() - started, 1),
        "usage": gateway.usage.as_dict(),
        "predictions_by_repeat": _by_repeat(rows),
        "context": _context_stats(rows),
        "no_verdict_rate": _no_verdict_rate(rows),
        "proven_rate": _proven_rate(rows),
        "mean_turns": _mean_turns(rows),
        "mean_requests_per_sample": _mean_requests(rows),
    }
    (out_dir / f"{run_id}.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return summary


# -- strict re-proof of a loose proof ---------------------------------------------------
#
# Measured on arbiter-gpt (P7b, gptoss-v3-r1..r3): 5, 6 and 5 of the 7, 9 and 8 true
# positives were proven only under a loose predicate, whose baseline the agent writes
# itself. Such a proof still blocks deployment, but it cannot be measured (A/B/G) or
# patched. The follow-up asks the same model, in a fresh audit offered only the strict
# predicates, to express that same attack as victim_loss, and hands it the loose proof
# in full rather than the trace (whose arguments are cut at 4000 characters).

STRICT_RETRY_LABELS = {
    # "proven" is worded per predicate (STRICT_RETRY_PROVEN); this is the fallback.
    "proven": "以嚴格謂詞重新證實",
    "not_proven": "嚴格謂詞重試沒有成功，保留原本的寬鬆證明",
    "skipped": "沒有進行嚴格謂詞重試",
    "error": "嚴格謂詞重試沒有完成（執行錯誤），保留原本的寬鬆證明",
}
STRICT_RETRY_PROVEN = {
    "victim_loss": "以嚴格謂詞 victim_loss 重新證實：受害者確實因攻擊少拿回錢",
    "liveness_broken": "以嚴格謂詞 liveness_broken 重新證實：攻擊後一般使用者的操作無法完成",
}

MAX_BRIEF_SOLIDITY = 24000

STRICT_RETRY_BRIEF = """

An earlier audit of this exact contract demonstrated an attack, but only under the loose \
predicate {predicate}, which compares the attacker against a baseline the same agent \
wrote. That is weaker evidence: it cannot be measured or patched. This audit accepts only \
the strict predicates, {strict}.

The earlier attack's hypothesis:
  {hypothesis}

The complete test file the harness composed and ran for it{cut} -- the attack is the \
Attacker contract (or the statements in the attacker's pranked block), the deployment is \
the code that assigns `target`:

```solidity
{solidity}
```

Express the same theft as victim_loss. Reuse the deployment and the attack, and add \
victim_enter and victim_exit for an ordinary user whose value the attack takes; the \
harness then checks that this user recovers less because the attack ran and that the \
attacker holds what they lost. If the damage is that an ordinary operation stops working \
rather than value moving, use liveness_broken instead. If no ordinary user loses anything \
to this attack, say why with conclude_safe.\
"""


def loose_proof(outcome: Any) -> PocRecord | None:
    """The loose PoC behind a proven outcome that has no strict one; otherwise None."""
    if outcome is None or not outcome.proven:
        return None
    passed = [p for p in outcome.pocs if p.passed and p.adjudicated]
    if not passed or any(p.predicate in STRICT_PREDICATES for p in passed):
        return None
    cited = {f.get("poc_name") for f in outcome.findings}
    return next((p for p in passed if p.name in cited), passed[0])


def strict_retry_brief(loose: PocRecord) -> str:
    solidity = loose.solidity or ""
    cut = ""
    if len(solidity) > MAX_BRIEF_SOLIDITY:
        solidity, cut = solidity[:MAX_BRIEF_SOLIDITY], f" (first {MAX_BRIEF_SOLIDITY} characters)"
    return STRICT_RETRY_BRIEF.format(
        predicate=loose.predicate, strict=", ".join(STRICT_PREDICATES),
        hypothesis=" ".join((loose.hypothesis or "(none given)").split()),
        solidity=solidity.strip(), cut=cut)


class _CountingGateway:
    """Counts this audit's model requests; a shared gateway's usage spans every worker."""

    def __init__(self, gateway: Any) -> None:
        self._gateway = gateway
        self.requests = 0

    def chat(self, *args: Any, **kwargs: Any) -> Any:
        self.requests += 1
        return self._gateway.chat(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._gateway, name)


def run_strict_retry(
    gateway: Any,
    outcome: AgentOutcome,
    make_workspace: Any,
    *,
    max_turns: int,
    max_tokens: int = 4096,
    trace_sink: list[dict[str, Any]] | None = None,
) -> tuple[AgentOutcome, dict[str, Any]]:
    """One strict-only audit after a loose proof. Returns (outcome to record, record).

    Success means a passed, adjudicated strict PoC: the one a retry finding cites, else
    the first victim_loss (measurable and patchable), else the first liveness_broken. Its
    outcome then lists that PoC FIRST, the retry's other PoCs after it and the loose
    outcome's last, so everything that takes the first admissible PoC
    (patch.exploit_from_row, report_arm.winning_predicate) takes it, and its findings cite
    it: the retry's own findings, or -- only when the retry submitted no finding at all --
    the loose finding re-pointed at it ("carried"). Anything else keeps the loose outcome,
    with the retry's failed PoCs appended after it so every attempt stays on record.
    """
    loose = loose_proof(outcome)
    rec: dict[str, Any] = {
        "status": "skipped", "reason": "", "predicate": None, "poc_name": None,
        "turns": 0, "requests": 0, "elapsed_s": 0.0, "label": "",
        "loose": {"poc_name": loose.name if loose else None,
                  "predicate": loose.predicate if loose else None},
    }
    if loose is None:
        rec.update(reason="no loose-only proof", label=STRICT_RETRY_LABELS["skipped"])
        return outcome, rec
    t0 = time.monotonic()
    counting = _CountingGateway(gateway)
    retry: AgentOutcome | None = None
    ws = None
    try:
        ws = make_workspace()
        retry = audit(counting, ws, max_turns=max_turns, max_tokens=max_tokens,
                      trace_sink=trace_sink, proposals=strict_retry_brief(loose),
                      predicates=STRICT_PREDICATES)
    except BuildUnavailable as exc:
        rec.update(status="error", reason=f"error: toolchain_unavailable: {exc}"[:300])
    except Exception as exc:  # noqa: BLE001 -- the loose proof must survive a failed retry
        rec.update(status="error", reason=f"error: {type(exc).__name__}: {exc}"[:300])
    finally:
        if ws is not None:
            ws.cleanup()
        rec["requests"] = counting.requests
        rec["elapsed_s"] = round(time.monotonic() - t0, 2)

    merged = outcome
    if retry is not None:
        rec["turns"] = retry.turns
        strict = _strict_proof(retry)
        refusals = dict(outcome.refusals)
        for gate, n in retry.refusals.items():
            refusals[gate] = refusals.get(gate, 0) + n
        if strict is not None:
            findings = [f for f in retry.findings if f.get("poc_name") == strict.name]
            # (_strict_proof takes a PoC a retry finding cites whenever there is one, so this
            # is the case where the retry submitted nothing)
            carried = not findings
            if carried:
                base = next((f for f in outcome.findings if f.get("poc_name") == loose.name),
                            outcome.findings[0] if outcome.findings else {})
                findings = [{**base, "poc_name": strict.name,
                             "poc_hypothesis": strict.hypothesis}]
            merged = AgentOutcome(
                verdict="vulnerable", findings=findings, safe_reason=None,
                pocs=[strict] + [p for p in retry.pocs if p is not strict] + list(outcome.pocs),
                rejected_submissions=outcome.rejected_submissions + retry.rejected_submissions,
                turns=outcome.turns, stop_reason=outcome.stop_reason, refusals=refusals)
            rec.update(status="proven", predicate=strict.predicate, poc_name=strict.name,
                       reason=("strict_poc_passed_finding_carried" if carried
                               else "strict_proven"))
        else:
            merged = AgentOutcome(
                verdict=outcome.verdict, findings=outcome.findings,
                safe_reason=outcome.safe_reason, pocs=list(outcome.pocs) + list(retry.pocs),
                rejected_submissions=outcome.rejected_submissions + retry.rejected_submissions,
                turns=outcome.turns, stop_reason=outcome.stop_reason, refusals=refusals)
            why = (retry.safe_reason or {}).get("reason") or ""
            rec.update(status="not_proven",
                       reason=(retry.stop_reason or "no strict PoC passed")
                       + (f": {' '.join(str(why).split())[:240]}" if why else ""))
    rec["label"] = (STRICT_RETRY_PROVEN.get(rec["predicate"], STRICT_RETRY_LABELS["proven"])
                    if rec["status"] == "proven" else STRICT_RETRY_LABELS[rec["status"]])
    return merged, rec


def _strict_proof(retry: AgentOutcome) -> PocRecord | None:
    """The strict re-proof's PoC: a passed, adjudicated strict PoC a retry finding cites
    (the first passed record of that name), else the first victim_loss -- the one A/B/G
    and the patch can use -- else the first liveness_broken; None when none passed. It
    used to be simply the first passed one, so a liveness proof run before the victim_loss
    the model submitted displaced it (gate-logic-5)."""
    passed = [p for p in retry.pocs if p.passed and p.adjudicated
              and p.predicate in STRICT_PREDICATES]
    for f in retry.findings:
        hit = next((p for p in passed if p.name == f.get("poc_name")), None)
        if hit is not None:
            return hit
    return min(passed, key=lambda p: STRICT_PREDICATES.index(p.predicate), default=None)


def _strict_retry_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    recs = [r["strict_retry"] for r in rows if r.get("strict_retry")]
    by: dict[str, int] = {}
    for rec in recs:
        by[rec["status"]] = by.get(rec["status"], 0) + 1
    return {"triggered": len(recs), "by_status": by,
            "requests": sum(int(rec.get("requests") or 0) for rec in recs)}


def _safe_call(hook: Any, *args: Any) -> None:
    if hook is None:
        return
    try:
        hook(*args)
    except Exception:  # noqa: BLE001 -- a progress display must never cost a sample
        pass


class _TurnSink(list):
    """The agent's trace list, which also reports each turn as it is appended."""

    def __init__(self, hook: Any, meta: dict[str, Any]) -> None:
        super().__init__()
        self._hook, self._meta = hook, meta

    def append(self, entry: Any) -> None:  # noqa: D102
        super().append(entry)
        _safe_call(self._hook, {**self._meta, **entry})


def _by_repeat(rows: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for row in rows:
        out.setdefault(str(row["repeat"]), {})[row["sample_id"]] = row["predicted"]
    return out


def _context_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """How many contracts the harness could actually compile, and by which route.

    This is the number that decides whether a low recall is a finding or an artifact. A
    tool that compiles nothing reports everything safe, which is a degenerate predictor
    pointed the other way from a 53-detector OR -- so the count travels in the summary
    rather than being left to be inferred from a confusion matrix.
    """
    if not rows:
        return {}
    modes: dict[str, int] = {}
    for row in rows:
        ctx = row.get("context") or {}
        modes[str(ctx.get("mode", "unknown"))] = modes.get(str(ctx.get("mode", "unknown")), 0) + 1
    ok = sum(1 for r in rows if (r.get("context") or {}).get("ok"))
    return {
        "buildable": ok,
        "n": len(rows),
        "buildable_rate": round(ok / len(rows), 4),
        "by_mode": modes,
    }


def _no_verdict_rate(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    n = sum(1 for r in rows if r["outcome"]["verdict"] == "no_verdict")
    return round(n / len(rows), 4)


def _proven_rate(rows: list[dict[str, Any]]) -> float:
    """Share of vulnerable verdicts backed by an execution.

    Structurally 1.0 for ARBITER, because the submission gate rejects anything else, and
    structurally 0.0 for Bastet, because it has no execution stage. Reported anyway so
    the gate can be verified rather than believed.
    """
    positives = [r for r in rows if r["predicted"] == "vuln"]
    if not positives:
        return 0.0
    return round(
        sum(1 for r in positives if r["outcome"]["proven"]) / len(positives), 4
    )


def _mean_requests(rows: list[dict[str, Any]]) -> float:
    """Gateway requests spent per sample: one per turn, summed over attempts.

    Reported because it is the axis the gateway actually rations. Bastet spends 53 per
    sample by construction; if ARBITER exceeds that, its accuracy advantage is bought
    rather than earned and the comparison has to say so. A strict re-proof's requests
    count too (rows without one are unchanged).
    """
    if not rows:
        return 0.0
    total = sum(sum(a["turns"] for a in r.get("attempts", [])) for r in rows)
    total += sum(int((r.get("strict_retry") or {}).get("requests") or 0) for r in rows)
    return round(total / len(rows), 2)


def _mean_turns(rows: list[dict[str, Any]]) -> float:
    if not rows:
        return 0.0
    return round(sum(r["outcome"]["turns"] for r in rows) / len(rows), 2)
