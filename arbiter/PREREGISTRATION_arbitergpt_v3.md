# Pre-registration: ARBITER with arbiter-gpt on v3_authored.json, three runs

Written and committed **before** the first run, and tagged `eval-freeze`. Nothing below may
change after any of the three runs has produced a row. Like `PREREGISTRATION_V2.md` and
`PREREGISTRATION_vloss4.md`, this exists so that the report cannot be rewritten to fit
whatever comes out.

## 1. What this is, and what it is not

The model changes from the AIS3 course gateway's `ais3/nemotron-3-ultra-550b` to
`arbiter-gpt:latest`, a locally served gpt-oss 120B. This measures how ARBITER does on the
40-sample v3 set under the new model, three times.

- **It is a reference measurement, not a comparison.** The AIS3 numbers come from a
  different model, a different gateway and an older harness (section 4). They are shown
  next to the new numbers and are never paired with them, tested against them, or merged
  into one figure.
- **v3 is the TUNE set.** `PREREGISTRATION_V2.md` §2 declared it burnt. Every number here
  is labelled **TUNE**, and is labelled **arbiter-gpt**.
- No Bastet arm runs (user decision D4, 2026-10-29). The 70-sample A/B in plan chapter 9
  is deferred until after the finals.

## 2. Fixed inputs

| item | value |
|---|---|
| model | `arbiter-gpt:latest` on Ollama 0.40.11. digest `e914c3a9517b9824cb35fd945b7c5148baca5442819d19e44c549f1ff6cd50a3` (`/api/tags`, read 2026-10-29). parent `gpt-oss:120b`, 116.8B, MXFP4, gguf, llama.cpp runner. Modelfile parameters: `num_ctx 65536`, `temperature 1` (the harness sends its own temperature per request). No SYSTEM prompt |
| endpoint | OpenAI-compatible `/v1` on the Ollama host, reached through an SSH tunnel to `localhost:11434`. The host address is not recorded in the repository |
| dataset | `evalsets/v3_authored.json`, sha256 `0ab903b9dbc9a8218a958a595106c82ac855995a641e8c2b49dda832d653d33f`. 40 samples, 20 vulnerable and 20 patched, 20 pairs |
| code | the commit tagged `eval-freeze` (this document's commit). Runs execute only in a separate worktree checked out at that tag |
| run ids | `gptoss-v3-r1`, `gptoss-v3-r2`, `gptoss-v3-r3`, one per run, run one at a time in that order |

## 3. Settings — copied from `runs/h2h-arbiter.summary.json`

The AIS3 run was launched as
`python cli.py run --evalset evalsets/v3_authored.json --model ais3/nemotron-3-ultra-550b --run-id h2h-arbiter --attempts 3`
(`RESULTS.md` L108–109, `README.md` L294–295). Its summary records `attempts_per_sample` 3,
`max_turns` 16, `max_tokens` 4096, `repeats` 1. At that commit (`abf7077`, 2026-07-26)
`cli.py run` defaulted to `--max-turns 16`, `--concurrency 8`, `--rpm 45`. Today's default
for `--max-turns` is 26, so every value is passed explicitly:

```bash
python3 cli.py run --evalset evalsets/v3_authored.json --model arbiter-gpt:latest \
  --run-id <run-id> --attempts 3 --max-turns 16 --max-tokens 4096 \
  --concurrency 1 --rpm 45 --repeats 1
```

- **predicates**: none passed, so the agent gets the harness default `STRICT_PREDICATES`
  (`victim_loss`, `liveness_broken`; tools.py L94). `cli.py run` has no predicates flag.
- **mode**: hermetic. The v3 items carry no `path`, so `run.py` compiles each contract on its
  own (`context.mode = "hermetic"`).
- **concurrency**: **1**, decided by a throughput test on 2 samples
  (`V_/S_reentrancy_unstake`, same settings, run ids `tput-c1` / `tput-c2`, not part of
  this evaluation). Concurrency 1: 16 requests in 427 s, per-request latency median 22.3 s,
  p90 44.9 s, 38 completion tokens/s. Concurrency 2: 18 requests in 481 s, median 33.5 s,
  p90 58.6 s, max 116.5 s, 24 tokens/s. Both work out to 26.7 s of wall clock per request:
  the server shares one throughput between parallel requests, so 2 buys nothing and
  lengthens every request. AIS3 used 8 against a different server; that is listed in
  section 4, not copied.
- `--rpm 45` as in AIS3. It is not the binding limit against a local server.
- `scripts/eval_launch.sh <run-id>` runs exactly this command inside tmux and refuses to
  start from any tree whose HEAD is not `eval-freeze`.

## 4. Known differences from the AIS3 run (not aligned, on purpose)

| | AIS3 `h2h-arbiter` (2026-07-26) | this run |
|---|---|---|
| model | `ais3/nemotron-3-ultra-550b`, vLLM 0.24.0 tp8 | `arbiter-gpt:latest` (gpt-oss 120B MXFP4), Ollama 0.40.11 |
| predicates the agent could use | eth_profit, token_profit, state_change, liveness_broken. `STRICT_PREDICATES` only arrived in `0538719` (2026-07-28) | harness default STRICT (victim_loss, liveness_broken). But `_run_exploit` does not enforce the enum and the `run_exploit` description still lists the old names (CLAUDE.md trap 13), so loose predicates can still appear; they are scored separately (section 5) |
| harness gates | before the cheatcode ban, negation test, halt sentinel, drain invariant and forgery gates (`PREREGISTRATION_vloss4.md`) | all of them |
| concurrency | 8 (default then) | 1 (measured, section 3) |
| forge | no record | 1.8.6 |
| solc | no record (the `solc 0.8.24` in `test_pairs_v2.json` refers to authoring on an ethereumjs harness, not to this run) | 0.8.37 via `auto_detect_solc`; 0.8.20 also installed. Every v3 contract is `pragma ^0.8.20` |

These are recorded, not corrected. The solc setting is not changed to match anything.
Because the predicate set and the gates both changed, a difference from the AIS3 figures
cannot be attributed to the model alone.

## 5. What will be reported, whatever it says

Per run, and as mean / min / max over the three runs (`score.summarise_runs`):

1. **Confusion matrix and metrics.** TP, TN, FP, FN, precision, recall, specificity, F1,
   accuracy, MCC, from `arbiter/score.py` (`score()`, `Confusion.as_dict()`), using the
   `predictions_by_repeat` the harness wrote. **Primary: MCC.**
2. **95% intervals.** Bootstrap over sample ids, 10,000 draws, seed 20260726, the
   generator in `score.py` (`_Lcg`). For MCC this is exactly
   `score.bootstrap_delta(a=constant_no, b=run, metric="mcc")`, since the constant-no
   predictor's MCC is 0 in every resample. The other metrics are resampled the same way
   by the P7b report script, which only calls `score.score()`.
3. **Two scorings, by winning predicate.** For each positive, `winning_predicate()`
   (`scripts/report_arm.py`: the predicate of the first PoC with `passed and adjudicated`).
   - *as reported*: the harness's own label — the number the product shows.
   - *strict only*: a positive counts only if its winning predicate is `victim_loss` or
     `liveness_broken`; a positive proven only by a loose predicate (eth_profit,
     token_profit, state_change, anything else) is scored as safe.
   Both get the full matrix and metrics. The count of loose-predicate positives on
   vulnerable and on patched samples is reported per predicate.
4. **not_executed rows**, counted beside the matrix with their reasons:
   `context_unbuildable`, `toolchain_unavailable`, any `error: …`, and rows whose
   infrastructure-error requeue cap was reached (section 7). They stay in the denominator
   and score as safe, as `score.score()` does.
5. **Analyst time**: `scripts/analyst_cost.py` with the AIS3 assumptions unchanged:
   15 minutes per unproven finding, 2 per proven finding, false positives always at full
   triage (15).
6. **Cost**: requests, prompt and completion tokens (from the ledger, which survives
   resumes), wall-clock time per run (sum of the sessions in `<run-id>.sessions.log`),
   mean turns, mean requests per sample, `no_verdict_rate`, `finish_reason=length` count.

## 6. Validity — a run that fails this is void and rerun

- The ledger's `model_served` has exactly one value, and so does the summary's
  `usage.models_seen`. The ledger is the authority because `usage` restarts on a resume.
- No row has a `ModelMismatch` error.

`scripts/eval_requeue.py <run-id> --check` performs both checks and runs automatically when
each run ends. A void run keeps its files under a new name (`…​.void-<n>`) and is rerun
from the start under the same run id; the report says so.

## 7. Infrastructure errors (for example a dropped tunnel)

What `run.py` does, read before writing this: `agent.audit` does not catch gateway errors,
so `GatewayError` (raised after 7 retries on connection errors, timeouts, 429 and 5xx) ends
the attempt with `stop_reason = "error: GatewayError: gave up after …"` and the next attempt
starts. The row is written to `results.jsonl` like any other, and on a rerun with the same
run id `run.py` skips every sample that has a row (`done` set, run.py L82–90). Left alone,
such a row would be scored as a measured "safe".

The rule:

1. An **infrastructure-error row** is one in which any attempt stopped with
   `error: GatewayError: gave up after`. It is requeued **whatever its outcome**, including
   a row that a later attempt proved, so the rule cannot favour either label.
2. Not requeued, scored as the harness scores it and reported as not_executed: HTTP 4xx
   other than 429 (`error: GatewayError: HTTP 4xx`, a bad request that will not improve),
   any other `error:`, `context_unbuildable`, `toolchain_unavailable`.
3. After a run ends, `scripts/eval_requeue.py <run-id>` copies `results.jsonl` to a
   timestamped `.bak.jsonl`, appends the infrastructure-error rows (with time and reasons)
   to `<run-id>.requeued.jsonl`, removes them from `results.jsonl`, and the run is resumed
   with `scripts/eval_launch.sh <run-id> --resume` — same run id, same settings.
4. A sample is requeued at most **twice**. After that its last row stands as not_executed.
5. No sample is deleted and no setting is changed to make a retry succeed. The report lists
   every requeued row, how many times it was requeued, and the final outcome.

## 8. What would not count as a win

- **Against AIS3.** The AIS3 runs that measured same-configuration spread were on v4 (70
  samples, 26 turns, 2 attempts): MCC 0.118, 0.261, 0.303 (`TALK.md` L11–13). On v3 there is
  one AIS3 run per configuration: `h2h-arbiter` MCC 0.267 (TP 9, TN 16, FP 4, FN 11),
  and two cascade runs with the same turns and attempts, 0.329 (`cascade-clean`) and 0.168
  (`h2h-cascade`). The v3 spread is therefore unknown, and the v4 range is the only
  spread on record. If the new mean MCC lies inside 0.118–0.303, **or** differs from
  `h2h-arbiter`'s 0.267 by no more than 0.185 (the width of that range), it is written as
  **"difference within the variation range"**, in either direction. A larger gap is
  still not attributed to the model alone (section 4).
- **Degradation.** If any of the three runs has MCC ≤ 0, the result is written as
  **"degraded after the model change"**, in the first line, whatever the other two show.
- **Spread.** If the three runs' MCC range is wider than the gap to AIS3, the gap is
  not reported as a difference.
- **Precision without recall.** Precision is never shown without recall beside it.
- **Loose predicates.** If the as-reported recall is carried by loose-predicate proofs,
  that is stated, and the strict-only numbers are shown with equal prominence.

## 9. Extra control arms — zero LLM requests, computed in P7b

- **F0**: `constant_yes_baseline` and `constant_no_baseline` on the same 40 labels.
- **S**: Slither 0.11.6 (the version of the AIS3 `runs/slither.json`), installed in a
  separate venv, run once per sample. A sample is "vuln" if it has a finding with impact
  ≥ Medium and confidence ≥ Medium. The threshold is fixed here and is **not** re-selected;
  `slither_arm.py`'s `best` field is not read. Note that Medium/Medium was itself chosen
  on v3 with the answers in hand (slither_arm.py L9–13), so S is an optimistic baseline.
  The solc Slither uses is recorded; the stored AIS3 Slither result is shown beside it.

## 10. Scope

Single-file, self-written contracts of about 1,600 characters, one model, one local
server, one scorer, a TUNE set. Nothing here supports a claim about larger code bases or
about the model in general.
