# arbiter-gpt on v3_authored.json after the November fixes (run me-strict-r1)

One run of the ME-hackathon build over the same 40 authored contracts as the finals evaluation
(`innoserve/eval/arbitergpt-v3/`, runs gptoss-v3-r1..r3), with the same model, settings and
scoring code. Pre-registered in `arbiter/PREREGISTRATION_me_strict.md` before the first row.

| file | what |
|---|---|
| `me-strict-r1.summary.json` | the harness's summary, unchanged (includes `strict_retry`: triggered / by status / requests) |
| `me-strict-r1.results.jsonl.gz` | every row with its per-attempt trace and `strict_retry` record, `gzip -n -9` of the original |
| `me-strict-r1.requeued.jsonl.gz` | the 2 rows moved aside as infrastructure errors (the tunnel dropped while the machine slept) and re-run by `scripts/eval_requeue.py`, as the pre-registration requires |
| `me-strict-r1.ledger.jsonl.gz` | one line per model request (724; model served: arbiter-gpt:latest only) |
| `me-strict-r1.report.json` | `python3 scripts/p7b_report.py --run-ids me-strict-r1` — the P7b scoring code, unchanged except for the run-id option |
| `SHA256SUMS` | `sha256sum -c SHA256SUMS` |

Model: `arbiter-gpt:latest` (Ollama digest `e914c3a9…`, the same as in the finals runs).
Settings: `--attempts 3 --max-turns 16 --max-tokens 4096 --concurrency 1 --rpm 45 --repeats 1`,
hermetic, plus `--strict-retry`. Run from a clean checkout of `me-hackathon` at `ed4ae05`.

## Result (arbiter-gpt, v3 tuning set, 1 new run vs the 3 finals runs)

| | me-strict-r1 | gptoss-v3-r1 / r2 / r3 (finals) |
|---|---|---|
| vulnerable 20: proven under the strict predicates (victim_loss, liveness_broken) | **4 of 20** | 2 / 3 / 3 of 20 |
| fixed 20: proven under the strict predicates (false positives) | **0 of 20** | 0 / 0 / 0 of 20 |
| vulnerable 20: proven as reported (strict or loose) | 7 of 20 | 7 / 9 / 8 of 20 |
| fixed 20: proven as reported (false positives) | 2 of 20 | 2 / 1 / 0 of 20 |
| MCC, strict only | 0.3333 | 0.2294 / 0.2847 / 0.2847 |
| MCC, as reported | 0.2993 | 0.2993 / 0.4619 / 0.5000 |

- Hypotheses from the pre-registration: H1 (strict-only TP at least 4 of 20) held; H2 (strict-only
  FP 0 of 20) held; H3 (as-reported FP at most 2 of 20) held.
- Strict re-proof: triggered 6 times (after a proof that used only a loose predicate), proved 1
  of the 6 (`V_commit_reveal_frontrun`, as liveness_broken), 32 requests in total. On both fixed
  contracts the loose proof was a false positive and the strict re-proof did not pass.
- The other 3 strict positives (`V_reentrancy_unstake`, `V_delegatecall_unchecked_module`,
  `V_ecrecover_zero_address_session`) were strict on the first proof.
- Five changes shipped together (see the pre-registration), so no single change is credited.
  One run against three is a small comparison: 20 vulnerable contracts, strict-only recall
  95% CI [0.05, 0.39].

## Deviations (reported in the pre-registration, section 8)

- The run was launched at ed4ae05, which also contained the treasury/ERC20 extension of
  victim_loss (it changed the run_exploit text the model read: token_expr for victim_loss and
  an optional treasury_exit property). The model composed 2 PoCs with each; none passed, so no
  positive in the run depends on them. So this is "the
  me-hackathon build at ed4ae05 against the finals runs".
- The model digest was checked after the run, not recorded at launch: e914c3a9..., the same.
