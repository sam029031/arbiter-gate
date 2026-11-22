# Pre-registration: ME build with strict re-proof, one run (arbiter-gpt, v3, TUNE)

Committed together with `scripts/eval_launch_me.sh`, before run `me-strict-r1` has written
a row. Nothing below changes after the first row. Every number is labelled **arbiter-gpt**
and **TUNE** (v3 is the tuning set, `PREREGISTRATION_V2.md` §2).

## 1. What is compared

| | old (P7b) | new |
|---|---|---|
| runs | `gptoss-v3-r1`, `-r2`, `-r3` (3 runs) | `me-strict-r1` (**1 run**) |
| code | tag `eval-freeze` | branch `me/core-strict` (the five commits in §2), launched by `scripts/eval_launch_me.sh`, which checks they are in HEAD |
| model | `arbiter-gpt:latest`, Ollama 0.40.11, digest `e914c3a9…cd50a3` | the same; the digest read from `/api/tags` at launch is recorded in the report, and a different digest voids the comparison |
| dataset | `evalsets/v3_authored.json`, sha256 `0ab903b9…d653d33f`, 40 samples | the same |
| settings | `--attempts 3 --max-turns 16 --max-tokens 4096 --concurrency 1 --rpm 45 --repeats 1`, hermetic | the same, plus `--strict-retry` |

Only one new run fits in the time available, so the comparison is **1 new run against 3
old runs**. The three old runs are the only spread on record: as-reported TP 7 / 9 / 8,
FP 2 / 1 / 0, MCC 0.2993 / 0.4619 / 0.5000; strict-only TP 2 / 3 / 3, FP 0 / 0 / 0,
MCC 0.2294 / 0.2847 / 0.2847 (`scripts/p7b_report.py`, rerun on 2026-11-21 with the
default run ids: unchanged).

## 2. What changed (all five ship together)

1. `victim_loss: refuse harness identities in setup, neuter EOA victim mode` — setup and
   the victim's steps may no longer name the drawn accounts; negation now also runs on
   EOA-mode victim_loss proofs.
2. `run_exploit: one accepted predicate set for schema, description and dispatcher` — the
   description explains victim_loss first; the enum lists all five predicates, strict
   first, and the dispatcher now enforces it; a missing predicate is an error (it used to
   run as eth_profit). In P7b the enum offered only the strict pair, unenforced, while the
   description advertised only the loose ones.
3. `agent.py: stop steering the model away from victim_loss` — four prompt edits (ERC20
   value → victim_loss + token_expr; the nudge names victim_loss; the drain sentence is
   attributed to the profit predicates; "two strict predicates").
4. `Strict re-proof: follow a loose-only proof with one strict-only audit` — after an
   outcome proven only under a loose predicate, one more audit (at most 16 turns) offered
   only victim_loss / liveness_broken and briefed with the loose PoC. On success the strict
   PoC is listed first and the findings cite it.
5. `run_exploit: name contract-owned value as the loose fallback; per-predicate label` —
   the loose paragraph says that value owned by the contract itself (a treasury, fees, a
   prize pool) has no depositor for victim_loss and should be proven with a loose
   predicate instead of concluding safe. Added after a live smoke (arbiter-gpt, 7
   requests) in which the strict-first wording led the model to conclude safe on
   `V_missing_access_control_disburse`, a sample P7b proved with eth_profit in 3 of 3
   runs. That smoke is why as-reported TP is watched too (§6).

Because they ship together, no effect is attributed to one change alone. Per-row
`strict_retry` records show which positives came from the re-proof.

## 3. Hypotheses (stated before the run)

- **H1** strict-only TP is higher than in every P7b run: **at least 4 of 20**.
- **H2** strict-only FP stays **0 of 20**.
- **H3** as-reported FP does not go up: **at most 2 of 20** (the P7b maximum).

## 4. Metrics — the P7b definitions, unchanged

`python3 scripts/p7b_report.py --run-ids me-strict-r1 --runs-dir <run dir> --out <file>`:
the same code as P7b, which only gained the `--run-ids` option.

- *as reported*: the harness's label (`predictions_by_repeat`).
- *strict only*: a positive counts only if its winning predicate
  (`report_arm.winning_predicate`: the predicate of the first PoC with `passed and
  adjudicated`) is victim_loss or liveness_broken; otherwise it scores as safe.
  A successful re-proof puts the strict PoC first, so it becomes the winning predicate —
  that is the effect being measured. A failed re-proof leaves the loose PoC first, and the
  row scores as safe under strict-only, exactly as in P7b.
- Confusion matrix, precision, recall, specificity, F1, accuracy, MCC, 95% bootstrap
  intervals (10,000 draws, seed 20260726), not_executed rows, analyst time: as P7b §5.
- Cost: `cost.ledger_requests` and the ledger tokens include the re-proof requests;
  `mean_requests_per_sample` in p7b_report sums the attempts' turns only and does **not**.
  Both are reported, with `summary.strict_retry` (triggered, by status, requests).

## 5. Validity and infrastructure errors

As P7b §6–7, through `scripts/eval_requeue.py`. One addition: a row whose strict re-proof
stopped with `error: GatewayError: gave up after …` is an infrastructure-error row too,
and is requeued like the others.

## 6. How the result will be written

- Always "M of N", never percentages; every attempt reported, failures included.
- Strict-only TP of 2 or 3: **"no measurable difference from P7b"** (inside the old range).
  4 or more: "higher than each of the three P7b runs, in one run". One run gives no
  spread of its own, so no interval comparison is claimed.
- Any strict-only FP, or as-reported FP above 2, goes in the first line of the report.
- As-reported TP below 7 (the P7b minimum) also goes in the first line, as "the strict-first
  wording cost loose proofs", with the samples named.
- The as-reported and strict-only numbers are shown with equal prominence.

## 7. Scope

As P7b §10: single-file self-written contracts, one model, one local server, a TUNE set.

## 8. Result (appended after the run; sections 1-7 above are unchanged)

Run me-strict-r1 finished on 2026-11-22: 40 rows valid, 724 requests, model served
arbiter-gpt:latest only (digest e914c3a9..., the same as P7b). Two rows stopped with a
gateway error when the tunnel dropped while the machine slept; scripts/eval_requeue.py moved
them aside (me-strict-r1.requeued.jsonl) and they were re-run, as section 5 says. Files and
checksums: me/eval/me-strict-r1/.

Written as section 6 fixes it (arbiter-gpt, TUNE, 1 run):

- Strict-only: TP **4 of 20**, FP **0 of 20** - higher than each of the three P7b runs
  (2 / 3 / 3), in one run. MCC 0.3333 (P7b 0.2294 / 0.2847 / 0.2847).
- As reported: TP 7 of 20 (P7b 7 / 9 / 8), FP 2 of 20 (P7b 2 / 1 / 0). MCC 0.2993
  (P7b 0.2993 / 0.4619 / 0.5000). As-reported TP is not below the P7b minimum and
  as-reported FP is not above 2, so neither goes in a first line.
- H1, H2 and H3 held.
- Strict re-proof: triggered 6 times, proved 1 (V_commit_reveal_frontrun, liveness_broken),
  32 requests. The two as-reported false positives (S_stale_cached_price_liquidation,
  S_weak_randomness_flip_payout, both eth_profit) were not re-proved under the strict
  predicates. The other three strict positives were strict on the first proof.
- Cost: 724 ledger requests (re-proof included); p7b_report mean requests per sample 16.55
  (attempt turns only), summary 17.35.

### Deviations from sections 1-5 (found by the review after the run)

- **Code.** Section 1 says the run measures branch me/core-strict (the five commits of
  section 2). It was launched at ed4ae05, the merge of me/treasury into me-hackathon, so it
  also contained the treasury/ERC20 extension of victim_loss (git diff 728f0f5 ed4ae05 --
  arbiter/arbiter: 9 files, +635/-54, mostly workspace.py, patch.py, units.py). What the
  model saw changed with it: the run_exploit description of token_expr for victim_loss and a
  new optional treasury_exit property. The model composed 2 PoCs with token_expr and 2 with
  treasury_exit; none of them passed, so every positive in this run is plain ether
  victim_loss, liveness_broken or a loose predicate. Still, the description
  the model read was not the one section 2 lists. The comparison is therefore "the
  me-hackathon build at ed4ae05 against P7b", not "core-strict against P7b".
- **Model digest.** Section 1 says the digest is read from /api/tags at launch and recorded.
  No code did that. It was read after the run (2026-11-22 16:3x): arbiter-gpt:latest
  e914c3a9..., the same as P7b. The ledger shows one served model for all 724 requests.
