# arbiter-gpt on v3_authored.json, three runs (gptoss-v3-r1..r3)

Prepared 2026-10-30 for plan 9.2 "data publication": published with the competition branch cut
from upstream `arbiter-harness` (this snapshot), never the user's fork. The numbers built from
these files are in `innoserve/README.md` ("40 份評測結果") and
`innoserve/docs/reports/eval_arbitergpt_v3_2026-10-30.md`.

| file | what |
|---|---|
| `gptoss-v3-r{1,2,3}.summary.json` | the harness's summary, unchanged |
| `gptoss-v3-r{1,2,3}.results.jsonl.gz` | every row with its per-attempt trace, gzip -n -9 of the original |
| `SHA256SUMS` | the originals' and these files' sha256 |

- Pre-registration: `arbiter/PREREGISTRATION_arbitergpt_v3.md`, tag `eval-freeze` = 1c7f896.
  Model `arbiter-gpt:latest` (gpt-oss 120B, MXFP4) on a local Ollama server. TUNE set.
- r1's `summary.json` was written by the resumed session (22:30-23:09, 3 requeued rows), so
  its `usage` and `wall_clock_s` cover that session only; its metrics cover all 40 rows.
  Requests and tokens are taken from the ledger (not included here), as the
  pre-registration says.
- Scanned before copying (2026-10-30): no `/home/`, `/mnt/c/Users/`, Windows paths, host
  name, user name, e-mail address, server address or key-like string; the only paths are
  the harness's own `/tmp/arbiter-ws/...` workspaces. No v1_paired14 withheld sample: none
  of its 7 ids or identifying words, and none of the 7 `code_sha256` matches any JSON string
  (as is, stripped, with a trailing newline).

Check: `sha256sum -c SHA256SUMS` verifies the six files here (the three `(original)` lines name the
uncompressed files and warn as unreadable); `zcat gptoss-v3-r1.results.jsonl.gz | sha256sum` gives
the `(original)` value.
