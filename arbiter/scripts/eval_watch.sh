#!/usr/bin/env bash
# Watch a running pre-registered eval; started by eval_launch.sh in tmux window "watch".
#
#   scripts/eval_watch.sh <run-id>
#
# Every 10 minutes: rows finished, rows with an error, and when the ledger last grew
# (the gateway appends one line per answered request). Every minute: whether 11434
# answers; if not, the time is logged and tmux window eval:tunnel is respawned.
# Writes runs/<run-id>.watch.log. Never prints the tunnel host.
set -u

RUN_ID="${1:?usage: eval_watch.sh <run-id>}"
ARB="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ARB/runs/$RUN_ID.results.jsonl"
LEDGER="$ARB/runs/$RUN_ID.ledger.jsonl"
SESSIONS="$ARB/runs/$RUN_ID.sessions.log"
LOG="$ARB/runs/$RUN_ID.watch.log"
TUNNEL_SH="${EVAL_TUNNEL_SH:-$ARB/runs/.tunnel.sh}"
SESSION="${EVAL_SESSION:-eval}"
PORT="${EVAL_PORT:-11434}"
REPORT_EVERY="${EVAL_REPORT_EVERY:-600}"
PROBE_EVERY="${EVAL_PROBE_EVERY:-60}"
TOTAL=40

say() { echo "$(date '+%F %T') $*" | tee -a "$LOG"; }

report() {
  local rows=0 errs=0 last="never" reqs=0
  [ -f "$RESULTS" ] && rows=$(grep -c . "$RESULTS")
  [ -f "$RESULTS" ] && errs=$(python3 -c '
import json, sys
print(sum(1 for l in open(sys.argv[1], encoding="utf-8") if l.strip() and json.loads(l).get("error")))
' "$RESULTS" 2>/dev/null || echo "?")
  if [ -f "$LEDGER" ]; then
    reqs=$(grep -c . "$LEDGER")
    last=$(date -r "$LEDGER" '+%F %T')
  fi
  say "rows $rows/$TOTAL  error_rows $errs  requests $reqs  last_request $last"
}

tunnel_ok() { curl -s --max-time 10 http://localhost:$PORT/api/version >/dev/null 2>&1; }

run_finished() {
  [ -f "$SESSIONS" ] || return 1
  # The run is over when the newest sessions-log line is an "end" line.
  tail -1 "$SESSIONS" | grep -q " end $RUN_ID "
}

say "watch start $RUN_ID"
report
elapsed=0
down_since=""
while true; do
  sleep "$PROBE_EVERY"
  elapsed=$((elapsed + PROBE_EVERY))
  if tunnel_ok; then
    if [ -n "$down_since" ]; then
      say "$PORT back (down since $down_since)"
      down_since=""
    fi
  else
    [ -z "$down_since" ] && down_since="$(date '+%F %T')"
    say "$PORT not answering; respawning tmux window $SESSION:tunnel"
    tmux respawn-window -k -t "$SESSION:tunnel" "bash '$TUNNEL_SH'" 2>>"$LOG" \
      || say "respawn failed"
  fi
  if [ "$elapsed" -ge "$REPORT_EVERY" ]; then
    report
    elapsed=0
  fi
  if run_finished; then
    report
    say "run finished: $(tail -1 "$SESSIONS" | cut -d' ' -f3-); watch exits"
    exit 0
  fi
done
