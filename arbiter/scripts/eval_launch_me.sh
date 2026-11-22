#!/usr/bin/env bash
# Launch the ME-build arbiter-gpt run (strict re-proof on) over v3_authored.json in tmux.
#
#   scripts/eval_launch_me.sh me-strict-r1 [--resume]
#   scripts/eval_launch_me.sh dryrun --dry-run
#
# Adapted from eval_launch.sh (the P7b launcher, which only runs at tag eval-freeze).
# Settings are the P7b ones (PREREGISTRATION_arbitergpt_v3.md) plus --strict-retry;
# PREREGISTRATION_me_strict.md says what changed and what is compared. Differences from
# eval_launch.sh:
#   * the tree must be a clean checkout whose history contains the ME core-strict commits
#     (matched by subject, so a rebase or cherry-pick still passes);
#   * if something already answers on localhost:11434 (the integrator's tunnel), no
#     tunnel is started and none is killed; only if nothing listens is the tunnel window
#     of eval_launch.sh started (needs ~/.config/arbiter/tunnel.conf);
#   * tmux session "eval-me"; the env file may be given as ARBITER_ENV_FILE.
#
# What it starts, in tmux session "eval-me":
#   window "tunnel"  (only when 11434 was not answering) ssh -N, restarted if it exits
#   window "run"     cli.py run --strict-retry, stdout+stderr -> runs/<run-id>.log
#   window "watch"   scripts/eval_watch.sh <run-id>
#
# --dry-run (run id "dryrun") runs every precheck and the same tmux layout with a stub in
# the run window, sends no LLM request, starts no tunnel, and removes its session.
set -u

ALLOWED_RUN_IDS="me-strict-r1"
EVALSET="evalsets/v3_authored.json"
MODEL="arbiter-gpt:latest"
ATTEMPTS=3
MAX_TURNS=16
MAX_TOKENS=4096
RPM=45
CONCURRENCY=1   # as in P7b (PREREGISTRATION_arbitergpt_v3.md section 3)
TUNNEL_CONF="${ARBITER_TUNNEL_CONF:-$HOME/.config/arbiter/tunnel.conf}"
MIN_FREE_GB=20
SESSION=eval-me
PORT=11434
DRY=0
# Subjects of the commits this run measures (branch me/core-strict).
REQUIRED_SUBJECTS=(
  "victim_loss: refuse harness identities in setup, neuter EOA victim mode"
  "run_exploit: one accepted predicate set for schema, description and dispatcher"
  "Strict re-proof: follow a loose-only proof with one strict-only audit"
  "agent.py: stop steering the model away from victim_loss"
  "run_exploit: name contract-owned value as the loose fallback; per-predicate label"
)

RUN_ID="${1:-}"; shift || true
RESUME=0
while [ $# -gt 0 ]; do
  case "$1" in
    --resume) RESUME=1; shift ;;
    --dry-run) DRY=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

ARB="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # .../arbiter
TREE="$(cd "$ARB/.." && pwd)"
ENV_FILE="${ARBITER_ENV_FILE:-$TREE/.env}"
fail() { echo "PRECHECK FAIL: $*" >&2; exit 1; }
ok() { echo "  ok  $*"; }

echo "prechecks (no LLM request):"
if [ "$DRY" -eq 1 ]; then
  [ "$RUN_ID" = "dryrun" ] || fail "--dry-run takes run id 'dryrun'"
  ALLOWED_RUN_IDS="dryrun"; SESSION=eval-me-dry
  # Dry-run logs are scratch: moved out of runs/ (never deleted), before and after.
  DRY_OUT="/tmp/eval-me-dryrun-$(date +%Y%m%d-%H%M%S)"
  stash_dry() {
    mkdir -p "$DRY_OUT"
    for f in "$ARB/runs/dryrun.sessions.log" "$ARB/runs/dryrun.watch.log"; do
      [ -e "$f" ] && mv "$f" "$DRY_OUT/"
    done
    return 0
  }
  stash_dry
fi
case " $ALLOWED_RUN_IDS " in
  *" $RUN_ID "*) ok "run id $RUN_ID is allowed" ;;
  *) fail "run id '$RUN_ID' is not one of: $ALLOWED_RUN_IDS" ;;
esac

head_sha="$(git -C "$TREE" rev-parse HEAD 2>/dev/null)"
[ -n "$head_sha" ] || fail "$TREE is not a git checkout"
[ -z "$(git -C "$TREE" status --porcelain --untracked-files=no)" ] || fail "tracked files are modified; commit or stash first"
subjects="$(git -C "$TREE" log --format=%s HEAD)"
for s in "${REQUIRED_SUBJECTS[@]}"; do
  printf '%s\n' "$subjects" | grep -qxF "$s" || fail "HEAD ${head_sha:0:7} lacks the commit '$s'"
done
ok "HEAD ${head_sha:0:7} contains the ${#REQUIRED_SUBJECTS[@]} core-strict commits, tracked files clean"

if [ -f "$ENV_FILE" ]; then
  ok "env file present"
elif [ "$DRY" -eq 1 ]; then
  echo "  WARN env file missing ($([ -n "${ARBITER_ENV_FILE:-}" ] && echo ARBITER_ENV_FILE || echo .env at the tree root)); a real launch would refuse"
else
  fail "env file missing: put .env at the tree root or set ARBITER_ENV_FILE"
fi

others="$(pgrep -af 'gptoss-v[3]|me-stric[t]|cli\.py ru[n]' | grep -v -e pgrep -e eval_launch -e eval_watch || true)"
[ -z "$others" ] || fail "another evaluation process is running"
tmux has-session -t "$SESSION" 2>/dev/null && fail "tmux session '$SESSION' already exists (tmux attach -t $SESSION)"
ok "no other evaluation process, no tmux session '$SESSION'"

free_gb="$(df --output=avail -BG /mnt/c 2>/dev/null | tail -1 | tr -dc 0-9)"
[ -n "$free_gb" ] || fail "cannot read free space on C:"
[ "$free_gb" -gt "$MIN_FREE_GB" ] || fail "C: has ${free_gb} GB free, need more than ${MIN_FREE_GB} GB"
ok "C: ${free_gb} GB free"

results="$ARB/runs/$RUN_ID.results.jsonl"
if [ -s "$results" ] && [ "$RESUME" -ne 1 ]; then
  fail "$RUN_ID already has rows; pass --resume to continue it (after eval_requeue.py if rows hit infrastructure errors)"
fi
if [ "$RESUME" -eq 1 ] && [ ! -s "$results" ]; then
  fail "--resume given but $RUN_ID has no rows yet"
fi

PATH="$HOME/.foundry/bin:$PATH"
command -v forge >/dev/null || fail "forge not on PATH"
command -v tmux >/dev/null || fail "tmux not installed"
ok "forge $(forge --version | head -1 | awk '{print $3}'), tmux present"
( cd "$ARB" && python3 cli.py run --help 2>/dev/null | grep -q -- '--strict-retry' ) \
  || fail "cli.py run has no --strict-retry"
ok "cli.py run --strict-retry available"

port_up() { curl -s --max-time 3 "http://localhost:$PORT/api/version" >/dev/null 2>&1; }
OWN_TUNNEL=0
if port_up; then
  ok "something already answers on $PORT; using it (no tunnel started, none closed)"
elif [ "$DRY" -eq 1 ]; then
  echo "  WARN nothing answers on $PORT; a real launch would start its own tunnel"
else
  [ -f "$TUNNEL_CONF" ] || fail "nothing answers on $PORT and tunnel config ~/.config/arbiter/tunnel.conf is missing"
  # shellcheck disable=SC1090
  . "$TUNNEL_CONF"
  [ -n "${ARBITER_TUNNEL_TARGET:-}" ] || fail "ARBITER_TUNNEL_TARGET not set in tunnel config"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$ARBITER_TUNNEL_TARGET" true >/dev/null 2>&1 \
    || fail "ssh to the tunnel host failed (key auth, BatchMode)"
  ok "nothing answers on $PORT; ssh to the tunnel host works (address not shown)"
  OWN_TUNNEL=1
fi

mkdir -p "$ARB/runs"
SESSIONS_LOG="$ARB/runs/$RUN_ID.sessions.log"
TUNNEL_SH="$ARB/runs/.tunnel-me.sh"
tmux new-session -d -s "$SESSION" -n tunnel -x 200 -y 50
tmux set-option -t "$SESSION" remain-on-exit on >/dev/null
if [ "$OWN_TUNNEL" -eq 1 ]; then
  cat > "$TUNNEL_SH" <<EOF
#!/usr/bin/env bash
# Generated by eval_launch_me.sh. Foreground ssh -N, restarted whenever it exits.
. "$TUNNEL_CONF"
while true; do
  echo "\$(date '+%F %T') tunnel up"
  ssh -N -o BatchMode=yes -o ExitOnForwardFailure=yes \\
      -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \\
      \$ARBITER_TUNNEL_FORWARDS "\$ARBITER_TUNNEL_TARGET" 2>&1 | sed -E 's/[0-9]{1,3}(\.[0-9]{1,3}){3}/<host>/g'
  echo "\$(date '+%F %T') tunnel exited (rc \${PIPESTATUS[0]}), restarting in 5 s"
  sleep 5
done
EOF
  chmod 700 "$TUNNEL_SH"
  tmux send-keys -t "$SESSION:tunnel" "exec bash '$TUNNEL_SH'" Enter
  up=0
  for _ in $(seq 1 30); do
    if port_up; then up=1; break; fi
    sleep 1
  done
  if [ "$up" -ne 1 ]; then
    tmux kill-session -t "$SESSION"
    fail "tunnel in tmux did not answer on $PORT within 30 s (session removed)"
  fi
  ok "tunnel in tmux answers on $PORT"
else
  # The watcher respawns this window when the port stops answering; with an external
  # tunnel there is nothing of ours to restart, so the window only says so.
  cat > "$TUNNEL_SH" <<EOF
#!/usr/bin/env bash
echo "\$(date '+%F %T') external tunnel on $PORT is not answering; it is not managed here"
sleep 30
EOF
  chmod 700 "$TUNNEL_SH"
  tmux send-keys -t "$SESSION:tunnel" "echo 'external tunnel on $PORT; not managed by this session'" Enter
fi

RUN_CMD="cd '$ARB' && export PATH='$HOME/.foundry/bin':\$PATH && set -a && . '$ENV_FILE' && set +a && \
echo \"\$(date '+%F %T') start $RUN_ID concurrency=$CONCURRENCY resume=$RESUME head=${head_sha:0:7} strict_retry=on\" >> '$SESSIONS_LOG' && \
python3 cli.py run --evalset $EVALSET --model $MODEL --run-id $RUN_ID \
  --attempts $ATTEMPTS --max-turns $MAX_TURNS --max-tokens $MAX_TOKENS \
  --concurrency $CONCURRENCY --rpm $RPM --repeats 1 --strict-retry >> runs/$RUN_ID.log 2>&1; \
rc=\$?; echo \"\$(date '+%F %T') end $RUN_ID rc=\$rc\" >> '$SESSIONS_LOG'; \
python3 scripts/eval_requeue.py $RUN_ID --check >> runs/$RUN_ID.log 2>&1; \
echo \"run finished rc=\$rc; see runs/$RUN_ID.log\""
if [ "$DRY" -eq 1 ]; then
  RUN_CMD="cd '$ARB' && echo \"\$(date '+%F %T') start dryrun (stub, no LLM request) head=${head_sha:0:7}\" >> '$SESSIONS_LOG' && \
sleep 8 && echo \"\$(date '+%F %T') end dryrun rc=0\" >> '$SESSIONS_LOG'"
fi
tmux new-window -t "$SESSION" -n run
tmux send-keys -t "$SESSION:run" "$RUN_CMD" Enter
tmux new-window -t "$SESSION" -n watch
WATCH_ENV="EVAL_SESSION=$SESSION EVAL_PORT=$PORT EVAL_TUNNEL_SH='$TUNNEL_SH'"
[ "$DRY" -eq 1 ] && WATCH_ENV="$WATCH_ENV EVAL_PROBE_EVERY=5 EVAL_REPORT_EVERY=10"
tmux send-keys -t "$SESSION:watch" "cd '$ARB' && $WATCH_ENV bash scripts/eval_watch.sh $RUN_ID" Enter

if [ "$DRY" -eq 1 ]; then
  for _ in $(seq 1 40); do
    grep -q "watch exits" "$ARB/runs/dryrun.watch.log" 2>/dev/null && break
    sleep 1
  done
  echo "--- dryrun.sessions.log"; cat "$SESSIONS_LOG"
  echo "--- dryrun.watch.log"; cat "$ARB/runs/dryrun.watch.log" 2>/dev/null
  echo "--- tmux windows"; tmux list-windows -t "$SESSION" -F '#{window_name} dead=#{pane_dead}'
  tmux kill-session -t "$SESSION"
  rm -f "$TUNNEL_SH"
  grep -q "watch exits" "$ARB/runs/dryrun.watch.log" 2>/dev/null; seen=$?
  stash_dry
  echo "(dry-run logs moved to $DRY_OUT)"
  [ "$seen" -eq 0 ] \
    && { echo "dry run OK (session $SESSION removed)"; exit 0; } \
    || { echo "dry run FAILED: watcher did not see the stub finish" >&2; exit 1; }
fi

echo
echo "launched $RUN_ID in tmux session '$SESSION' (windows: tunnel, run, watch)"
echo "  attach:  tmux attach -t $SESSION      (detach: Ctrl-b d)"
echo "  log:     arbiter/runs/$RUN_ID.log (inside this checkout)"
echo "  watch:   arbiter/runs/$RUN_ID.watch.log"
