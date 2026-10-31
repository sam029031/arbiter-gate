#!/usr/bin/env bash
# The ARBITER Gate finals demo (11/7) as one command: plan 12.7's preflight, then plan
# 12.4's six-minute script beat by beat. scripts/demo.sh is the AIS3-era demo, unchanged.
#
# P8 (reports/reliability_final_*.md) settled that the six minutes run from the recording
# from 0:00. D6 keeps one live upload going in the background, revealed in the Q&A.
#
#   scripts/demo_gate.sh                   pause between segments, press Enter to go on
#   scripts/demo_gate.sh --auto            fixed pauses (recording, merge checks)
#   --talk-pace                            with --auto: each pause fills its segment up to
#                                          the 12.4 budget, so the run lasts six minutes
#   --live                                 D6: at 0:00 one contract goes to the model in the
#                                          background (a judge picks one of the page's demo
#                                          contracts); the Q&A segment reveals the result
#   --live --live-upload                   the upload sent with curl instead of a person
#                                          (examples/StakingVault.sol; rehearsal / recording)
#   --cache-result RID                     use a saved result page (runs/gate/web/RID.json)
#                                          and its job page as the recording, instead of
#                                          playing spark-test-2 back
#   --speed 1|4                            playback speed of spark-test-2 (default 4)
#   --preflight-only                       segment 0 only; exit 0 = PREFLIGHT OK
#   --timings FILE                         also write per-segment seconds as TSV
#   --pause N                              seconds per pause with --auto (default 6)
#   --no-smoke                             send nothing to the model host: api_smoke is
#                                          skipped (the preflight says so) and --live is
#                                          refused. For merge checks while an eval runs.
#
# The only model requests are api_smoke and --live. The preflight is plan 12.7's list;
# any exit code other than 0 stops the script before the six minutes ("改走 L1").
#
# The page runs ONE job at a time and a live upload holds that slot for 2-8 minutes. So
# the recording is played back in segment 0, before the live upload is sent; during the
# six minutes the presenter shows its finished job page and result page, which need no
# slot.
set -u

AUTO=""; LIVE=""; LIVE_SKIPPED=""; LIVE_UPLOAD=""; TIMINGS=""
PAUSE=6; NO_SMOKE=""; TALK_PACE=""; CACHE_RESULT=""; SPEED=4; PREFLIGHT_ONLY=""
PORT=8765
while [ $# -gt 0 ]; do
    case "$1" in
        --auto) AUTO=1; shift ;;
        --talk-pace) TALK_PACE=1; shift ;;
        --live) LIVE=1; shift ;;
        --live-upload) LIVE_UPLOAD=1; shift ;;
        --cache-result) CACHE_RESULT="$2"; shift 2 ;;
        --speed) SPEED="$2"; shift 2 ;;
        --preflight-only) PREFLIGHT_ONLY=1; shift ;;
        --timings) TIMINGS="$2"; shift 2 ;;
        --pause) PAUSE="$2"; shift 2 ;;
        --no-smoke) NO_SMOKE=1; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [ -n "$NO_SMOKE" ] && [ -n "$LIVE" ]; then
    echo "--live sends requests to the model host; it cannot run with --no-smoke" >&2; exit 2
fi
if [ -n "$LIVE_UPLOAD" ] && [ -z "$LIVE" ]; then
    echo "--live-upload needs --live" >&2; exit 2
fi
if [ -n "$TALK_PACE" ] && [ -z "$AUTO" ]; then
    echo "--talk-pace needs --auto" >&2; exit 2
fi
case "$SPEED" in 1|4) ;; *) echo "--speed is 1 or 4" >&2; exit 2 ;; esac
if [ -n "$CACHE_RESULT" ] && ! [[ "$CACHE_RESULT" =~ ^[0-9a-f]{12}$ ]]; then
    echo "--cache-result takes a 12-hex result id (runs/gate/web/<id>.json)" >&2; exit 2
fi

RIG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RIG" || exit 1
BASE="http://127.0.0.1:$PORT"
REPLAY_RUN="spark-test-2"
TARGET="$RIG/examples/StakingVault.sol"
STATE="$RIG/runs/gate/demo"          # runs/gate/ is ignored by git
mkdir -p "$STATE"
DEMO_REPO="https://github.com/sam029031/arbiter-gate-demo"
VENV_PY="$RIG/../../venv-tools/bin/python"   # jsonschema, for the SARIF check (optional)
CHAIN_LINE="這段鏈上攻擊是事先寫好的參考攻擊（victim_probe 的 DRAIN），不是 AI 這次產生的"

B=$(printf '\033[1m'); D=$(printf '\033[2m'); Y=$(printf '\033[33m'); R=$(printf '\033[0m')

since() { awk -v a="$1" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.1f", b-a}'; }

# -- timing: each segment's own seconds, pauses excluded; the six-minute budget per beat --
SEG_NAMES=(); SEG_SECS=(); SEG_BUDGETS=(); SEG_T0=""; SEG_BUDGET=""
WALL_T0=$EPOCHREALTIME

seg() {   # seg "<title>" "<one-line point>" [budget seconds, from plan 12.4]
    SEG_T0=$EPOCHREALTIME
    SEG_BUDGET="${3:-}"
    SEG_NAMES+=("$1")
    printf '\n%s%s\n  %s\n%s%s\n' "$B" "$(printf '=%.0s' $(seq 74))" "$1" \
        "$(printf '=%.0s' $(seq 74))" "$R"
    [ -n "${2:-}" ] && printf '%s  %s%s\n' "$D" "$2" "$R"
    echo
}

seg_end() {
    local s
    s=$(since "$SEG_T0")
    SEG_SECS+=("$s")
    SEG_BUDGETS+=("${SEG_BUDGET:--}")
    if [ -n "$SEG_BUDGET" ]; then
        printf '\n%s  (this segment: %s s of the program; 12.4 gives the beat %s s)%s\n' \
            "$D" "$s" "$SEG_BUDGET" "$R"
    else
        printf '\n%s  (this segment: %s s)%s\n' "$D" "$s" "$R"
    fi
}

pause() {
    if [ -n "$AUTO" ]; then
        local n="$PAUSE"
        if [ -n "$TALK_PACE" ] && [ -n "$SEG_BUDGET" ]; then
            n=$(awk -v b="$SEG_BUDGET" -v s="${SEG_SECS[-1]}" 'BEGIN{n=int(b-s+0.5); print (n<1?1:n)}')
            printf '%s  （講話時間 %s 秒）%s\n' "$D" "$n" "$R"
            sleep "$n"
            return
        fi
        printf '%s  ' "$D"
        while [ "$n" -gt 0 ]; do printf '.'; sleep 1; n=$((n - 1)); done
        printf '%s\n' "$R"
    else
        printf '\n%s  [Enter]%s ' "$D" "$R"; read -r _ || true
    fi
}

warn() { printf '%s  !! %s%s\n' "$Y" "$*" "$R"; }

say() {   # what the presenter should say out loud, set apart from program output
    printf '%s  >> %s%s\n' "$B" "$*" "$R"
}

# A section that printed nothing must not look like a section that passed.
show() {
    local out rc
    out=$("$@" 2>&1); rc=$?
    if [ -z "$out" ]; then
        warn "$1 produced NO OUTPUT -- this step did not run."
        return 99
    fi
    printf '%s\n' "$out"
    return $rc
}

web_up() { [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$BASE/")" = "200" ]; }

port_busy() { ss -ltn 2>/dev/null | awk '{print $4}' | grep -q ":$1\$"; }

job_field() {   # job_field <job id> <field>: one field of /api/job/<id>'s job, or ''
    curl -s --max-time 5 "$BASE/api/job/$1" | python3 -c \
        'import json,sys; print(json.load(sys.stdin)["job"].get(sys.argv[1]) or "")' "$2" 2>/dev/null
}

# What the page shows, printed from the same saved result, for when the browser fails.
# summary <part> <runs/gate/web/RID.json> [<job dir>]
summary() {
    python3 - "$@" <<'PY'
import json, sys
from pathlib import Path

part, saved_path = sys.argv[1], sys.argv[2]
job_dir = Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else None
saved = json.load(open(saved_path, encoding="utf-8"))
rep = saved["report"]
eth = lambda w: "?" if w is None else f"{w / 10**18:g}"
abg = lambda envs: "、".join(f"{eth(e.get('A'))}/{eth(e.get('B'))}/{eth(e.get('G'))}" for e in envs)
fl = (rep.get("files") or [{}])[0]
f = (fl.get("findings") or [{}])[0]
STATUS = {"pass": "通過", "fail": "沒過", "not_applicable": "不適用（單檔上傳）",
          "skipped": "略過（不算通過）", "not_reached": "沒有跑到", "off": "關閉"}
CHECKS = [("0", "重現原攻擊"), ("L", "格式與改動行數"), ("3", "介面不變"),
          ("1", "同一攻擊在 4 個環境都失效"), ("2", "一般使用者取回不少於修補前"),
          ("4", "專案自己的測試"), ("5", "修補後換手法再攻擊")]

if part == "turns":
    job = json.loads((job_dir / "job.json").read_text(encoding="utf-8")) if job_dir else {}
    p = job.get("params") or {}
    if job.get("kind") == "playback":
        print(f"  錄製回放：{p.get('recorded_on')} 的實際紀錄（{p.get('model')}，{p.get('speed')} 倍速重播；"
              "損失數字與修補檢查是當場用 forge 重跑的）")
    else:
        print(f"  錄製紀錄：{saved.get('meta', {}).get('at', '')[:10]} 的實際紀錄（{'、'.join(rep.get('models') or [])}；"
              f"來源：{saved.get('meta', {}).get('source')}）")
    evs = []
    if job_dir and (job_dir / "events.jsonl").exists():
        evs = [json.loads(l) for l in (job_dir / "events.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    pending = None
    for e in evs:
        if e.get("kind") == "turn":
            if pending:
                print(pending)
            tools = e.get("tools") or []
            names = "、".join(t.get("name", "?") for t in tools) or "（沒有呼叫工具）"
            pending = f"    回合 {e.get('turn')}  {names}"
        elif e.get("kind") == "tool_result" and pending:
            pending += f" → {e.get('text')}"
    if pending:
        print(pending)
    if not evs:
        print("    （這份紀錄沒有工作頁的逐回合事件）")
elif part == "result":
    print(f"    判定      {fl.get('label')}")
    print(f"    模型      {'、'.join(rep.get('models') or [])}；這次產生頁面的 LLM 請求 "
          f"{rep.get('input', {}).get('llm_requests_this_invocation')}")
    if f:
        a = f.get("abg") or {}
        print(f"    謂詞      {f.get('predicate')}（嚴格謂詞：{'是' if f.get('predicate_strict') else '否'}）")
        print(f"    A/B/G     {abg(a.get('environments') or []) or a.get('label')}（ETH，4 個環境）")
elif part == "ladder":
    ev = f.get("evidence") or {}
    if not ev:
        print("    （這份結果沒有證據等級）")
    else:
        r2, r3 = ev.get("rung2") or {}, ev.get("rung3") or {}
        print(f"    證據等級  爬到第 {ev.get('reached', 1)} 階（1 合成環境、2 獨立 Foundry 專案、3 本地真鏈）")
        print(f"    第 2 階   {STATUS.get(r2.get('status'), r2.get('status'))}")
        print(f"    第 3 階   {STATUS.get(r3.get('status'), r3.get('status'))}：{r3.get('reason') or ''}")
elif part == "patch":
    p = f.get("patch") or {}
    if not p:
        print("    （這份結果沒有修補）")
    else:
        print(f"    修補      {p.get('label') or p.get('status')}，改 {p.get('changed_lines')} 行（{p.get('model')} 產生）")
        gc = p.get("gate_checks") or {}
        for k, name in CHECKS:
            if k in gc:
                print(f"    檢查 {k:<2}  {name}：{STATUS.get(gc[k], gc[k])}")
            elif k == "5":
                print(f"    檢查 5   {name}：這份紀錄沒有（修補是錄製時產生的，當時還沒有檢查 5；回放不呼叫 AI）")
        if p.get("after"):
            print(f"    修補後    A/B/G {abg(p['after'])}")
        tl = p.get("timeline") or []
        if tl:
            print(f"    攻防過程  {len(tl)} 步（結果頁「攻防過程」時間軸）")
        diff = [l for l in (p.get("diff") or "").splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))]
        for l in diff[:10]:
            print(f"      {l}")
elif part == "sarif":
    sar = json.load(open(sys.argv[3], encoding="utf-8"))
    run = (sar.get("runs") or [{}])[0]
    res = run.get("results") or []
    levels = {}
    for r in res:
        levels[r.get("level")] = levels.get(r.get("level"), 0) + 1
    tool = (run.get("tool") or {}).get("driver") or {}
    print(f"    SARIF     {sar.get('version')}，工具 {tool.get('name')}；"
          f"error {levels.get('error', 0)}、warning {levels.get('warning', 0)}"
          f"（error＝已證實可攻擊，warning＝靜態工具提示）")
    for r in res[:3]:
        loc = ((r.get("locations") or [{}])[0].get("physicalLocation") or {})
        print(f"      {r.get('level')}  {r.get('ruleId')}  {(loc.get('artifactLocation') or {}).get('uri')}"
              f":{(loc.get('region') or {}).get('startLine')}")
PY
}

# =========================================================================================
seg "第 0 段  開場前：preflight（計劃書 12.7）＋準備錄製紀錄" "全部結束碼 0 才開場；不算在 6 分鐘裡"

if [ -f "$RIG/../.env" ]; then
    set -a; source "$RIG/../.env"; set +a
    echo "  .env       loaded (model: ${ARBITER_MODEL:-${AIS3_MODEL:-?}})"
else
    warn ".env not found next to arbiter/ -- api_smoke and the live upload will fail"
fi

PF_FAIL=0; PF_NOTE=""
pf() {   # pf <label> <command...>: run it, print the exit code and the last line
    local label="$1" out rc t
    shift
    t=$EPOCHREALTIME
    out=$("$@" 2>&1); rc=$?
    printf '  %-22s rc=%s %6s s  %s\n' "$label" "$rc" "$(since "$t")" \
        "$(printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -1 | sed -E 's#https?://[^ ]+#<endpoint>#g' | cut -c1-80)"
    [ "$rc" -eq 0 ] || PF_FAIL=1
}

echo "  ${B}preflight（12.7 的清單，逐一檢查結束碼）${R}"
pf "forge/anvil/cast" bash -c 'forge --version | head -1 && anvil --version | head -1 && cast --version | head -1'
if [ -n "$NO_SMOKE" ]; then
    echo "  api_smoke              跳過（--no-smoke）：preflight 不完整，只能排練、不能開場"
    PF_NOTE="api_smoke 跳過"
else
    t=$EPOCHREALTIME
    smoke=$(timeout 90 python3 scripts/api_smoke.py 2>&1); rc=$?
    printf '  %-22s rc=%s %6s s  %s\n' "api_smoke" "$rc" "$(since "$t")" \
        "$(printf '%s\n' "$smoke" | head -1 | sed -E 's#https?://[^ ]+#<endpoint>#g' | cut -c1-80)"
    [ "$rc" -eq 0 ] || PF_FAIL=1
    LLM_OK=$([ "$rc" -eq 0 ] && echo 1 || echo "")
fi
for p in victim forgery halt drain sweep latebinding setup_forgery gain; do
    pf "${p}_probe" python3 "scripts/${p}_probe.py"
done
pf "patch_probe" python3 scripts/patch_probe.py
pf "live_attack" python3 scripts/live_attack.py --port 8599
pf "live_attack --patched" python3 scripts/live_attack.py --port 8600 --patched
if [ "$PF_FAIL" -eq 0 ]; then
    echo "  ${B}PREFLIGHT OK${R}${PF_NOTE:+（$PF_NOTE）}"
else
    warn "PREFLIGHT FAILED: 不開場，改走 L1（DEMO_RUNBOOK「備援」：首頁的錄製回放；再不行就 L2 播 6 分鐘備援影片）"
    seg_end
    exit 1
fi
LLM_OK="${LLM_OK:-}"
if [ -n "$PREFLIGHT_ONLY" ]; then
    seg_end
    exit 0
fi

echo
echo "  ${B}網頁、本地鏈埠、錄製紀錄${R}"
if web_up || port_busy "$PORT"; then
    web_up && echo "  web        already running at $BASE/ (reused)" \
           || warn "port $PORT is taken but the page does not answer within 10 s"
else
    nohup python3 -m arbiter.web --port "$PORT" >"$STATE/web.server.log" 2>&1 &
    WEB_PID=$!
    disown "$WEB_PID" 2>/dev/null || true
    for _ in $(seq 20); do web_up && break; sleep 0.5; done
    if web_up && kill -0 "$WEB_PID" 2>/dev/null; then
        echo "  web        started at $BASE/ (pid $WEB_PID, log ${STATE#"$RIG"/}/web.server.log; left running)"
    else
        warn "web did not come up; see ${STATE#"$RIG"/}/web.server.log"
    fi
fi

BUSY=""
for p in 8600 8601 8610 8611; do port_busy "$p" && BUSY="$BUSY $p"; done
[ -n "$BUSY" ] && warn "ports in use:$BUSY -- the chain in segment 3 needs 8600/8601/8610/8611"

# Plan e (D21) is the 2:30 chain; a cold first run of forge/anvil/cast has taken 70 s
# here, so it runs once now. If it fails, segment 3 switches to backup 3b (WithdrawalQueue).
CHAIN_PLAN="e"
t=$EPOCHREALTIME
if out=$(python3 scripts/live_attack_stakingvault.py --port 8600 2>&1) && printf '%s\n' "$out" | grep -q '^  PROVEN'; then
    echo "  chain      方案 e 暖機一次：PROVEN（$(since "$t") s）"
else
    warn "方案 e（live_attack_stakingvault.py）在這台跑不起來（$(since "$t") s）：第 3 段改用備案 3b（WithdrawalQueue）"
    CHAIN_PLAN="3b"
fi

# The recording: spark-test-2 played back now, while the page's single job slot is free.
CACHE_RID=""; CACHE_JOB=""
if [ -n "$CACHE_RESULT" ]; then
    if [ -f "runs/gate/web/$CACHE_RESULT.json" ]; then
        CACHE_RID="$CACHE_RESULT"
        CACHE_JOB=$(python3 -c 'import json,sys; print((json.load(open(sys.argv[1]))["meta"].get("job")) or "")' \
            "runs/gate/web/$CACHE_RESULT.json")
        echo "  recording  saved result $CACHE_RID${CACHE_JOB:+ (job $CACHE_JOB)}"
    else
        warn "runs/gate/web/$CACHE_RESULT.json does not exist"
    fi
elif [ ! -f "runs/$REPLAY_RUN.results.jsonl" ]; then
    warn "runs/$REPLAY_RUN.results.jsonl is missing -- no recording to play back"
elif web_up; then
    t=$EPOCHREALTIME
    job=$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 30 \
        --data "run_id=$REPLAY_RUN&speed=$SPEED" "$BASE/playback")
    jid="${job##*/}"
    if [[ "$jid" =~ ^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$ ]]; then
        for _ in $(seq 1 300); do
            CACHE_RID=$(job_field "$jid" rid)
            st=$(job_field "$jid" status)
            [ -n "$CACHE_RID" ] && break
            [ "$st" = "failed" ] || [ "$st" = "interrupted" ] && break
            sleep 2
        done
        CACHE_JOB="$jid"
        if [ -n "$CACHE_RID" ]; then
            echo "  recording  $REPLAY_RUN 錄製回放（${SPEED} 倍速）跑完：$(since "$t") s（重播＋forge 重跑，0 個 LLM 請求）"
        else
            warn "playback job $jid ended without a result page (status ${st:-?}, $(since "$t") s)"
        fi
    else
        warn "the page did not start a playback: '$job'"
    fi
fi

SAVED=""; JOBDIR=""
if [ -n "$CACHE_RID" ]; then
    SAVED="$RIG/runs/gate/web/$CACHE_RID.json"
    [ -n "$CACHE_JOB" ] && [ -d "runs/gate/jobs/$CACHE_JOB" ] && JOBDIR="$RIG/runs/gate/jobs/$CACHE_JOB"
fi
echo
echo "  ${B}瀏覽器先開好這幾個分頁（12.4「開場前 10 分鐘」）${R}"
echo "    1 上傳頁    $BASE/"
[ -n "$CACHE_JOB" ] && echo "    2 錄製紀錄  $BASE/job/$CACHE_JOB?stay=1   （工作頁，逐回合；留在這頁不跳轉）"
[ -n "$CACHE_RID" ] && echo "    3 結果頁    $BASE/result/$CACHE_RID"
echo "    4 PR 頁     $BASE/github   （本機截圖，不用網路）；有網路時另開 $DEMO_REPO/pull/1"
seg_end
pause

# =========================================================================================
UPLOAD_T0=""
seg "第 1 段  0:00–1:45  上傳／快取播放" "現場上傳放背景（D6）；6 分鐘講的是錄製紀錄" 105
if [ -n "$LIVE" ]; then
    UPLOAD_T0=$EPOCHREALTIME
    if [ -z "$LLM_OK" ]; then
        warn "api_smoke failed -- live upload SKIPPED, nothing uploaded"
        LIVE=""; LIVE_SKIPPED=1
    elif [ -n "$LIVE_UPLOAD" ]; then
        rm -f "$STATE/live_upload.out" "$STATE/live_upload.job"
        ( t0=$EPOCHREALTIME
          job=$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 60 -F "contract=@$TARGET" "$BASE/upload")
          jid="${job##*/}"; echo "$job" > "$STATE/live_upload.job"
          for _ in $(seq 1 1800); do
              rid=$(job_field "$jid" rid)
              [ -n "$rid" ] && { printf '%s/result/%s\n%s\n' "$BASE" "$rid" "$(since "$t0")" > "$STATE/live_upload.out"; break; }
              sleep 2
          done ) &
        echo "  現場上傳（curl 送出 ${TARGET#"$RIG"/}，pid $!）已送出，背景執行"
    else
        echo "  分頁 1：請評審從「① 上傳一份合約」的示範合約挑一份按下（D6）。按下後跳到工作頁，放著。"
    fi
    if [ -n "$LIVE" ]; then
        say "這一份現在真的交給 AI，大約 2 到 8 分鐘；我們先看同一套系統錄好的完整紀錄，問答時再回來揭曉。"
    fi
fi
echo
if [ -n "$SAVED" ]; then
    echo "  分頁 2（錄製紀錄的工作頁）：$BASE/job/${CACHE_JOB:-?}?stay=1"
    show summary turns "$SAVED" "$JOBDIR"
else
    warn "no recording was prepared in segment 0 -- runbook 備援 L1"
fi
say "（0:00）ARBITER Gate 是部署前的證據閘門：AI 寫攻擊，系統在沙箱裡實際執行，只有真的成功、受害者真的少拿回錢，才擋部署。"
say "（0:15–0:50）警報器 vs 證據：別的工具給的是警報，我們給的是能重跑的攻擊。D7 沒有海報，這段指首頁或口頭講。"
say "（0:50–1:45）逐回合念：AI 不能宣稱有漏洞，只能交出能跑的攻擊；成功條件在系統手上，AI 看不到。"
say "這是錄製紀錄，畫面上方標著日期；不是現在這一次。"
seg_end
pause

# =========================================================================================
seg "第 2 段  1:45–2:30  結果與 A/B/G" "結果卡：已證實可攻擊（擋部署）；4 個環境的 A、B、G" 45
# The two chain runs take 30-70 s here, more than the 50 s of 2:30-3:20. They start now,
# live, behind segment 2, and segment 3 prints them (waiting for whatever is left).
CHAIN_T0=$EPOCHREALTIME
rm -f "$STATE"/chain-[12].txt "$STATE"/chain-[12].rc
(
    if [ "$CHAIN_PLAN" = "e" ]; then
        python3 scripts/live_attack_stakingvault.py --port 8600 >"$STATE/chain-1.txt" 2>&1
        echo $? >"$STATE/chain-1.rc"
        python3 scripts/live_attack_stakingvault.py --port 8610 --patched "$REPLAY_RUN" >"$STATE/chain-2.txt" 2>&1
        echo $? >"$STATE/chain-2.rc"
    else
        python3 scripts/live_attack.py --port 8600 >"$STATE/chain-1.txt" 2>&1
        echo $? >"$STATE/chain-1.rc"
        python3 scripts/live_attack.py --port 8610 --patched >"$STATE/chain-2.txt" 2>&1
        echo $? >"$STATE/chain-2.rc"
    fi
) &
CHAIN_PID=$!
echo "  （本地鏈兩向已在背景開跑，第 3 段印出）"
if [ -n "$SAVED" ]; then
    echo "  分頁 3（結果頁）：$BASE/result/$CACHE_RID"
    echo
    show summary result "$SAVED"
else
    warn "no recording -- nothing to show"
fi
say "A 是沒有攻擊時受害者拿回多少，B 是有攻擊時拿回多少，G 是攻擊者賺多少。別人少拿的錢在攻擊者手上。"
say "數字照實顯示：哪幾個環境受害者沒有受損，畫面就是那樣。"
seg_end
pause

# =========================================================================================
seg "第 3 段  2:30–3:20  證據等級與鏈上重播" "結果頁的證據等級；本地鏈（anvil）兩條鏈：一條有攻擊，一條沒有" 50
if [ -n "$SAVED" ]; then
    show summary ladder "$SAVED"
    echo
fi
chain_out() {   # chain_out <n> <what>: one finished chain run, or a warning that it did not run
    local rc
    rc=$(cat "$STATE/chain-$1.rc" 2>/dev/null || echo "?")
    if [ -s "$STATE/chain-$1.txt" ]; then
        cat "$STATE/chain-$1.txt"
    else
        warn "chain run $1 produced NO OUTPUT -- this step did not run."
    fi
    [ "$rc" = "0" ] || warn "$2: expected rc 0, got rc $rc"
}
wait "$CHAIN_PID" 2>/dev/null
if [ "$CHAIN_PLAN" = "e" ]; then
    say "$CHAIN_LINE。"
    echo
    echo "  ${B}-- 原合約 examples/StakingVault.sol${R}"
    chain_out 1 "original contract (expected PROVEN)"
    echo
    echo "  ${B}-- 同一個參考攻擊，打 arbiter-gpt 的修補（$REPLAY_RUN）${R}"
    chain_out 2 "patched contract (expected NOT PROVEN)"
    echo
    say "這一步沒有作弊碼：要當誰就要有私鑰，要花錢就要有餘額，要上鏈就付 gas。攻擊是參考攻擊，修補是 AI 產生的。"
else
    echo "  ${B}【換了合約：WithdrawalQueue（不是 StakingVault）。這段鏈上攻擊是事先寫好的參考攻擊，不是 AI 這次產生的】${R}"
    chain_out 1 "WithdrawalQueue original (expected PROVEN)"
    chain_out 2 "WithdrawalQueue patched (expected NOT PROVEN)"
    say "這裡換成另一個合約 WithdrawalQueue，攻擊一樣是事先寫好的參考攻擊，不是 AI 這次產生的。"
fi
echo "  ${D}（鏈上兩向從第 2 段開始在背景跑，共 $(since "$CHAIN_T0") 秒）${R}"
seg_end
pause

# =========================================================================================
seg "第 4 段  3:20–4:20  修補燈號" "修補 diff；修補閘門逐項打勾；修補前後的 A/B/G" 60
if [ -n "$SAVED" ]; then
    echo "  分頁 3（結果頁）往下：修補前後、修補閘門的燈號"
    echo
    show summary patch "$SAVED"
fi
say "同一招在 4 個環境都失效、沒攻擊時受害者取回不少於修補前；編譯不過不算失效。"
say "通過的意思是「針對這個攻擊」通過驗證，不代表合約已經沒有漏洞；修補仍需要人工審查。"
seg_end
pause

# =========================================================================================
seg "第 5 段  4:20–5:10  PR 分頁（紅轉綠、SARIF）" "部署前的閘門：證實可攻擊就擋合併；套用修補後重新稽核才放行" 50
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$BASE/github")
shots=$(ls webassets/github/*.png 2>/dev/null | wc -l)
echo "  分頁 4：$BASE/github（HTTP $code，本機截圖 $shots 張；2026-10-30 在公開示範 repo 的實際紀錄）"
echo "  有網路時：$DEMO_REPO/pull/1（PR #1 是決賽的紅轉綠，不合併、不推 commit、不重跑）"
if [ -n "$CACHE_RID" ]; then
    if curl -s --max-time 10 -o "$STATE/demo.sarif" "$BASE/result/$CACHE_RID/report.sarif" && [ -s "$STATE/demo.sarif" ]; then
        echo "  結果頁「下載區」的 report.sarif（同一份錄製紀錄）："
        show summary sarif "$SAVED" "$STATE/demo.sarif"
        if [ -x "$VENV_PY" ]; then
            python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["report"], open(sys.argv[2], "w"))' \
                "$SAVED" "$STATE/demo.gate.json"
            "$VENV_PY" scripts/sarif_validate.py "$STATE/demo.sarif" "$STATE/demo.gate.json" 2>&1 \
                | sed -E 's/^[[:space:]]*/    schema    /'
        fi
    else
        warn "report.sarif did not download"
    fi
fi
say "第一個 commit 紅燈：AI 證實了重入攻擊，留言附 A/B/G、回歸測試和修補 suggestion；套用修補的 commit 綠燈。"
say "綠燈只代表新 commit「未發現可證明攻擊（不等於安全）」。落後超過 20 秒就只看紅轉綠，跳過 SARIF。"
seg_end
pause

# =========================================================================================
seg "第 6 段  5:10–6:00  判定用語、收尾" "結果頁底部的說明；5:45 硬停，回到一句話介紹" 50
python3 - <<'PY'
from arbiter.verdict import LABELS
for k, v in LABELS.items():
    print(f"    {v}  ({k})")
print("    未涵蓋  （PR 改到函式外、或只刪除程式碼：系統沒有審，不算任何一種判定）")
PY
say "沒找到不等於安全，我們只說證明了什麼。只收自有程式碼，forge 與 anvil 在不對外連線的沙箱裡跑。"
say "（5:45）一句話介紹，交給評審提問。"
seg_end
pause

# =========================================================================================
seg "問答  揭曉現場上傳（D6）" "不在 6 分鐘裡"
if [ -n "$LIVE" ]; then
    waited=$(since "$UPLOAD_T0")
    echo "  現場上傳已經過 ${waited} 秒（P8 主設定 10 次：結果頁出現在 112～303 秒，arbiter-gpt）。"
    if [ -n "$LIVE_UPLOAD" ]; then
        if [ -s "$STATE/live_upload.out" ]; then
            echo "  結果頁：$(head -1 "$STATE/live_upload.out")（共 $(sed -n 2p "$STATE/live_upload.out") 秒）"
        else
            echo "  還沒跑完；工作頁：$(cat "$STATE/live_upload.job" 2>/dev/null)，完成後結果網址會寫進 ${STATE#"$RIG"/}/live_upload.out"
        fi
    else
        echo "  回到分頁 1 跳出去的那個工作頁：跑完會自己跳到結果頁。"
    fi
    say "證實了：照第 2～4 段講。沒證實：照實顯示，「未發現可證明攻擊（不等於安全）」只代表這次 AI 沒寫出能在 EVM 上成立的攻擊。"
    say "StakingVault 這類沒證實時常顯示「靜態工具提示但未證實」：那是掃描工具的提示，不是證據。P8：10 次中 6 次證實。"
else
    [ -n "$LIVE_SKIPPED" ] && echo "  現場上傳已跳過：第 0 段的 api_smoke 失敗。"
    say "「已證實可攻擊」附可重跑的證據；其他判定都不代表合約沒有漏洞。"
fi
seg_end

# -- timing summary --------------------------------------------------------------------------
echo
echo "  ${B}耗時（程式本身，不含暫停與講話）${R}"
lines=""; show_total=0; budget_total=0; over=""
for i in "${!SEG_NAMES[@]}"; do
    printf '    %7s s  （12.4 預算 %4s s）  %s\n' "${SEG_SECS[$i]}" "${SEG_BUDGETS[$i]}" "${SEG_NAMES[$i]}"
    lines+="${SEG_NAMES[$i]}"$'\t'"${SEG_SECS[$i]}"$'\t'"${SEG_BUDGETS[$i]}"$'\n'
    if [ "${SEG_BUDGETS[$i]}" != "-" ]; then
        show_total=$(awk -v a="$show_total" -v b="${SEG_SECS[$i]}" 'BEGIN{printf "%.1f", a+b}')
        budget_total=$((budget_total + SEG_BUDGETS[$i]))
        awk -v s="${SEG_SECS[$i]}" -v b="${SEG_BUDGETS[$i]}" 'BEGIN{exit !(s>b)}' && over="$over ${SEG_NAMES[$i]%%  *}"
    fi
done
wall=$(awk -v a="$WALL_T0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.1f", b-a}')
printf '    %7s s  %s\n' "$show_total" "6 分鐘內各段的程式時間合計（第 1～6 段）"
printf '    %7s s  %s\n' "$budget_total" "12.4 的 6 分鐘預算（第 1～6 段）"
if [ -n "$over" ]; then
    echo "    超過預算的段：$over"
else
    echo "    每一段的程式時間都在 12.4 的預算內"
fi
printf '    %7s s  %s\n' "$wall" "含 preflight、暫停的總時間"
if [ -n "$TIMINGS" ]; then
    { printf '%s' "$lines"; printf 'show_total\t%s\t%s\nwall_incl_pauses\t%s\t-\n' "$show_total" "$budget_total" "$wall"; } >"$TIMINGS"
fi
