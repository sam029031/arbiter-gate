#!/usr/bin/env bash
# The ARBITER Gate finals demo (11/7), as one command. scripts/demo.sh is the AIS3-era
# demo and is kept unchanged; this one walks the gate: web page, recorded proof, chain.
#
#   scripts/demo_gate.sh                   pause between segments, press Enter to go on
#   scripts/demo_gate.sh --auto            fixed pauses (for a recording)
#   scripts/demo_gate.sh --live            add segment 1: upload StakingVault.sol in the
#                                          browser first, look at it again in segment 4
#   scripts/demo_gate.sh --live --live-upload
#                                          segment 1 sends the same multipart upload with
#                                          curl instead of a person (rehearsal / recording)
#   --timings FILE                         also write per-segment seconds as TSV
#   --pause N                              seconds per pause with --auto (default 6)
#
# Segments 0, 2 and 3 make no LLM request except api_smoke in segment 0. A failed
# api_smoke only warns: the recorded result and the chain need no model.
#
# The page runs ONE gate job at a time. A live upload holds that slot for 2-8 minutes, and
# a "看結果" click on a recorded run would wait behind it. So segment 0 renders the
# spark-test-2 page BEFORE segment 1 starts, and segment 2 only prints its address.
set -u

AUTO=""; LIVE=""; LIVE_SKIPPED=""; LIVE_UPLOAD=""; TIMINGS=""; PAUSE=6
PORT=8765
while [ $# -gt 0 ]; do
    case "$1" in
        --auto) AUTO=1; shift ;;
        --live) LIVE=1; shift ;;
        --live-upload) LIVE_UPLOAD=1; shift ;;
        --timings) TIMINGS="$2"; shift 2 ;;
        --pause) PAUSE="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
if [ -n "$LIVE_UPLOAD" ] && [ -z "$LIVE" ]; then
    echo "--live-upload needs --live" >&2; exit 2
fi

RIG="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$RIG" || exit 1
BASE="http://127.0.0.1:$PORT"
REPLAY_RUN="spark-test-2"
TARGET="$RIG/examples/StakingVault.sol"
STATE="$RIG/runs/gate/demo"          # runs/gate/ is ignored by git
mkdir -p "$STATE"

B=$(printf '\033[1m'); D=$(printf '\033[2m'); Y=$(printf '\033[33m'); R=$(printf '\033[0m')

# -- timing: each segment's own seconds, pauses excluded ----------------------------------
SEG_NAMES=(); SEG_SECS=(); SEG_T0=""
WALL_T0=$EPOCHREALTIME

seg() {   # seg "<title>" "<one-line point>"
    SEG_T0=$EPOCHREALTIME
    SEG_NAMES+=("$1")
    printf '\n%s%s\n  %s\n%s%s\n' "$B" "$(printf '=%.0s' $(seq 74))" "$1" \
        "$(printf '=%.0s' $(seq 74))" "$R"
    [ -n "${2:-}" ] && printf '%s  %s%s\n' "$D" "$2" "$R"
    echo
}

seg_end() {
    local s
    s=$(awk -v a="$SEG_T0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.1f", b-a}')
    SEG_SECS+=("$s")
    printf '\n%s  (this segment: %s s)%s\n' "$D" "$s" "$R"
}

pause() {
    if [ -n "$AUTO" ]; then
        local n="$PAUSE"
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

# =========================================================================================
seg "第 0 段  前置檢查" "通道、工具、網頁；先把預錄結果頁產生好"

if [ -f "$RIG/../.env" ]; then
    set -a; source "$RIG/../.env"; set +a
    echo "  .env       loaded (model: ${ARBITER_MODEL:-${AIS3_MODEL:-?}}, endpoint: ${ARBITER_BASE_URL:-${AIS3_BASE_URL:-?}})"
else
    warn ".env not found at $RIG/../.env -- api_smoke and the live upload will fail"
fi

LLM_OK=""
t0=$EPOCHREALTIME
if smoke=$(timeout 90 python3 scripts/api_smoke.py 2>&1); then
    LLM_OK=1
    echo "  api_smoke  $(printf '%s\n' "$smoke" | head -1) ($(awk -v a="$t0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.1f", b-a}') s)"
else
    warn "api_smoke FAILED after $(awk -v a="$t0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.0f", b-a}') s (DGX Spark / SSH tunnel?): $(printf '%s\n' "$smoke" | tail -1 | cut -c1-120)"
    warn "continuing: segments 2 and 3 need no LLM. Skip segment 1."
fi

MISSING=""
for tool in forge anvil cast; do
    if p=$(command -v "$tool"); then
        echo "  $(printf '%-10s' "$tool") $p"
    else
        warn "$tool is not on PATH"; MISSING="$MISSING $tool"
    fi
done

web_up() { [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "$BASE/")" = "200" ]; }
if web_up; then
    echo "  web        already running at $BASE/ (reused)"
else
    nohup python3 -m arbiter.web --port "$PORT" >"$STATE/web.server.log" 2>&1 &
    WEB_PID=$!
    disown "$WEB_PID" 2>/dev/null || true
    for _ in $(seq 20); do web_up && break; sleep 0.5; done
    if web_up; then
        echo "  web        started at $BASE/ (pid $WEB_PID, log $STATE/web.server.log; left running)"
    else
        warn "web did not come up; see $STATE/web.server.log"
    fi
fi

# Render the recorded page now, while the page's single job slot is free.
REPLAY_URL=""; REPLAY_RID=""
if [ ! -f "runs/$REPLAY_RUN.results.jsonl" ]; then
    warn "runs/$REPLAY_RUN.results.jsonl is missing -- no recorded result to show"
elif web_up; then
    t0=$EPOCHREALTIME
    REPLAY_URL=$(curl -s -o /dev/null -w '%{redirect_url}' --max-time 600 \
        --data "run_id=$REPLAY_RUN" "$BASE/replay")
    secs=$(awk -v a="$t0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.1f", b-a}')
    REPLAY_RID="${REPLAY_URL##*/result/}"
    if [[ "$REPLAY_RID" =~ ^[0-9a-f]{12}$ ]]; then
        echo "  recorded   $REPLAY_RUN re-adjudicated by the page in ${secs} s (forge, 0 LLM requests)"
        echo "             $REPLAY_URL"
    else
        warn "the page did not render $REPLAY_RUN (${secs} s): '${REPLAY_URL}'"
        REPLAY_URL=""; REPLAY_RID=""
    fi
fi
seg_end
pause

# =========================================================================================
UPLOAD_T0=""
if [ -n "$LIVE" ]; then
    seg "第 1 段  即時稽核（背景執行）" "上傳後就去講別的，第 4 段再回來看"
    UPLOAD_T0=$EPOCHREALTIME
    if [ -z "$LLM_OK" ]; then
        warn "api_smoke failed in segment 0 -- SKIPPED, nothing uploaded (runbook: 備案 1)"
        say "模型主機現在連不上，即時稽核這段跳過；後面的預錄與真鏈都不需要模型。"
        LIVE=""; LIVE_SKIPPED=1
    elif [ -n "$LIVE_UPLOAD" ]; then
        rm -f "$STATE/live_upload.url" "$STATE/live_upload.time"
        ( curl -s -o /dev/null -w '%{redirect_url}\n%{time_total}\n' --max-time 960 \
              -F "contract=@$TARGET" "$BASE/upload" >"$STATE/live_upload.out" 2>&1 ) &
        echo "  sent the browser's multipart upload with curl (pid $!): $TARGET"
    else
        echo "  1. 瀏覽器開 $BASE/"
        echo "  2. 「上傳合約即時稽核」選這個檔案，按「開始稽核」："
        echo "       $TARGET"
        command -v wslpath >/dev/null && echo "       （Windows 路徑：$(wslpath -w "$TARGET")）"
        echo "  3. 這個分頁會停在載入中，2～8 分鐘後自己跳到結果頁。不要關、不要重新整理。"
    fi
    if [ -n "$LIVE" ]; then
        say "這一次是真的呼叫模型，大約 2 到 8 分鐘；我們先看錄好的結果，最後再回來看它。"
        say "等待時不要按首頁其他「看結果」：網頁一次只跑一個工作，會排在即時稽核後面。"
    fi
    seg_end
    pause
fi

# =========================================================================================
seg "第 2 段  預錄結果（$REPLAY_RUN）" "判定、A/B/G、修補 diff"
if [ -n "$REPLAY_URL" ]; then
    echo "  在瀏覽器打開：$REPLAY_URL"
    echo
    show python3 - "$RIG/runs/gate/web/$REPLAY_RID.json" <<'PY'
import json, sys
saved = json.load(open(sys.argv[1], encoding="utf-8"))
rep = saved["report"]
eth = lambda w: "?" if w is None else f"{w / 10**18:g}"
abg = lambda envs: "、".join(f"{eth(e.get('A'))}/{eth(e.get('B'))}/{eth(e.get('G'))}" for e in envs)
print("  頁面上的內容（同一份 gate.json；瀏覽器打不開時就念這裡）：")
print(f"    模型      {'、'.join(rep.get('models') or [])}；"
      f"本次 LLM 請求 {rep.get('input', {}).get('llm_requests_this_invocation')}")
for fl in rep.get("files", []):
    print(f"    判定      {fl.get('label')}")
    for f in fl.get("findings", []):
        a = f.get("abg") or {}
        p = f.get("patch") or {}
        print(f"    謂詞      {f.get('predicate')}（strict={f.get('predicate_strict')}）")
        print(f"    A/B/G     {abg(a.get('environments') or []) or a.get('label')}  (ETH，4 個環境)")
        print(f"    修補      {p.get('label') or p.get('status')}，{p.get('changed_lines')} 行，"
              f"檢查 {' '.join(f'{k}:{v}' for k, v in (p.get('gate_checks') or {}).items())}")
        if p.get("after"):
            print(f"    修補後    {abg(p['after'])}")
PY
else
    warn "no recorded page was rendered in segment 0."
    echo "  備案：首頁 $BASE/ 的 $REPLAY_RUN 按「看結果」（約 1 分鐘以內；即時稽核在跑時會排隊）。"
fi
say "A 是沒有攻擊時受害者拿回多少，B 是有攻擊時拿回多少，G 是攻擊者賺多少。"
say "前三個環境模型的攻擊沒有讓受害者受損，第 4 個環境（8 輪）才 2/0/7，我們照實顯示。"
say "修補是 arbiter-gpt 產生的，經過 0→L→3→1→2 五道檢查，標示只說「針對此攻擊」通過。"
seg_end
pause

# =========================================================================================
seg "第 3 段  真鏈：同一個合約，真的交易" "anvil 兩條鏈：一條有 attack()，一條沒有"
if [ -n "$MISSING" ] && [[ "$MISSING" == *anvil* || "$MISSING" == *cast* || "$MISSING" == *forge* ]]; then
    warn "missing:$MISSING -- skip the chain (runbook: 備案 3，只看網頁預錄的 A/B/G)"
else
    say "鏈上的攻擊是 victim_probe.py 的 DRAIN：7/28 為了校正判定寫的已知參考攻擊，不是模型寫的。"
    echo
    echo "  ${B}-- 原合約 examples/StakingVault.sol${R}"
    show python3 scripts/live_attack_stakingvault.py --port 8600
    rc=$?
    [ $rc -ne 0 ] && warn "original contract: expected PROVEN (rc 0), got rc $rc"
    echo
    echo "  ${B}-- 同一個攻擊，打 arbiter-gpt 的修補（$REPLAY_RUN）${R}"
    show python3 scripts/live_attack_stakingvault.py --port 8610 --patched "$REPLAY_RUN"
    rc=$?
    [ $rc -ne 0 ] && warn "patched contract: expected NOT PROVEN (rc 0), got rc $rc"
    echo
    say "攻擊合約、帳戶、金額、交易都一樣，只差修補的那幾行。修補是 AI 產生的，攻擊是已知的參考攻擊。"
fi
seg_end
pause

# =========================================================================================
seg "第 4 段  收尾" ""
if [ -n "$LIVE" ]; then
    waited=$(awk -v a="$UPLOAD_T0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.0f", b-a}')
    echo "  即時稽核已經過 ${waited} 秒（10/28 repo 模式實測 125～465 秒）。"
    if [ -n "$LIVE_UPLOAD" ]; then
        if [ -s "$STATE/live_upload.out" ]; then
            echo "  結果頁：$(head -1 "$STATE/live_upload.out")（gate 共 $(sed -n 2p "$STATE/live_upload.out") 秒）"
        else
            echo "  還沒跑完；完成後網址會寫進 $STATE/live_upload.out"
        fi
    else
        echo "  回到第 1 段那個瀏覽器分頁：跑完會自己跳到結果頁。"
        echo "  分頁不見了的話，結果也會存在 runs/gate/web/（最新的「上傳檔案」那筆）。"
    fi
    say "已證實：看判定、A/B/G、模型修補。沒有證實：照實說，repo 模式累計 victim_loss 證實 9/15（10/28），改看剛才的預錄。"
    say "「未發現可證明攻擊」不等於安全：只代表這次模型沒寫出能在 EVM 上成立的攻擊。"
else
    [ -n "$LIVE_SKIPPED" ] && echo "  第 1 段（即時稽核）已跳過：segment 0 的 api_smoke 失敗。"
    say "「已證實可攻擊」附可重跑的證據；其他判定都不代表合約沒有漏洞。"
fi
seg_end

# -- timing summary --------------------------------------------------------------------------
total=0
echo
echo "  ${B}耗時（不含暫停）${R}"
lines=""
for i in "${!SEG_NAMES[@]}"; do
    printf '    %7s s  %s\n' "${SEG_SECS[$i]}" "${SEG_NAMES[$i]}"
    lines+="${SEG_NAMES[$i]}"$'\t'"${SEG_SECS[$i]}"$'\n'
    total=$(awk -v a="$total" -v b="${SEG_SECS[$i]}" 'BEGIN{printf "%.1f", a+b}')
done
wall=$(awk -v a="$WALL_T0" -v b="$EPOCHREALTIME" 'BEGIN{printf "%.1f", b-a}')
printf '    %7s s  %s\n' "$total" "合計（各段相加）"
printf '    %7s s  %s\n' "$wall" "含暫停的總時間"
if [ -n "$TIMINGS" ]; then
    { printf '%s' "$lines"; printf 'total\t%s\nwall_incl_pauses\t%s\n' "$total" "$wall"; } >"$TIMINGS"
fi
