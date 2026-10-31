#!/usr/bin/env bash
# Runner-side driver for the ARBITER Gate GitHub Action (.github/actions/arbiter-gate).
#
#   scripts/gate_pr.sh audit <checkout> <base-sha> <head-sha> <out-dir> [run-url]
#   scripts/gate_pr.sh fork  -          <base-sha> <head-sha> <out-dir> [run-url]
#
# Writes <out-dir>/{gate.json,report.sarif,comment.md} (and regression/ when a proven
# finding has one), appends the comment to $GITHUB_STEP_SUMMARY, prints a short summary
# and exits with the gate's code: 1 block, 2 not executed (not a pass, not a finding),
# 0 pass. The PR comment is posted by scripts/gate_pr_publish.py, a separate step.
#
# The Actions log of a public repository is public, so this script prints verdict labels
# and counts only. The gate's own output (paths of this host, model endpoint) goes to a
# log under runs/gate-pr/logs/ on the runner host. No `set -x`, no environment dumps.
#
# Runner-host settings come from the environment the action sourced from the runner's
# config file (never from GitHub secrets):
#   ARBITER_DOTENV               the .env with the model endpoint / key (sourced here)
#   ARBITER_GATE_BLOCK_PATTERN   optional; if `pgrep -f` matches it (the pre-registered
#                                evaluation is using the model server), the gate runs with
#                                --llm-blocked: no model request, files that need an audit
#                                are "not executed"
set -u

mode="${1:?mode}"; repo="${2:?checkout}"; base="${3:?base}"; head="${4:?head}"
out="${5:?out-dir}"; run_url="${6:-}"
ARB="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
logs="$ARB/runs/gate-pr/logs"
mkdir -p "$logs"
hostlog="$logs/$(date +%Y%m%d-%H%M%S)-${head:0:12}.log"
export PATH="$HOME/.foundry/bin:$PATH"

summary() {
  # Labels and counts from gate.json only; nothing that carries a path.
  python3 - "$out/gate.json" <<'EOF'
import json, sys
g = json.load(open(sys.argv[1], encoding="utf-8"))
pr = g.get("pr") or {}
print(f"ARBITER Gate exit code {g.get('exit_code')}")
for e in g.get("files") or []:
    uri = (e.get("artifact") or {}).get("uri")
    print(f"  {e.get('label')}  {uri}")
if pr.get("refused"):
    print(f"  {pr['refused']['label']}")
skipped = {s.get("path") for s in pr.get("skipped") or []}
print(f"  touched functions: {sum(len(v) for p, v in (pr.get('touched') or {}).items() if p not in skipped)}, "
      f"uncovered: {len(pr.get('unscanned') or [])}, skipped: {len(pr.get('skipped') or [])}")
for e in g.get("files") or []:
    for fd in e.get("findings") or []:
        p = fd.get("patch") or {}
        rt, ra = p.get("repo_tests") or {}, p.get("reattack") or {}
        if p.get("gate_checks"):
            print("  patch gate: " + " ".join(f"{k}:{v}" for k, v in p["gate_checks"].items()))
        if rt.get("before_passed") is not None:
            print(f"  project tests (check 4): {rt['before_passed']} passed before the patch, "
                  f"{rt.get('after_passed')} after")
        if ra.get("attacks"):
            print(f"  re-attack (check 5): {ra.get('status')}, {ra.get('attacks')} attack(s), "
                  f"{ra.get('requests')} request(s), {ra.get('elapsed_s')} s")
rr = (pr.get("regression_rerun") or {}).get("status")
if rr and rr != "absent":
    print(f"  TestArbiterRegression: {rr}")
inp = g.get("input") or {}
print(f"  model requests: {inp.get('llm_requests_this_invocation')}, "
      f"sandbox: {(inp.get('sandbox') or {}).get('status')}")
EOF
}

finish() {
  local rc="$1"
  [ -s "$out/comment.md" ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ] && cat "$out/comment.md" >> "$GITHUB_STEP_SUMMARY"
  [ -s "$out/gate.json" ] && summary
  echo "rc=$rc"
  exit "$rc"
}

refuse() {
  # A gate.json / comment / SARIF for a run that did not happen: not executed, exit 2.
  local code="$1" label="$2" detail="$3"
  (cd "$ARB" && python3 - "$out" "$code" "$label" "$detail" "$base" "$head" <<'EOF'
import json, sys
from pathlib import Path
from arbiter.prgate import comment_markdown, refused_report
from arbiter.sarif import to_sarif
out, code, label, detail, base, head = sys.argv[1:7]
rep = refused_report(code, label, detail, base=base, head=head)
Path(out, "gate.json").write_text(json.dumps(rep, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
Path(out, "comment.md").write_text(comment_markdown(rep), encoding="utf-8")
sar = to_sarif(rep)
inv = sar["runs"][0]["invocations"][0]
inv["executionSuccessful"] = False
inv["toolExecutionNotifications"] = [{"level": "error", "message": {"text": f"無法判定（稽核未完成）：{label}"}}]
Path(out, "report.sarif").write_text(json.dumps(sar, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
EOF
  ) >>"$hostlog" 2>&1
  finish 2
}

if [ "$mode" = fork ]; then
  (cd "$ARB" && python3 -m arbiter.prgate refuse-fork --out "$out/gate.json" \
     --comment "$out/comment.md" --sarif "$out/report.sarif" --base "$base" --head "$head") >>"$hostlog" 2>&1
  finish 2
fi
[ "$mode" = audit ] || { echo "unknown mode"; exit 64; }

mb="$(git -C "$repo" merge-base "$base" "$head" 2>>"$hostlog")" || \
  refuse pr_input "讀不到這個 PR 的基準 commit。" "git merge-base 失敗；checkout 需要 fetch-depth: 0。"

if ! git -C "$repo" diff --name-only "$mb" "$head" 2>>"$hostlog" | grep -q '\.sol$'; then
  # Nothing for the gate: no comment, a pass. The workflow runs on every PR (a required
  # check that never runs would block merging), the audit only when .sol files changed.
  echo "這個 PR 沒有動到 .sol 檔，ARBITER Gate 沒有執行稽核。"
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] && echo "這個 PR 沒有動到 .sol 檔，ARBITER Gate 沒有執行稽核。" >> "$GITHUB_STEP_SUMMARY"
  echo "rc=0"
  exit 0
fi

if [ -n "${ARBITER_DOTENV:-}" ] && [ -r "$ARBITER_DOTENV" ]; then
  set -a; . "$ARBITER_DOTENV"; set +a
else
  refuse runner_config "runner 主機沒有模型端點設定。" "runner 主機的 .env 不存在或讀不到；這是 runner 的設定問題，不是合約的問題。"
fi

blocked=()
if [ -n "${ARBITER_GATE_BLOCK_PATTERN:-}" ] && pgrep -f -- "$ARBITER_GATE_BLOCK_PATTERN" >/dev/null 2>&1; then
  # Scope, uncovered changes and the regression re-run still run; any file that would
  # need the model is "not executed" (exit 2) and no request is sent.
  blocked=(--llm-blocked "模型伺服器正在跑預先登記的評測（runner 主機的共用規則：評測進行中不送 AI 請求）；評測結束後重新執行這個檢查即可")
fi

(cd "$ARB" && python3 -m arbiter.gate "${blocked[@]}" --repo "$repo" --base "$mb" --head "$head" \
   --sandbox on --repair --workdir runs/gate-pr \
   --out "$out/gate.json" --sarif "$out/report.sarif" --pr-comment "$out/comment.md" \
   --regression-out "$out/regression" --run-url "$run_url") >>"$hostlog" 2>&1
rc=$?
if [ ! -s "$out/comment.md" ] || [ ! -s "$out/gate.json" ]; then
  refuse gate_crashed "ARBITER Gate 本身沒有跑完（程式錯誤），所以沒有結論。" \
    "錯誤紀錄留在 runner 主機上（不公開）。這不是發現漏洞，也不算通過。"
fi
finish "$rc"
