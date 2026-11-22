#!/usr/bin/env bash
# ARBITER Gate × ME testnet: the live on-chain demonstration (run once, with your keystore).
#
#   bash me/scripts/me_live_demo.sh [keystore name]      (default: me-testnet)
#
# Inputs, from the environment (all optional; every input is checked before the first tx):
#   ME_DEMO_JOB    StakingVault audit: a job folder with gate.json, e.g. arbiter/runs/gate/jobs/<id>
#                  or just <id> (default: the 2026-11-06 recording)
#   ME_DEMO_RID    the web UI's saved copy of the same result (runs/gate/web/<rid>.json), so the
#                  result page shows the on-chain card (default: be2e752405bb, used only when it
#                  is the same gate.json)
#   me/dogfood/AuditRegistry.gate.json, me/dogfood/AuditEscrow.gate.json: our own contracts'
#                  audits; replace the files to record newer audits. A gate.json that audited
#                  another version of the source is refused (ME_DEMO_DOGFOOD=0 skips dogfood).
#   ME_EVIDENCE_BASE_ROOT  where me/evidence is published (default: the public GitHub copy);
#                  ME_EVIDENCE_BASE_URL (older) still names the staking-vault folder directly.
#
# What it does (each step is recorded in me/deployments/me-testnet.demo.json; rerunning the
# script skips finished steps, so it is safe to run again after an interruption):
#   0. checks chain id 400, the inputs and your MEC balance; prints the faucet link and your
#      me1 address if the balance is too low, and how much MEC the whole run needs at most
#   1a deploys AuditRegistry (plain CREATE: a registry cannot be deployed through itself)
#   1b registers ARBITER Gate's audit of AuditRegistry (we audited our own contract)
#   1c linkDeployment(1b, registry) -> LINK_CLAIMED, after showing that the registry's on-chain
#      codehash equals the compiled artifact's runtime hash
#   1d registers ARBITER Gate's audit of AuditEscrow (initcode includes the registry address)
#   1e deploys AuditEscrow through the registry (deployAudited -> LINK_GATED); every later step
#      uses this escrow. (If me/deployments/me-testnet.json exists from a run without these
#      steps, nothing is redeployed: the records are added and the existing escrow stays.)
#   2. escrow request (0.001 MEC, paid back to the same account when settled)
#   3. registers the proven StakingVault result (verdict 3); the registry refuses to deploy it,
#      and the refusal is sent as a reverting tx so it is visible on the explorer; the record
#      settles the escrow request
#   4. registers the patched StakingVault (verdict 1, parent = step 3) and deploys it through
#      the registry (CREATE2 at the predicted address, LINK_GATED)
#   5. writes me/EVIDENCE.md (every address and tx with explorer links and what it shows, and
#      when and by which code each gate.json was produced) and the web result page's sidecars
# 11 transactions; about 0.0010002 MEC including the 0.001 MEC fee that comes back.
# The keystore password is asked once (hidden). Nothing secret is printed or written.
set -euo pipefail
NAME="${1:-me-testnet}"
export PATH="$HOME/.foundry/bin:$PATH"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$HERE/.."

if [ ! -e "$HOME/.foundry/keystores/$NAME" ]; then
  echo "找不到 keystore '$NAME'。先建立錢包：bash me/scripts/new_wallet.sh $NAME"
  exit 2
fi

# Evidence bundles are written to me/evidence/staking-vault/{original,patched} and
# me/evidence/self/{registry,escrow}; the records point at their public copy (raw.githubusercontent
# serves it with CORS *, so the verify page can re-hash the files). Commit and push me/evidence/
# after this run so the links resolve. An older ME_EVIDENCE_BASE_URL (the staking-vault folder)
# still works on its own: self/ is then taken from the same parent folder.
if [ -z "${ME_EVIDENCE_BASE_ROOT+x}" ] && [ -z "${ME_EVIDENCE_BASE_URL:-}" ]; then
  export ME_EVIDENCE_BASE_ROOT="https://raw.githubusercontent.com/sam029031/arbiter-gate/me-hackathon/me/evidence"
fi

DEMO_ARGS=()
if [ -n "${ME_DEMO_JOB:-}" ]; then DEMO_ARGS+=(--job "$ME_DEMO_JOB"); fi
if [ -n "${ME_DEMO_RID:-}" ]; then DEMO_ARGS+=(--rid "$ME_DEMO_RID"); fi
if [ "${ME_DEMO_DOGFOOD:-1}" = "0" ]; then DEMO_ARGS+=(--no-dogfood); fi

python3 me/me.py preflight AuditRegistry --network me-testnet
python3 me/me.py preflight AuditEscrow --network me-testnet
python3 me/me.py demo --account "$NAME" --network me-testnet ${DEMO_ARGS[@]+"${DEMO_ARGS[@]}"}
echo
echo "完成。請把 me/EVIDENCE.md、me/deployments/me-testnet*.json、me/evidence/ 一起保存（可提交到 git）。"
echo "網頁結果頁會讀 arbiter/runs/gate/web/${ME_DEMO_RID:-be2e752405bb}.me.json 顯示鏈上紀錄。"
