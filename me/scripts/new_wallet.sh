#!/usr/bin/env bash
# Create a testnet-only Foundry keystore for ME Network and print both address forms.
#
#   bash me/scripts/new_wallet.sh [name]      (default name: me-testnet)
#
# - You type the keystore password yourself (hidden prompt). The private key is generated and
#   encrypted by `cast`; this script never prints or stores it in clear text.
# - Use this wallet for ME testnet only. Fund it at https://www.mec.me/zh-TW/faucet with the
#   me1... address printed below (2 MEC per address per day).
set -euo pipefail
NAME="${1:-me-testnet}"
export PATH="$HOME/.foundry/bin:$PATH"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KS="$HOME/.foundry/keystores"
mkdir -p "$KS"
chmod 700 "$KS"

if [ -e "$KS/$NAME" ]; then
  echo "keystore '$NAME' already exists; reading its address (type its password)."
  ADDR="$(cast wallet address --account "$NAME")"
else
  echo "Creating keystore '$NAME' in $KS — choose a password and keep it yourself."
  OUT="$(cast wallet new "$KS" "$NAME")"
  ADDR="$(printf '%s\n' "$OUT" | grep -oE '0x[0-9a-fA-F]{40}' | head -1)"
fi

ME1="$(python3 "$HERE/arbiter_me/bech32.py" "$ADDR")"
cat <<EOF

  keystore : $NAME   ($KS/$NAME)
  EVM 0x   : $ADDR
  ME  me1  : $ME1

Next:
  1. Faucet: https://www.mec.me/zh-TW/faucet  -> paste the me1 address above (needs your testnet ME ID).
  2. Check the balance:  python3 me/me.py wallet balance $ADDR
  3. Run the live demo:  bash me/scripts/me_live_demo.sh $NAME
EOF
