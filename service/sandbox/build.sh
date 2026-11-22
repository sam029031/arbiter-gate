#!/usr/bin/env bash
# Build the ARBITER sandbox image from this machine's verified toolchain.
#
#   python3 service/sandbox/fetch_solc.py   -> ~/.svm gets every solc in solc.lock (verified)
#   service/sandbox/build.sh                -> image arbiter-sandbox:me1 (+ host copy of /opt/soldeps)
#   ARBITER_SANDBOX_IMAGE=<tag> service/sandbox/build.sh   -> the same under another tag
#
# Copies forge/anvil/cast (Foundry 1.8.6) and every solc in solc.lock (0.6.12, 0.7.6 and
# 0.8.0 to 0.8.37) from the local install into a temporary build context. Each solc must
# match the official sha256 recorded in solc.lock; then the sha256 of every tool goes to
# tools.lock, which is checked again inside the image. The only network use is during
# the build (apt, PyPI, git).
#
# Why every 0.8.x: the container has no network and a read-only root, so forge cannot
# install a compiler at audit time. The finals image (arbiter-sandbox:p3) carried only
# 0.8.20 and 0.8.37, so an exact pragma such as "pragma solidity 0.8.24;" ended as
# "Read-only file system (os error 30)" and an undetermined verdict. This script no
# longer builds p3 by default and refuses to overwrite it.
set -euo pipefail

IMAGE="${ARBITER_SANDBOX_IMAGE:-arbiter-sandbox:me1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RIG="$(cd "$HERE/../../arbiter" && pwd)"
FOUNDRY_VERSION="1.8.6"
SOLC_LOCK="$HERE/solc.lock"
SOLC_VERSIONS="$(awk '!/^#/ && NF {print $1}' "$SOLC_LOCK" | tr '\n' ' ')"

if [ "$IMAGE" = "arbiter-sandbox:p3" ] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "refusing to overwrite $IMAGE (the image the finals ran); pick another tag" >&2
    exit 1
fi

CTX="$(mktemp -d)"
trap 'rm -rf "$CTX"' EXIT
mkdir -p "$CTX/bin" "$CTX/svm"

for tool in forge anvil cast; do
    src="$(readlink -f "$(command -v "$tool")")"
    got="$("$src" --version | head -1)"
    case "$got" in *"$FOUNDRY_VERSION"*) ;; *) echo "$tool is not $FOUNDRY_VERSION: $got" >&2; exit 1 ;; esac
    cp "$src" "$CTX/bin/$tool"
done
for v in $SOLC_VERSIONS; do
    src="$HOME/.svm/$v/solc-$v"
    [ -f "$src" ] || { echo "missing ~/.svm/$v/solc-$v (run service/sandbox/fetch_solc.py)" >&2; exit 1; }
    want="$(awk -v v="$v" '$1 == v {print substr($2, 3)}' "$SOLC_LOCK")"
    got="$(sha256sum "$src" | cut -d' ' -f1)"
    [ "$got" = "$want" ] || { echo "solc $v: sha256 $got but solc.lock says $want" >&2; exit 1; }
    mkdir -p "$CTX/svm/$v"
    cp "$src" "$CTX/svm/$v/solc-$v"
done
echo "solc: $(echo "$SOLC_VERSIONS" | wc -w) versions, each matching the official sha256 in solc.lock"
cp "$RIG/scripts/build_dep_cache.sh" "$CTX/"
cp "$HERE/Dockerfile" "$HERE/slither-constraints.txt" "$CTX/"

# Paths as they will be inside the image.
( cd "$CTX" && {
    for tool in forge anvil cast; do printf '%s  usr/local/bin/%s\n' "$(sha256sum "bin/$tool" | cut -d' ' -f1)" "$tool"; done
    for v in $SOLC_VERSIONS; do printf '%s  opt/svm/%s/solc-%s\n' "$(sha256sum "svm/$v/solc-$v" | cut -d' ' -f1)" "$v" "$v"; done
  } > tools.lock )
echo "tools.lock:"; sed 's/^/  /' "$CTX/tools.lock"

t0=$(date +%s)
docker build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" -t "$IMAGE" "$CTX"
echo "docker build: $(( $(date +%s) - t0 )) s"
docker image inspect "$IMAGE" --format 'image {{.RepoTags}} {{.Id}} size {{.Size}} bytes'

# The host resolves imports (arbiter/repo.py) against the same library files the image
# carries: export /opt/soldeps to the host cache. A sandboxed job then gets a copy inside
# its own directory (repo.localize_dep_cache), the only path its container can see.
# A host cache identical to the export is kept; a different one is moved aside, never
# deleted (uniswap-v2-periphery is cloned at master, so two builds can differ).
DEST="${ARBITER_DEP_CACHE:-$HOME/soldeps}"
cid="$(docker create "$IMAGE")"
rm -rf "$DEST.new"
docker cp -q "$cid:/opt/soldeps" "$DEST.new"
docker rm -f "$cid" >/dev/null
if [ -d "$DEST" ] && diff -rq "$DEST" "$DEST.new" >/dev/null 2>&1; then
    rm -rf "$DEST.new"
    echo "host dependency cache identical to the image's: kept ($(ls "$DEST" | wc -l) packages)"
else
    if [ -e "$DEST" ]; then
        prev="$DEST.prev-$(date +%Y%m%d-%H%M%S)"
        mv "$DEST" "$prev"
        echo "host dependency cache differed from the image's: moved to $prev"
    fi
    mv "$DEST.new" "$DEST"
    echo "dependency cache exported to the host: $(ls "$DEST" | wc -l) packages"
fi
