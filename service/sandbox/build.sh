#!/usr/bin/env bash
# Build the ARBITER sandbox image from this machine's verified toolchain.
#
#   service/sandbox/build.sh            -> image arbiter-sandbox:p3 (+ host copy of /opt/soldeps)
#
# Copies forge/anvil/cast (Foundry 1.8.6) and solc 0.8.20 / 0.8.37 from the local install
# into a temporary build context, writes their sha256 to tools.lock (checked again inside
# the image), and builds. The only network use is during the build (apt, PyPI, git).
set -euo pipefail

IMAGE="${ARBITER_SANDBOX_IMAGE:-arbiter-sandbox:p3}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RIG="$(cd "$HERE/../../arbiter" && pwd)"
FOUNDRY_VERSION="1.8.6"
SOLC_VERSIONS="0.8.20 0.8.37"

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
    mkdir -p "$CTX/svm/$v"
    cp "$HOME/.svm/$v/solc-$v" "$CTX/svm/$v/solc-$v"
done
cp "$RIG/scripts/build_dep_cache.sh" "$CTX/"
cp "$HERE/Dockerfile" "$CTX/"

# Paths as they will be inside the image.
( cd "$CTX" && {
    for tool in forge anvil cast; do printf '%s  usr/local/bin/%s\n' "$(sha256sum "bin/$tool" | cut -d' ' -f1)" "$tool"; done
    for v in $SOLC_VERSIONS; do printf '%s  opt/svm/%s/solc-%s\n' "$(sha256sum "svm/$v/solc-$v" | cut -d' ' -f1)" "$v" "$v"; done
  } > tools.lock )
echo "tools.lock:"; sed 's/^/  /' "$CTX/tools.lock"

docker build --build-arg UID="$(id -u)" --build-arg GID="$(id -g)" -t "$IMAGE" "$CTX"
docker image inspect "$IMAGE" --format 'image {{.RepoTags}} {{.Id}} size {{.Size}} bytes'

# The host resolves imports (arbiter/repo.py) against the same library files the image
# carries: export /opt/soldeps to the host cache. A sandboxed job then gets a copy inside
# its own directory (repo.localize_dep_cache), the only path its container can see.
DEST="${ARBITER_DEP_CACHE:-$HOME/soldeps}"
cid="$(docker create "$IMAGE")"
rm -rf "$DEST.new"
docker cp -q "$cid:/opt/soldeps" "$DEST.new"
docker rm -f "$cid" >/dev/null
rm -rf "$DEST" && mv "$DEST.new" "$DEST"
echo "dependency cache exported to the host: $(ls "$DEST" | wc -l) packages"
