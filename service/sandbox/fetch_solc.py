#!/usr/bin/env python3
"""Put the official static solc builds the sandbox image carries into ~/.svm.

    python3 service/sandbox/fetch_solc.py            # fetch what is missing, verify all
    python3 service/sandbox/fetch_solc.py --check    # verify only, download nothing

Why: the sandbox runs with --network none and a read-only root, so forge cannot install a
compiler at audit time. A contract pinned to an exact version the image lacks ("pragma
solidity 0.8.24;") used to end as "Read-only file system (os error 30)" and an
undetermined verdict. build.sh copies every version listed in solc.lock from ~/.svm into
the image; this script fills ~/.svm from binaries.soliditylang.org.

Trust: every file's sha256 is checked against the official list.json from the same host
before it is installed, and against solc.lock (the hashes recorded when the list was
first chosen) when solc.lock already names the version. A mismatch is refused and
nothing is written. An existing ~/.svm/<v>/solc-<v> is never overwritten; it is verified
the same way. Standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

BASE = "https://binaries.soliditylang.org/linux-amd64/"
HERE = Path(__file__).resolve().parent
LOCK = HERE / "solc.lock"
SVM = Path(os.environ.get("SVM_HOME", Path.home() / ".svm"))
# 0.6.12 and 0.7.6 are the last releases of their lines (the corpus spans 0.6 to 0.8);
# every 0.8.x up to 0.8.37. Not 0.8.38+: auto-detection picks the highest installed
# version, and the harness was measured with 0.8.37, so adding a newer one would change
# which compiler every caret pragma gets.
VERSIONS = ["0.6.12", "0.7.6"] + [f"0.8.{i}" for i in range(38)]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return "0x" + h.hexdigest()


def read_lock() -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    if LOCK.exists():
        for line in LOCK.read_text(encoding="utf-8").splitlines():
            if line.strip() and not line.startswith("#"):
                v, sha, keccak, name = line.split()
                out[v] = {"sha256": sha, "keccak256": keccak, "path": name}
    return out


def write_lock(builds: dict[str, dict[str, str]]) -> None:
    rows = ["# solc builds the ARBITER sandbox image carries (service/sandbox/build.sh).",
            "# Source: " + BASE + "list.json; sha256 verified on download (fetch_solc.py)",
            "# and again by build.sh before the image is built.",
            "# version  sha256  keccak256  list.json path"]
    rows += [f"{v} {builds[v]['sha256']} {builds[v]['keccak256']} {builds[v]['path']}"
             for v in VERSIONS]
    LOCK.write_text("\n".join(rows) + "\n", encoding="utf-8")


def fetch(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "solc-fetch"})
    with urllib.request.urlopen(req, timeout=120) as resp, dest.open("wb") as fh:  # noqa: S310
        while chunk := resp.read(1 << 20):
            fh.write(chunk)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify only; download nothing")
    args = ap.parse_args()

    staging = Path(tempfile.mkdtemp(prefix="solc-fetch-"))
    fetch(BASE + "list.json", staging / "list.json")
    listing = json.loads((staging / "list.json").read_text(encoding="utf-8"))
    official = {b["version"]: b for b in listing["builds"]
                if not b.get("prerelease") and listing["releases"].get(b["version"]) == b["path"]}
    locked = read_lock()
    builds: dict[str, dict[str, str]] = {}
    bad = 0
    for v in VERSIONS:
        b = official.get(v)
        if b is None:
            print(f"  REFUSE {v}: not a release in list.json")
            bad += 1
            continue
        want = b["sha256"].lower()
        if v in locked and locked[v]["sha256"] != want:
            print(f"  REFUSE {v}: list.json says {want}, solc.lock says {locked[v]['sha256']}")
            bad += 1
            continue
        builds[v] = {"sha256": want, "keccak256": b["keccak256"].lower(), "path": b["path"]}
        target = SVM / v / f"solc-{v}"
        if target.exists():
            got = sha256(target)
            state = "have  " if got == want else "MISMATCH"
            bad += got != want
            print(f"  {state} {v} {got}")
            continue
        if args.check:
            print(f"  MISSING {v}")
            bad += 1
            continue
        tmp = staging / b["path"]
        fetch(BASE + b["path"], tmp)
        got = sha256(tmp)
        if got != want:
            print(f"  REFUSE {v}: downloaded {got}, expected {want}")
            bad += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        part = target.with_name(target.name + ".part")
        part.write_bytes(tmp.read_bytes())
        part.chmod(0o755)
        if target.exists():  # appeared meanwhile: keep it, never overwrite
            part.unlink()
        else:
            os.link(part, target)
            part.unlink()
        (target.parent / ".lock").touch()
        tmp.unlink()
        print(f"  got   {v} {got} ({target.stat().st_size} bytes)")
    if not bad and not args.check:
        write_lock(builds)
        print(f"solc.lock: {len(builds)} versions")
    print(f"{len(builds)} of {len(VERSIONS)} verified, {bad} problems; staging {staging}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
