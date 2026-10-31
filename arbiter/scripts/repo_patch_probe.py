#!/usr/bin/env python3
"""Repo-mode patching and check 4, both directions, with no LLM request.

A small Foundry project -- the vulnerable StakingVault (v3_authored V_reentrancy_unstake,
the same contract as the demo repository's PR #1) plus the project's own honest-user
tests -- and victim_probe's DRAIN exploit composed in REPO mode (it imports
arbiter-target/StakingVault.sol, as an exploit from `cli.py audit` or a PR does). Then:

  repo_fix        the human CEI fix                        -> accepted; check 4 pass
  breaks_tests    CEI fix that also stops updating         -> rejected by check 4 alone
                  totalStaked (the exploit fails, the        (0, L, 3, 1, 2 pass)
                  victim is paid, the ABI is unchanged)
  with_import     the target imports a project file         -> accepted; the copy builds
                  (./IStakingVault.sol)                       with the import resolved
  not_foundry     the same fix in a project with no         -> accepted; check 4 skipped
                  foundry.toml                                (never shown as a pass)
  untouched       the user's project files are byte-identical before and after
  sandbox_deps    (with --sandbox) a target importing OpenZeppelin and chainlink builds
                  in the per-job container, with the libraries copied into the job; and
                  without the copy it does not (the P3 gap this closes)

    python3 scripts/repo_patch_probe.py [--sandbox]
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import victim_probe as vp  # noqa: E402
from arbiter.patch import GATE_ORDER, reproduce, verify_fix  # noqa: E402
from arbiter.repo import localize_dep_cache, plan_for  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

V = vp.load("V_reentrancy_unstake")
S = vp.load("S_reentrancy_unstake")
REL = "src/StakingVault.sol"

FOUNDRY_TOML = """[profile.default]
src = "src"
test = "test"
out = "out"
libs = []
solc = "0.8.20"
"""

HONEST_TESTS = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/StakingVault.sol";

contract HonestUser {
    receive() external payable {}
    function stake(StakingVault vault) external payable { vault.stake{value: msg.value}(); }
    function unstake(StakingVault vault) external { vault.unstake(); }
}

contract StakingVaultHonestTest {
    StakingVault vault;

    function setUp() public { vault = new StakingVault{value: 5 ether}(); }

    function test_honest_user_gets_stake_back() public {
        HonestUser alice = new HonestUser();
        alice.stake{value: 2 ether}(vault);
        alice.unstake(vault);
        require(address(alice).balance == 2 ether, "alice did not get her 2 ether back");
        require(vault.totalStaked() == 5 ether, "totalStaked out of step");
    }

    function test_unstake_without_position_reverts() public {
        (bool ok, ) = address(vault).call(abi.encodeWithSignature("unstake()"));
        require(!ok, "unstake with no position should revert");
    }
}
"""

# Fixes the reentrancy (state cleared before the call) but forgets totalStaked: the
# exploit fails, the victim is paid in full, the ABI is the same -- only the project's
# own test notices.
BREAKS_TESTS = S.replace("        totalStaked -= amount;\n", "", 1)
assert BREAKS_TESTS != S

IMPORT_IFACE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStakingVault {
    function stake() external payable;
    function unstake() external;
}
"""


def with_import(src: str) -> str:
    return src.replace("pragma solidity ^0.8.20;\n",
                       'pragma solidity ^0.8.20;\n\nimport "./IStakingVault.sol";\n', 1)


def make_project(root: Path, source: str, *, foundry: bool = True, iface: bool = False) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "test").mkdir()
    (root / REL).write_text(source, encoding="utf-8")
    (root / "test" / "StakingVault.t.sol").write_text(HONEST_TESTS, encoding="utf-8")
    if iface:
        (root / "src" / "IStakingVault.sol").write_text(IMPORT_IFACE, encoding="utf-8")
    if foundry:
        (root / "foundry.toml").write_text(FOUNDRY_TOML, encoding="utf-8")
    return root


def tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(p.relative_to(root).as_posix().encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def compose(project: Path, work: Path, source: str) -> str:
    """DRAIN composed in repo mode: it imports arbiter-target/StakingVault.sol."""
    plan = plan_for(project / REL, repo_root=project)
    ws = Workspace(work, "compose", source, plan=plan)
    try:
        return ws.compose_victim_loss(**vp.DRAIN)
    finally:
        ws.cleanup()


results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'WRONG'}] {name:14s} {detail}")


def statuses(r: dict) -> str:
    return " ".join(f"{n}:{r['checks'][n]['status']}" for n in GATE_ORDER)


def case_gate(work: Path, name: str, project: Path, original: str, patched: str,
              want_accept: bool, want4: str) -> dict:
    solidity = compose(project, work, original)
    repo = {"root": str(project), "rel": REL, "solidity": solidity}
    t0 = time.monotonic()
    base = reproduce(original, solidity, work, f"{name}_base", repo=repo)
    if base["status"] != "pass":
        check(name, False, f"check 0 failed: {base.get('reason')} {base.get('error', '')[:120]}")
        return base
    r = verify_fix(original, solidity, patched=patched, root=work, sample_id=name,
                   baseline=base, repo=repo, run_all=True)
    c4 = r["checks"]["4"]
    others = all(r["checks"][n]["status"] == "pass" for n in GATE_ORDER if n != "4")
    ok = r["accepted"] == want_accept and c4["status"] == want4 and others
    extra = ""
    if c4.get("newly_failed"):
        extra = f" newly failed: {c4['newly_failed']}"
    elif c4.get("reason"):
        extra = f" ({c4['reason']})"
    rt = base.get("repo_tests") or {}
    check(name, ok, f"{'ACCEPTED' if r['accepted'] else 'REJECTED'}  {statuses(r)}  "
                    f"tests before: {len(rt.get('passed') or [])} passed{extra}  "
                    f"({time.monotonic() - t0:.1f}s)")
    return r


def case_sandbox(work: Path) -> None:
    from arbiter import sandbox
    ok, why = sandbox.available()
    if not ok:
        check("sandbox_deps", False, f"sandbox unavailable: {why}")
        return
    job = work / "sbjob"
    proj = job / "feed" / "src"
    proj.mkdir(parents=True)
    (proj / "Feed.sol").write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
        'import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";\n'
        'import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";\n'
        "contract Feed is ReentrancyGuard {\n"
        "    AggregatorV3Interface public feed;\n"
        "    constructor(address f) { feed = AggregatorV3Interface(f); }\n"
        "    function poke() external nonReentrant {}\n}\n", encoding="utf-8")
    box = sandbox.JobSandbox(job, "repo-patch-probe")
    env = box.__enter__()
    got = {}
    try:
        for label, local in (("without_copy", False), ("with_copy", True)):
            e = dict(env)
            if local:
                info = localize_dep_cache(job / "soldeps")
                e["ARBITER_DEP_CACHE"] = str(job / "soldeps")
            saved = os.environ.pop("ARBITER_DEP_CACHE", None)
            try:
                with sandbox.applied_env(e):
                    plan = plan_for(proj / "Feed.sol", repo_root=job / "feed")
                    ws = Workspace(job / "ws", f"feed_{label}", (proj / "Feed.sol").read_text(),
                                   plan=plan)
                    got[label] = ws.prepare_context().get("ok")
                    ws.cleanup()
            finally:
                if saved is not None:
                    os.environ["ARBITER_DEP_CACHE"] = saved
    finally:
        box.__exit__(None, None, None)
    check("sandbox_deps", got.get("with_copy") is True and got.get("without_copy") is False,
          f"OpenZeppelin + chainlink in the container: without the job copy builds="
          f"{got.get('without_copy')}, with it builds={got.get('with_copy')} "
          f"({info.get('files')} .sol files copied)")


def main() -> int:
    use_sandbox = "--sandbox" in sys.argv[1:]
    print("repo-mode patch gate: copies of the project, the project's own tests as check 4\n")
    work = Path(tempfile.mkdtemp(prefix="repo-patch-probe-",
                                 dir=HERE.parent / "runs" if use_sandbox else None))
    try:
        p1 = make_project(work / "proj1", V)
        before = tree_digest(p1)
        case_gate(work, "repo_fix", p1, V, S, True, "pass")
        case_gate(work, "breaks_tests", p1, V, BREAKS_TESTS, False, "fail")
        check("untouched", tree_digest(p1) == before,
              "the user's project files are byte-identical after both runs")
        p2 = make_project(work / "proj2", with_import(V), iface=True)
        case_gate(work, "with_import", p2, with_import(V), with_import(S), True, "pass")
        p3 = make_project(work / "proj3", V, foundry=False)
        case_gate(work, "not_foundry", p3, V, S, True, "skipped")
        if use_sandbox:
            case_sandbox(work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    good = sum(ok for _, ok, _ in results)
    print(f"\n{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
