#!/usr/bin/env python3
"""Does the downloadable regression test tell a real fix from a fake one?

TestArbiterRegression (dump.write_regression) ships two kinds of test: testExploitBlocked
(the proven attack, replayed in four environments, must fail) and testHonestPath0..3
(with no attack the user still gets back what the original paid). Each project is built
once and run with `forge test` against three versions of the contract:

  original       testExploitBlocked FAILS (the attack still works), honest tests PASS
  real fix       everything PASSES
  always-revert  testExploitBlocked PASSES -- the attack fails, and so does everyone --
                 and every honest test FAILS. Shipping only the first test would have
                 passed this fake fix.

Two exploits, so the check does not depend on one recording:

  A  V_reentrancy_unstake + victim_probe's DRAIN (the patch_probe material);
     fix = S_reentrancy_unstake, always-revert = patch_probe's `revert("paused")`.
     Always available: built from evalsets/.
  B  runs/spark-test-2 (examples/StakingVault.sol, exploit written by arbiter-gpt);
     fix = the arbiter-gpt patch in runs/spark-test-2.patches.jsonl, always-revert =
     the same `revert("paused")` at the top of unstake(). runs/ is not in git, so a
     clone without it passes --evalset-only.

Pure CPU and forge. No gateway requests.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))
sys.path.insert(0, str(RIG / "scripts"))

import victim_probe as vp  # noqa: E402
from arbiter.dump import REGRESSION_DIR, write_regression  # noqa: E402
from arbiter.patch import apply_diff, exploit_from_row, reproduce  # noqa: E402
from arbiter.workspace import VICTIM_ENVIRONMENTS, Workspace  # noqa: E402

_UNSTAKE = "    function unstake() external {\n"
EXPECT = {
    "original": ("fail", "pass"),
    "fix": ("pass", "pass"),
    "always_revert": ("pass", "fail"),
}


def always_revert(src: str) -> str:
    assert _UNSTAKE in src, "unstake() header not found"
    return src.replace(_UNSTAKE, _UNSTAKE + "        revert(\"paused\");\n", 1)


def environments(abg: list[dict]) -> list[dict]:
    rows = []
    for i, (endow, warp, rounds) in enumerate(VICTIM_ENVIRONMENTS):
        m = next((r for r in abg if r["env"] == i), {})
        rows.append({"env": i, "endow_wei": endow, "warp_s": warp, "rounds": rounds,
                     "A": m.get("A"), "B": m.get("B"), "G": m.get("G")})
    return rows


def forge_results(proj: Path) -> dict[str, str]:
    """{test name: "pass"|"fail"} for TestArbiterRegression."""
    proc = subprocess.run(  # noqa: S603
        [shutil.which("forge") or "forge", "test", "--json", "--offline",
         "--match-contract", "^TestArbiterRegression$"],
        cwd=proj, capture_output=True, text=True, timeout=600)
    start = proc.stdout.find("{")
    if start < 0:
        raise RuntimeError(f"forge printed no JSON: {(proc.stderr or proc.stdout)[-800:]}")
    data = json.loads(proc.stdout[start:])
    out = {}
    for suite in data.values():
        for name, res in (suite.get("test_results") or {}).items():
            out[name.split("(")[0]] = "pass" if res.get("status") == "Success" else "fail"
    return out


def run_case(label: str, base_proj: Path, contract_file: str, source: str,
             work: Path) -> tuple[bool, str]:
    proj = work / label
    shutil.copytree(base_proj, proj)
    (proj / "src" / contract_file).write_text(source, encoding="utf-8")
    got = forge_results(proj)
    blocked = got.pop("testExploitBlocked", "missing")
    honest = sorted(got.items())
    want_blocked, want_honest = EXPECT[label]
    ok = (blocked == want_blocked and honest
          and all(v == want_honest for _, v in honest))
    marks = " ".join(f"{k.removeprefix('test')}:{v}" for k, v in honest)
    return bool(ok), f"ExploitBlocked:{blocked}  {marks}"


def build(name: str, source: str, solidity: str, contract_file: str, root: Path,
          solc: str = "") -> tuple[Path, list[dict]]:
    base = reproduce(source, solidity, root, f"{name}_base")
    if base["status"] != "pass":
        raise RuntimeError(f"{name}: the stored exploit does not reproduce: {base}")
    envs = environments(base["abg"])
    proj = root / f"{name}_project"
    write_regression(proj, source=source, contract_file=contract_file,
                     exploit_solidity=solidity, environments=envs,
                     finding={"title": name}, solc=solc)
    return proj, envs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evalset-only", action="store_true",
                    help="skip B (runs/spark-test-2 is not in git)")
    args = ap.parse_args()
    if shutil.which("forge") is None:
        print("forge not on PATH")
        return 1

    print("a regression test passes a real fix and fails both the unfixed contract and an")
    print("always-revert fake: the attack must fail AND the honest user must still be paid.\n")
    root = Path(tempfile.mkdtemp(prefix="regression-probe-"))
    results: list[bool] = []
    try:
        groups = []
        V = vp.load("V_reentrancy_unstake")
        S = vp.load("S_reentrancy_unstake")
        drain = Workspace(root, "compose", V).compose_victim_loss(**vp.DRAIN)
        groups.append(("A  V_reentrancy_unstake + DRAIN", "A", V, drain, "Target.sol", "",
                       {"original": V, "fix": S, "always_revert": always_revert(V)}))

        results_file = RIG / "runs" / "spark-test-2.results.jsonl"
        patches_file = RIG / "runs" / "spark-test-2.patches.jsonl"
        if args.evalset_only:
            print("  B  skipped (--evalset-only)\n")
        elif not (results_file.exists() and patches_file.exists()):
            print("  B  runs/spark-test-2.{results,patches}.jsonl missing; "
                  "pass --evalset-only on a clone without runs/")
            return 1
        else:
            row = json.loads(results_file.read_text(encoding="utf-8").splitlines()[0])
            ex = exploit_from_row(row)
            rec = next(json.loads(l) for l in patches_file.read_text(encoding="utf-8").splitlines()
                       if l.strip() and json.loads(l).get("status") == "accepted")
            fixed, how = apply_diff(ex["source"], rec["diff"])
            if fixed is None:
                print(f"  B  spark-test-2 patch does not apply: {how}")
                return 1
            solc = (row.get("context") or {}).get("solc") or ""
            groups.append(("B  spark-test-2 (StakingVault, arbiter-gpt exploit and patch)", "B",
                           ex["source"], ex["solidity"], "StakingVault.sol", solc,
                           {"original": ex["source"], "fix": fixed,
                            "always_revert": always_revert(ex["source"])}))

        for title, key, source, solidity, cfile, solc, variants in groups:
            t0 = time.monotonic()
            proj, envs = build(key, source, solidity, cfile, root, solc)
            a = " ".join("?" if e["A"] is None else f"{e['A'] / 1e18:g}" for e in envs)
            print(f"  {title}")
            print(f"     honest baseline A (ETH) per env: {a}   "
                  f"[{REGRESSION_DIR}/, built in {time.monotonic() - t0:.1f}s]")
            for label, src in variants.items():
                t1 = time.monotonic()
                ok, marks = run_case(label, proj, cfile, src, root / f"{key}_cases")
                print(f"     [{'OK  ' if ok else 'WRONG'}] {label:14s} {marks}  "
                      f"({time.monotonic() - t1:.1f}s)")
                results.append(ok)
            print()
        print(f"{sum(results)}/{len(results)} as expected")
        return 0 if results and all(results) else 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
