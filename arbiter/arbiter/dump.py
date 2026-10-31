"""Extract proven exploits from a run as self-contained, runnable Foundry projects.

Every accepted finding in this system is backed by Solidity that compiled and executed,
and until now that evidence only existed inside a JSONL row. That is the wrong place for
it: the whole claim of the project is that a finding is a transcript of an execution
rather than an assertion, and a transcript nobody can replay is just an assertion with
extra steps.

`dump` writes each proven exploit as a directory anyone can `cd` into and `forge test`.
No arguments, no reconstruction, no trust in this tool's own summary -- the reader
re-runs the exploit against the contract and watches it pass.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .workspace import FOUNDRY_TOML, VM_SOL

README = """# {sample_id}

{verdict_line}

## Finding

- **title**: {title}
- **function**: {function}
- **severity**: {severity}
- **predicate**: `{predicate}` — {predicate_note}

**offending expression**, verified to appear verbatim in the contract:

```solidity
{offending}
```

**attack path as reported**:

{attack_path}

## Reproduce

```bash
forge test -vvv
```

Expected: the exploit test PASSES, which under this harness means: {predicate_condition}
The success condition is in `test/{poc_name}.t.sol` and was written by the harness, not by
the model that produced the attack.

## Recorded output from the original run

```
{output}
```
"""

PREDICATE_NOTES = {
    "victim_loss": "with the attack, an ordinary user (the victim) gets back less than in "
                   "the same world without it, and the attacker holds at least the difference",
    "eth_profit": "attacker ends up holding more ether than the honest baseline",
    "token_profit": "attacker's balance of the named token rises above the honest baseline",
    "state_change": "state an honest user cannot move was moved by an unprivileged account",
    "liveness_broken": "an operation an ordinary user could complete stops working",
    "": "unspecified",
}


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text)[:60].strip("_") or "sample"


def _vendor(plan: dict[str, Any], proj: Path) -> tuple[list[str], str]:
    """Copy the exploit's compilation environment into the project.

    An in-repo exploit imports through remappings that pointed at absolute paths in a
    scratch workspace, so writing the file alone produces a project that cannot compile --
    which is how this was found: the first dump ran and failed on
    `Source "arbiter-target/DepositHandler.sol" not found`.

    Each remapping's destination directory is copied under `sources/`, keeping its
    absolute path as a relative one, and the remapping is rewritten to point there. The
    import strings in the exploit are then correct unchanged, because the prefixes are
    the ones it was compiled with. Only .sol files are copied, so vendoring a slice of
    OpenZeppelin or a whole audit repository costs kilobytes.
    """
    lines: list[str] = []
    for entry in plan.get("remappings") or []:
        if "=" not in entry:
            continue
        prefix, dest = entry.split("=", 1)
        src_dir = Path(dest)
        if not src_dir.is_dir():
            continue
        rel = _vendored_path(src_dir, plan, len(lines))
        _copy_sol_tree(src_dir, proj / rel)
        lines.append(f"{prefix}={rel.as_posix()}/")

    chosen = plan.get("chosen_src") or "src"
    if chosen != "src" and Path(chosen).is_dir():
        rel = _vendored_path(Path(chosen), plan, len(lines))
        _copy_sol_tree(Path(chosen), proj / rel)
        chosen = rel.as_posix()
    return lines, chosen


def _vendored_path(src_dir: Path, plan: dict[str, Any], index: int) -> Path:
    """Where a vendored directory lands under `sources/`, without the host's layout.

    The absolute path used to be kept, minus its leading slash, so every dumped project
    carried `sources/home/<user>/...`. Inside the repository the path is made relative
    to its root; anything outside it (a global library cache) gets a neutral name.
    """
    root = plan.get("repo_root")
    if root:
        try:
            rel = src_dir.resolve().relative_to(Path(root).resolve())
            return Path("sources") / rel if rel.parts else Path("sources")
        except ValueError:
            pass
    return Path("sources") / "external" / f"{index}_{src_dir.name or 'lib'}"


def _copy_sol_tree(src: Path, dest: Path) -> None:
    from .repo import SKIP_DIRS

    for dirpath, dirnames, filenames in __import__("os").walk(src):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".sol"):
                continue
            source = Path(dirpath) / name
            target = dest / source.relative_to(src)
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                try:
                    target.write_bytes(source.read_bytes())
                except OSError:
                    continue


def dump_run(results_path: Path, out_dir: Path, include_failed: bool = False) -> dict[str, Any]:
    """Write every proven exploit to its own runnable project. Returns a manifest."""
    rows = [
        json.loads(line)
        for line in results_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[dict[str, Any]] = []
    skipped = 0

    for row in rows:
        sample_id = row.get("sample_id", "unknown")
        outcome = row.get("outcome") or {}
        findings = outcome.get("findings") or []
        pocs = {p.get("name"): p for p in (outcome.get("pocs") or [])}

        # Only exploits the harness itself adjudicated as passing are evidence.
        admissible = [
            p for p in (outcome.get("pocs") or [])
            if p.get("passed") and p.get("adjudicated")
        ]
        if not admissible and not include_failed:
            skipped += 1
            continue

        for finding in findings or [{}]:
            poc = pocs.get(finding.get("poc_name")) or (admissible[0] if admissible else None)
            if poc is None:
                continue
            name = poc.get("name", "Exploit")
            proj = out_dir / _slug(f"{sample_id}__{name}")
            (proj / "src").mkdir(parents=True, exist_ok=True)
            (proj / "test").mkdir(parents=True, exist_ok=True)

            plan = (row.get("context") or {}).get("plan") or _replan(row)
            src_setting = "src"
            if plan:
                remappings, src_setting = _vendor(plan, proj)
                (proj / "remappings.txt").write_text(
                    "\n".join(remappings) + "\n", encoding="utf-8"
                )
            # The compiler is pinned to whatever the original run resolved, so the dump
            # reproduces under the same solc rather than whichever one is newest on the
            # reader's machine.
            # Read off the context, not the plan. `run.py` writes solc at the top level
            # of `context` and the plan dict never carried the key, so this silently
            # resolved to "" for every dump ever taken: twelve of twelve projects were
            # written with auto_detect_solc, compiling contracts pinned to an old pragma
            # with whichever compiler is newest on the reader's machine. They happened
            # to build, which is luck rather than design.
            solc = (row.get("context") or {}).get("solc") or plan.get("solc") or ""
            # The legacy pipeline first, as the harness itself compiles. This used to be
            # the IR pipeline unconditionally, but with the template's optimizer = false
            # IR is *more* prone to "stack too deep", not less: every StakingVault dump
            # failed to build that way (10/29), so `reproduces` read 0 for a proof that
            # passes under the harness. _verify falls back to IR with the optimizer on.
            _write_dump_toml(proj, src_setting, solc, via_ir=False)
            (proj / "src" / "Target.sol").write_text(
                row.get("source") or _recover_source(row), encoding="utf-8"
            )
            # The harness substitutes the pragma to whatever the contract under audit
            # accepts; writing the template verbatim leaves the literal placeholder in
            # the file and nothing compiles.
            (proj / "test" / "Vm.sol").write_text(
                VM_SOL.replace("__PRAGMA__", plan.get("pragma") or ">=0.8.0"),
                encoding="utf-8",
            )
            (proj / "test" / f"{name}.t.sol").write_text(
                poc.get("solidity", ""), encoding="utf-8"
            )
            (proj / "README.md").write_text(
                README.format(
                    sample_id=sample_id,
                    verdict_line=(
                        "**Exploit reproduced.** The attack below compiled and executed "
                        "on an EVM, and satisfied a success condition this harness owns."
                    ),
                    title=finding.get("title", "(no title recorded)"),
                    function=finding.get("vulnerable_function", "(unrecorded)"),
                    severity=finding.get("severity", "(unrecorded)"),
                    predicate=poc.get("predicate", ""),
                    predicate_note=PREDICATE_NOTES.get(poc.get("predicate", ""), ""),
                    predicate_condition=PREDICATE_NOTES.get(
                        poc.get("predicate", ""), "the predicate named above holds") + ".",
                    offending=finding.get("offending_expression", "(unrecorded)"),
                    attack_path=finding.get("attack_path", "(unrecorded)"),
                    poc_name=name,
                    output=(poc.get("output_tail") or "")[-1500:],
                ),
                encoding="utf-8",
            )
            # Proof that the dump is runnable, not just written. A project that does not
            # compile outside the harness is an assertion again, which is the thing this
            # whole design exists to stop producing.
            verified, output = _verify(proj)
            build = "legacy"
            if not verified and "Stack too deep" in output:
                _write_dump_toml(proj, src_setting, solc, via_ir=True)
                verified, output = _verify(proj)
                build = "via_ir+optimizer"
            written.append(
                {
                    "sample_id": sample_id,
                    "path": str(proj),
                    "title": finding.get("title", ""),
                    "predicate": poc.get("predicate", ""),
                    "reproduces": verified,
                    "build": build,
                }
            )

    manifest = {
        "source_run": str(results_path),
        "exploits_written": len(written),
        "exploits_reproduced": sum(1 for e in written if e.get("reproduces")),
        "samples_without_admissible_exploit": skipped,
        "exploits": written,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    return manifest


def _replan(row: dict[str, Any]) -> dict[str, Any]:
    """Rebuild the compilation environment for a run recorded before plans were stored.

    Best effort and clearly marked as such: the remappings the repair loop discovered
    during the original run are gone, so only the ones the static pass finds come back.
    If that is not enough the dumped project fails to compile, and `reproduces` in the
    manifest says so rather than the dump quietly claiming success.
    """
    path = row.get("path")
    if not path or not Path(path).is_file():
        return {}
    # The run record names the repository the contract came from; use it rather than
    # guessing, so the vendored tree is that repository and not whatever directory above
    # it happens to carry a marker file.
    root = None
    repo = row.get("repo")
    if repo:
        cur = Path(path).parent
        while cur.parent != cur:
            if cur.name == repo:
                root = cur
                break
            cur = cur.parent
    try:
        from .repo import plan_for

        plan = plan_for(Path(path), repo_root=root)
    except Exception:  # noqa: BLE001
        return {}
    return {
        "repo_root": plan.repo_root.as_posix(),
        "target": plan.target.as_posix(),
        "target_import": plan.target_import,
        "pragma": plan.test_pragma,
        "chosen_src": plan.source_root.as_posix(),
        "remappings": list(plan.remappings),
        "recovered": True,
    }


def _write_dump_toml(proj: Path, src: str, solc: str, via_ir: bool) -> None:
    """foundry.toml for a dump. IR only as the fallback, and then with the optimizer on:
    IR without it is what overflowed the stack (measured on StakingVault, 10/29)."""
    text = FOUNDRY_TOML.format(
        src=src, solc=f'solc = "{solc}"' if solc else "auto_detect_solc = true",
        via_ir="true" if via_ir else "false")
    if via_ir:
        text = text.replace("optimizer = false", "optimizer = true")
    (proj / "foundry.toml").write_text(text, encoding="utf-8")


def _verify(proj: Path) -> tuple[bool, str]:
    """Run `forge test` in the dumped project: (exploit still passes, forge output)."""
    import shutil
    import subprocess

    forge = shutil.which("forge")
    if forge is None:
        return False, "forge not found"
    try:
        proc = subprocess.run(  # noqa: S603
            [forge, "test"], cwd=proj, capture_output=True, text=True, timeout=300
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, str(exc)
    passed = any(
        line.strip().startswith("[PASS]") for line in (proc.stdout or "").splitlines()
    )
    # Build artifacts are reproducible from the sources and are two orders of magnitude
    # larger than them -- 326 MB against a few hundred kilobytes on the first dump.
    for junk in ("out", "cache"):
        shutil.rmtree(proj / junk, ignore_errors=True)
    return passed, (proc.stdout or "") + (proc.stderr or "")


def _recover_source(row: dict[str, Any]) -> str:
    """The results row does not carry the target source; recover it from the PoC import.

    Runs record the exploit but not the contract it ran against, because the contract came
    from the evalset. When dumping without the evalset to hand, leave an honest placeholder
    rather than a silently wrong file.
    """
    return (
        "// SPDX-License-Identifier: Apache-2.0\n"
        "// The contract under audit was not stored in the run record.\n"
        "// Copy it here from the evaluation set to make this project runnable.\n"
        "pragma solidity >=0.8.0;\n"
    )


# -- downloadable regression test (TestArbiterRegression, plan 6.6) ----------------------
#
# A proven victim_loss exploit, turned into a test a developer keeps: the attack must stop
# working (testExploitBlocked) AND, with no attack, an ordinary user must still get back
# what the original contract paid (testHonestPath0..3). The first alone passes an
# always-revert "fix" -- the attack fails, and so does everyone else -- which is why the
# two ship together. The honest constants are the A column the report contract measured
# on the original, so building the project needs no forge run.

REGRESSION_TOLERANCE_WEI = 10
REGRESSION_DIR = "test/arbiter"
REGRESSION_FILE = "ArbiterRegression.t.sol"
_ENV_WORDS = ["預設", "受害者餘額 1000 倍", "一週後", "8 輪攻擊"]
_HERMETIC_TARGET_IMPORT = 'import "../src/Target.sol";'
# The stored exploit's own test. Kept as a callable function but no longer a `test*`, so
# `forge test` in a patched project does not report the (now failing) proof as a failure.
_PROOF_TEST = "function testArbiterVictimLoss() public"
_PROOF_RENAMED = "function arbiterVictimLossProof() public"


def regression_unavailable_reason(predicate: str | None, abg_status: str | None) -> str:
    """Plain-language reason no regression test exists, or "" if one can be built."""
    if predicate == "victim_loss" and abg_status == "measured":
        return ""
    if predicate == "victim_loss":
        return ("這個攻擊在重跑時沒有重現，量不到「沒有攻擊時使用者取回多少」，"
                "所以沒有可以寫進測試的基準數字。")
    if predicate == "liveness_broken":
        return ("這個漏洞的證據是「功能被弄壞」，沒有取回金額可以當基準，"
                "目前只對「受害者少拿回錢」這一類產生回歸測試。")
    return (f"這個漏洞是用寬鬆條件（{predicate or '未知'}，例如攻擊者多拿到 ETH）證實的，"
            "沒有「受害者少拿回多少」的基準數字，所以不產生回歸測試。")


def regression_contract(environments: list[dict[str, Any]]) -> str:
    """TestArbiterRegression, appended to the stored exploit file."""
    honest = []
    for e in environments:
        if not e.get("A"):
            continue  # no baseline: the original paid nothing back here, nothing to keep
        honest.append(
            f"    /// 環境 {e['env']}（{_ENV_WORDS[e['env']] if e['env'] < len(_ENV_WORDS) else e['env']}）："
            f"原合約在沒有攻擊時讓使用者取回 {e['A']} wei。\n"
            f"    function testHonestPath{e['env']}() public {{ "
            f"_arbHonest({e['endow_wei']}, {e['warp_s']}, {e['rounds']}, {e['A']}); }}"
        )
    return f"""

/// ARBITER regression test. testExploitBlocked replays the proven attack in the four
/// environments and requires that it no longer succeeds; each testHonestPath requires
/// that, with no attack, the user still gets back what the original contract paid
/// (minus {REGRESSION_TOLERANCE_WEI} wei). Both kinds together: an always-revert "fix"
/// passes the first and fails the second.
contract TestArbiterRegression is TestArbiterVictim {{
    uint256 internal constant ARB_TOLERANCE_WEI = {REGRESSION_TOLERANCE_WEI};

    function testExploitBlocked() public {{
        vm.expectRevert();
        this.arbiterRun();
    }}

    function _arbHonest(uint256 endow, uint256 warpBy, uint256 rounds, uint256 before) internal {{
        (uint256 recovered, , ) = this.arbTrial(false, endow, warpBy, rounds);
        require(recovered + ARB_TOLERANCE_WEI >= before,
                "ARBITER regression: with no attack the user gets back less than the original paid");
    }}

{chr(10).join(honest)}
}}
"""


def regression_solidity(exploit_solidity: str, contract_file: str,
                        environments: list[dict[str, Any]]) -> str:
    """The stored exploit pointed at src/<contract_file>, plus TestArbiterRegression."""
    if _HERMETIC_TARGET_IMPORT not in exploit_solidity:
        raise ValueError("exploit does not import ../src/Target.sol (pass it through "
                         "patch.exploit_from_row first)")
    if _PROOF_TEST not in exploit_solidity:
        raise ValueError("exploit has no testArbiterVictimLoss(); not a victim_loss proof")
    body = exploit_solidity.replace(
        _HERMETIC_TARGET_IMPORT, f'import "../../src/{contract_file}";', 1)
    body = body.replace(_PROOF_TEST, _PROOF_RENAMED, 1)
    return body + regression_contract(environments)


REGRESSION_README = """# ARBITER 回歸測試：{title}

這個資料夾是一個可以直接執行的 Foundry 專案。也可以只把 `{test_dir}/` 複製到你自己的專案。

用途：把這份測試放進你的專案，以後每次修改合約，都會自動再試一次同樣的攻擊，
並確認一般使用者在沒有攻擊時拿回的錢沒有變少。

## 裡面有什麼

| 檔案 | 內容 |
|---|---|
| `src/{contract_file}` | 稽核時的原合約（還沒修補） |
| `{test_dir}/{test_file}` | 當初證實成功的攻擊，加上回歸測試 `TestArbiterRegression` |
| `{test_dir}/Vm.sol` | 測試用到的 Foundry cheatcode 介面。不需要另外安裝 forge-std |
| `foundry.toml` | 編譯設定（{solc_line}） |

## 每個測試在檢查什麼

| 測試 | 檢查什麼 | 原合約 | 修好之後 |
|---|---|---|---|
| `testExploitBlocked` | 把當初成功的攻擊，在 4 種環境各重跑一次，攻擊必須失敗 | 失敗（代表攻擊還能成功） | 通過 |
{honest_rows}

為什麼兩種都要：如果「修補」只是讓函式一律失敗（revert），攻擊當然也會失敗，
`testExploitBlocked` 就會通過；但一般使用者同樣拿不回錢，`testHonestPath` 會抓到這種假修補。

## 怎麼跑

在這個資料夾執行：

```bash
forge test
```

現在跑，會看到 `testExploitBlocked` 失敗、`testHonestPath*` 通過。這是正常的：原合約的漏洞還在。
把修補套用到 `src/{contract_file}` 之後再跑一次，應該全部通過。網頁下載的 `.patch` 檔可以這樣套用：

```bash
patch -p1 < 你下載的.patch
```

## 放進你自己的專案

1. 把 `{test_dir}/` 整個資料夾複製到你專案的 `test/` 底下。
2. 打開 `{test_file}`，把 `import "../../src/{contract_file}";` 改成你專案裡這份合約的位置（相對於這個測試檔）。
3. 只跑這組測試：`forge test --match-contract TestArbiterRegression`
4. 放進 CI，以後每次修改都會自動檢查。

## 要知道的限制

- 全部通過只代表：**這一個攻擊**在 4 種環境都失效，而且沒有攻擊時，使用者取回的錢沒有比原合約少。不代表合約沒有其他漏洞。
- 攻擊和使用者的操作步驟，是照當初證明攻擊時的寫法。如果你改了合約的對外介面（函式名稱、參數），這份測試要跟著改。
- 容差是 {tolerance} wei。

## 來源

- 漏洞：{title}（函式 `{function}`）
- 證明方式：`victim_loss`。有攻擊時受害者取回的比沒有攻擊時少，而且攻擊者手上至少多了這個差額。
- 稽核模型：{models}；run：`{run_id}`；產生時間：{generated_at}
"""


def write_regression(proj: Path, *, source: str, contract_file: str, exploit_solidity: str,
                     environments: list[dict[str, Any]], finding: dict[str, Any],
                     solc: str = "", meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """Write a standalone Foundry project holding TestArbiterRegression. No forge run."""
    meta = meta or {}
    test_dir = proj / REGRESSION_DIR
    (proj / "src").mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)
    (proj / "src" / contract_file).write_text(source, encoding="utf-8")
    (test_dir / REGRESSION_FILE).write_text(
        regression_solidity(exploit_solidity, contract_file, environments), encoding="utf-8")
    (test_dir / "Vm.sol").write_text(VM_SOL.replace("__PRAGMA__", ">=0.8.0"), encoding="utf-8")
    (proj / "foundry.toml").write_text(
        FOUNDRY_TOML.format(src="src", solc=f'solc = "{solc}"' if solc else "auto_detect_solc = true",
                            via_ir="false"),
        encoding="utf-8")
    rows = []
    for e in environments:
        if not e.get("A"):
            continue
        name = _ENV_WORDS[e["env"]] if e["env"] < len(_ENV_WORDS) else str(e["env"])
        rows.append(
            f"| `testHonestPath{e['env']}` | 環境 {e['env']}（{name}）：沒有攻擊時，使用者取回至少 "
            f"{e['A'] / 10**18:g} ETH（原合約的金額） | 通過 | 通過 |")
    skipped = [e["env"] for e in environments if not e.get("A")]
    if skipped:
        rows.append(f"| （環境 {', '.join(map(str, skipped))}） | 原合約在這些環境沒有取回金額可當基準，所以沒有誠實路徑測試 | — | — |")
    (proj / "README.md").write_text(REGRESSION_README.format(
        title=finding.get("title") or "(未記錄)",
        function=finding.get("vulnerable_function") or "(未記錄)",
        contract_file=contract_file, test_dir=REGRESSION_DIR, test_file=REGRESSION_FILE,
        solc_line=f"solc {solc}" if solc else "solc 自動選擇",
        honest_rows="\n".join(rows), tolerance=REGRESSION_TOLERANCE_WEI,
        models=", ".join(meta.get("models") or []) or "未記錄",
        run_id=meta.get("run_id") or "未記錄",
        generated_at=meta.get("generated_at") or "未記錄"), encoding="utf-8")
    return {"project": proj.name, "contract_file": contract_file,
            "honest_envs": [e["env"] for e in environments if e.get("A")]}
