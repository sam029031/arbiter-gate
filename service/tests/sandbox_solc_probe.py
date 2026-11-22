#!/usr/bin/env python3
"""The sandbox's compilers: exact pragmas build, missing ones are explained, isolation holds.

    python3 service/tests/sandbox_solc_probe.py [--only N]

The finals image (arbiter-sandbox:p3) carried solc 0.8.20 and 0.8.37 only. The container
has no network and a read-only root, so a contract pinned to any other version ("pragma
solidity 0.8.24;", the most common shape in the wild) failed with "Read-only file system
(os error 30)" and the verdict was undetermined. arbiter-sandbox:me1 carries every solc in
service/sandbox/solc.lock; anything else is now reported in zh-TW.

  1  image: sandbox.py picks me1 (p3 untouched, still present; p3 only as a fallback when
     me1 is absent and no image is named); inside, tools.lock verifies and /opt/svm holds
     exactly the solc.lock versions with the official sha256
  2  forge, called as workspace.py calls it (no --offline): 0.8.24, 0.7.6 and 0.6.12
     pinned contracts compile with exactly that compiler; ^0.8.20 still auto-detects 0.8.37
  3  the audit machinery, no model: the gate's compile check (repo mode) admits 0.8.24 and
     0.7.6, and a hand-written victim-loss exploit composed by the harness is proven
     under both compilers; its results row then goes through what the gate does with a
     proof -- patch.exploit_from_row + reproduce (A/B/G) -- and the downloadable
     regression project runs (attack still works on the original, honest path holds),
     under both: below 0.8 these were rebuilt hermetically and failed with "Found
     incompatible versions" (sandbox-misc-1)
  4  zh-TW reasons instead of raw forge errors: 0.5.17, 0.8.38, ^0.6.12, a version pinned
     in foundry.toml; the result page gives the matching advice; a real compile error
     below 0.8 is refused with solc's diagnostic and its line, exactly as at 0.8, not
     the hermetic probe's "Found incompatible versions" (sandbox-misc-4)
  5  isolation unchanged: network none, read-only root, ~/.svm not writable, no outbound
     connection
  6  end to end, no model: gate --sandbox on with AuditRegistry.sol (pragma 0.8.24) passes
     the compile stage on me1 and is refused with the zh-TW reason on p3; gate on a 0.5.17
     file is not executed with that reason and 0 requests
  7  Slither (static hints) runs inside the sandbox for 0.8.24 and 0.7.6 pins (on p3 it
     failed: the host's ~/.svm had versions the image did not)

No check sends anything to a model host: the gate runs in 6 have no API key in their
environment and a closed local port as the model URL, and stop before any request.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
RIG = REPO / "arbiter"
sys.path.insert(0, str(RIG))

from arbiter import sandbox, solc_avail  # noqa: E402
from arbiter.sandbox import JobSandbox, applied_env  # noqa: E402

FORGE = str(sandbox.SERVICE_BIN / "forge")
EXEC = str(sandbox.SERVICE_BIN / "_sandbox_exec")
SOLC_LOCK = REPO / "service" / "sandbox" / "solc.lock"
LOCKED = {ln.split()[0]: ln.split()[1][2:] for ln in SOLC_LOCK.read_text().splitlines()
          if ln.strip() and not ln.startswith("#")}
SUPPORTED = "0.7.6、0.8.0～0.8.37"

BANK = """// SPDX-License-Identifier: MIT
pragma solidity {p};
contract Bank {{
    mapping(address => uint256) public bal;
    function deposit() external payable {{ bal[msg.sender] += msg.value; }}
    function withdraw() external {{
        uint256 a = bal[msg.sender];
        (bool ok, ) = msg.sender.call{{value: a}}("");
        require(ok);
        bal[msg.sender] = 0;
    }}
}}
"""
ATTACKER = """contract Attacker {
    Bank public b;
    uint256 public n;
    constructor(address t) { b = Bank(t); }
    function attack() external {
        b.deposit{value: 1 ether}();
        b.withdraw();
    }
    receive() external payable {
        if (address(b).balance >= 1 ether && n < 20) { n++; b.withdraw(); }
    }
}"""


def run(cmd: list[str], env: dict[str, str] | None = None, cwd: Path | None = None,
        timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, env={**os.environ, **(env or {})}, cwd=cwd,
                          capture_output=True, text=True, timeout=timeout)


def forge_build(proj: Path, code: str, pin: str = "") -> tuple[bool, list[str], str]:
    """(ok, compiler versions used, output) for one file, as workspace.py runs forge."""
    (proj / "src").mkdir(parents=True, exist_ok=True)
    (proj / "src" / "C.sol").write_text(code, encoding="utf-8")
    line = f'solc = "{pin}"' if pin else "auto_detect_solc = true"
    (proj / "foundry.toml").write_text(
        f'[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n{line}\n', encoding="utf-8")
    r = run([FORGE, "build"], cwd=proj)
    used = sorted({json.loads(json.loads(p.read_text())["rawMetadata"])["compiler"]["version"].split("+")[0]
                   for p in (proj / "out").glob("*/*.json")
                   if "rawMetadata" in p.read_text()}) if r.returncode == 0 else []
    return r.returncode == 0, used, r.stdout + r.stderr


def repo_item(job: Path, name: str, code: str) -> dict[str, str]:
    """What gate.py builds for a self-contained file in --mode repo."""
    repo = job / name / "contracts"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "Target.sol").write_text(code, encoding="utf-8")
    return {"id": f"file::{name}", "code": code, "path": str(repo / "Target.sol"),
            "repo_root": str(repo)}


# -- 1 -------------------------------------------------------------------------------------
def c1(tmp: Path) -> tuple[bool, str]:
    saved = os.environ.pop("ARBITER_SANDBOX_IMAGE", None)
    try:
        ok_avail, why = sandbox.available()
        chosen = sandbox.IMAGE
        # The fallback, without touching any image: pretend me1 was never built.
        default = sandbox.DEFAULT_IMAGE
        sandbox.DEFAULT_IMAGE = "arbiter-sandbox:never-built"
        try:
            fb_ok, _ = sandbox.available()
            fallback = sandbox.IMAGE
        finally:
            sandbox.DEFAULT_IMAGE = default
        os.environ["ARBITER_SANDBOX_IMAGE"] = "arbiter-sandbox:never-built"
        named_ok, named_why = sandbox.available()
        del os.environ["ARBITER_SANDBOX_IMAGE"]
        sandbox.available()
    finally:
        if saved is not None:
            os.environ["ARBITER_SANDBOX_IMAGE"] = saved
    p3 = run(["docker", "image", "inspect", sandbox.FALLBACK_IMAGE, "--format", "{{.Id}}"]).stdout.strip()
    job = tmp / "c1"
    with JobSandbox(job, "solcprobe1") as env, applied_env(env):
        lock = run([EXEC, "sh", "-c", "cd / && sha256sum --quiet -c /opt/arbiter/tools.lock"], cwd=job)
        listed = run([EXEC, "ls", "/opt/svm"], cwd=job).stdout.split()
        sums = run([EXEC, "sh", "-c", "cd /opt/svm && sha256sum */solc-*"], cwd=job).stdout.split("\n")
    inside = {ln.split()[1].split("/")[0]: ln.split()[0] for ln in sums if ln.strip()}
    ok = (ok_avail and chosen == "arbiter-sandbox:me1" and fb_ok and fallback == "arbiter-sandbox:p3"
          and not named_ok and "never-built" in named_why and p3.startswith("sha256:")
          and lock.returncode == 0 and sorted(listed) == sorted(LOCKED) and inside == LOCKED)
    return ok, (f"default image {chosen}; with me1 absent -> {fallback}; a named missing image -> "
                f"refused ({named_why}); p3 still present {p3[7:19]}; tools.lock rc {lock.returncode}; "
                f"/opt/svm {len(listed)} versions = solc.lock {sorted(listed) == sorted(LOCKED)}, "
                f"sha256 all official {inside == LOCKED}")


# -- 2 -------------------------------------------------------------------------------------
def c2(tmp: Path) -> tuple[bool, str]:
    job = tmp / "c2"
    cases = [("0.8.24", ["0.8.24"]), ("0.7.6", ["0.7.6"]), ("0.6.12", ["0.6.12"]),
             ("^0.8.20", ["0.8.37"])]
    res = []
    with JobSandbox(job, "solcprobe2") as env, applied_env(env):
        for i, (p, want) in enumerate(cases):
            ok, used, out = forge_build(job / f"p{i}", BANK.format(p=p))
            res.append((p, ok and used == want, used, out.strip().splitlines()[-1:] if not ok else ""))
    bad = [r for r in res if not r[1]]
    return not bad, ("; ".join(f"pragma {p} -> {'+'.join(u) or 'FAILED ' + str(o)}" for p, _, u, o in res))


# -- 3 -------------------------------------------------------------------------------------
def c3(tmp: Path) -> tuple[bool, str]:
    from arbiter import gate
    from arbiter.dump import REGRESSION_DIR, write_regression
    from arbiter.patch import exploit_from_row, reproduce
    from arbiter.repo import plan_for
    from arbiter.workspace import VICTIM_ENVIRONMENTS, Workspace
    job = tmp / "c3"
    notes, ok = [], True
    with JobSandbox(job, "solcprobe3") as env, applied_env(env):
        for p in ("0.8.24", "0.7.6"):
            tag = p.replace(".", "")
            code = BANK.format(p=p)
            item = repo_item(job, "g" + tag, code)
            err = gate._hermetic_compile_error(code, job / ("w" + tag), item)
            plan = plan_for(Path(item["path"]), repo_root=Path(item["repo_root"]))
            ws = Workspace(job / ("x" + tag), "x", code, plan=plan)
            ctx = ws.prepare_context()
            sol = ws.compose_victim_loss(deploy_code="Bank target = new Bank();",
                                         victim_enter="target.deposit{value: 5 ether}();",
                                         victim_exit="target.withdraw();", attacker_code=ATTACKER)
            name = ws.write_poc("Exploit", sol)
            built = ws.build()
            r = ws.run_poc(name) if built.ok else None
            proven = bool(r and "[PASS] testArbiterVictimLoss()" in r.combined)
            ws.cleanup()
            # What the gate does with that proof: the row as run.py records it, A/B/G, and
            # the regression download.
            row = {"sample_id": item["id"], "source": code, "path": item["path"],
                   "context": {**ctx, "plan": {"repo_root": plan.repo_root.as_posix(),
                                               "target": plan.target.as_posix(),
                                               "target_import": plan.target_import,
                                               "pragma": plan.test_pragma,
                                               "chosen_src": plan.chosen_src,
                                               "remappings": list(plan.remappings)}},
                   "outcome": {"proven": True, "pocs": [
                       {"name": "ExploitPoc", "passed": True, "adjudicated": True,
                        "predicate": "victim_loss", "solidity": sol, "hypothesis": "re-entry"}],
                       "findings": [{"poc_name": "ExploitPoc", "title": "re-entry"}]}}
            ex = exploit_from_row(row)
            base = reproduce(ex["source"], ex["solidity"], job / ("e" + tag), "bank",
                             repo=ex["repo"])
            abg = base.get("abg") or []
            measured = (base["status"] == "pass" and len(abg) == 4
                        and all(e["A"] and e["B"] is not None and e["B"] < e["A"] for e in abg))
            envs = [{"env": e["env"], "endow_wei": endow, "warp_s": warp, "rounds": rounds,
                     "A": e["A"], "B": e["B"], "G": e["G"], "unit": e.get("unit")}
                    for e, (endow, warp, rounds) in zip(abg, VICTIM_ENVIRONMENTS)]
            proj = job / ("reg" + tag)
            reg_ok, reg_note = False, "not built (A/B/G not measured)"
            if measured:
                write_regression(proj, source=code, contract_file="Bank.sol",
                                 exploit_solidity=ex["solidity"], environments=envs,
                                 finding={"title": "re-entry"}, solc=str(ctx.get("solc") or ""))
                t = run([FORGE, "test", "--json", "--offline", "--match-contract",
                         "^TestArbiterRegression$"], cwd=proj)
                start = t.stdout.find("{")
                res = {}
                if start >= 0:
                    for suite in json.loads(t.stdout[start:]).values():
                        for tn, tr in (suite.get("test_results") or {}).items():
                            res[tn.split("(")[0]] = tr.get("status") == "Success"
                honest = [v for k, v in res.items() if k.startswith("testHonestPath")]
                reg_ok = res.get("testExploitBlocked") is False and len(honest) == 4 and all(honest)
                reg_note = (f"{REGRESSION_DIR}: ExploitBlocked "
                            f"{'fails (attack works)' if res.get('testExploitBlocked') is False else res.get('testExploitBlocked')}, "
                            f"{sum(honest)}/4 honest pass" if res else
                            f"no test ran: {(t.stdout + t.stderr).strip().splitlines()[-1:]}")
            route = "one-file repo" if ex["repo"] else "hermetic"
            want_route = "one-file repo" if p.startswith("0.7") else "hermetic"
            ok &= (err is None and ctx.get("ok") and ctx.get("solc") == p and proven
                   and measured and reg_ok and route == want_route)
            notes.append(f"{p}: gate compile check {'admits' if err is None else 'REFUSES ' + str(err)}, "
                         f"context solc {ctx.get('solc')}, test pragma {ws.pragma}, "
                         f"victim-loss exploit {'proven' if proven else 'NOT proven'}; A/B/G "
                         f"({route}) {base['status']}"
                         + (f" A={abg[0]['A'] / 1e18:g} B={abg[0]['B'] / 1e18:g} ETH" if measured else
                            f" {base.get('reason')} {str(base.get('error') or '')[:60]}")
                         + f"; regression {reg_note}")
    return bool(ok), "; ".join(notes)


# -- 4 -------------------------------------------------------------------------------------
def c4(tmp: Path) -> tuple[bool, str]:
    from arbiter import gate, webui
    from arbiter.workspace import _first_error
    job = tmp / "c4"
    want = {
        "0.5.17": f"context_unbuildable: 沙箱裡沒有 solc 0.5.17（目前支援 {SUPPORTED}；ARBITER 的測試程式需要 solc 0.7.4 以上）",
        "0.8.38": f"context_unbuildable: 沙箱裡沒有 solc 0.8.38（目前支援 {SUPPORTED}）",
        "^0.6.12": ("context_unbuildable: ARBITER 的測試程式需要 solc 0.7.4 以上，這份合約的 pragma（^0.6.12）"
                    f"只接受更舊的版本，所以目前沒辦法稽核（沙箱裡可用 {SUPPORTED}）"),
    }
    # A genuine compile error (msg.valu), below 0.8 and at 0.8: the same solc diagnostic and
    # line either way. Below 0.8 it used to be the hermetic probe's version mismatch.
    typo_want = ('context_unbuildable: Error (9582): Member "valu" not found or not visible after '
                 'argument-dependent lookup in msg. --> src/Target.sol:5:62:')
    got, typo, pinned = {}, {}, ""
    t0 = time.monotonic()
    with JobSandbox(job, "solcprobe4") as env, applied_env(env):
        for p in want:
            code = BANK.format(p=p).replace("call{value: a}(\"\")", "call.value(a)(\"\")") \
                if p == "0.5.17" else BANK.format(p=p)
            item = repo_item(job, "g" + p.replace(".", "").replace("^", "c"), code)
            got[p] = gate._hermetic_compile_error(code, job / ("w" + p.replace(".", "").replace("^", "c")), item)
        for p in ("^0.7.0", "^0.8.0"):
            code = BANK.format(p=p).replace("msg.value", "msg.valu")
            tag = "t" + p.replace(".", "").replace("^", "c")
            typo[p] = gate._hermetic_compile_error(code, job / ("w" + tag), repo_item(job, tag, code))
        ok_b, _, out = forge_build(job / "pinned", BANK.format(p="^0.5.0"), pin="0.5.17")
        pinned = _first_error(out, "0.5.17")
    took = time.monotonic() - t0
    page_missing = webui.verdict_card({"verdict": "not_executed", "reason": "context_unbuildable",
                                       "detail": got["0.8.38"]})
    page_plain = webui.verdict_card({"verdict": "not_executed", "reason": "context_unbuildable",
                                     "detail": "context_unbuildable: Error (2314): Expected ';' but got '}'"})
    ok = (got == want and not ok_b and pinned == f"沙箱裡沒有 solc 0.5.17（目前支援 {SUPPORTED}）"
          and "改成上面列出的其中一個版本" in page_missing and "沙箱不能連網" in page_missing
          and "forge build" not in page_missing and "forge build" in page_plain
          and typo == {"^0.7.0": typo_want, "^0.8.0": typo_want})
    detail = "; ".join(f"{p} -> {got[p]!r}" + ("" if got[p] == want[p] else f" (WANTED {want[p]!r})")
                       for p in want)
    detail += "; " + "; ".join(f"{p} with msg.valu -> {typo[p]!r}"
                               + ("" if typo[p] == typo_want else " (WANTED the solc diagnostic and line)")
                               for p in typo)
    return ok, (f"{detail}; foundry.toml pinned 0.5.17 -> {pinned!r}; result page advice switches "
                f"to the pragma advice: {'改成上面列出的其中一個版本' in page_missing} (plain compile "
                f"error keeps the forge build advice: {'forge build' in page_plain}); {took:.0f}s")


# -- 5 -------------------------------------------------------------------------------------
_NET = r"""
import socket
for host, port in [("1.1.1.1", 443), ("github.com", 443), ("binaries.soliditylang.org", 443)]:
    try:
        socket.create_connection((host, port), timeout=3).close(); print("REACHED", host)
    except OSError as exc:
        print("blocked", host, type(exc).__name__)
"""


def c5(tmp: Path) -> tuple[bool, str]:
    job = tmp / "c5"
    with JobSandbox(job, "solcprobe5") as env, applied_env(env):
        name = env["ARBITER_SANDBOX_CONTAINER"]
        info = json.loads(run(["docker", "inspect", name]).stdout)[0]["HostConfig"]
        (job / "net.py").write_text(_NET, encoding="utf-8")
        net = run([EXEC, "python3", "net.py"], cwd=job).stdout.split("\n")
        w_svm = run([EXEC, "sh", "-c", "touch /home/arbiter/.svm/0.8.24/x"], cwd=job)
        w_root = run([EXEC, "sh", "-c", "touch /x"], cwd=job)
        w_job = run([EXEC, "sh", "-c", f"touch {job}/ok && echo yes"], cwd=job)
    reached = [ln for ln in net if ln.startswith("REACHED")]
    ok = (info["NetworkMode"] == "none" and info["ReadonlyRootfs"] is True and not reached
          and len([ln for ln in net if ln.startswith("blocked")]) == 3
          and w_svm.returncode != 0 and "Read-only" in w_svm.stderr
          and w_root.returncode != 0 and w_job.stdout.strip() == "yes")
    return ok, (f"NetworkMode {info['NetworkMode']}, ReadonlyRootfs {info['ReadonlyRootfs']}; "
                f"outbound blocked {3 - len(reached)}/3 (incl. binaries.soliditylang.org); "
                f"write into ~/.svm: {w_svm.stderr.strip()[-40:]!r}; write to /: refused "
                f"{w_root.returncode != 0}; job dir writable {w_job.stdout.strip() == 'yes'}")


# -- 6 -------------------------------------------------------------------------------------
def _gate(tmp: Path, name: str, src: Path, image: str | None) -> tuple[dict, list[dict]]:
    """gate --file <src> --sandbox on, with no key and a closed model port: no request."""
    out, events = tmp / f"{name}.gate.json", tmp / f"{name}.events.jsonl"
    env = {k: v for k, v in os.environ.items()
           if k not in ("ARBITER_API_KEY", "AIS3_API_KEY", "OPENAI_API_KEY", "ARBITER_SANDBOX_IMAGE")}
    env.update(ARBITER_BASE_URL="http://127.0.0.1:9/v1", AIS3_BASE_URL="http://127.0.0.1:9/v1")
    if image:
        env["ARBITER_SANDBOX_IMAGE"] = image
    subprocess.run([sys.executable, "-m", "arbiter.gate", "--file", str(src), "--sandbox", "on",
                    "--slither", "off", "--out", str(out), "--events", str(events),
                    "--workdir", str(tmp / f"{name}-w")],
                   cwd=RIG, env=env, capture_output=True, text=True, timeout=900)
    rep = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
    evs = [json.loads(ln) for ln in events.read_text(encoding="utf-8").splitlines()
           if ln.strip()] if events.exists() else []
    return rep, evs


def c6(tmp: Path) -> tuple[bool, str]:
    reg = REPO / "me" / "contracts" / "src" / "AuditRegistry.sol"
    old = tmp / "Old0517.sol"
    old.write_text(BANK.format(p="0.5.17").replace("call{value: a}(\"\")", "call.value(a)(\"\")"),
                   encoding="utf-8")
    notes, ok = [], True
    for name, src, image in (("me1", reg, None), ("p3", reg, "arbiter-sandbox:p3"),
                             ("old", old, None)):
        rep, evs = _gate(tmp, name, src, image)
        f = (rep.get("files") or [{}])[0]
        inp = rep.get("input") or {}
        kinds = [e.get("type") or e.get("kind") or e.get("event") for e in evs]
        compiled = "compile_ok" in kinds
        notes.append(f"{name}: image {inp.get('sandbox', {}).get('image')}, compile stage "
                     f"{'passed' if compiled else 'did not pass'}, verdict {f.get('verdict')}, "
                     f"reason {f.get('reason')}, detail {str(f.get('detail'))[:110]!r}, "
                     f"requests {inp.get('llm_requests_this_invocation')}")
        if name == "me1":
            ok &= compiled and inp.get("sandbox", {}).get("image") == "arbiter-sandbox:me1" \
                and "solc" not in str(f.get("detail"))
        elif name == "p3":
            ok &= (not compiled and f.get("verdict") == "not_executed"
                   and str(f.get("detail")).startswith("context_unbuildable: 沙箱裡沒有 solc 0.8.24（目前支援 0.8.20、0.8.37）")
                   and inp.get("llm_requests_this_invocation") == 0)
        else:
            ok &= (not compiled and f.get("verdict") == "not_executed"
                   and str(f.get("detail")).startswith("context_unbuildable: 沙箱裡沒有 solc 0.5.17")
                   and inp.get("llm_requests_this_invocation") == 0)
    left = [n for n in sandbox.running() if n.startswith("arbiter-sbx-")]
    ok &= not left
    return bool(ok), "; ".join(notes) + f"; containers left {left or 'none'}"


# -- 7 -------------------------------------------------------------------------------------
def c7(tmp: Path) -> tuple[bool, str]:
    """Slither picks forge's solc from the HOST's ~/.svm by pragma and the wrapper maps it to
    /opt/svm; on p3 every pin the host had but the image lacked failed with "No such file"."""
    from arbiter.static_hints import run_slither
    reg = (REPO / "me" / "contracts" / "src" / "AuditRegistry.sol").read_text(encoding="utf-8")
    job = tmp / "c7"
    out = []
    with JobSandbox(job, "solcprobe7") as env, applied_env(env):
        for name, code, want in (("AuditRegistry.sol", reg, "0.8.24"),
                                 ("Bank.sol", BANK.format(p="0.7.6"), "0.7.6")):
            d = run_slither(code, name, job / name[:-4], timeout=180).as_dict()
            out.append((name, d["status"] == "ran" and d["solc"] == want, d["status"], d["solc"],
                        d["findings_total"], d.get("reason") or ""))
    return all(o[1] for o in out), "; ".join(
        f"{n}: Slither {s} with solc {v}, {k} findings" + (f" ({r[:80]})" if s != "ran" else "")
        for n, _, s, v, k, r in out)


CHECKS = [("image and lock", c1), ("exact pragmas build", c2), ("audit machinery", c3),
          ("zh-TW reasons", c4), ("isolation unchanged", c5), ("gate end to end", c6),
          ("Slither exact pins", c7)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", type=int, default=0)
    args = ap.parse_args()
    ok, why = sandbox.available()
    if not ok:
        print(f"sandbox unavailable: {why}")
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="sandbox-solc-"))
    passed = 0
    chosen = [(i, c) for i, c in enumerate(CHECKS, 1) if not args.only or i == args.only]
    try:
        for i, (name, fn) in chosen:
            t0 = time.monotonic()
            try:
                res, detail = fn(tmp)
            except Exception as exc:  # noqa: BLE001
                res, detail = False, f"{type(exc).__name__}: {exc}"
            print(f"  [{'OK  ' if res else 'FAIL'}] {i} {name:20s} {detail}  ({time.monotonic() - t0:.1f}s)")
            passed += bool(res)
    finally:
        for n in sandbox.running():
            if n.startswith("arbiter-sbx-solcprobe"):
                sandbox.remove(n)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    left = sandbox.running()
    print(f"\n{passed}/{len(chosen)} passed; sandbox containers left: {left or 'none'}")
    return 0 if passed == len(chosen) and not left else 1


if __name__ == "__main__":
    raise SystemExit(main())
