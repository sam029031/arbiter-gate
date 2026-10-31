#!/usr/bin/env python3
"""The seven sandbox assertions (plan Step 3 / risk R9), as one repeatable test.

    python3 service/tests/sandbox_assertions.py [--only N]

  1  nothing inside the container reaches out: internet, DNS, the host (its LAN address
     and the container's own 127.0.0.1), the DGX tunnel port, a forge fork cheatcode
  2  forge sees PATH and nothing else: a Solidity test reads AIS3_API_KEY & co. (set to
     fake secrets in the caller) and the host's .env, and gets neither
  3  every pragma the evalsets and examples use compiles with no network (auto-detect
     -> 0.8.37, pinned 0.8.20, the harness's own Vm.sol stub)
  4  a sandboxed gate run never imports arbiter.onchain
  5  a job that overruns is ended and leaves nothing: a SIGKILLed caller's in-container
     process, a parent that died without cleaning up (job_max), the web page's timeout
     (reported as not executed, container removed)
  6  two jobs get different directories, run ids and containers, and one container
     cannot see the other job's directory; a second job waits for the first
  7  the model is still reachable from OUTSIDE the container (api_smoke, with the
     sandbox's environment applied). Sends one request to the model host, so it is
     SKIPPED while the pre-registered eval (gptoss-v3-*) is running.

No assertion except 7 sends anything to the model host. 5's web-timeout case points the
gateway at a closed local port, so it waits without reaching any server.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
RIG = REPO / "arbiter"
sys.path.insert(0, str(RIG))

from arbiter import sandbox  # noqa: E402
from arbiter.sandbox import JobSandbox, applied_env  # noqa: E402

EXEC = sandbox.SERVICE_BIN / "_sandbox_exec"
# Placeholder values (not key-shaped, so the repository's secret scan does not flag them).
FAKE = {"AIS3_API_KEY": "PLACEHOLDER_AIS3_KEY", "ARBITER_API_KEY": "PLACEHOLDER_ARBITER_KEY",
        "AIS3_BASE_URL": "http://fake.invalid/v1", "OPENAI_API_KEY": "PLACEHOLDER_OPENAI_KEY"}


def run(cmd: list[str], env: dict[str, str] | None = None, cwd: Path | None = None,
        timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, env={**os.environ, **(env or {})}, cwd=cwd,
                          capture_output=True, text=True, timeout=timeout)


def project(root: Path, test_sol: str, extra_toml: str = "") -> Path:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "test").mkdir(parents=True, exist_ok=True)
    (root / "foundry.toml").write_text(
        '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\nlibs = []\n'
        f"auto_detect_solc = true\n{extra_toml}", encoding="utf-8")
    (root / "test" / "T.t.sol").write_text(test_sol, encoding="utf-8")
    return root


def host_ip() -> str:
    out = run(["hostname", "-I"]).stdout.split()
    return out[0] if out else "127.0.0.1"


# -- 1 -------------------------------------------------------------------------------------
_PROBE = r"""
import socket, sys
fails = []
for host, port in [("1.1.1.1", 443), ("8.8.8.8", 53), ("github.com", 443),
                   ("host.docker.internal", 11434), ("127.0.0.1", 11434),
                   ("127.0.0.1", 8765), (sys.argv[1], int(sys.argv[2])),
                   (sys.argv[1], 11434), (sys.argv[1], 8765)]:
    try:
        socket.create_connection((host, port), timeout=3).close()
        print(f"REACHED {host}:{port}")
    except OSError as exc:
        print(f"blocked {host}:{port} ({type(exc).__name__})")
"""

_FORK_TEST = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface Vm { function createSelectFork(string calldata) external returns (uint256); }
contract T {
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    function testForkMustFail() public {
        try vm.createSelectFork("https://cloudflare-eth.com") returns (uint256) {
            revert("FORK REACHED THE NETWORK");
        } catch {}
    }
}
"""


def a1(tmp: Path) -> tuple[bool, str]:
    # A listener on the host, so "unreachable" is measured against something that exists.
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    threading.Thread(target=lambda: [srv.accept()[0].close() for _ in range(20)],
                     daemon=True).start()
    try:
        host_reach = socket.create_connection((host_ip(), port), timeout=3)
        host_reach.close()
        control = "host listener reachable from the host itself (control ok)"
    except OSError:
        control = "host listener NOT reachable even from the host"
    job = tmp / "a1"
    with JobSandbox(job, "assert1") as env, applied_env(env):
        (job / "probe.py").write_text(_PROBE, encoding="utf-8")
        r = run([str(EXEC), "python3", "probe.py", host_ip(), str(port)], cwd=job)
        proj = project(job / "fork", _FORK_TEST)
        f = run([str(sandbox.SERVICE_BIN / "forge"), "test", "-vv"], cwd=proj)
    srv.close()
    lines = r.stdout.strip().splitlines()
    reached = [ln for ln in lines if ln.startswith("REACHED")]
    fork_ok = "[PASS] testForkMustFail()" in f.stdout
    ok = len(lines) == 9 and not reached and fork_ok and "control ok" in control
    return ok, (f"{len(lines) - len(reached)}/9 destinations blocked "
                f"({', '.join(ln.split()[1] for ln in lines[:4])}, host {host_ip()}:{port}/11434/8765, "
                f"container 127.0.0.1); fork cheatcode failed: {fork_ok}; {control}"
                + (f"; REACHED: {reached}" if reached else ""))


# -- 2 -------------------------------------------------------------------------------------
def _env_test(dotenv: str) -> str:
    checks = "\n".join(
        f'        require(keccak256(bytes(vm.envOr("{k}", string("ABSENT")))) == '
        f'keccak256("ABSENT"), "{k} visible");' for k in FAKE)
    return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface Vm {{
    function envOr(string calldata, string calldata) external view returns (string memory);
    function readFile(string calldata) external view returns (string memory);
}}
contract T {{
    Vm constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);
    function testNoSecrets() public view {{
{checks}
        require(bytes(vm.envOr("PATH", string(""))).length > 0, "PATH missing");
        require(keccak256(bytes(vm.envOr("HOME", string("ABSENT")))) == keccak256("ABSENT"), "HOME visible");
    }}
    function testNoDotEnv() public view {{
        try vm.readFile("{dotenv}") returns (string memory s) {{
            revert(string(abi.encodePacked("READ .env: ", s)));
        }} catch {{}}
    }}
}}
"""


def a2(tmp: Path) -> tuple[bool, str]:
    dotenv = str(REPO / ".env")
    job = tmp / "a2"
    with JobSandbox(job, "assert2") as env, applied_env({**env, **FAKE}):
        assert all(os.environ.get(k) == v for k, v in FAKE.items())  # really in the caller
        # fs_permissions opened to "/" on purpose: the file must be absent, not just denied.
        proj = project(job / "env", _env_test(dotenv),
                       'fs_permissions = [{ access = "read", path = "/" }]\n')
        f = run([str(sandbox.SERVICE_BIN / "forge"), "test", "-vv"], cwd=proj)
        e = run([str(EXEC), "env"], cwd=job)
    names = sorted(line.split("=", 1)[0] for line in e.stdout.splitlines() if "=" in line)
    passed = [t for t in ("testNoSecrets()", "testNoDotEnv()") if f"[PASS] {t}" in f.stdout]
    ok = len(passed) == 2 and names == ["PATH"] and Path(dotenv).exists()
    return ok, (f"forge tests passed {len(passed)}/2 (secrets absent, host .env unreadable "
                f"though fs_permissions allowed /); `env` inside: {names}; "
                f"caller held {len(FAKE)} fake keys")


# -- 3 -------------------------------------------------------------------------------------
def a3(tmp: Path) -> tuple[bool, str]:
    from arbiter.workspace import VM_SOL
    v3 = json.loads((RIG / "evalsets" / "v3_authored.json").read_text())["items"]
    tp = json.loads((RIG / "evalsets" / "test_pairs_v2.json").read_text())["pairs"]
    sources = {
        "StakingVault (examples)": (RIG / "examples" / "StakingVault.sol").read_text(),
        f"v3 {v3[0]['id']}": v3[0]["code"],
        f"v3 {v3[-1]['id']}": v3[-1]["code"],
        f"test_pairs_v2 {tp[0]['slug']} (vuln)": tp[0]["vulnerable_code"],
        f"test_pairs_v2 {tp[-1]['slug']} (patched)": tp[-1]["patched_code"],
        "harness Vm.sol (>=0.8.0)": VM_SOL.replace("__PRAGMA__", ">=0.8.0"),
    }
    job = tmp / "a3"
    results = []
    with JobSandbox(job, "assert3") as env, applied_env(env):
        for i, (label, code) in enumerate(sources.items()):
            for solc in ("", "0.8.20"):
                proj = job / f"p{i}{solc.replace('.', '')}"
                (proj / "src").mkdir(parents=True)
                (proj / "src" / "C.sol").write_text(code, encoding="utf-8")
                pin = f'solc = "{solc}"' if solc else "auto_detect_solc = true"
                (proj / "foundry.toml").write_text(
                    f'[profile.default]\nsrc = "src"\nout = "out"\nlibs = []\n{pin}\n',
                    encoding="utf-8")
                # Without --offline, as workspace.py calls it: no network must still work.
                r = run([str(sandbox.SERVICE_BIN / "forge"), "build"], cwd=proj)
                used = sorted({json.loads(p.read_text()).get("rawMetadata") and
                               json.loads(json.loads(p.read_text())["rawMetadata"])["compiler"]["version"].split("+")[0]
                               for p in (proj / "out").glob("*/*.json")} - {None}) if r.returncode == 0 else []
                results.append((label, solc or "auto", r.returncode == 0, used))
    bad = [r for r in results if not r[2]]
    auto = sorted({v for r in results if r[1] == "auto" for v in r[3]})
    ok = not bad and auto == ["0.8.37"]
    return ok, (f"{len(results) - len(bad)}/{len(results)} builds offline "
                f"({len(sources)} sources x auto/0.8.20); auto-detect used {auto}"
                + (f"; FAILED: {bad}" if bad else ""))


# -- 4 -------------------------------------------------------------------------------------
def a4(tmp: Path) -> tuple[bool, str]:
    code = (
        "import sys, argparse\n"
        f"sys.path.insert(0, {str(RIG)!r})\n"
        "from arbiter import gate\n"
        "import arbiter.web\n"
        "a = gate.main(['--from-results', 'runs/spark-test-2.results.jsonl', '--sandbox', 'on',"
        f"'--out', {str(tmp / 'a4.json')!r}, '--workdir', {str(tmp / 'a4w')!r}])\n"
        "print('ONCHAIN_IMPORTED' if 'arbiter.onchain' in sys.modules else 'onchain not imported', a)\n")
    r = run([sys.executable, "-c", code], cwd=RIG)
    rep = json.loads((tmp / "a4.json").read_text()) if (tmp / "a4.json").exists() else {}
    ok = "onchain not imported 1" in r.stdout and rep.get("input", {}).get("sandbox", {}).get("status") == "on"
    return ok, (f"sandboxed gate (spark-test-2 replay, rc 1) + arbiter.web imported: "
                f"{r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-200:]}")


# -- 5 -------------------------------------------------------------------------------------
def a5(tmp: Path) -> tuple[bool, str]:
    notes, ok = [], True
    # (a) the caller is SIGKILLed (what subprocess.run(timeout=) does to the wrapper)
    job = tmp / "a5a"
    box = JobSandbox(job, "assert5a")
    env = box.__enter__()
    try:
        with applied_env(env):
            p = subprocess.Popen([str(EXEC), "sleep", "300"], cwd=job)
            time.sleep(2)
            p.send_signal(signal.SIGKILL)
            p.wait()
            inside = run(["docker", "exec", box.name, "pgrep", "-x", "sleep"]).stdout.split()
            # pid 1 is the container's own `sleep <job_max>`
            notes.append(f"after SIGKILL of the caller, in-container sleep pids {inside}")
    finally:
        box.__exit__(None, None, None)
    gone = box.name not in sandbox.running()
    host_left = run(["pgrep", "-f", f"docker exec.*{box.name}"]).stdout.split()
    ok &= gone and not host_left
    notes.append(f"job end: container gone {gone}, host docker-exec left {host_left or 'none'}")
    # (b) the parent dies without cleaning up: the container ends itself at job_max
    job = tmp / "a5b"
    box = JobSandbox(job, "assert5b", job_max_s=4)
    box.__enter__()
    box._unlock()                     # simulate a crashed parent: never call __exit__
    time.sleep(9)
    gone = box.name not in sandbox.running()
    ok &= gone
    notes.append(f"orphaned container (job_max 4 s) gone by itself after 9 s: {gone}")
    # (c) the web page's timeout: not executed, container removed. The gateway points at a
    # closed local port, so the audit waits in retries without reaching any model host.
    from arbiter import web
    saved = {k: os.environ.get(k) for k in ("ARBITER_BASE_URL", "ARBITER_API_KEY", "AIS3_BASE_URL")}
    os.environ.update(ARBITER_BASE_URL="http://127.0.0.1:9/v1", ARBITER_API_KEY="dummy",
                      AIS3_BASE_URL="http://127.0.0.1:9/v1")
    try:
        src = tmp / "a5c" / "TimeoutVault.sol"
        src.parent.mkdir(parents=True, exist_ok=True)
        src.write_text((RIG / "examples" / "StakingVault.sol").read_text(), encoding="utf-8")
        t0 = time.monotonic()
        rep, err = web.run_gate_cli(["--file", str(src), "--mode", "repo", "--workdir",
                                     str(tmp / "a5c" / "w")], timeout=20, sandboxed=True)
        took = time.monotonic() - t0
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    verdict = ((rep or {}).get("files") or [{}])[0].get("verdict")
    left = [n for n in sandbox.running() if n.startswith("arbiter-sbx-web-")]
    ok &= verdict == "not_executed" and not left
    notes.append(f"web job over its 20 s limit ({took:.0f} s): verdict {verdict}, "
                 f"containers left {left or 'none'}")
    return ok, "; ".join(notes)


# -- 6 -------------------------------------------------------------------------------------
def a6(tmp: Path) -> tuple[bool, str]:
    from arbiter import gate
    def ns(**kw):
        base = dict(workdir=str(tmp / "a6w"), from_results=None, file=None, run_id=None)
        base.update(kw)
        return argparse.Namespace(**base)
    jobs = [gate._job_for(ns(file="examples/StakingVault.sol")) for _ in range(2)]
    jobs += [gate._job_for(ns(from_results="runs/spark-test-2.results.jsonl")) for _ in range(2)]
    dirs_distinct = len({str(j[1]) for j in jobs}) == 4
    file_ids_distinct = jobs[0][0] != jobs[1][0]
    a, b = tmp / "a6a", tmp / "a6b"
    b.mkdir(parents=True)
    (b / "secret-of-job-b.txt").write_text("b", encoding="utf-8")
    with JobSandbox(a, "assert6a") as env, applied_env(env):
        seen = run([str(EXEC), "ls", str(b)], cwd=a)
        waited = "no"
        try:
            JobSandbox(b, "assert6b", lock_timeout_s=2).__enter__()
            waited = "NOT BLOCKED"
        except RuntimeError:
            waited = "blocked (another sandbox job is running)"
    hidden = seen.returncode != 0
    names = {sandbox.container_name(j[0]) for j in jobs[:2]}
    ok = dirs_distinct and file_ids_distinct and hidden and len(names) == 2 and waited.startswith("blocked")
    return ok, (f"4 job dirs distinct {dirs_distinct}; file run ids distinct {file_ids_distinct}; "
                f"containers {len(names)} distinct; job A sees job B's dir: {not hidden}; "
                f"second job while one runs: {waited}")


# -- 7 -------------------------------------------------------------------------------------
def a7(tmp: Path) -> tuple[bool | None, str]:
    busy = run(["pgrep", "-af", "gptoss-v3"]).stdout
    busy = [ln for ln in busy.splitlines() if "pgrep" not in ln and "sandbox_assertions" not in ln]
    if busy:
        return None, "SKIPPED: the pre-registered eval (gptoss-v3-*) is running; rerun after it ends"
    dotenv = REPO / ".env"
    extra: dict[str, str] = {}
    if dotenv.exists():
        for line in dotenv.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                extra[k.strip()] = v.strip()
    job = tmp / "a7"
    with JobSandbox(job, "assert7") as env:
        r = run([sys.executable, "scripts/api_smoke.py"], env={**extra, **env}, cwd=RIG,
                timeout=200)
    first = (r.stdout or r.stderr).strip().splitlines()[:1]
    return r.returncode == 0, (f"api_smoke from the host with the sandbox environment "
                               f"(forge -> service/bin): rc {r.returncode}, {first}")


ASSERTIONS = [("network blocked", a1), ("PATH only", a2), ("offline pragmas", a3),
              ("onchain not imported", a4), ("timeouts leave nothing", a5),
              ("jobs isolated", a6), ("model reachable outside", a7)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", type=int, default=0)
    args = ap.parse_args()
    ok, why = sandbox.available()
    if not ok:
        print(f"sandbox unavailable: {why}")
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="sandbox-assert-"))
    passed = skipped = 0
    chosen = [(i, a) for i, a in enumerate(ASSERTIONS, 1) if not args.only or i == args.only]
    try:
        for i, (name, fn) in chosen:
            t0 = time.monotonic()
            try:
                res, detail = fn(tmp)
            except Exception as exc:  # noqa: BLE001
                res, detail = False, f"{type(exc).__name__}: {exc}"
            tag = "SKIP" if res is None else ("OK  " if res else "FAIL")
            print(f"  [{tag}] {i} {name:24s} {detail}  ({time.monotonic() - t0:.1f}s)")
            passed += res is True
            skipped += res is None
    finally:
        for n in sandbox.running():
            if n.startswith("arbiter-sbx-assert"):
                sandbox.remove(n)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    left = sandbox.running()
    print(f"\n{passed}/{len(chosen)} passed, {skipped} skipped; sandbox containers left: {left or 'none'}")
    return 0 if passed + skipped == len(chosen) and not left else 1


if __name__ == "__main__":
    raise SystemExit(main())
