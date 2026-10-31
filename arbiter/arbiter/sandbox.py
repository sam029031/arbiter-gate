"""One job, one container: forge / anvil / cast / Slither run inside, the model stays out.

    with JobSandbox(job_dir, name) as env:      # env: the variables to run the job with
        ...                                      # forge & co. now resolve to service/bin/*

Why a container (plan Step 3, risk R9): forge inherits the caller's whole environment, an
agent-written test can read it with vm.envString, and an uploaded contract's comments can
ask the agent to. So the harness's own code is unchanged and the *names* it calls --
`shutil.which("forge")` in workspace.py and dump.py, "anvil"/"cast" in live.py, Slither
via $ARBITER_SLITHER -- resolve to wrappers in service/bin that `docker exec` into this
job's container with an environment of PATH only.

The container: image arbiter-sandbox (service/sandbox/build.sh, the host's verified
toolchain), --network none, --read-only root with tmpfs /tmp and ~/.foundry, non-root
(host uid), memory/cpu/pids limits, no capabilities, only the job directory mounted at
its own path. Its main process is `sleep <job_max>`, and it is started with --rm, so even
if every process outside dies it stops and disappears by itself. One sandbox job at a
time (a lock file): Docker and WSL share 7.6 GiB.

When the sandbox is asked for and cannot be had, the caller is told why (`available()`)
and must report "not executed"; nothing here falls back to the host.
"""

from __future__ import annotations

import fcntl
import os
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent.parent       # the repository root
SERVICE_BIN = REPO / "service" / "bin"
IMAGE = os.environ.get("ARBITER_SANDBOX_IMAGE", "arbiter-sandbox:p3")
LABEL = "arbiter.sandbox=1"
LOCK = Path(os.environ.get("ARBITER_SANDBOX_LOCK", "/tmp/arbiter-sandbox.lock"))
JOB_MAX_S = int(os.environ.get("ARBITER_SANDBOX_JOB_MAX", "1800"))
MEMORY = os.environ.get("ARBITER_SANDBOX_MEMORY", "2g")
CPUS = os.environ.get("ARBITER_SANDBOX_CPUS", "2")
UNAVAILABLE_NOTE = ("沙箱無法使用，所以這次沒有執行任何編譯或攻擊，也沒有改在沒有隔離的環境下執行。"
                    "請確認 Docker Desktop 已開啟、沙箱映像已建立（service/sandbox/build.sh）後再試一次。")


def enabled(default: bool = False) -> bool:
    """ARBITER_SANDBOX=1/0 decides; unset means `default` (each caller states its own)."""
    raw = os.environ.get("ARBITER_SANDBOX")
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "on", "yes")


def available() -> tuple[bool, str]:
    """(usable, reason). Checks the docker CLI, the daemon and the image."""
    docker = shutil.which("docker")
    if docker is None:
        return False, "找不到 docker 指令（Docker Desktop 沒有開，或 WSL integration 沒開）"
    try:
        info = subprocess.run([docker, "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"docker 沒有回應（{type(exc).__name__}）"
    if info.returncode != 0:
        return False, "docker daemon 連不上（Docker Desktop 沒有開？）"
    img = subprocess.run([docker, "image", "inspect", IMAGE, "--format", "{{.Id}}"],
                         capture_output=True, text=True, timeout=30)
    if img.returncode != 0:
        return False, f"沙箱映像 {IMAGE} 不存在（先執行 service/sandbox/build.sh）"
    return True, ""


def container_name(run_id: str) -> str:
    return "arbiter-sbx-" + re.sub(r"[^A-Za-z0-9_.-]", "-", run_id)[:80]


def remove(name: str) -> None:
    """Destroy a job's container; safe to call when it is already gone."""
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=60)


def running(label: str = LABEL) -> list[str]:
    out = subprocess.run(["docker", "ps", "-a", "--filter", f"label={label}",
                          "--format", "{{.Names}}"], capture_output=True, text=True, timeout=30)
    return [n for n in out.stdout.split() if n]


class JobSandbox:
    """Context manager: start the job's container, yield the environment, destroy it."""

    def __init__(self, job_dir: Path, run_id: str | None = None, *,
                 job_max_s: int = JOB_MAX_S, lock_timeout_s: int = 1800) -> None:
        self.job = Path(job_dir).resolve()
        self.name = container_name(run_id or uuid.uuid4().hex[:12])
        self.job_max_s = job_max_s
        self.lock_timeout_s = lock_timeout_s
        self._lock_fh: Any = None
        self.started_s: float | None = None
        self.memory_peak: int | None = None

    def _lock(self) -> None:
        LOCK.parent.mkdir(parents=True, exist_ok=True)
        self._lock_fh = LOCK.open("w")
        deadline = time.monotonic() + self.lock_timeout_s
        while True:
            try:
                fcntl.flock(self._lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise RuntimeError("another sandbox job is still running") from None
                time.sleep(1)

    def __enter__(self) -> dict[str, str]:
        self._lock()
        self.job.mkdir(parents=True, exist_ok=True)
        (self.job / "tmp").mkdir(exist_ok=True)
        remove(self.name)  # a leftover with this name would make `docker run` fail
        t0 = time.monotonic()
        cmd = ["docker", "run", "-d", "--rm", "--name", self.name, "--label", LABEL,
               "--network", "none", "--read-only",
               "--tmpfs", "/tmp:rw,exec,size=512m",
               "--tmpfs", "/home/arbiter/.foundry:rw,size=64m",
               # crytic-compile (Slither) imports solc-select, which creates this on start.
               "--tmpfs", "/home/arbiter/.solc-select:rw,size=16m",
               "--memory", MEMORY, "--memory-swap", MEMORY, "--cpus", CPUS,
               "--pids-limit", "512", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges",
               "--user", f"{os.getuid()}:{os.getgid()}",
               "-v", f"{self.job}:{self.job}:rw",
               IMAGE, "sleep", str(self.job_max_s)]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            self._unlock()
            raise RuntimeError(f"沙箱容器啟動失敗：{(proc.stderr or proc.stdout).strip()[-200:]}")
        self.started_s = round(time.monotonic() - t0, 2)
        return {
            "PATH": f"{SERVICE_BIN}{os.pathsep}{os.environ.get('PATH', '')}",
            "ARBITER_SANDBOX_CONTAINER": self.name,
            "ARBITER_SANDBOX_JOB_DIR": str(self.job),
            "ARBITER_SANDBOX_JOB_MAX": str(self.job_max_s),
            "ARBITER_SLITHER": str(SERVICE_BIN / "slither"),
            "TMPDIR": str(self.job / "tmp"),
        }

    def _unlock(self) -> None:
        if self._lock_fh is not None:
            fcntl.flock(self._lock_fh, fcntl.LOCK_UN)
            self._lock_fh.close()
            self._lock_fh = None

    def memory_peak_bytes(self) -> int | None:
        """The container's cgroup high-water mark (cgroup v2 memory.peak)."""
        out = subprocess.run(["docker", "exec", self.name, "cat", "/sys/fs/cgroup/memory.peak"],
                             capture_output=True, text=True, timeout=30)
        return int(out.stdout.strip()) if out.returncode == 0 and out.stdout.strip().isdigit() else None

    def __exit__(self, *exc: Any) -> None:
        try:
            self.memory_peak = self.memory_peak_bytes()
            remove(self.name)
        finally:
            self._unlock()


class applied_env:
    """Temporarily apply a JobSandbox environment to this process (os.environ)."""

    def __init__(self, env: dict[str, str]) -> None:
        self.env = env
        self.saved: dict[str, str | None] = {}

    def __enter__(self) -> None:
        for k, v in self.env.items():
            self.saved[k] = os.environ.get(k)
            os.environ[k] = v

    def __exit__(self, *exc: Any) -> None:
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def main(argv: list[str] | None = None) -> int:
    """python3 -m arbiter.sandbox exec [--job DIR] -- <command...>

    Run one of our own scripts (live_attack.py, patch_probe.py, ...) with every forge /
    anvil / cast call inside a fresh job container. The command itself runs on the host
    (it may call the model); its toolchain does not."""
    import argparse
    import sys
    import tempfile

    ap = argparse.ArgumentParser(prog="python3 -m arbiter.sandbox")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ex = sub.add_parser("exec")
    ex.add_argument("--job", type=Path, default=None)
    ex.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        ap.error("no command")
    ok, why = available()
    if not ok:
        print(f"sandbox unavailable: {why}", file=sys.stderr)
        return 125
    job = args.job or Path(tempfile.mkdtemp(prefix="arbiter-sbx-job-"))
    with JobSandbox(job, f"exec-{uuid.uuid4().hex[:8]}") as env:
        proc = subprocess.run(command, env={**os.environ, **env})
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
