#!/usr/bin/env python3
"""Smallest MCP client for scripts/arbiter_mcp.py: does the server start, list its tools,
and adjudicate a tool call on today's harness?

Speaks newline-delimited JSON-RPC over stdio, exactly what an MCP host sends:
initialize -> notifications/initialized -> tools/list -> tools/call read_source ->
tools/call run_exploit (victim_probe's DRAIN on V_reentrancy_unstake, which the harness
must prove) -> tools/call run_exploit (the same attack on S_reentrancy_unstake, which it
must refuse) -> EOF. The server runs forge only; it never talks to a model -- the model is
whoever drives the server -- so this probe sends no LLM request.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG / "scripts"))

import victim_probe as vp  # noqa: E402


class Client:
    def __init__(self, source: Path, root: Path, outcome: Path) -> None:
        self.proc = subprocess.Popen(  # noqa: S603
            [sys.executable, str(RIG / "scripts" / "arbiter_mcp.py"), "--source", str(source),
             "--sample-id", "mcp-probe", "--root", str(root), "--outcome", str(outcome)],
            cwd=RIG, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        self.next_id = 0

    def send(self, method: str, params: dict | None = None, notify: bool = False) -> dict | None:
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            self.next_id += 1
            msg["id"] = self.next_id
        assert self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        if notify:
            return None
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(f"server closed: {self.proc.stderr.read()[-500:] if self.proc.stderr else ''}")
        return json.loads(line)

    def close(self) -> int:
        assert self.proc.stdin
        self.proc.stdin.close()
        return self.proc.wait(timeout=60)


def call(c: Client, name: str, args: dict) -> str:
    r = c.send("tools/call", {"name": name, "arguments": args})
    return r["result"]["content"][0]["text"]


def drain_args() -> dict:
    return {"name": "McpDrain", "predicate": "victim_loss",
            "hypothesis": "unstake() pays before clearing stakeOf; re-entering drains the pool",
            **vp.DRAIN}


def main() -> int:
    if shutil.which("forge") is None:
        print("forge not on PATH")
        return 1
    tmp = Path(tempfile.mkdtemp(prefix="mcp-probe-"))
    ok = []
    try:
        for label, sample, want in (("V", "V_reentrancy_unstake", True),
                                    ("S", "S_reentrancy_unstake", False)):
            src = tmp / f"{sample}.sol"
            src.write_text(vp.load(sample), encoding="utf-8")
            outcome = tmp / f"{label}.outcome.json"
            c = Client(src, tmp / f"ws-{label}", outcome)
            t0 = time.monotonic()
            init = c.send("initialize", {"protocolVersion": "2024-11-05", "capabilities": {},
                                         "clientInfo": {"name": "mcp_probe", "version": "1"}})
            c.send("notifications/initialized", notify=True)
            tools = [t["name"] for t in c.send("tools/list")["result"]["tools"]]
            if label == "V":
                print(f"  initialize: server {init['result']['serverInfo']}, "
                      f"protocol {init['result']['protocolVersion']}")
                print(f"  tools/list: {len(tools)} tools: {', '.join(tools)}")
                text = call(c, "read_source", {"start_line": 1, "end_line": 6})
                print(f"  tools/call read_source: {len(text)} chars, first line "
                      f"{text.splitlines()[0][:70]!r}")
                ok.append(len(tools) >= 5 and "run_exploit" in tools and "pragma" in text)
            text = call(c, "run_exploit", drain_args())
            rc = c.close()
            rec = json.loads(outcome.read_text(encoding="utf-8"))
            proven = any(p.get("passed") and p.get("adjudicated") for p in rec.get("pocs", []))
            first = next((ln for ln in text.splitlines() if ln.strip()), "")
            print(f"  tools/call run_exploit DRAIN on {sample}: adjudicated pass={proven} "
                  f"(want {want}); server rc {rc}; {time.monotonic() - t0:.1f}s")
            print(f"      reply: {first[:150]}")
            ok.append(proven == want and rc == 0)
        print(f"\n{sum(ok)}/{len(ok)} as expected (no LLM request: the server runs forge only)")
        return 0 if all(ok) else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
