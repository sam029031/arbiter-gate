#!/usr/bin/env python3
"""The strict re-proof after a loose proof, end to end with a scripted model (no LLM).

run_arbiter(strict_retry=True) follows an outcome proven only under a loose predicate
with one more audit offered only victim_loss / liveness_broken and briefed with the loose
PoC. Everything here is real except the model: the gateway is a script that answers each
turn with a fixed tool call, and the exploits run on forge against V_reentrancy_unstake.

  1. loose then strict success: the row records strict_retry proven (turns, requests);
     the strict PoC is FIRST, so patch.exploit_from_row and report_arm.winning_predicate
     take it; the retry was offered only the strict pair and its brief carried the loose
     PoC's full solidity; gate._file_entry measures A/B/G and puts strict_retry on the
     finding;
  2. loose then strict failure: the loose proof is kept (still proven, loose PoC first,
     not patched), the retry's attempts are appended, strict_retry not_proven sits on the
     loose finding;
  3. strict first: no retry, no extra request;
  4. strict_retry off: a loose proof is left alone (the old behaviour);
  5. a retry whose gateway raises: status error, the loose proof kept.
  6. eval_requeue.py requeues a row whose retry lost the gateway, and only that.
  7. the retry reuses the loose PoC's name (its brief says "reuse the attack"): the
     evidence-ladder dump (rung 2) takes the PoC the finding cites -- the strict proof
     when the retry succeeds, the loose proof when it fails -- and it reproduces; the
     dump used to take the LAST record of that name (gate-logic-4);
  8. which strict PoC the retry's result is (no forge; the retry audit is fabricated):
     the one its finding cites, not merely the first that passed; with no finding, a
     victim_loss over a liveness_broken run before it; "carried" only then
     (gate-logic-5).

Needs forge. No gateway requests.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))
sys.path.insert(0, str(RIG / "scripts"))

import arbiter.run as run_mod  # noqa: E402
from arbiter import gate  # noqa: E402
from arbiter.gateway import Usage  # noqa: E402
from arbiter.patch import exploit_from_row  # noqa: E402
from arbiter.tools import STRICT_PREDICATES  # noqa: E402

import victim_probe as vp  # noqa: E402
from report_arm import winning_predicate  # noqa: E402

WORK = Path("/tmp/strict-retry-probe")
SAMPLE = "V_reentrancy_unstake"
BRIEF_MARK = "An earlier audit of this exact contract demonstrated an attack"

LOOSE = {"name": "LooseDrain", "predicate": "eth_profit", "mode": "contract",
         "hypothesis": "unstake() pays before zeroing stakeOf, so re-entering pays twice",
         "deploy_code": vp.DRAIN["deploy_code"], "attacker_code": vp.DRAIN["attacker_code"],
         "honest_body": "target.stake{value: 1 ether}(); target.unstake();"}
STRICT = {"name": "StrictDrain", "predicate": "victim_loss",
          "hypothesis": "the same re-entry drains a depositor's stake", **vp.DRAIN}
OFFENDING = '(bool ok, ) = msg.sender.call{value: amount}("");'


def submit(poc: str) -> tuple[str, dict]:
    return ("submit_finding", {"title": "reentrancy in unstake", "vulnerable_function":
                               "unstake", "offending_expression": OFFENDING,
                               "attack_path": "re-enter from receive()", "severity": "high",
                               "vuln_class": "Reentrancy", "poc_name": poc})


SAFE = ("conclude_safe", {"reason": "no depositor loses", "guards_verified": [],
                          "hypotheses_tested": ["re-entry"]})


class ScriptedGateway:
    """Stands in for arbiter.gateway.Gateway. Each audit is told apart by its user
    message: the strict re-proof carries the brief. Every request is recorded."""

    scripts: dict[str, list] = {}
    raise_in_retry = False
    seen: list[dict] = []

    def __init__(self, model: str = "", api_key=None, limiter=None, ledger_path=None,  # noqa: ANN001
                 **_: object) -> None:
        self.usage = Usage()
        self.on_request = None
        self.step = {"main": 0, "retry": 0}

    def chat(self, messages, max_tokens=4096, tools=None, tag="", **_):  # noqa: ANN001
        phase = "retry" if BRIEF_MARK in messages[1]["content"] else "main"
        enum = next(t["function"]["parameters"]["properties"]["predicate"]["enum"]
                    for t in tools or [] if t["function"]["name"] == "run_exploit")
        ScriptedGateway.seen.append({"phase": phase, "enum": enum,
                                     "user": messages[1]["content"]})
        if phase == "retry" and ScriptedGateway.raise_in_retry:
            raise RuntimeError("scripted gateway failure")
        script = ScriptedGateway.scripts[phase]
        name, args = script[min(self.step[phase], len(script) - 1)]
        self.step[phase] += 1
        self.usage.requests += 1
        return {"content": "", "tool_calls": [
            {"id": f"{phase}{self.step[phase]}",
             "function": {"name": name, "arguments": json.dumps(args)}}]}


def run_case(label: str, main: list, retry: list, *, strict_retry: bool = True,
             raise_in_retry: bool = False) -> tuple[dict, list[dict], dict]:
    ScriptedGateway.scripts = {"main": main, "retry": retry}
    ScriptedGateway.raise_in_retry = raise_in_retry
    ScriptedGateway.seen = []
    case = WORK / label
    case.mkdir(parents=True, exist_ok=True)
    evalset = case / "input.json"
    evalset.write_text(json.dumps({"meta": {"n": 1}, "items": [
        {"id": SAMPLE, "label": "vuln", "code": vp.load(SAMPLE)}]}), encoding="utf-8")
    summary = run_mod.run_arbiter(evalset=evalset, model="scripted", run_id=label,
                                  out_dir=case, concurrency=1, max_turns=6,
                                  workspace_root=case / "ws", strict_retry=strict_retry)
    row = json.loads((case / f"{label}.results.jsonl").read_text(encoding="utf-8"))
    return row, list(ScriptedGateway.seen), summary


def gate_entry(row: dict, label: str) -> dict:
    return gate._file_entry(row, slither="off", work=WORK / label / "evidence", patches=[],
                            do_repair=False, gateway=None, rounds=0, log=lambda *_: None)


def main() -> int:
    if shutil.which("forge") is None:
        print("forge not on PATH")
        return 2
    shutil.rmtree(WORK, ignore_errors=True)
    run_mod.Gateway = ScriptedGateway
    results: list[bool] = []

    def report(ok: bool, label: str, detail: str = "") -> None:
        results.append(ok)
        print(f"  [{'OK  ' if ok else 'FAIL'}] {label:62s} {detail}")

    # 1. loose, then the strict re-proof succeeds
    row, seen, summary = run_case("success", [("run_exploit", LOOSE), submit("LooseDrain")],
                                  [("run_exploit", STRICT), submit("StrictDrain")])
    sr = row.get("strict_retry") or {}
    pocs = row["outcome"]["pocs"]
    report(sr.get("status") == "proven" and sr.get("predicate") == "victim_loss"
           and sr.get("turns") == 2 and sr.get("requests") == 2
           and set(gate.STRICT_RETRY_KEYS) <= set(sr)
           and sr.get("label") == run_mod.STRICT_RETRY_PROVEN["victim_loss"],
           "success: strict_retry proven, 2 turns, 2 requests",
           f"{sr.get('status')} {sr.get('reason')}")
    report(row["outcome"]["proven"] and pocs[0]["predicate"] == "victim_loss"
           and any(p["predicate"] == "eth_profit" and p["passed"] for p in pocs[1:]),
           "success: strict PoC first, loose PoC kept after it",
           " > ".join(f"{p['name']}:{p['predicate']}:{p['passed']}" for p in pocs))
    ex = exploit_from_row(row)
    report(ex["poc_name"] == sr.get("poc_name") and winning_predicate(row) == "victim_loss"
           and row["outcome"]["findings"][0]["poc_name"] == ex["poc_name"],
           "success: exploit_from_row and winning_predicate take it", ex["poc_name"])
    retry_seen = [s for s in seen if s["phase"] == "retry"]
    loose_sol = next(p["solidity"] for p in pocs if p["predicate"] == "eth_profit")
    report(retry_seen and all(s["enum"] == list(STRICT_PREDICATES) for s in retry_seen)
           and all(s["enum"][0] == "victim_loss" and len(s["enum"]) == 5
                   for s in seen if s["phase"] == "main")
           and loose_sol.strip() in retry_seen[0]["user"] and len(loose_sol) > 4000,
           "success: retry offered only strict; brief has the full loose PoC",
           f"{len(loose_sol)} chars of solidity")
    entry = gate_entry(row, "success")
    fd = entry["findings"][0] if entry["findings"] else {}
    report(entry["verdict"] == gate.PROVEN and fd.get("predicate") == "victim_loss"
           and (fd.get("abg") or {}).get("status") == "measured"
           and (fd.get("strict_retry") or {}).get("status") == "proven"
           and set(fd["strict_retry"]) == set(gate.STRICT_RETRY_KEYS),
           "success: gate measures A/B/G, finding carries strict_retry",
           f"abg {(fd.get('abg') or {}).get('status')}")
    report(summary.get("strict_retry") == {"triggered": 1, "by_status": {"proven": 1},
                                           "requests": 2}
           and summary["mean_requests_per_sample"] == 4.0,
           "success: summary counts the retry and its requests",
           json.dumps(summary.get("strict_retry")))

    # 2. loose, then the strict re-proof fails: loose kept
    row, seen, _ = run_case("failure", [("run_exploit", LOOSE), submit("LooseDrain")],
                            [("run_exploit", {**LOOSE, "name": "AgainLoose"}),
                             ("run_exploit", {**STRICT, "name": "NoHarm", "attacker_code": (
                                 "contract Attacker { constructor(address) payable {} "
                                 "function attack() external {} }")}),
                             SAFE])
    sr = row.get("strict_retry") or {}
    pocs = row["outcome"]["pocs"]
    report(sr.get("status") == "not_proven" and sr.get("turns") == 3
           and "conclude_safe" in str(sr.get("reason")),
           "failure: strict_retry not_proven after 3 turns", str(sr.get("reason"))[:60])
    report(row["outcome"]["proven"] and row["predicted"] == "vuln"
           and pocs[0]["predicate"] == "eth_profit" and winning_predicate(row) == "eth_profit"
           and [(p["predicate"], p["passed"]) for p in pocs[1:]] == [("victim_loss", False)]
           and row["outcome"]["refusals"].get("predicate not accepted here") == 1,
           "failure: loose kept first, failed retry PoC appended, eth_profit refused",
           " > ".join(f"{p['name']}:{p['predicate']}:{p['passed']}" for p in pocs))
    try:
        exploit_from_row(row)
        refused = False
    except ValueError as exc:
        refused = "not patched" in str(exc)
    entry = gate_entry(row, "failure")
    fd = entry["findings"][0] if entry["findings"] else {}
    report(refused and fd.get("predicate") == "eth_profit"
           and (fd.get("strict_retry") or {}).get("status") == "not_proven",
           "failure: still not patched; strict_retry on the loose finding",
           (fd.get("strict_retry") or {}).get("label", ""))

    # 3. strict first: nothing to retry
    row, seen, _ = run_case("strict_first", [("run_exploit", STRICT), submit("StrictDrain")],
                            [SAFE])
    report("strict_retry" not in row and all(s["phase"] == "main" for s in seen)
           and len(seen) == 2 and row["outcome"]["proven"],
           "strict first: no retry, no extra request", f"{len(seen)} requests")

    # 4. off: the old behaviour
    row, seen, summary = run_case("off", [("run_exploit", LOOSE), submit("LooseDrain")],
                                  [SAFE], strict_retry=False)
    report("strict_retry" not in row and len(seen) == 2 and summary["strict_retry"] is None
           and winning_predicate(row) == "eth_profit",
           "strict_retry off: loose proof left alone", f"{len(seen)} requests")

    # 5. the retry's gateway raises
    row, seen, _ = run_case("error", [("run_exploit", LOOSE), submit("LooseDrain")],
                            [SAFE], raise_in_retry=True)
    sr = row.get("strict_retry") or {}
    report(sr.get("status") == "error" and "scripted gateway failure" in sr.get("reason", "")
           and sr.get("requests") == 1 and row["outcome"]["proven"]
           and winning_predicate(row) == "eth_profit",
           "retry error: recorded, loose proof kept", sr.get("reason", "")[:50])

    # 6. eval_requeue: a retry that lost the gateway requeues the row; nothing else does
    import eval_requeue  # noqa: E402

    base = {"attempts": [{"stop_reason": "submit_finding"}],
            "outcome": {"stop_reason": "submit_finding"}}
    infra = {**base, "strict_retry": {"reason": eval_requeue.INFRA_PREFIX + " 7 tries"}}
    plain = {**base, "strict_retry": {"reason": "error: RuntimeError: boom"}}
    report(eval_requeue.classify(infra) == "infra"
           and eval_requeue.classify(plain) == eval_requeue.classify(base),
           "eval_requeue: only a gateway loss in the retry requeues",
           f"{eval_requeue.classify(infra)} / {eval_requeue.classify(plain)}")

    # 7. the retry reuses the loose PoC's name; the dump must take the cited, passed record
    from arbiter.dump import dump_run  # noqa: E402

    for label, retry, want in (
            ("reuse_proven", [("run_exploit", {**STRICT, "name": "LooseDrain"}),
                              submit("LooseDrain")], "victim_loss"),
            ("reuse_failed", [("run_exploit", {**STRICT, "name": "LooseDrain", "attacker_code": (
                "contract Attacker { constructor(address) payable {} "
                "function attack() external {} }")}), SAFE], "eth_profit")):
        row, _, _ = run_case(label, [("run_exploit", LOOSE), submit("LooseDrain")], retry)
        names = [p["name"] for p in row["outcome"]["pocs"]]
        man = dump_run(WORK / label / f"{label}.results.jsonl", WORK / label / "dump")
        ex = (man.get("exploits") or [{}])[0]
        test = next(iter(sorted(Path(ex.get("path") or WORK).glob("test/*.t.sol"))), None)
        text = test.read_text(encoding="utf-8") if test else ""
        harness = "TestArbiterVictim" if want == "victim_loss" else "TestArbiterExploit"
        report(len(set(names)) == 1 and len(names) == 2 and ex.get("predicate") == want
               and f"contract {harness}" in text and ex.get("reproduces") is True,
               f"{label}: dump takes the cited {want} proof, and it reproduces",
               f"pocs {names}; dumped {ex.get('predicate')} reproduces={ex.get('reproduces')}")

    # 8. which strict PoC is the retry's result (fabricated retry outcomes, no forge)
    from arbiter.tools import AgentOutcome, PocRecord  # noqa: E402

    class _WS:
        def cleanup(self) -> None:
            pass

    def poc(name: str, predicate: str) -> PocRecord:
        return PocRecord(name, f"{predicate} proof", f"// {name}", True, True, "",
                         adjudicated=True, predicate=predicate)

    loose = PocRecord("LooseExploitPoc", "drain", "// loose", True, True, "", adjudicated=True,
                      predicate="eth_profit")
    real_audit = run_mod.audit
    try:
        for label, pocs, cites, want, why in (
                ("cited", [poc("LiveExploitPoc", "liveness_broken"),
                           poc("VictimExploitPoc", "victim_loss")], "VictimExploitPoc",
                 "VictimExploitPoc", "strict_proven"),
                ("cited_liveness", [poc("VictimExploitPoc", "victim_loss"),
                                    poc("LiveExploitPoc", "liveness_broken")], "LiveExploitPoc",
                 "LiveExploitPoc", "strict_proven"),
                ("uncited", [poc("LiveExploitPoc", "liveness_broken"),
                             poc("VictimExploitPoc", "victim_loss")], None,
                 "VictimExploitPoc", "strict_poc_passed_finding_carried")):
            outcome = AgentOutcome(verdict="vulnerable", turns=5, stop_reason="submit_finding",
                                   pocs=[loose], findings=[{"poc_name": "LooseExploitPoc",
                                                            "title": "LOOSE finding"}])
            retry = AgentOutcome(verdict="vulnerable" if cites else "no_verdict", turns=3,
                                 stop_reason="submit_finding" if cites else "turn_budget_exhausted",
                                 pocs=list(pocs),
                                 findings=[{"poc_name": cites, "title": "RETRY finding"}]
                                 if cites else [])
            run_mod.audit = lambda *a, _r=retry, **k: _r
            merged, rec = run_mod.run_strict_retry(object(), outcome, _WS, max_turns=6)
            row = {"outcome": merged.as_dict(), "source": "contract C {}", "sample_id": label}
            picked = exploit_from_row(row)
            title = merged.findings[0].get("title") if merged.findings else None
            report(rec["poc_name"] == want and rec["reason"] == why
                   and merged.pocs[0].name == want and picked["poc_name"] == want
                   and merged.findings[0]["poc_name"] == want
                   and title == ("RETRY finding" if cites else "LOOSE finding"),
                   f"retry result ({label}): {want}, {why}",
                   f"{rec['poc_name']} {rec['reason']}; exploit_from_row -> {picked['poc_name']}; "
                   f"finding '{title}'")
    finally:
        run_mod.audit = real_audit

    print(f"\n{sum(results)}/{len(results)} as expected")
    shutil.rmtree(WORK, ignore_errors=True)
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
