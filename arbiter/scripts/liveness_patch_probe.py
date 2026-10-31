#!/usr/bin/env python3
"""The patch gate for liveness_broken, both directions, with no LLM request.

Material: the liveness_broken exploit the pre-registered run r2 proved on
V_unchecked_call_return_buyback (BuybackPool.sell ignores the token transfer's result;
the attack drains the pool, after which an ordinary sell fails). The results file is
only read. Plan 6.3: check 1 -- the stored exploit, unchanged, must stop breaking the
operation (and must compile); check 2 -- a patch under which the operation already
fails before the attack is refused; L, 3 as for victim_loss; no A/B/G.

  s_fix            v3's S_unchecked_call_return_buyback (1 line: require the call's
                   result)                                  -> REJECTED by check 2 alone.
                   Recorded, not tuned away: this exploit's "honest operation" is a sell
                   by an account holding no tokens, which succeeds on V only because of
                   the bug; any fix that reverts on a failed transfer makes it fail
                   before the attack, which is exactly what plan 6.3's check 2 refuses
  min_fix          a hand-written 1-line fix: on a failed transfer, return without
                   paying                                   -> accepted, 0 L 3 1 2 pass
                   (the "returns without doing anything" shape plan 6.10 names as
                   liveness_broken's blind spot -- here it is also a correct fix)
  always_revert    `revert` first thing in sell()           -> rejected by 2 and L
  always_fail      require(amount == 0) first in sell(): no -> rejected by 2 alone (the
                   lint rule matches it                        operation fails before the
                                                               attack)
  deleted          sell() removed                           -> rejected by 3
  unchanged        the vulnerable source as the "patch"     -> rejected by 1 (and L)
  check2_note      three S_-style proposals, all refused by check 2 -> rejected, and the
                   plain-language note (user decision 10/30) reaches gate.json's patch,
                   the PR comment and the result page; an accepted patch carries none
  extra            the same exploit as check 5's new evidence: passes against min_fix,
                   fails against always_fail; and the repair loop keeps a
                   liveness_broken re-attack as evidence for the next defence

    python3 scripts/liveness_patch_probe.py [--results PATH]
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

from arbiter import patch as patch_mod  # noqa: E402
from arbiter.patch import GATE_ORDER, exploit_from_row, make_diff, verify_fix  # noqa: E402

DEFAULT_RESULTS = (Path.home() / "innoserve" / "eval-worktree" / "arbiter" / "runs"
                   / "gptoss-v3-r2.results.jsonl")
SAMPLE = "V_unchecked_call_return_buyback"
SELL_HEAD = "    function sell(uint256 amount) external {\n"

results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'WRONG'}] {name:14s} {detail}")


def statuses(r: dict) -> dict[str, str]:
    return {n: r["checks"][n]["status"] for n in GATE_ORDER}


def deleted(src: str) -> str:
    start = src.index(SELL_HEAD)
    end = src.index("\n    }\n", start) + len("\n    }\n")
    return src[:start] + src[end:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=str(DEFAULT_RESULTS))
    a = ap.parse_args()
    path = Path(a.results)
    if not path.is_file():
        print(f"material missing: {path} (the r2 results file of the pre-registered run)")
        return 2
    row = next((json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()
                if json.loads(l)["sample_id"] == SAMPLE), None)
    ex = exploit_from_row(row)
    V = ex["source"]
    evalset = json.loads((Path(__file__).resolve().parent.parent / "evalsets" /
                          "v3_authored.json").read_text(encoding="utf-8"))
    S = next(i["code"] for i in evalset["items"] if i["id"] == "S_" + SAMPLE[2:])
    assert SELL_HEAD in V
    min_fix = V.replace(
        "        tokensBought += amount;\n",
        "        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) return;\n"
        "        tokensBought += amount;\n", 1)
    assert min_fix != V
    always_revert = V.replace(SELL_HEAD, SELL_HEAD + '        revert("paused");\n', 1)
    always_fail = V.replace(SELL_HEAD, SELL_HEAD + '        require(amount == 0, "sales closed");\n', 1)
    print(f"liveness_broken patch gate: r2 {SAMPLE}, exploit {ex['poc_name']}\n")

    root = Path(tempfile.mkdtemp(prefix="liveness-probe-"))
    try:
        base = patch_mod.reproduce(V, ex["solidity"], root, "base")
        check("check0", base["status"] == "pass" and base.get("abg") is None,
              f"the exploit reproduces on V: {base['status']}; A/B/G: {base.get('abg')}")
        cases = [
            ("s_fix", S, False, {"0": "pass", "L": "pass", "3": "pass", "1": "pass", "2": "fail",
                                 "4": "not_applicable"}),
            ("min_fix", min_fix, True, {"0": "pass", "L": "pass", "3": "pass", "1": "pass",
                                        "2": "pass", "4": "not_applicable"}),
            ("always_revert", always_revert, False, {"2": "fail", "L": "fail"}),
            ("always_fail", always_fail, False, {"2": "fail", "L": "pass", "1": "pass", "3": "pass"}),
            ("deleted", deleted(V), False, {"3": "fail"}),
            ("unchanged", V, False, {"1": "fail"}),
        ]
        for name, patched, accept, must in cases:
            r = verify_fix(V, ex["solidity"], patched=patched, root=root, sample_id=name,
                           baseline=base, run_all=True)
            got = statuses(r)
            ok = r["accepted"] == accept and all(got[n] == s for n, s in must.items())
            extra = ""
            if name in ("s_fix", "min_fix"):
                extra = f" ({r['changed_lines']} changed line)"
            if r["checks"]["3"].get("abi_diff", {}).get("removed"):
                extra = f" removed {r['checks']['3']['abi_diff']['removed']}"
            check(name, ok, f"{'ACCEPTED' if r['accepted'] else 'REJECTED'}  "
                            + " ".join(f"{n}:{v}" for n, v in got.items()) + extra)

        # check 5's evidence: the same liveness exploit as an extra
        x = {"poc_name": "LivenessExtraPoc", "solidity": ex["solidity"],
             "repo_solidity": ex["solidity"], "predicate": "liveness_broken"}
        r1 = verify_fix(V, ex["solidity"], patched=min_fix, root=root, sample_id="x1",
                        baseline=base, extra_exploits=[x])
        r2 = patch_mod._extra_exploit_fails(root, "x2", always_fail, x, None)
        ok = r1["accepted"] and r1["checks"]["1"]["extra"][0]["status"] == "pass" \
            and r2["status"] == "fail" and "before the attack" in r2.get("reason", "")
        check("extra", ok, f"vs min_fix: {r1['checks']['1']['extra'][0]['status']}; "
                           f"vs always_fail: {r2['status']} ({r2.get('reason')})")

        # the repair loop: a liveness_broken re-attack becomes the next defence's evidence
        class Usage:
            requests = 0

        class GW:
            model = "scripted"
            usage = Usage()

            def __init__(self, diffs: list[str] | None = None) -> None:
                self.diffs = diffs or [make_diff(V, min_fix), make_diff(V, min_fix)]

            def chat(self, messages: list, **_: Any) -> dict:
                self.usage.requests += 1
                return {"content": "", "tool_calls": [{"id": "c", "function": {
                    "name": "propose_patch",
                    "arguments": json.dumps({"diff": self.diffs.pop(0), "rationale": "s"})}}]}

        script = [{"status": "proven", "turns": 2, "tried": [], "exploit": {
            **x, "hypothesis": "a second way to break sell", "finding": {"vulnerable_function": "sell"}}},
            {"status": "not_proven", "turns": 3, "tried": []}]
        real = patch_mod.reattack
        patch_mod.reattack = lambda *a_, **k: {**script.pop(0), "elapsed_s": 0.0, "requests": 0,
                                                "ruled_out": list(k.get("ruled_out") or [])}
        try:
            rec = patch_mod.repair(GW(), {**ex, "sample_id": "loop"}, root=root / "loop",
                                   rounds=3, reattack_turns=16)
        finally:
            patch_mod.reattack = real
        tl = " -> ".join(f"{e['side'][0].upper()}{e['round']}:{e['result']}" for e in rec["timeline"])
        ok = (rec["predicate"] == "liveness_broken" and rec["status"] == "accepted"
              and len(rec["extra_exploits"]) == 1 and rec["honest"] is None)
        check("repair_loop", ok and "check2_note" not in rec,
              f"predicate={rec['predicate']} status={rec['status']} "
              f"extra evidence kept={len(rec['extra_exploits'])} timeline: {tl}; "
              f"note on an accepted patch: {'check2_note' in rec}")

        # user decision 10/30: a check-2 refusal of a liveness patch says why
        from arbiter.prgate import comment_markdown
        from arbiter.webui import finding_html
        rec2 = patch_mod.repair(GW([make_diff(V, S)] * 3), {**ex, "sample_id": "note"},
                                root=root / "note", rounds=3, reattack_turns=0)
        note = rec2.get("check2_note") or ""
        fd = {"title": "t", "vulnerable_function": "sell", "predicate": "liveness_broken",
              "poc_name": ex["poc_name"], "abg": {"status": "not_supported"},
              "patch": {"status": "rejected", "label": "未能產生通過驗證的修補",
                        "check2_note": note, "timeline": []}, "regression": {}}
        report = {"exit_code": 1, "models": ["m"], "input": {"llm_requests_this_invocation": 0},
                  "files": [{"id": "x", "verdict": "proven_exploitable", "label": "已證實可攻擊（擋部署）",
                             "artifact": {"uri": "src/Target.sol"}, "findings": [fd]}],
                  "pr": {"head": "a" * 40}}
        md = comment_markdown(report)
        html = finding_html(fd, 0, "", 0, 0, {})
        ok = (rec2["status"] == "rejected" and [r["first_failure"] for r in rec2["rounds"]] == ["2"] * 3
              and note.startswith("檢查 2 以攻擊程式裡的『一般使用者操作』為基準") and note in md
              and note in html)
        check("check2_note", ok, f"status={rec2['status']} first failures="
                                 f"{[r['first_failure'] for r in rec2['rounds']]}; note in comment="
                                 f"{note in md}, on the page={note in html}")
    finally:
        shutil.rmtree(root, ignore_errors=True)
    good = sum(ok for _, ok, _ in results)
    print(f"\n{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
