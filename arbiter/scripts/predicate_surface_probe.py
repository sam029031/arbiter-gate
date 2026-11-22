#!/usr/bin/env python3
"""Is what the model is told about run_exploit what the harness actually runs?

Pitfall 13 (CLAUDE.md section 7). Before the ME build the three disagreed:
  * the schema's predicate enum was the strict pair (victim_loss, liveness_broken);
  * the description never mentioned victim_loss and advertised eth_profit,
    token_profit and state_change, telling the model to use token_profit for ERC20s;
  * the dispatcher never checked the enum, and a missing predicate ran as eth_profit.

Now one call (tools.offered_predicates) decides the accepted set, and the schema, the
description and the dispatcher are all built from it. Cases:

  1. default schema: enum = all five, strict first; the description explains
     victim_loss first (4 environments, conservation, token_expr), then liveness_broken,
     then the loose three as weaker evidence;
  2. strict schema: enum = the strict pair, and nothing loose is described or offered;
  3. victim_loss alone: no honest_body or liveness_call property;
  4. offered_predicates normalises order and refuses unknown names;
  5. a strict dispatcher refuses eth_profit before compiling, and it is not an attempt;
  6. a missing predicate is an error, not eth_profit;
  7. the default dispatcher still accepts eth_profit (it reaches composition);
  8. agent.audit hands the same set to the schema and the dispatcher (scripted gateway);
  9. arbiter_mcp's dispatcher enforces the set its schema offers.
 10. the system prompt sends ERC20 value to victim_loss + token_expr; the nudge names victim_loss.

Pure CPU, no forge, no gateway requests.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))
sys.path.insert(0, str(RIG / "scripts"))

from arbiter import agent  # noqa: E402
from arbiter.tools import (  # noqa: E402
    ALL_PREDICATES, STRICT_PREDICATES, ToolDispatcher, offered_predicates, tool_schemas,
)
from arbiter.workspace import VICTIM_ENVIRONMENTS, Workspace  # noqa: E402

WS = Path("/tmp/predicate-surface-probe")
SOURCE = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\ncontract Box { uint x; }\n"


def run_exploit_schema(predicates=None) -> dict:
    schemas = tool_schemas(predicates) if predicates is not None else tool_schemas()
    return next(s["function"] for s in schemas if s["function"]["name"] == "run_exploit")


class ScriptedGateway:
    """Answers each chat() with the next scripted tool call and records what it was sent."""

    def __init__(self, calls: list[tuple[str, dict]]) -> None:
        self.calls = list(calls)
        self.tools_seen: list[list[dict]] = []
        self.messages: list[dict] = []

    def chat(self, messages, max_tokens=4096, tools=None, tag=""):  # noqa: ANN001
        self.tools_seen.append(tools or [])
        self.messages = messages
        name, args = self.calls.pop(0)
        return {"content": "", "tool_calls": [
            {"id": f"c{len(self.tools_seen)}",
             "function": {"name": name, "arguments": json.dumps(args)}}]}


def main() -> int:
    results: list[bool] = []

    def report(ok: bool, label: str, detail: str = "") -> None:
        results.append(ok)
        print(f"  [{'OK  ' if ok else 'FAIL'}] {label:58s} {detail}")

    # 1. default schema
    fn = run_exploit_schema()
    d = fn["description"]
    enum = fn["parameters"]["properties"]["predicate"]["enum"]
    order = [d.find(p) for p in ("victim_loss", "liveness_broken", "eth_profit")]
    report(enum == list(ALL_PREDICATES) and enum[:2] == list(STRICT_PREDICATES),
           "default enum: all five, strict first", str(enum))
    report(all(i >= 0 for i in order) and order == sorted(order),
           "description: victim_loss, then liveness_broken, then loose", str(order))
    report(f"{len(VICTIM_ENVIRONMENTS)} environments" in d and len(VICTIM_ENVIRONMENTS) == 4
           and "at least what the victim lost" in d and "strictly LESS" in d,
           "description: 4 environments and the conservation rule")
    tok = fn["parameters"]["properties"]["token_expr"]["description"]
    report("token_expr" in d and "victim_loss" in tok and "token_profit" in tok,
           "token_expr is described for victim_loss and token_profit")
    report("weaker evidence" in d and "prove the same attack again under victim_loss" in d
           and "use this whenever the value stolen is an ERC20" not in d
           and "a treasury" in d and "instead of concluding safe" in d,
           "loose: weaker evidence, and the fallback for contract-owned value")

    # 2. strict schema
    fs = run_exploit_schema(STRICT_PREDICATES)
    ds = fs["description"]
    props = fs["parameters"]["properties"]
    report(props["predicate"]["enum"] == list(STRICT_PREDICATES),
           "strict enum: victim_loss, liveness_broken", str(props["predicate"]["enum"]))
    loose_named = [p for p in ("eth_profit", "token_profit", "state_change")
                   if p in ds or p in json.dumps(props)]
    report(not loose_named and "observed_getter" not in props,
           "strict schema names no loose predicate", str(loose_named))

    # 3. victim_loss alone
    pv = run_exploit_schema(("victim_loss",))["parameters"]["properties"]
    report("honest_body" not in pv and "liveness_call" not in pv and "token_expr" in pv,
           "victim_loss alone: no honest_body or liveness_call")

    # 4. offered_predicates
    try:
        offered_predicates(["bogus"])
        refused = False
    except ValueError:
        refused = True
    report(offered_predicates(None) == ALL_PREDICATES
           and offered_predicates(["state_change", "victim_loss"]) == ("victim_loss", "state_change")
           and refused, "offered_predicates: default, order, unknown refused")

    ws = Workspace(WS, "surface", SOURCE)
    try:
        # 5. strict dispatcher refuses a loose predicate before anything runs
        disp = ToolDispatcher(ws, predicates=STRICT_PREDICATES)
        text, terminal = disp.dispatch("run_exploit", {
            "name": "x", "predicate": "eth_profit", "hypothesis": "h",
            "deploy_code": "Box target = new Box();", "attacker_code": "contract Attacker {}",
            "honest_body": "{}"})
        report("is not accepted in this audit" in text and not terminal
               and not disp.outcome.pocs and not disp.has_tried_exploit
               and disp.outcome.refusals.get("predicate not accepted here") == 1,
               "strict audit refuses eth_profit, not counted as attempt", text[:60])

        # 6. missing predicate
        disp = ToolDispatcher(ws)
        text, _ = disp.dispatch("run_exploit", {
            "name": "x", "hypothesis": "h", "deploy_code": "Box target = new Box();",
            "attacker_code": "contract Attacker {}"})
        report("needs a predicate" in text and not disp.outcome.pocs,
               "missing predicate is an error, not eth_profit", text[:60])

        # 7. default dispatcher accepts eth_profit: composition is reached and refuses the
        # empty honest_body, which only compose_exploit says.
        text, _ = disp.dispatch("run_exploit", {
            "name": "x", "predicate": "eth_profit", "hypothesis": "h",
            "deploy_code": "Box target = new Box();",
            "attacker_code": "contract Attacker { constructor(address) {} "
                             "function attack() external {} }"})
        report("profit predicates need honest_body" in text,
               "default audit still accepts eth_profit", text[:60])

        # 8. agent.audit: same set to schema and dispatcher
        for preds, want in ((None, list(ALL_PREDICATES)),
                            (STRICT_PREDICATES, list(STRICT_PREDICATES))):
            gw = ScriptedGateway([
                ("run_exploit", {"name": "x", "predicate": "eth_profit", "hypothesis": "h",
                                 "deploy_code": "Box target = new Box();",
                                 "attacker_code": "contract Attacker {}"}),
                ("conclude_safe", {"reason": "r", "guards_verified": [],
                                   "hypotheses_tested": []}),
                ("conclude_safe", {"reason": "r", "guards_verified": [],
                                   "hypotheses_tested": []}),
            ])
            agent.audit(gw, ws, max_turns=4, predicates=preds)
            seen = next(t["function"] for t in gw.tools_seen[0]
                        if t["function"]["name"] == "run_exploit")
            tool_text = next(m["content"] for m in gw.messages if m.get("role") == "tool")
            refused_here = "is not accepted in this audit" in tool_text
            report(seen["parameters"]["properties"]["predicate"]["enum"] == want
                   and refused_here == (preds is not None),
                   f"audit(predicates={'strict' if preds else 'None'}): schema = dispatcher",
                   "refused eth_profit" if refused_here else "eth_profit reached compose")
    finally:
        ws.cleanup()

    # 9. the MCP server
    import arbiter_mcp  # noqa: E402

    ws = Workspace(WS, "mcp", SOURCE)
    try:
        srv = arbiter_mcp.Server(ws, WS / "mcp-outcome.json", ("victim_loss",))
        mcp_enum = next(t for t in srv.tools if t["name"] == "run_exploit")[
            "inputSchema"]["properties"]["predicate"]["enum"]
        report(srv.disp.predicates == ("victim_loss",) and mcp_enum == ["victim_loss"],
               "arbiter_mcp: dispatcher enforces the offered set", str(mcp_enum))
    finally:
        ws.cleanup()

    # 10. the system prompt and the nudge no longer steer away from victim_loss
    sp, nudge = agent.SYSTEM_PROMPT, agent.NUDGE_TO_EXPLOIT
    stale = [s for s in ("use token_profit", "airdrop to the attacker",
                         "It also checks something you cannot talk it out of: **the value")
             if s in sp] + [s for s in ("eth_profit or state_change",) if s in nudge]
    report(not stale and "name the token in token_expr" in sp and "victim_loss" in nudge
           and "two strict predicates" in sp,
           "prompt: ERC20 -> victim_loss + token_expr; nudge names victim_loss", str(stale))

    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
