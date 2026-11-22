"""Did the re-attack try a different technique? A mechanical answer, from forge's trace.

Check 5 tells the agent to attack the PATCHED contract with a different technique, and
nothing used to check that it did. At the finals three of five re-attacks were the
patched mechanism reworded -- "re-enter unstake via fallback" after "re-enter unstake",
or the same sentence twice -- and all five lit 換手法再攻擊 as passed. A hypothesis is the
model's own description of its attack, so it cannot settle the question. The call trace
can: every exploit is run once more with `forge test -vvvv --json`, and the calls the
attack made are read out of forge's trace.

Which frames are the attack. The victim_loss harness runs the agent's attack inside its
own external frame, `arbAttack()`, so the attack is exactly the subtree under every such
frame; setup (`arbSetup`, `arbDeploy`) and the victim's own calls fall outside it by
construction. The other harness (`TestArbiterExploit`, liveness_broken) has no such
frame: there the attack is `Attacker.attack()`, or the calls pranked as the EOA whose
address the harness drew into the file.

Who is who. forge leaves the trace undecoded, so contracts are named by matching each
CREATE's initcode against the build artifacts in `out/`: a contract from the audited file
is the target; a contract created by the attacker's deployment or by the attacker is the
attacker's; anything else is a third party. Selectors are named from the artifacts'
`methodIdentifiers`.

The fingerprint (all lists sorted, so two fingerprints compare as data):

    entry        state-changing calls into the target from outside it
    reads        view calls into the target from outside it
    reentry      "outer() -> inner()": the target called out, and while it was still
                 running the target was entered again ("(view)" when the inner call is a
                 STATICCALL: read-only re-entrancy)
    callbacks    "outer() -> hook": the target handed control to an attacker hook
    third_party  "Label.fn()": calls the attacker made to third-party contracts
    value_sent   target functions the attacker sent ether with
    force_feed   ether forced into the target by selfdestruct (the beneficiary must be the
                 target: the finals exploit self-destructs a helper to fund ITSELF)
    donation     a third-party token transfer(target, ...) by the attacker
    hook_calls   target functions the attacker's hooks reach in its SOURCE -- what it
                 meant to re-enter, even where a patch keeps the hook from ever running.
                 Followed through the attacker's own code: a hook that calls a helper,
                 this.f(), the attacker's attack(), or a function of another contract the
                 agent wrote counts the target calls made there too
    classes      reentrancy / readonly_reentrancy / force_feed / donation / callback /
                 direct

A PoC that does not compile has no trace; it gets the same fields from its source alone
(`source: "static"`: entry and hook_calls by function name). So does a PoC whose trace
never reaches the target. A static fingerprint can show an attempt repeats a known
attack, never that it is new: it ran nothing against the patch, so its novelty is
"same" or "unknown" (fingerprint_attempts), and only a compiled, traced attempt can be
new_entry / new_class.

novelty(original, attempt):
    same       shares a re-entry edge with the original; or re-enters nothing in its trace
               while its hooks call what the original re-entered (the patch closed the
               callback, the attacker had not changed its mind); or re-enters nothing
               while the target hands it control from a function the original re-entered,
               through no entry the original did not call (the same, from the trace
               alone); or the same classes through no function the original did not
               already call
    new_entry  the same classes through a different door: disjoint re-entry edges, or a
               state-changing entry the original never called
    new_class  a different set of classes
    unknown    no fingerprint, or the attempt never touched the target

Only new_entry and new_class count as a different technique. Limits, stated rather than
hidden: a reworded attack that adds a harmless call to a function the original never
called reads as new_entry; ether forced in by a selfdestruct whose beneficiary appears
neither in that frame's input nor in the self-destructing contract's constructor
arguments is not seen; a proxy's DELEGATECALL is not followed into the implementation;
target storage slots are not compared (that needs -vvvvv, 15 MB of JSON for a toy); a
hook's calls are followed by function name through the agent's source, so a call made
through a function pointer or assembly is not, and a griefing hook that only reverts
from a function the original re-entered reads as the same attack.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

NOVELTY = ("same", "unknown", "new_entry", "new_class")   # weakest first
NOVEL = ("new_entry", "new_class")
TRACE_TIMEOUT = 240
_REENTRY = {"reentrancy", "readonly_reentrancy"}

_VM = "7109709ecfa91a80626ff3989d68f67f5b1dd12d"
_CONSOLE = "000000000000000000636f6e736f6c652e6c6f67"
_HARNESSES = ("TestArbiterVictim", "TestArbiterExploit")
_ETH_HOOK = "receive/fallback"
# Callbacks a token or lender makes into the receiver, named even when the attacker
# catches them in a bare fallback (its own artifact then has no selector for them).
_KNOWN_HOOKS = {
    "0x150b7a02": "onERC721Received(address,address,uint256,bytes)",
    "0xf23a6e61": "onERC1155Received(address,address,uint256,uint256,bytes)",
    "0xbc197c81": "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)",
    "0x0023de29": "tokensReceived(address,address,address,uint256,bytes,bytes)",
    "0x75ab9782": "tokensToSend(address,address,address,uint256,bytes,bytes)",
    "0x23e30c8b": "onFlashLoan(address,address,uint256,uint256,bytes)",
    "0x10d1e85c": "uniswapV2Call(address,uint256,uint256,bytes)",
    "0xa4c0ed36": "onTokenTransfer(address,uint256,bytes)",
}
_HOOK_NAMES = {"receive", "fallback"} | {s.split("(")[0] for s in _KNOWN_HOOKS.values()} | {
    "executeOperation", "receiveFlashLoan", "pancakeCall", "uniswapV3SwapCallback",
    "uniswapV3FlashCallback"}
_LINK = re.compile(r"__\$[0-9a-f]{34}\$__")
_EOA_LITERAL = re.compile(r"address\s+eoa\s*=\s*address\(uint160\((0x[0-9a-fA-F]+)\)\)")
_EOA_PRANK = re.compile(r"vm\.startPrank\((?:arbEoa|eoa),\s*(?:arbEoa|eoa)\);(.*?)vm\.stopPrank\(\);",
                        re.DOTALL)


# -- build artifacts -----------------------------------------------------------------------

def load_artifacts(out_dir: Path) -> list[dict[str, Any]]:
    """Every compiled contract under `out/`: name, source file, creation code, selectors."""
    arts = []
    for p in sorted(Path(out_dir).rglob("*.json")):
        if "build-info" in p.parts:
            continue
        try:
            j = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(j, dict):
            continue
        code = _hex((j.get("bytecode") or {}).get("object"))
        arts.append({"name": p.stem, "file": p.parent.name, "bytecode": code,
                     "runtime": _hex((j.get("deployedBytecode") or {}).get("object")),
                     "sel": {"0x" + v: k for k, v in (j.get("methodIdentifiers") or {}).items()}})
    return arts


def _hex(s: Any) -> str:
    return str(s or "").lower().removeprefix("0x")


def _addr(a: Any) -> str:
    return _hex(a)[-40:]


def _match(art: dict[str, Any], initcode: str, runtime: str) -> bool:
    code = art["bytecode"]
    if not code:
        return False
    if initcode.startswith(code):
        return True
    if "__$" in code:   # unlinked library placeholders: any address fits
        pattern = "".join(".{40}" if _LINK.fullmatch(part) else re.escape(part)
                          for part in re.split(f"({_LINK.pattern})", code))
        if re.match(pattern, initcode):
            return True
    return bool(runtime) and runtime == art["runtime"]


# -- the trace -----------------------------------------------------------------------------

def last_json(stdout: str) -> dict[str, Any] | None:
    """forge --json prints one object; tolerate anything printed before it."""
    for line in reversed((stdout or "").splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    try:
        return json.loads(stdout)
    except (ValueError, TypeError):
        return None


def _arena(report: dict[str, Any]) -> list[dict[str, Any]] | None:
    for suite in report.values():
        for name, res in ((suite or {}).get("test_results") or {}).items():
            if not name.startswith("testArbiter"):
                continue
            for kind, arena in res.get("traces") or []:
                if kind == "Execution":
                    return (arena or {}).get("arena")
    return None


def trace_fingerprint(report: dict[str, Any] | None, artifacts: list[dict[str, Any]],
                      target_file: str, solidity: str, source: str) -> dict[str, Any] | None:
    """The attack's mechanism from one forge -vvvv --json run, or None if it cannot be read."""
    nodes = _arena(report or {})
    if not nodes:
        return None
    by_idx = {n["idx"]: n for n in nodes}
    harness = _addr(nodes[0]["trace"]["address"])
    label: dict[str, dict[str, Any]] = {}
    created_input: dict[str, str] = {}
    for n in nodes:
        t = n["trace"]
        if t["kind"] in ("CREATE", "CREATE2") and t.get("success"):
            a, init = _addr(t["address"]), _hex(t.get("data"))
            created_input[a] = init
            hits = [x for x in artifacts if _match(x, init, _hex(t.get("output")))]
            if hits:
                label[a] = max(hits, key=lambda x: len(x["bytecode"]))
    hart = next((x for x in artifacts if x["name"] in _HARNESSES and x["file"].endswith(".t.sol")
                 and "arbiterRun()" in x["sel"].values()), None)
    if hart is not None:
        label.setdefault(harness, hart)
    global_sel: dict[str, str] = {}
    for x in artifacts:
        for k, v in x["sel"].items():
            global_sel.setdefault(k, v)
    targets = {a for a, x in label.items() if x["file"] == target_file}

    def sig(t: dict[str, Any]) -> str:
        if t["kind"] in ("CREATE", "CREATE2"):
            return "constructor"
        data = _hex(t.get("data"))
        if len(data) < 8:
            return _ETH_HOOK
        sel = "0x" + data[:8]
        own = (label.get(_addr(t["address"])) or {}).get("sel") or {}
        return own.get(sel) or global_sel.get(sel) or _KNOWN_HOOKS.get(sel) or sel

    # The attacker's contracts: created while the attacker is deployed or attacking, or
    # created by another attacker contract; liveness has no arbDeploy, so also by name.
    attack_sel = next((k for k, v in (hart or {}).get("sel", {}).items() if v == "arbAttack()"),
                      None)
    deploy_sel = next((k for k, v in (hart or {}).get("sel", {}).items() if v == "arbDeploy()"),
                      None)
    attacker: set[str] = set()
    in_attacker_frame: set[int] = set()
    for n in nodes:
        t, parent = n["trace"], by_idx.get(n.get("parent"))
        own = (_addr(t["address"]) == harness and _hex(t.get("data"))[:8] in
               {(s or "0x")[2:] for s in (attack_sel, deploy_sel) if s})
        if own or (parent is not None and parent["idx"] in in_attacker_frame):
            in_attacker_frame.add(n["idx"])
        if t["kind"] in ("CREATE", "CREATE2") and t.get("success"):
            a = _addr(t["address"])
            if (n["idx"] in in_attacker_frame or _addr(t["caller"]) in attacker
                    or (label.get(a) or {}).get("name") == "Attacker"):
                attacker.add(a)

    def role(a: str) -> str:
        if a in targets:
            return "target"
        if a in attacker:
            return "attacker"
        return "harness" if a == harness else "other"

    # Where the attack runs (module docstring): every arbAttack() frame, or for the other
    # harness Attacker.attack() and the EOA's pranked calls, all straight under the harness.
    roots: list[tuple[int, bool]] = []          # (node idx, walk the node itself?)
    if attack_sel:
        roots = [(n["idx"], False) for n in nodes
                 if _addr(n["trace"]["address"]) == harness
                 and _hex(n["trace"].get("data"))[:8] == attack_sel[2:]]
    else:
        m = _EOA_LITERAL.search(solidity)
        eoa = _addr(m.group(1)) if m else None
        for n in nodes:
            t, parent = n["trace"], by_idx.get(n.get("parent"))
            if parent is None or _addr(parent["trace"]["address"]) != harness:
                continue
            a = _addr(t["address"])
            if (role(a) == "attacker" and sig(t) == "attack()") or (eoa and _addr(t["caller"]) == eoa
                                                                    and a not in (_VM, _CONSOLE)):
                roots.append((n["idx"], True))
    if not roots:
        return None

    fp: dict[str, Any] = {k: set() for k in ("entry", "reads", "reentry", "callbacks",
                                             "third_party", "value_sent")}
    fp.update(force_feed=False, donation=False, mode="eoa", hook_failed=False, hook_acted=False)
    pad = {"0" * 24 + a for a in targets}
    top = ("root", "attacker", "", "CALL")      # the frame acting for the attacker
    todo: list[tuple[int, tuple]] = []
    for idx, itself in reversed(roots):
        if itself:
            todo.append((idx, (top,)))
        else:
            todo.extend((c, (top,)) for c in reversed(by_idx[idx]["children"]))
    while todo:
        idx, stack = todo.pop()
        n = by_idx[idx]
        t = n["trace"]
        a = _addr(t["address"])
        if a in (_VM, _CONSOLE) or t.get("maybe_precompile") or (a and int(a, 16) <= 0x100):
            continue
        r, s, kind = role(a), sig(t), t["kind"]
        parent = stack[-1]
        outer = next((f for f in reversed(stack) if f[1] == "target"), None)
        if r == "target":
            if outer is None:
                fp["reads" if kind == "STATICCALL" else "entry"].add(s)
                if int(_hex(t.get("value")) or "0", 16) > 0:
                    fp["value_sent"].add(s)
            elif parent[1] != "target":
                fp["reentry"].add(f"{outer[2]} -> {s}" + (" (view)" if kind == "STATICCALL" else ""))
            elif kind == "STATICCALL":
                # A view of a target that is still mid-call and has handed control away.
                for k in range(len(stack) - 1, -1, -1):
                    if stack[k][0] == a and any(f[1] != "target" for f in stack[k + 1:]):
                        fp["reentry"].add(f"{stack[k][2]} -> {s} (view)")
                        break
        elif r == "attacker":
            if parent is top and s == "attack()":
                fp["mode"] = "contract"
            if outer is not None and parent[1] != "attacker":
                fp["callbacks"].add(f"{outer[2]} -> {s}")
                if not t.get("success"):
                    fp["hook_failed"] = True
                if any(_addr(by_idx[c]["trace"]["address"]) not in (_VM, _CONSOLE)
                       for c in n["children"]):
                    fp["hook_acted"] = True
        elif r == "other" and parent[1] == "attacker" and (a in label or s != _ETH_HOOK):
            # (plain ether to an address with no known code -- the attacker paying its own
            # EOA -- is not a call to anyone)
            name = (label.get(a) or {}).get("name") or ("0x" + a[:8])
            fp["third_party"].add(f"{name}.{s}")
            if s == "transfer(address,uint256)" and _hex(t.get("data"))[8:72] in pad:
                fp["donation"] = True
        if _self_destructed(t) and any(p in _hex(t.get("data")) or p in created_input.get(a, "")
                                       for p in pad):
            fp["force_feed"] = True
        frame = (a, r, s, kind)
        todo.extend((c, stack + (frame,)) for c in reversed(n["children"]))

    static = static_fingerprint(solidity, source)
    out = {"source": "trace", "mode": fp["mode"],
           **{k: sorted(fp[k]) for k in ("entry", "reads", "reentry", "callbacks",
                                         "third_party", "value_sent")},
           "force_feed": fp["force_feed"], "donation": fp["donation"],
           "hook_calls": static["hook_calls"]}
    if not (out["entry"] or out["reads"] or out["reentry"]):
        return None     # the trace never reached the target: judge it by its source
    out["classes"] = _classes(out, static, hook_failed=fp["hook_failed"],
                              hook_acted=fp["hook_acted"])
    return out


def _self_destructed(t: dict[str, Any]) -> bool:
    """forge marks a CALL frame that ran SELFDESTRUCT; a constructor that self-destructs
    is a successful CREATE that returned no code (forge 1.8.6 leaves selfdestruct_* null)."""
    if t.get("status") == "SelfDestruct":
        return True
    return t["kind"] in ("CREATE", "CREATE2") and bool(t.get("success")) and not _hex(t.get("output"))


def _classes(fp: dict[str, Any], static: dict[str, Any], *, hook_failed: bool = False,
             hook_acted: bool = False) -> list[str]:
    edges = fp.get("reentry") or []
    cls = set()
    if any(not e.endswith("(view)") for e in edges) or static.get("hook_writes"):
        cls.add("reentrancy")
    if any(e.endswith("(view)") for e in edges) or static.get("hook_reads"):
        cls.add("readonly_reentrancy")
    if fp.get("force_feed"):
        cls.add("force_feed")
    if fp.get("donation"):
        cls.add("donation")
    if not cls and fp.get("callbacks") and (hook_failed or hook_acted):
        cls.add("callback")    # a hook that reverts or acts: griefing, not re-entry
    return sorted(cls or {"direct"})


# -- the source ----------------------------------------------------------------------------

def _bodies(code: str) -> list[tuple[str, str]]:
    """(function name, body) for every function, receive and fallback in `code`."""
    out = []
    for m in re.finditer(r"\b(?:function\s+(\w+)|(receive|fallback))\s*\(", code):
        name = m.group(1) or m.group(2)
        i = m.end()
        while i < len(code) and code[i] not in "{;":
            i += 1
        if i >= len(code) or code[i] == ";":
            continue
        depth, j = 0, i
        while j < len(code):
            depth += {"{": 1, "}": -1}.get(code[j], 0)
            if depth == 0:
                break
            j += 1
        out.append((name, code[i + 1:j]))
    return out


def _called(code: str, names: set[str]) -> set[str]:
    found = set(re.findall(r"\.\s*(\w+)\s*(?:\{[^{}]*\}\s*)?\(", code))
    found |= set(re.findall(r"encodeWithSignature\(\s*\"(\w+)\(", code))
    found |= set(re.findall(r"\.(\w+)\.selector\b", code))
    found |= set(re.findall(r"encodeCall\(\s*\w+\.(\w+)", code))
    return found & names


def _strip_comments(code: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", code, flags=re.DOTALL)


def _own_calls(code: str, own: set[str]) -> set[str]:
    """Functions of the agent's own code that `code` calls: internal f(), this.f(),
    helper.f(), f{value: ...}(), or by signature / selector."""
    found = set(re.findall(r"(?<![\w$])(\w+)\s*(?:\{[^{}]*\}\s*)?\(", code))
    found |= set(re.findall(r"encodeWithSignature\(\s*\"(\w+)\(", code))
    found |= set(re.findall(r"\.(\w+)\.selector\b", code))
    found |= set(re.findall(r"encodeCall\(\s*[\w.]+\.(\w+)", code))
    return found & own


def _hook_reach(agent: str, names: set[str]) -> set[str]:
    """Target functions the attacker's hooks reach in its source.

    Followed through the agent's own code, not only the calls written inline in a hook: a
    receive() that calls an internal helper, this.again(), the attacker's own attack(), or
    a function of another contract the agent wrote re-enters just as surely. Missing that
    made a patch that closes the callback (transfer's 2300 gas, pull payment) read the
    SAME re-entrancy as a new class of attack: the trace shows no re-entry because the
    patch stopped it, and the hook's own body named no target function (gate-logic-1)."""
    bodies = _bodies(agent)
    own: dict[str, list[str]] = {}
    for name, body in bodies:
        own.setdefault(name, []).append(body)
    todo = [body for name, body in bodies if name in _HOOK_NAMES]
    seen: set[str] = set()
    reached: set[str] = set()
    while todo:
        body = todo.pop()
        reached |= _called(body, names)
        for f in _own_calls(body, set(own)) - seen:
            seen.add(f)
            todo.extend(own[f])
    return reached


def static_fingerprint(solidity: str, source: str) -> dict[str, Any]:
    """What the PoC's own source says it does: target functions it calls, and from where."""
    src = _strip_comments(source)
    fns = set(re.findall(r"\bfunction\s+(\w+)\s*\(", src))
    views = set(re.findall(r"\bfunction\s+(\w+)\s*\([^)]*\)[^{;]*\b(?:view|pure)\b", src))
    views |= set(re.findall(r"\b(?:mapping\s*\([^;]*\)|\w+)\s+public\s+(?:immutable\s+|constant\s+)?(\w+)\s*[;=]",
                            src))
    names = fns | views
    sol = _strip_comments(solidity)
    end = min((i for i in (sol.find("contract TestArbiterVictim"),
                           sol.find("contract TestArbiterExploit")) if i >= 0), default=len(sol))
    start = max(sol.rfind("interface _ArbiterHarness", 0, end),
                sol.rfind("interface _ArbiterToken", 0, end), 0)
    agent = sol[start:end]
    hooks = _hook_reach(agent, names)
    entry_code = agent
    for name, body in _bodies(agent):
        if name in _HOOK_NAMES:
            entry_code = entry_code.replace(body, "", 1)
    m = _EOA_PRANK.search(sol[end:])
    if m:
        entry_code = m.group(1)
    contracts = set(re.findall(r"\bcontract\s+(\w+)", src))
    vars_ = {"target"} | {v for c in contracts
                          for v in re.findall(rf"\b{c}\s+(?:public\s+|internal\s+|private\s+|immutable\s+)*(\w+)",
                                              agent)}
    feed = any(re.search(rf"\b({'|'.join(map(re.escape, vars_))})\b", arg)
               for arg in re.findall(r"selfdestruct\s*\((.*?)\)\s*;", agent))
    out = {"source": "static", "mode": "eoa" if m else "contract",
           "entry": sorted(_called(entry_code, names - views)),
           "reads": sorted(_called(entry_code, views)), "reentry": [], "callbacks": [],
           "third_party": [], "value_sent": [], "force_feed": feed, "donation": False,
           "hook_calls": sorted(hooks),
           "hook_writes": sorted(hooks - views), "hook_reads": sorted(hooks & views)}
    out["classes"] = _classes(out, out)
    return out


# -- running it ----------------------------------------------------------------------------

def fingerprint_poc(ws: Any, poc: str, solidity: str, source: str) -> dict[str, Any]:
    """Trace test/<poc>.t.sol (already written and built in `ws`) and fingerprint it;
    the source alone when the trace cannot be read or never reaches the target."""
    static = static_fingerprint(solidity, source)
    contract = ("^TestArbiterVictim$" if "contract TestArbiterVictim" in solidity
                else "^TestArbiterExploit$")
    target_file = ws.plan.target.name if ws.plan is not None else "Target.sol"
    try:
        # Workspace._forge and ._force: the same forge binary, timeout and repo-mode
        # --force that every other run in this workspace uses.
        r = ws._forge(["test", "--match-path", f"test/{poc}.t.sol", "--match-contract",
                       contract, "-vvvv", "--json", "--offline", *ws._force],
                      timeout=TRACE_TIMEOUT)
        traced = trace_fingerprint(last_json(r.stdout), load_artifacts(ws.root / "out"),
                                   target_file, solidity, source)
    except Exception:  # noqa: BLE001 -- a fingerprint never decides whether an attack ran
        traced = None
    return traced or static


def fingerprint_attempts(ws: Any, pocs: list[dict[str, Any]], source: str,
                         known: list[dict[str, Any] | None]) -> list[dict[str, Any]]:
    """Every adjudicated PoC of an audit, re-run traced in the audit's own workspace (the
    patched contract) and judged against the attacks already known; one entry per
    adjudicated PoC, in order.

    Only a compiled exploit whose trace reached the target ran anything against the
    patch. One judged from its source alone (it did not compile, or its trace never
    touched the target) may show it repeats a known attack -- "same" -- but never that it
    is new: such an attempt is "unknown" rather than new_entry / new_class, so a PoC that
    never built cannot make check 5 pass (gate-logic-3)."""
    attempts = []
    for p in pocs:
        if not p.get("adjudicated"):
            continue
        sol = p.get("solidity") or ""
        fp = None
        try:
            if p.get("compiled") and sol:
                name = ws.write_poc(p["name"], sol)
                if ws.build().ok:
                    fp = fingerprint_poc(ws, name, sol, source)
            if fp is None:
                fp = static_fingerprint(sol, source)
        except Exception:  # noqa: BLE001 -- never lose the audit's result to a fingerprint;
            fp = None      # an attempt that cannot be fingerprinted is "unknown", not new
        nv = novelty_against(known, fp)
        if nv in NOVEL and not (p.get("compiled") and (fp or {}).get("source") == "trace"):
            nv = "unknown"
        attempts.append({"name": p.get("name"), "predicate": p.get("predicate"),
                         "hypothesis": " ".join(str(p.get("hypothesis") or "").split())[:200],
                         "compiled": bool(p.get("compiled")), "passed": bool(p.get("passed")),
                         "fingerprint": fp, "novelty": nv})
    return attempts


def counts_as_new(attempt: dict[str, Any]) -> bool:
    """Does this re-attack attempt count as a different technique for check 5? Only one
    that compiled, was traced against the patched contract, and is new_entry / new_class
    (a recording made before fingerprint_attempts downgraded static ones included)."""
    return (attempt.get("novelty") in NOVEL and bool(attempt.get("compiled"))
            and (attempt.get("fingerprint") or {}).get("source") == "trace")


# -- comparing -----------------------------------------------------------------------------

def _edges(fp: dict[str, Any]) -> set[tuple[str, str, bool]]:
    out = set()
    for e in fp.get("reentry") or []:
        view = e.endswith(" (view)")
        o, _, i = e.removesuffix(" (view)").partition(" -> ")
        out.add((o, i, view))
    return out


def _name(sig: str) -> str:
    return sig.split("(", 1)[0]


def _touches(fp: dict[str, Any]) -> bool:
    return bool(fp.get("entry") or fp.get("reads") or fp.get("reentry") or fp.get("hook_calls")
                or fp.get("force_feed"))


def novelty(original: dict[str, Any] | None, attempt: dict[str, Any] | None) -> str:
    """same / new_entry / new_class / unknown (module docstring)."""
    if not original or not attempt or not _touches(original) or not _touches(attempt):
        return "unknown"
    oe, ae = _edges(original), _edges(attempt)
    if oe & ae:
        return "same"
    reentered = {_name(i) for _, i, _ in oe} | set(original.get("hook_calls") or [])
    if not ae and set(attempt.get("hook_calls") or []) & reentered:
        return "same"
    oc, ac = set(original.get("classes") or []), set(attempt.get("classes") or [])
    # The trace alone, for a hook whose re-entrant call the source cannot show: the patch
    # stopped the re-entry, so the target only handed the attacker control -- from a
    # function the original re-entered -- and the attempt entered nothing the original
    # did not. That is the original attack failing, not a callback or direct attack.
    outer = {o for o, _, _ in oe}
    handed = {c.split(" -> ", 1)[0] for c in attempt.get("callbacks") or []}
    if (oc & _REENTRY and not ae and ac <= {"callback", "direct"} and handed & outer
            and {_name(s) for s in attempt.get("entry") or []}
            <= {_name(s) for s in original.get("entry") or []}):
        return "same"
    if oc != ac:
        return "new_class"
    if oc & _REENTRY:
        if not oe or not ae:   # one side has only its source's word for the re-entry
            return ("same" if set(attempt.get("hook_calls") or []) & reentered
                    else "new_entry")
        return "new_entry"
    fresh = {_name(s) for s in attempt.get("entry") or []} - \
        {_name(s) for s in original.get("entry") or []}
    return "new_entry" if fresh else "same"


def novelty_against(known: list[dict[str, Any] | None], attempt: dict[str, Any] | None) -> str:
    """The weakest novelty against every attack already proven: new only if new to all."""
    if not known:
        return "unknown"
    return min((novelty(k, attempt) for k in known), key=NOVELTY.index)


def strongest(attempts: list[dict[str, Any]]) -> str | None:
    return max((a["novelty"] for a in attempts), key=NOVELTY.index, default=None)


# -- words ---------------------------------------------------------------------------------

def describe(fp: dict[str, Any] | None, zh: bool = False) -> str:
    """One line for a prompt (English) or a page (zh-TW)."""
    if not fp:
        return "沒有量到" if zh else "not measured"
    sep, arrow = ("、", " → ") if zh else (", ", " -> ")
    parts = []
    if fp.get("entry"):
        parts.append(("入口 " if zh else "entry ") + sep.join(fp["entry"]))
    if fp.get("reentry"):
        parts.append(("重入 " if zh else "re-entry ")
                     + sep.join(e.replace(" -> ", arrow).replace("(view)", "（唯讀）" if zh else "(view)")
                                for e in fp["reentry"]))
    elif fp.get("hook_calls"):
        parts.append(("回呼裡呼叫 " if zh else "hooks call ") + sep.join(fp["hook_calls"]))
    hooks = sorted({c.split(" -> ")[-1] for c in fp.get("callbacks") or []})
    if hooks:
        parts.append(("經由 " if zh else "called back through ") + sep.join(hooks))
    if fp.get("force_feed"):
        parts.append("用 selfdestruct 強制轉入以太幣" if zh else "ether forced in by selfdestruct")
    if fp.get("donation"):
        parts.append("直接轉代幣給合約" if zh else "tokens transferred straight to the target")
    if fp.get("third_party"):
        parts.append(("第三方呼叫 " if zh else "third-party calls ") + sep.join(fp["third_party"]))
    if fp.get("source") == "static":
        parts.append("（由原始碼判斷，沒有執行軌跡）" if zh else "(from source; no trace)")
    return ("；" if zh else "; ").join(parts) or ("沒有呼叫目標合約" if zh else "no call into the target")


_BRIEF = """

RE-ATTACK OF A PATCHED CONTRACT. An earlier audit of this contract proved the attack(s) \
listed below, and the contract you are reading is the version patched to stop them. The \
patch, as a unified diff against the original:

```diff
{diff}```

Proven before this patch, each with the mechanism the harness measured from the forge \
call trace of its exploit:
{known}

Every exploit you run is traced the same way. One with the same mechanism -- the same \
re-entry edge, or the same kind of attack through the same functions -- is recorded as \
NOT a new technique however its hypothesis is worded, and a re-attack that only repeats \
it does not count. Look for a different mechanism: another function, another invariant, \
another class of attack. If none works, call conclude_safe and say what you tried."""

_FOLLOW_UP = """

A first re-attack of this patched contract already ran the exploits below, and none of \
them counts as a new technique:
{attempts}
Do not run them again. Try a genuinely different mechanism, or call conclude_safe."""

_FOLLOW_UP_EMPTY = """

A first re-attack of this patched contract ended without running any exploit, so it \
tested nothing. Run an exploit for a different mechanism, or call conclude_safe and say \
what you checked."""


def reattack_brief(diff: str, known: list[dict[str, Any]]) -> str:
    """The re-attack's briefing, appended to the audit task through audit(proposals=...)."""
    listed = "\n".join(f"  - {k.get('hypothesis') or '(no hypothesis recorded)'}\n"
                       f"    mechanism: {describe(k.get('fingerprint'))}" for k in known)
    return _BRIEF.format(diff=diff if diff.endswith("\n") else diff + "\n",
                         known=listed or "  (none recorded)")


def _why_not_new(a: dict[str, Any]) -> str:
    fp = a.get("fingerprint") or {}
    if not a.get("compiled"):
        return "it did not compile, so it tested nothing against the patched contract"
    if not fp:
        return "it could not be measured"
    if fp.get("source") != "trace":
        return "its trace did not reach the patched contract (or could not be read)"
    if a.get("novelty") == "same":
        return "its trace shows the same mechanism as a proven attack above"
    return "it could not be compared with the proven attacks"


def follow_up_brief(attempts: list[dict[str, Any]]) -> str:
    if not attempts:
        return _FOLLOW_UP_EMPTY
    return _FOLLOW_UP.format(attempts="\n".join(
        f"  - {a['name']}: {a['hypothesis'] or '(no hypothesis)'}\n"
        f"    mechanism: {describe(a['fingerprint'])}\n"
        f"    not new because {_why_not_new(a)}" for a in attempts))
