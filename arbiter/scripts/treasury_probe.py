#!/usr/bin/env python3
"""Can the strict predicate see a drained treasury or a stolen ERC20 -- and still refuse
the donation and contention shapes it was built to refuse?

victim_loss measured one harness account in ether, so a fee pot emptied through a missing
access check (the deployer's money is scenery: recA == recB) and theft of an ERC20 were
unprovable however real. `treasury_exit` (the deployer's own legitimate claim) and
`token_expr` (measure every party in that token) widen WHO can be harmed. Each true
positive below is paired with the false positive that widening could let in:

  treasury, ether
    1. fee pot drained through withdrawFees(to) with no access check     -> ACCEPTED
    2. the same attack, onlyOwner added (patched twin)                   -> refused
    3. the attacker triggers the owner's own payout early, gains nothing -> refused
    4. setup forces ether in, the attacker skims it by design            -> refused
    5. as 4, with the public skim() labelled as the owner's claim        -> refused
       (only the stranger replay refuses this one: a claim anybody can
       collect is a public pool, not the owner's)
    (1 and 4 again below 0.8.4, where the numbers travel in a revert string)
  ERC20
    6. token vault drained by reentrancy through a transfer hook         -> ACCEPTED
    7. the same attack, state updated before the transfer (patched twin) -> refused
    8. contention: the attacker uses up a shared withdrawal limit with its
       own money, the victim is stuck, the attacker gains nothing        -> refused
    9. as 8, but the attacker's "gain" is minted by a public faucet      -> refused
       (only the drain clause refuses this one)
   10. the attacker buys the victim's tokens at full price in ether      -> refused
       (only the ether-outlay clause refuses this one)
  unchanged
   11. the fee-pot theft of case 1 WITHOUT treasury_exit: the ether-only
       predicate still cannot see it, and composes the legacy file       -> refused
  composition (no forge)
   12. setup or the owner's claim naming a harness account is refused before compiling
  downstream (forge, no LLM)
   13. patch gate on case 1: the real fix passes; a fix that makes withdrawFees always
       revert keeps every depositor whole and still fails check 2 -- on the treasury
   14. gate.json environments, the regression project and the PR comment carry the unit
       and TA/TB; the live replay marks such proofs not supported instead of measuring
       ether

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))

from arbiter.workspace import Workspace  # noqa: E402

WS = Path("/tmp/treasury-probe")

FEE_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FeeVault {
    address public owner;
    uint256 public fees;
    uint256 public deposits;
    mapping(address => uint256) public balances;

    constructor() { owner = msg.sender; }

    function deposit() external payable {
        uint256 fee = msg.value / 100;
        fees += fee;
        deposits += msg.value - fee;
        balances[msg.sender] += msg.value - fee;
    }

    function withdraw() external {
        uint256 b = balances[msg.sender];
        balances[msg.sender] = 0;
        deposits -= b;
        payable(msg.sender).transfer(b);
    }

    /// The owner's fee claim.
    function withdrawFees(address payable to) external {__GUARD__
        uint256 f = fees;
        fees = 0;
        to.transfer(f);
    }

    /// Anyone may trigger the payout; it always goes to the owner.
    function sweepFeesToOwner() external {
        uint256 f = fees;
        fees = 0;
        payable(owner).transfer(f);
    }

    /// By design, anyone may take ether that nobody's balance accounts for.
    function skim() external {
        payable(msg.sender).transfer(address(this).balance - deposits - fees);
    }
}
"""
FEE_V = FEE_VAULT.replace("__GUARD__", "")
FEE_S = FEE_VAULT.replace("__GUARD__", '\n        require(msg.sender == owner, "not owner");')
# Below 0.8.4 there are no custom errors; the same quantities travel in a revert string.
FEE_V_OLD = FEE_V.replace("^0.8.20", "0.8.3")
FEE_S_OLD = FEE_S.replace("^0.8.20", "0.8.3")

TOKEN_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITokenReceiver { function onTokenReceived(address from, uint256 amount) external; }

/// An ERC20 with a receive hook (ERC777-style), so a transfer can re-enter.
contract HookToken {
    string public symbol = "HOOK";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    constructor() { balanceOf[msg.sender] = 1e30; }

    function faucet(uint256 n) external { require(n <= 100 ether, "faucet"); balanceOf[msg.sender] += n; }
    function approve(address s, uint256 n) external returns (bool) { allowance[msg.sender][s] = n; return true; }
    function transfer(address to, uint256 n) external returns (bool) { _move(msg.sender, to, n); return true; }
    function transferFrom(address f, address to, uint256 n) external returns (bool) {
        allowance[f][msg.sender] -= n;
        _move(f, to, n);
        return true;
    }
    function _move(address f, address to, uint256 n) internal {
        balanceOf[f] -= n;
        balanceOf[to] += n;
        if (to.code.length > 0) { try ITokenReceiver(to).onTokenReceived(f, n) {} catch {} }
    }
}

contract TokenVault {
    HookToken public token;
    mapping(address => uint256) public balances;
    uint256 public dailyLimit = 6 ether;
    uint256 public withdrawnToday;
    uint256 public day;

    constructor(HookToken t) { token = t; }

    function deposit(uint256 n) external {
        token.transferFrom(msg.sender, address(this), n);
        balances[msg.sender] += n;
    }

    function withdraw() external {
        uint256 b = balances[msg.sender];
        require(b > 0, "nothing");__WITHDRAW__
    }

    /// Shared daily limit across all users (contention, not theft).
    function withdrawLimited() external {
        if (block.timestamp / 1 days != day) { day = block.timestamp / 1 days; withdrawnToday = 0; }
        uint256 b = balances[msg.sender];
        require(withdrawnToday + b <= dailyLimit, "daily limit");
        withdrawnToday += b;
        balances[msg.sender] = 0;
        token.transfer(msg.sender, b);
    }

    /// Sells tokens the vault holds at one token per wei -- depositors' tokens included.
    function buy() external payable { token.transfer(msg.sender, msg.value); }
}
"""
TOKEN_V = TOKEN_VAULT.replace("__WITHDRAW__", (
    "\n        token.transfer(msg.sender, b);\n        balances[msg.sender] = 0;"))
TOKEN_S = TOKEN_VAULT.replace("__WITHDRAW__", (
    "\n        balances[msg.sender] = 0;\n        token.transfer(msg.sender, b);"))

FEE_ATTACKER = """
contract Attacker {
    FeeVault v;
    constructor(address t) { v = FeeVault(payable(t)); }
    function attack() external { v.__CALL__; }
    receive() external payable {}
}
"""
FEE_SETUP = "FeeVault target = new FeeVault();\ntarget.deposit{value: 10 ether}();"
FEE_VICTIM = dict(victim_enter="target.deposit{value: 2 ether}();", victim_exit="target.withdraw();")
OWNER_CLAIM = "target.withdrawFees(payable(address(this)));"
# Ether forced in during setup that no balance accounts for -- the 25-of-68 shape.
DONATE = "\nvm.deal(address(target), address(target).balance + 3 ether);"

FEE_DRAIN = dict(deploy_code=FEE_SETUP, mode="contract", treasury_exit=OWNER_CLAIM,
                 attacker_code=FEE_ATTACKER.replace("__CALL__", "withdrawFees(payable(address(this)))"),
                 **FEE_VICTIM)
FEE_EARLY = dict(FEE_DRAIN, attacker_code=FEE_ATTACKER.replace("__CALL__", "sweepFeesToOwner()"))
FEE_DONATION = dict(FEE_DRAIN,
                    deploy_code=FEE_SETUP + DONATE,
                    attacker_code=FEE_ATTACKER.replace("__CALL__", "skim()"))
FEE_DONATION_RELABELLED = dict(FEE_DONATION, treasury_exit="target.skim();")
FEE_LEGACY = {k: v for k, v in FEE_DRAIN.items() if k != "treasury_exit"}

TOKEN_SETUP = "HookToken tok = new HookToken();\nTokenVault target = new TokenVault(tok);"
TOKEN_VICTIM = dict(
    victim_enter="tok.approve(address(target), type(uint256).max);\ntarget.deposit(5 ether);",
    victim_exit="target.withdraw();")
TOKEN_ATTACKER = """
contract Attacker {
    TokenVault v;
    HookToken t;
    uint256 hops;
    constructor(address a) {
        v = TokenVault(a);
        t = v.token();
        t.faucet(__SEED__);
        t.approve(a, type(uint256).max);
    }
    function attack() external payable { __BODY__ }
    function onTokenReceived(address, uint256) external {
        if (msg.sender == address(t) && hops < 10 && t.balanceOf(address(v)) >= 1 ether) {
            hops++;
            v.withdraw();
        }
    }
    receive() external payable {}
}
"""


def _atk(seed: str, body: str) -> str:
    return TOKEN_ATTACKER.replace("__SEED__", seed).replace("__BODY__", body)


TOKEN_DRAIN = dict(deploy_code=TOKEN_SETUP, mode="contract", token_expr="address(tok)",
                   attacker_code=_atk("1 ether", "v.deposit(1 ether); v.withdraw();"),
                   **TOKEN_VICTIM)
_LIMITED = dict(victim_enter=TOKEN_VICTIM["victim_enter"], victim_exit="target.withdrawLimited();")
TOKEN_CONTENTION = dict(TOKEN_DRAIN, **_LIMITED,
                        attacker_code=_atk("5 ether", "v.deposit(5 ether); v.withdrawLimited();"))
TOKEN_FAUCET = dict(TOKEN_DRAIN, **_LIMITED,
                    attacker_code=_atk("0", "t.faucet(10 ether); v.deposit(5 ether); "
                                            "v.withdrawLimited();"))
TOKEN_PURCHASE = dict(TOKEN_DRAIN, attacker_code=_atk("0", "v.buy{value: 5 ether}();"))

REASON_RE = re.compile(r"(Arbiter[A-Za-z]+\([^)]*\)|ARBITER: [^\"'\]]{0,60})")


def compose(sample: str, source: str, spec: dict) -> tuple[Workspace, str]:
    ws = Workspace(WS, sample, source)
    return ws, ws.compose_victim_loss(**spec)


def probe(label: str, source: str, spec: dict, expect: bool, need: str = "",
          ablate: tuple[str, str] | None = None, custom_errors: bool = True) -> bool:
    """`ablate` = (clause text, replacement): the run with that clause switched off,
    which must then be ACCEPTED -- proof the clause is what refuses the case.
    `custom_errors=False` is what repo mode sets for a contract below 0.8.4."""
    ws = Workspace(WS, label, source)
    ws.custom_errors = custom_errors
    try:
        try:
            solidity = ws.compose_victim_loss(**spec)
        except ValueError as exc:
            print(f"  [WRONG] {label:22s} refused before compiling: {str(exc)[:70]}")
            return False
        if ablate:
            assert ablate[0] in solidity, ablate[0]
            solidity = solidity.replace(ablate[0], ablate[1])
        ws.write_poc("Treasury", solidity)
        build = ws.build()
        if not build.ok:
            errs = [ln.strip()[:110] for ln in build.combined.splitlines() if "Error" in ln][:3]
            print(f"  [WRONG] {label:22s} does not build: {errs}")
            return False
        run = ws.run_poc("TreasuryPoc")
        accepted = any(l.strip().startswith("[PASS]") for l in run.combined.splitlines())
        hit = REASON_RE.search(run.combined)
        full = hit.group(1) if hit else ""
        detail = full[:96]
    finally:
        ws.cleanup()
    ok = accepted == expect and (accepted or not need or need in full)
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:22s} {'ACCEPTED' if accepted else 'REFUSED '}  {detail}")
    return ok


def refused_at_compose(label: str, source: str, spec: dict, needle: str) -> bool:
    ws = Workspace(WS, label, source)
    try:
        ws.compose_victim_loss(**spec)
        ok, detail = False, "composed"
    except ValueError as exc:
        ok, detail = needle in str(exc), str(exc)[:70]
    finally:
        ws.cleanup()
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:22s} {detail}")
    return ok


def legacy_file_unchanged() -> bool:
    """Case 11's composition is the ether-only template: no per-asset code at all."""
    ws = Workspace(WS, "legacy_text", FEE_V)
    try:
        sol = ws.compose_victim_loss(**FEE_LEGACY)
    finally:
        ws.cleanup()
    ok = ("arbAsset" not in sol and "arbTreasury" not in sol
          and "error ArbiterNoHarm(" in sol and "ArbiterTreasuryNoHarm" not in sol
          and "(uint256 recA, , ) = abi.decode(ra, (uint256, uint256, bool));" in sol)
    print(f"  [{'OK  ' if ok else 'WRONG'}] {'legacy_text':22s} ether-only composition has no per-asset code")
    return ok


def dispatcher_passes_through() -> bool:
    """run_exploit's schema offers treasury_exit and token_expr for victim_loss, and the
    dispatcher hands both to compose_victim_loss (captured; nothing is compiled)."""
    from arbiter.tools import ToolDispatcher, tool_schemas
    props = next(t for t in tool_schemas() if t["function"]["name"] == "run_exploit"
                 )["function"]["parameters"]["properties"]
    ws = Workspace(WS, "dispatch", TOKEN_V)
    seen: dict = {}

    def capture(**kw):
        seen.update(kw)
        raise ValueError("captured")

    ws.compose_victim_loss = capture
    try:
        ToolDispatcher(ws).dispatch("run_exploit", dict(
            name="x", predicate="victim_loss", hypothesis="h", **TOKEN_DRAIN,
            treasury_exit="target.token();"))
    finally:
        ws.cleanup()
    ok = ("treasury_exit" in props and "victim_loss" in props["token_expr"]["description"]
          and seen.get("treasury_exit") == "target.token();"
          and seen.get("token_expr") == "address(tok)")
    print(f"  [{'OK  ' if ok else 'WRONG'}] {'tool_schema':22s} treasury_exit and token_expr reach compose_victim_loss")
    return ok


def _report(label: str, ok: bool, detail: str) -> bool:
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:22s} {detail}")
    return ok


def downstream() -> list[bool]:
    """Case 13 and 14: the patch gate, gate.json, the regression project, the PR comment
    and the live replay, on the case-1 and case-6 proofs."""
    import shutil
    import subprocess

    from arbiter.dump import write_regression
    from arbiter.gate import _environments
    from arbiter.live_replay import NOT_SUPPORTED_TOKEN, NOT_SUPPORTED_TREASURY, NotSupported, parse_poc
    from arbiter.patch import reproduce, verify_fix
    from arbiter.prgate import _abg_table

    out: list[bool] = []
    root = Path(tempfile.mkdtemp(prefix="treasury-downstream-"))
    try:
        fee_sol = Workspace(root, "compose_fee", FEE_V).compose_victim_loss(**FEE_DRAIN)
        tok_sol = Workspace(root, "compose_tok", TOKEN_V).compose_victim_loss(**TOKEN_DRAIN)

        base = reproduce(FEE_V, fee_sol, root, "fee_base")
        rows = base.get("abg") or []
        r0 = rows[0] if rows else {}
        out.append(_report("report_treasury", base["status"] == "pass" and r0.get("unit") == "wei"
                           and r0.get("TA", 0) > 0 and r0.get("TB") == 0 and r0.get("A") == r0.get("B"),
                           f"A={r0.get('A')} B={r0.get('B')} G={r0.get('G')} "
                           f"TA={r0.get('TA')} TB={r0.get('TB')} unit={r0.get('unit')}"))

        fix = verify_fix(FEE_V, fee_sol, patched=FEE_S, root=root, sample_id="fee_fix",
                         baseline=base)
        out.append(_report("patch_real_fix", bool(fix.get("accepted")),
                           "onlyOwner on withdrawFees: " + " ".join(
                               f"{k}:{v['status']}" for k, v in fix["checks"].items())))
        broken = FEE_V.replace("external {\n        uint256 f = fees;",
                               "external {\n        revert(\"paused\");\n        uint256 f = fees;", 1)
        assert broken != FEE_V
        bad = verify_fix(FEE_V, fee_sol, patched=broken, root=root, sample_id="fee_revert",
                         baseline=base, run_all=True)
        worse = bad["checks"]["2"].get("worse") or []
        parties = sorted({w["party"] for w in worse})
        out.append(_report("patch_always_revert", not bad.get("accepted")
                           and bad["checks"]["1"]["status"] == "pass"
                           and bad["checks"]["2"]["status"] == "fail" and parties == ["treasury"],
                           f"check 1 {bad['checks']['1']['status']}, check 2 "
                           f"{bad['checks']['2']['status']} on {parties}"))

        tbase = reproduce(TOKEN_V, tok_sol, root, "tok_base")
        t0 = (tbase.get("abg") or [{}])[0]
        out.append(_report("report_token", tbase["status"] == "pass"
                           and t0.get("unit") == {"token": "HOOK", "decimals": 18}
                           and "TA" not in t0 and (t0.get("G") or 0) >= (t0.get("A") or 1),
                           f"A={t0.get('A')} B={t0.get('B')} G={t0.get('G')} unit={t0.get('unit')}"))

        envs = _environments(rows)
        tenvs = _environments(tbase.get("abg"))
        out.append(_report("gate_environments", envs[0].get("unit") == "wei" and "TA" in envs[0]
                           and tenvs[0].get("unit", {}).get("token") == "HOOK"
                           and "TA" not in tenvs[0]
                           and _environments(None)[0].get("unit") == "wei",
                           "unit on every environment; TA/TB only with a treasury claim"))
        table = "\n".join(_abg_table(envs)) + "\n" + "\n".join(_abg_table(tenvs))
        out.append(_report("prgate_table", "TA 金庫沒攻擊時取回" in table and "0.12 ETH" in table
                           and "5 HOOK" in table, "PR comment shows TA/TB and token units"))

        proj = root / "fee_project"
        write_regression(proj, source=FEE_V, contract_file="FeeVault.sol",
                         exploit_solidity=fee_sol, environments=envs, finding={"title": "fee"})
        readme = (proj / "README.md").read_text(encoding="utf-8")

        def forge_tests(source: str) -> dict[str, bool]:
            (proj / "src" / "FeeVault.sol").write_text(source, encoding="utf-8")
            r = subprocess.run([shutil.which("forge") or "forge", "test", "--offline"],  # noqa: S603
                               cwd=proj, capture_output=True, text=True, timeout=600)
            return {m.group(2): m.group(1) == "PASS"
                    for m in re.finditer(r"\[(PASS|FAIL)[^\]]*\]\s+(test\w+)\(", r.stdout)}

        orig, fixed, reverted = forge_tests(FEE_V), forge_tests(FEE_S), forge_tests(broken)
        owner_tests = [k for k in orig if k.startswith("testOwnerClaim")]
        out.append(_report("regression_project",
                           bool(owner_tests) and orig.get("testExploitBlocked") is False
                           and all(orig[k] for k in owner_tests)
                           and all(fixed.values()) and len(fixed) == len(orig)
                           and reverted.get("testExploitBlocked") is True
                           and not any(reverted[k] for k in owner_tests)
                           and "testOwnerClaim0" in readme,
                           f"{len(orig)} tests; original blocks nothing, fix passes all, "
                           f"always-revert fails {sum(not reverted[k] for k in owner_tests)} owner tests"))

        reasons = []
        for name, sol in (("fee", fee_sol), ("tok", tok_sol)):
            poc = root / f"{name}.t.sol"
            poc.write_text(sol, encoding="utf-8")
            target = root / f"{name}.sol"
            target.write_text(FEE_V if name == "fee" else TOKEN_V, encoding="utf-8")
            try:
                parse_poc(poc, target, name)
                reasons.append("")
            except NotSupported as exc:
                reasons.append(str(exc))
        out.append(_report("live_replay", reasons == [NOT_SUPPORTED_TREASURY, NOT_SUPPORTED_TOKEN],
                           "treasury and token proofs are not replayed in ether"))
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return out


def main() -> int:
    print("treasury and ERC20 victims, with the donation and contention shapes still refused\n")
    results = [
        probe("fee_drain_V", FEE_V, FEE_DRAIN, True),
        probe("fee_drain_S", FEE_S, FEE_DRAIN, False),
        probe("fee_paid_early", FEE_V, FEE_EARLY, False, "ArbiterTreasuryNoHarm"),
        probe("fee_donation", FEE_S, FEE_DONATION, False, "ArbiterTreasuryNoHarm"),
        probe("fee_donation_relabel", FEE_S, FEE_DONATION_RELABELLED, False, "true)"),
        probe("fee_drain_V_0.8.3", FEE_V_OLD, FEE_DRAIN, True, custom_errors=False),
        probe("fee_donation_0.8.3", FEE_S_OLD, FEE_DONATION, False,
              "ArbiterTreasuryNoHarm(withoutAttack=", custom_errors=False),
        probe("token_reentrancy_V", TOKEN_V, TOKEN_DRAIN, True),
        probe("token_reentrancy_S", TOKEN_S, TOKEN_DRAIN, False, "ArbiterNoHarm"),
        probe("token_contention", TOKEN_V, TOKEN_CONTENTION, False, "ArbiterNoHarm"),
        probe("token_faucet_gain", TOKEN_V, TOKEN_FAUCET, False, "ArbiterGainNotFromTarget"),
        probe("token_purchase", TOKEN_V, TOKEN_PURCHASE, False, "ArbiterPaidInEther"),
        probe("ablated_stranger", FEE_S, FEE_DONATION_RELABELLED, True,
              ablate=('abi.encodeWithSignature("arbTreasuryStranger()")',
                      'abi.encodeWithSignature("arbEndPrank()")')),
        probe("ablated_drain_clause", TOKEN_V, TOKEN_FAUCET, True,
              ablate=("arbGainAccounted = gain == 0 ||", "arbGainAccounted = true ||")),
        probe("ablated_ether_outlay", TOKEN_V, TOKEN_PURCHASE, True,
              ablate=("arbPaidEther = netEth < 0;", "arbPaidEther = false;")),
        probe("fee_drain_legacy", FEE_V, FEE_LEGACY, False, "ArbiterNoHarm"),
        legacy_file_unchanged(),
        refused_at_compose("setup_names_victim", TOKEN_V, dict(
            TOKEN_DRAIN, deploy_code=TOKEN_SETUP + "\ntok.transfer(arbVictim, 5 ether);"),
            "arbVictim"),
        refused_at_compose("claim_names_attacker", FEE_V, dict(
            FEE_DRAIN, treasury_exit="target.withdrawFees(payable(arbEoa));"), "arbEoa"),
        refused_at_compose("claim_pranks", FEE_V, dict(
            FEE_DRAIN, treasury_exit="vm.prank(address(1)); " + OWNER_CLAIM), "vm.prank"),
        dispatcher_passes_through(),
        *downstream(),
    ]
    print(f"\n{sum(results)}/{len(results)} as expected")
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
