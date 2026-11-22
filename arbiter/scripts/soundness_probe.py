#!/usr/bin/env python3
"""Can an exploit composition make victim_loss pass on a contract with no flaw to exploit?

The promise of the strict predicate is that it cannot. The ME-build review found seven
compositions that did (predicate-soundness-1..7), and fixing them found eight more (X1,
X2, X5..X9 and C9 below). Every case here was ACCEPTED by forge on the code before the fix -- run this file
against commit c4adaaf to see it -- and every one targets a contract with no flaw the
attack uses. Where a refusal has more than one layer (a composition check, then the trial
itself), the case is run again with the composition checks switched off, to show which
layer is load-bearing and that the runtime one holds on its own.

  review findings
    1  token mode: a gain minted by a faucet, "accounted" by depositing 1 wei into the target
    1b the decoy token bank of finding 6, plus the 1-wei deposit
    2  token mode: a mock token with no allowance check; a decoy spender the victim approved
    3  token_expr re-read at every measurement: the attack switches which token is counted
    4  treasury: the owner's claim forwards what the stranger skimmed back to the owner
    5  setup reads the drawn accounts out of the harness's bytecode (and three other ways
       setup could learn them: the victim getter by selector, arbAtkEoa's old fixed
       preimage, the attacker contract's CREATE address)
    6  ether mode: the victim's value parked in a Bank the agent wrote; ether contention
       paired with a gain from a drip
    7  units: attacker_code spoofs arbAsset()/arbTreasuryExit()/a TestArbiter contract, so a
       token proof was reported, patched and replayed as ether
  found while fixing
    X1 the attack calls the harness's own frames (arbSetup redeploys under the victim)
    X2 an EOA attack reassigns `target`, so the victim's exit goes elsewhere
    X5 a second test contract in attacker_code: any [PASS] counted as the verdict
    X6 brace injection: deploy_code closes arbSetup and adds a receive() to the harness
    X7 cross-trial memory: a later trial's setup reads what an earlier attack recorded
    X8 `target` is a look-alike contract the agent wrote
    C9 the victim names an agent-written deputy as its withdrawer
    X9 a victim the attack paid out early counted as recovering nothing
  controls (must still be ACCEPTED, and their patched twins refused): reentrancy drain,
    EOA theft, token reentrancy, a fee pot drained, a vault that pulls from any address
    the victim approved it for, a vault that never debits used with an agent-written mock
    token through a cast, and an EOA attack whose local shadows a setup variable

Pure CPU. No gateway requests.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import sys
import tempfile
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RIG))
sys.path.insert(0, str(RIG / "scripts"))

import arbiter.workspace as wsmod  # noqa: E402
from arbiter.workspace import Workspace  # noqa: E402

import eoa_identity_probe as eip  # noqa: E402
import treasury_probe as tp  # noqa: E402
import victim_probe as vp  # noqa: E402

WS = Path("/tmp/soundness-probe")
REASON_RE = re.compile(r"(Arbiter[A-Za-z]+\([^)]*\)|ARBITER: [^\"'\]]{0,60})")

GUARDED = eip.GUARDED
VICTIM = eip.VICTIM

# Every composition check this file can switch off. Names that do not exist (on an older
# checkout) are skipped, so the file runs against the code before the fix as well.
COMPOSE_CHECKS = ("_reject_unbalanced", "_reject_test_functions", "_reject_code_reading",
                  "_reject_foreign_approval", "_reject_agent_custody", "_reject_harness_writes",
                  "_reject_harness_frames", "_reject_treasury_shape")


@contextlib.contextmanager
def checks_off(*names: str):
    saved = {}
    for n in names or COMPOSE_CHECKS:
        if hasattr(wsmod, n):
            saved[n] = getattr(wsmod, n)
            setattr(wsmod, n, lambda *a, **k: None)
    real_bound = getattr(wsmod, "_agent_bound_names", None)
    if real_bound is not None and (not names or "_agent_bound_names" in names):
        wsmod._agent_bound_names = lambda *a, **k: set()
    try:
        yield
    finally:
        for n, f in saved.items():
            setattr(wsmod, n, f)
        if real_bound is not None:
            wsmod._agent_bound_names = real_bound


def run(label: str, source: str, spec: dict) -> tuple[str, str]:
    """('ACCEPTED' | 'REFUSED' | 'COMPOSE' | 'NOBUILD', detail). ACCEPTED means forge
    printed a [PASS] line -- the reading the dispatcher used to give any test in the file."""
    ws = Workspace(WS, re.sub(r"\W+", "_", label)[:48], source)
    try:
        try:
            solidity = ws.compose_victim_loss(**spec)
        except ValueError as exc:
            return "COMPOSE", str(exc)[:90]
        ws.write_poc("Sound", solidity)
        build = ws.build()
        if not build.ok:
            errs = [ln.strip()[:90] for ln in build.combined.splitlines() if "Error" in ln][:2]
            return "NOBUILD", str(errs)
        out = ws.run_poc("SoundPoc").combined
        passed = [ln.strip() for ln in out.splitlines() if ln.strip().startswith("[PASS]")]
        hit = REASON_RE.search(out)
        return ("ACCEPTED" if passed else "REFUSED"), (
            passed[0][:60] if passed else (hit.group(1)[:90] if hit else ""))
    finally:
        ws.cleanup()


RESULTS: list[bool] = []


def expect(label: str, source: str, spec: dict, want: str, need: str = "", off: bool = False,
           off_names: tuple[str, ...] = ()) -> None:
    """want: ACCEPTED, REFUSED (by forge, reason must contain `need`) or COMPOSE (refused
    before compiling, message must contain `need`). `off`: composition checks disabled."""
    ctx = checks_off(*off_names) if off else contextlib.nullcontext()
    with ctx:
        got, detail = run(label, source, spec)
    ok = got == want and (not need or need in detail)
    RESULTS.append(ok)
    tag = ("[checks off] " if off else "") + label
    print(f"  [{'OK  ' if ok else 'WRONG'}] {tag:46s} {got:8s} {detail}", flush=True)


def report(label: str, ok: bool, detail: str) -> None:
    RESULTS.append(ok)
    print(f"  [{'OK  ' if ok else 'WRONG'}] {label:46s} {detail}", flush=True)


# ------------------------------------------------------------------- finding 1 and 1b

FAUCET_1WEI = dict(tp.TOKEN_FAUCET, attacker_code=tp._atk(
    "0", "t.faucet(10 ether); v.deposit(5 ether); v.withdrawLimited(); v.deposit(1);"))

TOKEN_BANK = """
contract TokenBank {
    mapping(address => uint256) public bal;
    function deposit(HookToken t, uint256 n) external { t.transferFrom(msg.sender, address(this), n); bal[msg.sender] += n; }
    function withdraw(HookToken t) external { uint256 b = bal[msg.sender]; bal[msg.sender] = 0; t.transfer(msg.sender, b); }
    function sweep(HookToken t) external { t.transfer(msg.sender, t.balanceOf(address(this))); }
}
"""
DECOY_TOKEN_BANK_1WEI = dict(
    mode="eoa",
    deploy_code="HookToken tok = new HookToken();\nTokenVault target = new TokenVault(tok);\n"
                "TokenBank bank = new TokenBank();",
    token_expr="address(tok)",
    victim_enter="tok.approve(address(bank), type(uint256).max);\nbank.deposit(tok, 5 ether);",
    victim_exit="bank.withdraw(tok);",
    attacker_code=TOKEN_BANK,
    attack_body="bank.sweep(tok);\ntok.faucet(1);\ntok.approve(address(target), 1);\ntarget.deposit(1);")

# --------------------------------------------------------------------------- finding 2

SAFE_TOKEN_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 n) external returns (bool);
    function transfer(address to, uint256 n) external returns (bool);
}

contract SafeTokenVault {
    IERC20 public immutable token;
    mapping(address => uint256) public balances;
    constructor(IERC20 t) { token = t; }
    function deposit(uint256 n) external {
        require(token.transferFrom(msg.sender, address(this), n), "tf");
        balances[msg.sender] += n;
    }
    function withdraw() external {
        uint256 b = balances[msg.sender];
        balances[msg.sender] = 0;
        require(token.transfer(msg.sender, b), "t");
    }
}
"""
MOCK_TOKEN = """
contract MockERC20 {
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    constructor() { balanceOf[msg.sender] = 1e30; }
    function approve(address s, uint256 n) external returns (bool) { allowance[msg.sender][s] = n; return true; }
    function transfer(address to, uint256 n) external returns (bool) {
        balanceOf[msg.sender] -= n; balanceOf[to] += n; return true;
    }
    function transferFrom(address f, address to, uint256 n) external returns (bool) {
        balanceOf[f] -= n; balanceOf[to] += n; return true;
    }
}

contract Attacker {
    MockERC20 t;
    constructor(address v) { t = MockERC20(address(SafeTokenVault(v).token())); }
    function attack() external {
        address victim = _ArbiterHarness(msg.sender).arbiterVictim();
        t.transferFrom(victim, address(this), t.balanceOf(victim));
    }
}
"""
SLOPPY_MOCK = dict(
    mode="contract",
    deploy_code="MockERC20 tok = new MockERC20();\n"
                "SafeTokenVault target = new SafeTokenVault(IERC20(address(tok)));",
    token_expr="address(tok)",
    victim_enter="tok.approve(address(target), type(uint256).max);\ntarget.deposit(5 ether);",
    victim_exit="target.withdraw();",
    attacker_code=MOCK_TOKEN,
)
DECOY_SPENDER = dict(
    mode="eoa",
    deploy_code="HookToken tok = new HookToken();\nTokenVault target = new TokenVault(tok);\n"
                "Router router = new Router();",
    token_expr="address(tok)",
    victim_enter="tok.approve(address(target), type(uint256).max);\n"
                 "tok.approve(address(router), type(uint256).max);\ntarget.deposit(5 ether);",
    victim_exit="target.withdraw();",
    attacker_code="""
contract Router {
    function pull(HookToken t, address from, uint256 n) external { t.transferFrom(from, msg.sender, n); }
}
""",
    attack_body="address who = _ArbiterHarness(address(this)).arbiterVictim();\n"
                "router.pull(tok, who, tok.balanceOf(who));",
)

# A real flaw of the same family, which must stay provable: the vault pulls from ANY
# address that approved it, so the attacker spends the victim's allowance to the vault.
PULL_VAULT = tp.TOKEN_VAULT.replace(
    "    /// Shared daily limit across all users",
    "    function depositFor(address from, address to, uint256 n) external {__GUARD__\n"
    "        token.transferFrom(from, address(this), n);\n"
    "        balances[to] += n;\n"
    "    }\n\n"
    "    /// Shared daily limit across all users").replace(
    "__WITHDRAW__", "\n        balances[msg.sender] = 0;\n        token.transfer(msg.sender, b);")
PULL_V = PULL_VAULT.replace("__GUARD__", "")
PULL_S = PULL_VAULT.replace("__GUARD__", '\n        require(from == msg.sender, "not yours");')
PULL_THEFT = dict(
    mode="eoa",
    deploy_code=tp.TOKEN_SETUP,
    token_expr="address(tok)",
    victim_enter="tok.approve(address(target), 10 ether);\ntarget.deposit(5 ether);",
    victim_exit="target.withdraw();",
    attack_body="address who = _ArbiterHarness(address(this)).arbiterVictim();\n"
                "target.depositFor(who, arbEoa, 5 ether);\ntarget.withdraw();",
)

# --------------------------------------------------------------------------- finding 3

TOKEN_SWITCH = dict(
    mode="eoa",
    deploy_code="HookToken a = new HookToken();\nHookToken b = new HookToken();\n"
                "TokenList reg = new TokenList(address(a), address(b));\n"
                "TokenVault target = new TokenVault(a);",
    token_expr="reg.cur()",
    victim_enter="a.approve(address(target), type(uint256).max);\ntarget.deposit(5 ether);",
    victim_exit="target.withdraw();",
    attacker_code="""
contract TokenList {
    address public cur;
    address public other;
    constructor(address x, address y) { cur = x; other = y; }
    function rotate() external { (cur, other) = (other, cur); }
}
""",
    attack_body="b.faucet(6 ether);\nreg.rotate();",
)

# --------------------------------------------------------------------------- finding 4

DONATION_FORWARD = dict(tp.FEE_DONATION, treasury_exit=(
    "uint256 s = address(target).balance;\ntarget.skim();\n"
    "s = s - address(target).balance;\npayable(address(this)).transfer(s);"))

# --------------------------------------------------------------------------- finding 5

CODESCAN = """
library CodeScan {
    function pick(bytes memory code) internal view returns (address found) {
        address victim = _ArbiterHarness(address(this)).arbiterVictim();
        uint256 i = 0;
        while (i < code.length) {
            uint8 op = uint8(code[i]);
            if (op == 0x73 && i + 20 < code.length) {
                uint160 v = 0;
                for (uint256 k = 1; k <= 20; k++) { v = (v << 8) | uint160(uint8(code[i + k])); }
                address a = address(v);
                if (a != victim && a != address(vm) && v != type(uint160).max && v > 2**64) {
                    found = a;
                }
            }
            if (op >= 0x60 && op <= 0x7f) { i += uint256(op) - 0x5f; }
            i++;
        }
    }
}
"""
BYTECODE_OWNER = dict(VICTIM, mode="eoa", attacker_code=CODESCAN,
                      deploy_code="Vault target = new Vault();\n"
                                  "target.setOwner(CodeScan.pick(address(this).code));",
                      attack_body="target.sweep(arbEoa);")

# The same read without asking for the victim (which the getter now refuses during setup):
# every address-sized PUSH operand becomes an operator, and arbEoa is one of them. This is
# what shows the bytecode check, and nothing else, stops the read.
OPERATOR_SRC = GUARDED.replace(
    "function sweep(address to) external onlyOwner { payable(to).transfer(address(this).balance); }",
    "mapping(address => bool) public operator;\n"
    "    function addOperator(address o) external onlyOwner { operator[o] = true; }\n"
    "    function sweep(address to) external { require(operator[msg.sender], \"not operator\");"
    " payable(to).transfer(address(this).balance); }")
CODESCAN_ALL = """
library CodeScanAll {
    function appointAll(bytes memory code, Vault v) internal {
        uint256 i = 0;
        while (i < code.length) {
            uint8 op = uint8(code[i]);
            if (op >= 0x68 && op <= 0x7f) {
                uint256 n = uint256(op) - 0x5f;
                uint256 x = 0;
                for (uint256 k = 1; k <= n && i + k < code.length; k++) {
                    x = (x << 8) | uint256(uint8(code[i + k]));
                }
                if (x > 2**64 && x < 2**160 - 1) { v.addOperator(address(uint160(x))); }
                i += n;
            } else if (op >= 0x60 && op <= 0x67) {
                i += uint256(op) - 0x5f;
            }
            i++;
        }
    }
}
"""
BYTECODE_OPERATORS = dict(VICTIM, mode="eoa", attacker_code=CODESCAN_ALL,
                          deploy_code="Vault target = new Vault();\n"
                                      "CodeScanAll.appointAll(address(this).code, target);",
                          attack_body="target.sweep(arbEoa);")

# The victim's address by a low-level call to the getter: no harness name is written.
# Knowing it, setup names the agent's deputy as the victim's withdrawer.
DEPUTY_SRC = GUARDED.replace(
    "function sweep(address to) external onlyOwner",
    "mapping(address => address) public withdrawer;\n"
    "    function setWithdrawer(address w) external { withdrawer[msg.sender] = w; }\n"
    "    function withdrawFor(address who, address payable to, uint256 a) external {\n"
    "        require(withdrawer[who] == msg.sender, \"not withdrawer\");\n"
    "        require(deposits[who] >= a, \"insufficient\");\n"
    "        deposits[who] -= a;\n"
    "        to.transfer(a);\n"
    "    }\n"
    "    function sweep(address to) external onlyOwner")
DEPUTY_CODE = """
contract Deputy {
    function pull(Vault v, address who, uint256 a) external { v.withdrawFor(who, payable(msg.sender), a); }
}
"""
SETUP_ASKS_VICTIM = dict(
    VICTIM, mode="eoa", attacker_code=DEPUTY_CODE,
    deploy_code=("Vault target = new Vault();\nDeputy dep = new Deputy();\n"
                 "(bool ok, bytes memory d) = address(this).staticcall(abi.encodeWithSelector("
                 "bytes4(keccak256(abi.encodePacked(\"arbiter\", \"Victim()\")))));\n"
                 "if (ok) { vm.prank(abi.decode(d, (address))); target.setWithdrawer(address(dep)); }"),
    attack_body=("address who = _ArbiterHarness(address(this)).arbiterVictim();\n"
                 "dep.pull(target, who, 4 ether);"))

# The attacker's EOA used to be keccak256("arbiter.attacker"); two string pieces rebuild it
# past the name check. The owner-set beneficiary is then paid by a public payout().
PAYOUT_SRC = GUARDED.replace(
    "function sweep(address to) external onlyOwner",
    "address public beneficiary;\n"
    "    function setBeneficiary(address b) external onlyOwner { beneficiary = b; }\n"
    "    function payout() external { payable(beneficiary).transfer(address(this).balance); }\n"
    "    function sweep(address to) external onlyOwner")
PREIMAGE = dict(
    VICTIM, mode="contract",
    attacker_code=("contract Attacker { Vault v; constructor(address t) { v = Vault(payable(t)); }\n"
                   "    function attack() external { v.payout(); } }"),
    deploy_code=("Vault target = new Vault();\n"
                 "target.setBeneficiary(address(uint160(uint256(keccak256("
                 "abi.encodePacked(\"arbiter.\", \"attacker\"))))));"))

# The attacker contract was created with CREATE from the harness, so its address was the
# harness's next nonce. Setup finds that nonce (one past the last CREATE slot holding code;
# the harness's first slot is empty) and appoints the address the attacker will land on.
NEXT_CREATE = dict(
    VICTIM, mode="contract", attacker_code=eip.SWEEP_ATTACKER,
    deploy_code=("Vault target = new Vault();\n"
                 "uint256 last = 0;\n"
                 "for (uint256 n = 1; n < 120; n++) {\n"
                 "    if (address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xd6), "
                 "bytes1(0x94), address(this), bytes1(uint8(n))))))).code.length > 0) { last = n; }\n"
                 "}\n"
                 "target.setOwner(address(uint160(uint256(keccak256(abi.encodePacked("
                 "bytes1(0xd6), bytes1(0x94), address(this), bytes1(uint8(last + 1))))))));"))

# --------------------------------------------------------------------------- finding 6

DECOY_BANK = dict(
    mode="eoa",
    deploy_code="Vault target = new Vault();\nBank bank = new Bank();",
    victim_enter="bank.deposit{value: 4 ether}();",
    victim_exit="bank.withdraw();",
    attacker_code="""
contract Bank {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external { uint256 b = bal[msg.sender]; bal[msg.sender] = 0; payable(msg.sender).transfer(b); }
    function sweep() external { payable(msg.sender).transfer(address(this).balance); }
}
""",
    attack_body="bank.sweep();",
)

# Contention, not theft: a shared daily limit the attacker uses up with its own ether, plus
# a gain from a drip setup funded. The victim only ever deals with the target.
ETH_LIMIT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LimitVault {
    mapping(address => uint256) public balances;
    uint256 public dailyLimit = 6 ether;
    uint256 public withdrawnToday;
    uint256 public day;
    function deposit() external payable { balances[msg.sender] += msg.value; }
    function withdraw() external {
        if (block.timestamp / 1 days != day) { day = block.timestamp / 1 days; withdrawnToday = 0; }
        uint256 b = balances[msg.sender];
        require(withdrawnToday + b <= dailyLimit, "daily limit");
        withdrawnToday += b;
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(b);
    }
}
"""
ETH_CONTENTION_DRIP = dict(
    mode="eoa",
    deploy_code="LimitVault target = new LimitVault();\nDrip drip = new Drip{value: 5 ether}();",
    victim_enter="target.deposit{value: 4 ether}();",
    victim_exit="target.withdraw();",
    attacker_code="""
contract Drip {
    constructor() payable {}
    function drip() external { payable(msg.sender).transfer(address(this).balance); }
}
""",
    attack_body="target.deposit{value: 5 ether}();\ntarget.withdraw();\ndrip.drip();",
)

# --------------------------------------------------------------------- found while fixing

FAKE_TEST = dict(VICTIM, mode="contract", deploy_code="Vault target = new Vault();",
                 attacker_code="""
contract Attacker {
    bool public ran;
    constructor(address) {}
    function attack() external { ran = true; }
}
contract TestFake {
    function testFake() public {
        TestArbiterVictim h = new TestArbiterVictim();
        h.arbSetup();
        h.arbDeploy();
        h.arbAttack();
        address a = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xd6), bytes1(0x94), address(h), bytes1(0x02))))));
        require(Attacker(a).ran(), "no attack");
    }
}
""")

BRACE = dict(VICTIM, mode="eoa",
             deploy_code=("Vault target = new Vault();\n}\n"
                          "receive() external payable { target.sweep(payable(msg.sender)); }\n"
                          "function arbPad() external {"),
             attack_body='(bool ok, ) = payable(address(this)).call(""); require(ok, "inj");')

REASSIGN = dict(VICTIM, mode="eoa",
                deploy_code="Vault target = new Vault();\nDrip drip = new Drip{value: 4 ether}();",
                attacker_code="""
contract Drip {
    constructor() payable {}
    function drip() external { payable(msg.sender).transfer(address(this).balance); }
}
""",
                attack_body="drip.drip();\ntarget = Vault(payable(address(0xdead)));")

# The attacker redeploys the world through arbSetup (selector built from pieces, so no
# frame name is written), then skims the donation skim() hands anyone by design.
REDEPLOY = dict(tp.FEE_DONATION, attacker_code="""
contract Attacker {
    FeeVault v;
    constructor(address t) { v = FeeVault(payable(t)); }
    function attack() external {
        v.skim();
        (bool ok, ) = msg.sender.call(abi.encodeWithSelector(
            bytes4(keccak256(abi.encodePacked("arb", "Setup()")))));
        ok;
    }
    receive() external payable {}
}
""")
REDEPLOY.pop("treasury_exit")

RECORDER = dict(VICTIM, mode="eoa",
                deploy_code=("Recorder rec = address(rec) == address(0) ? new Recorder() : rec;\n"
                             "Vault target = new Vault();\n"
                             "address w = rec.who();\n"
                             "if (w != address(0)) { target.setOwner(w); }"),
                attacker_code="""
contract Recorder {
    address public who;
    function note() external { who = tx.origin; }
}
""",
                attack_body="rec.note();\ntry target.sweep(payable(arbEoa)) {} catch {}")

EVIL_TARGET = dict(VICTIM, mode="eoa",
                   deploy_code="Vault target = Vault(payable(address(new EvilVault())));",
                   attacker_code="""
contract EvilVault {
    mapping(address => uint256) public deposits;
    function deposit() external payable { deposits[msg.sender] += msg.value; }
    function withdraw(uint256 a) external {
        require(deposits[msg.sender] >= a, "insufficient");
        deposits[msg.sender] -= a;
        payable(msg.sender).transfer(a);
    }
    function sweep(address to) external { payable(to).transfer(address(this).balance); }
}
""",
                   attack_body="target.sweep(arbEoa);")

DEPUTY = dict(mode="eoa", attacker_code=DEPUTY_CODE,
              deploy_code="Vault target = new Vault();\nDeputy dep = new Deputy();",
              victim_enter="target.deposit{value: 4 ether}();\ntarget.setWithdrawer(address(dep));",
              victim_exit="target.withdraw(4 ether);",
              attack_body=("address who = _ArbiterHarness(address(this)).arbiterVictim();\n"
                           "dep.pull(target, who, 4 ether);"))

# A public distribute() pays every depositor in full and pays the caller a keeper reward
# from a pot setup funded. The victim's own exit then has nothing to withdraw.
PAYALL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PayAllVault {
    address[] public users;
    mapping(address => uint256) public balances;
    uint256 public rewardPot;
    function fundReward() external payable { rewardPot += msg.value; }
    function deposit() external payable {
        if (balances[msg.sender] == 0) { users.push(msg.sender); }
        balances[msg.sender] += msg.value;
    }
    function withdraw() external {
        uint256 b = balances[msg.sender];
        require(b > 0, "nothing");
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(b);
    }
    /// Anyone may pay everybody out; the caller earns the keeper reward.
    function distribute() external {
        for (uint256 i = 0; i < users.length; i++) {
            uint256 b = balances[users[i]];
            balances[users[i]] = 0;
            if (b > 0) { payable(users[i]).transfer(b); }
        }
        uint256 r = rewardPot;
        rewardPot = 0;
        payable(msg.sender).transfer(r);
    }
}
"""
EARLY_PAYOUT = dict(mode="eoa",
                    deploy_code="PayAllVault target = new PayAllVault();\n"
                                "target.fundReward{value: 4 ether}();",
                    victim_enter="target.deposit{value: 4 ether}();",
                    victim_exit="target.withdraw();",
                    attack_body="target.distribute();")


# ------------------------------------------------------------------- controls (new rules)

# An honest mock token the agent writes for a vault that takes any ERC20, used by the
# victim through a cast: a plain call on agent code, no value, no authority handed over.
LEAKY_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transferFrom(address from, address to, uint256 n) external returns (bool);
    function transfer(address to, uint256 n) external returns (bool);
}

contract LeakyTokenVault {
    IERC20 public immutable token;
    mapping(address => uint256) public balances;
    constructor(IERC20 t) { token = t; }
    function deposit(uint256 n) external {
        require(token.transferFrom(msg.sender, address(this), n), "tf");
        balances[msg.sender] += n;
    }
    function withdraw(uint256 n) external {
        require(balances[msg.sender] >= n, "insufficient");__DEBIT__
        require(token.transfer(msg.sender, n), "t");
    }
}
"""
LEAKY_V = LEAKY_VAULT.replace("__DEBIT__", "")
LEAKY_S = LEAKY_VAULT.replace("__DEBIT__", "\n        balances[msg.sender] -= n;")
HONEST_MOCK_THEFT = dict(
    mode="contract",
    deploy_code="MockERC20 tok = new MockERC20();\n"
                "LeakyTokenVault target = new LeakyTokenVault(IERC20(address(tok)));",
    token_expr="address(tok)",
    victim_enter="MockERC20(address(target.token())).approve(address(target), 5 ether);\n"
                 "target.deposit(5 ether);",
    victim_exit="target.withdraw(5 ether);",
    attacker_code="""
contract MockERC20 {
    string public symbol = "MOCK";
    uint8 public decimals = 18;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    constructor() { balanceOf[msg.sender] = 1e30; }
    function faucet(uint256 n) external { balanceOf[msg.sender] += n; }
    function approve(address s, uint256 n) external returns (bool) { allowance[msg.sender][s] = n; return true; }
    function transfer(address to, uint256 n) external returns (bool) {
        balanceOf[msg.sender] -= n; balanceOf[to] += n; return true;
    }
    function transferFrom(address f, address to, uint256 n) external returns (bool) {
        allowance[f][msg.sender] -= n; balanceOf[f] -= n; balanceOf[to] += n; return true;
    }
}

contract Attacker {
    LeakyTokenVault v;
    MockERC20 t;
    constructor(address a) {
        v = LeakyTokenVault(a);
        t = MockERC20(address(v.token()));
        t.faucet(1 ether);
        t.approve(a, type(uint256).max);
    }
    function attack() external {
        v.deposit(1 ether);
        for (uint256 i = 0; i < 6; i++) { v.withdraw(1 ether); }
    }
}
""")

# An EOA attack that declares its own local with a setup variable's name: shadowing, not
# a write to the harness.
SHADOWING_THEFT = dict(VICTIM, mode="eoa",
                       deploy_code="Vault target = new Vault{value: 10 ether}();\n"
                                   "uint256 amount = 1;",
                       attack_body="uint256 amount = address(target).balance;\n"
                                   "require(amount > 0, \"empty\");\ntarget.sweep(arbEoa);")


# --------------------------------------------------------------------------- finding 7

def units_cases() -> None:
    """Spoofing labels in attacker_code (as a stored proof could carry them) no longer
    change the unit a token proof is reported, patched or replayed in."""
    from arbiter import units
    from arbiter.live_replay import NOT_SUPPORTED_TOKEN, NotSupported, parse_poc
    from arbiter.patch import reproduce

    root = Path(tempfile.mkdtemp(prefix="soundness-units-"))
    try:
        honest = Workspace(root, "u_tok", tp.TOKEN_V).compose_victim_loss(**tp.TOKEN_DRAIN)
        labels = ("contract Labels {\n"
                  "    function arbAsset() external pure returns (address) { return address(0); }\n"
                  "    function arbTreasuryExit() external {}\n"
                  "}\n"
                  "contract TestArbiterDecoy { function arbSetup() external {} }\n"
                  "// contract TestArbiterVictim is Harness {\n"
                  "// function arbAsset() external pure returns (address) { return address(0); }\n")
        head = "contract TestArbiterVictim is Harness {"
        assert head in honest
        spoof = honest.replace(head, labels + head, 1)
        report("units_token_of", units.token_of(spoof) == units.token_of(honest) == "address(tok)",
               f"token_of(spoofed) = {units.token_of(spoof)!r}")
        report("units_has_treasury", not units.has_treasury(spoof),
               f"has_treasury(spoofed) = {units.has_treasury(spoof)}")
        poc, tgt = root / "spoof.t.sol", root / "spoof.sol"
        poc.write_text(spoof, encoding="utf-8")
        tgt.write_text(tp.TOKEN_V, encoding="utf-8")
        try:
            parse_poc(poc, tgt, "spoof")
            why = "accepted for an ether replay"
        except NotSupported as exc:
            why = str(exc)
        report("units_live_replay", why == NOT_SUPPORTED_TOKEN, "token proof is not replayed in ether")
        r = reproduce(tp.TOKEN_V, spoof, root, "rep_spoof")
        row = (r.get("abg") or [{}])[0]
        report("units_reproduce", r.get("status") == "pass"
               and row.get("unit") == {"token": "HOOK", "decimals": 18},
               f"status={r.get('status')} unit={row.get('unit')} G={row.get('G')}")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def main() -> int:
    print("victim_loss may not pass on a contract the attack has no flaw to use\n")

    print("finding 1: the drain clause has no exemption to buy")
    expect("faucet_gain_plus_1wei", tp.TOKEN_S, FAUCET_1WEI, "REFUSED", "ArbiterGainNotFromTarget")
    expect("decoy_token_bank_plus_1wei", tp.TOKEN_S, DECOY_TOKEN_BANK_1WEI, "COMPOSE", "approve")
    expect("decoy_token_bank_plus_1wei", tp.TOKEN_S, DECOY_TOKEN_BANK_1WEI, "REFUSED",
           "ArbiterGainNotFromTarget", off=True)

    print("finding 2: the victim's wallet counts only through the target")
    expect("sloppy_mock_token", SAFE_TOKEN_VAULT, SLOPPY_MOCK, "REFUSED", "ArbiterGainNotFromTarget")
    expect("decoy_spender", tp.TOKEN_S, DECOY_SPENDER, "COMPOSE", "approve")
    expect("decoy_spender", tp.TOKEN_S, DECOY_SPENDER, "REFUSED", "ArbiterGainNotFromTarget",
           off=True)
    expect("control: pull_through_target_V", PULL_V, PULL_THEFT, "ACCEPTED")
    expect("control: pull_through_target_S", PULL_S, PULL_THEFT, "REFUSED")

    print("finding 3: the token is fixed when setup returns")
    expect("token_expr_switch", tp.TOKEN_S, TOKEN_SWITCH, "REFUSED", "ArbiterNoHarm")

    print("finding 4: the owner's claim is one call on the target")
    expect("claim_forwards_stranger_take", tp.FEE_S, DONATION_FORWARD, "COMPOSE", "exactly one call")
    expect("claim_forwards_stranger_take", tp.FEE_S, DONATION_FORWARD, "ACCEPTED", off=True)

    print("finding 5: nothing before the attack can learn the drawn accounts")
    expect("setup_reads_bytecode", GUARDED, BYTECODE_OWNER, "COMPOSE", "reads contract bytecode")
    expect("setup_reads_bytecode", GUARDED, BYTECODE_OWNER, "REFUSED", off=True)
    expect("setup_reads_bytecode_operators", OPERATOR_SRC, BYTECODE_OPERATORS, "COMPOSE",
           "reads contract bytecode")
    expect("setup_reads_bytecode_operators", OPERATOR_SRC, BYTECODE_OPERATORS, "ACCEPTED", off=True)
    expect("setup_asks_victim_by_selector", DEPUTY_SRC, SETUP_ASKS_VICTIM, "REFUSED")
    expect("setup_rebuilds_atk_eoa_preimage", PAYOUT_SRC, PREIMAGE, "REFUSED", "ArbiterNoHarm")
    expect("setup_predicts_attacker_address", GUARDED, NEXT_CREATE, "REFUSED")

    print("finding 6: the ether-only predicate ties the gain to the target")
    expect("decoy_bank_ether", GUARDED, DECOY_BANK, "COMPOSE", "bank")
    expect("decoy_bank_ether", GUARDED, DECOY_BANK, "REFUSED", "ArbiterGainNotFromTarget", off=True)
    expect("eth_contention_plus_drip", ETH_LIMIT, ETH_CONTENTION_DRIP, "REFUSED",
           "ArbiterGainNotFromTarget")

    print("finding 7: units are read from the harness's own test contract")
    units_cases()

    print("found while fixing")
    expect("X5 second_test_contract", GUARDED, FAKE_TEST, "COMPOSE", "testFake")
    expect("X5 second_test_contract", GUARDED, FAKE_TEST, "REFUSED", off=True)
    expect("X6 brace_injection_receive", GUARDED, BRACE, "COMPOSE", "never opened")
    expect("X6 brace_injection_receive", GUARDED, BRACE, "ACCEPTED", off=True)
    expect("X2 eoa_reassigns_target", GUARDED, REASSIGN, "COMPOSE", "target =")
    expect("X2 eoa_reassigns_target", GUARDED, REASSIGN, "REFUSED", off=True)
    expect("X1 attacker_redeploys_world", tp.FEE_S, REDEPLOY, "REFUSED", "ArbiterNoHarm")
    expect("X7 cross_trial_recorder", GUARDED, RECORDER, "REFUSED", "ArbiterNoHarm")
    expect("X8 lookalike_target", GUARDED, EVIL_TARGET, "COMPOSE", "'target'")
    expect("X8 lookalike_target", GUARDED, EVIL_TARGET, "ACCEPTED", off=True)
    expect("C9 victim_names_agent_deputy", DEPUTY_SRC, DEPUTY, "COMPOSE", "dep")
    expect("C9 victim_names_agent_deputy", DEPUTY_SRC, DEPUTY, "ACCEPTED", off=True)
    expect("X9 victim_paid_out_early", PAYALL, EARLY_PAYOUT, "REFUSED", "ArbiterNoHarm")

    print("controls: real flaws stay provable")
    expect("reentrancy_drain (contract mode)", vp.load("V_reentrancy_unstake"), vp.DRAIN, "ACCEPTED")
    expect("eoa_theft_unguarded_sweep", eip.UNGUARDED,
           dict(VICTIM, mode="eoa", deploy_code="Vault target = new Vault{value: 10 ether}();",
                attack_body="target.sweep(arbEoa);"), "ACCEPTED")
    expect("token_reentrancy", tp.TOKEN_V, tp.TOKEN_DRAIN, "ACCEPTED")
    expect("fee_pot_drained", tp.FEE_V, tp.FEE_DRAIN, "ACCEPTED")
    expect("agent_mock_token_used_by_cast_V", LEAKY_V, HONEST_MOCK_THEFT, "ACCEPTED")
    expect("agent_mock_token_used_by_cast_S", LEAKY_S, HONEST_MOCK_THEFT, "REFUSED")
    expect("eoa_attack_shadows_setup_name", eip.UNGUARDED, SHADOWING_THEFT, "ACCEPTED")

    print(f"\n{sum(RESULTS)}/{len(RESULTS)} as expected")
    return 0 if all(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
