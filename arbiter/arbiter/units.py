"""How an amount the harness measured is written for people: ether, or a token's units.

Every victim_loss environment carries `unit` (gate.json `abg.environments[].unit`):
"wei" -- the default, and every proof composed before token_expr was measured -- or
{"token": "<symbol>" or null, "decimals": n or None}. Amounts stay integers in the smallest
unit everywhere; only display divides.

The label is shown only when it is a plain symbol (what the report run accepts from the
token's symbol()) or an address. Results written before that rule kept the AI-written token
expression there, and an expression can carry markup (web-security-wording-1): it is never
printed, the amount is written in "token" (the web page says 「代幣」) instead.
"""

from __future__ import annotations

import re
from typing import Any

WEI = "wei"

# The token named by a stored proof. arbAsset() exists only in proofs composed with the
# per-asset trial; older token proofs are recognised by what they measure.
_ASSET_RE = re.compile(
    r"function arbAsset\(\) external (?:view|pure) returns \(address\) \{ return address\((.*?)\); \}")
_LEGACY_TOKEN_RE = re.compile(r"_ArbiterToken\((.+?)\)\.balanceOf\(arbVictim\)")
_TREASURY_RE = re.compile(r"function arbTreasuryExit\(\)")

# The harness's own test contract, as the template writes it. Everything the agent writes
# at file scope (attacker_code) comes BEFORE it, so the last such head is the harness's.
_HEAD_RE = re.compile(r"\bcontract\s+TestArbiterVictim\s+is\s+Harness\s*\{")
_NONCODE_RE = re.compile(
    r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)


def harness_body(solidity: str) -> tuple[str, str]:
    """(original, blanked) text of the harness's TestArbiterVictim body.

    Searching the whole file was spoofable: attacker_code is rendered above the harness,
    so `contract Labels { function arbAsset() external pure returns (address) { return
    address(0); } }` made a token proof read, patch and replay as ether. The body is found
    on a copy with comments and string literals blanked (offsets kept), so neither a
    comment nor a string inside a fragment can pose as the harness's own text either.
    Empty strings when there is no harness (not a victim_loss proof).
    """
    code = _NONCODE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), solidity or "")
    heads = list(_HEAD_RE.finditer(code))
    if not heads:
        return "", ""
    start = heads[-1].end()
    depth = 1
    for i in range(start, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return solidity[start:i], code[start:i]
    return solidity[start:], code[start:]


def token_of(solidity: str) -> str | None:
    """The token expression a victim_loss proof measures, or None for ether."""
    text, code = harness_body(solidity)
    m = _ASSET_RE.search(code)
    if m:
        expr = text[m.start(1):m.end(1)].strip()
        return None if expr == "0" else expr
    m = _LEGACY_TOKEN_RE.search(code)
    return text[m.start(1):m.end(1)].strip() if m else None


def has_treasury(solidity: str) -> bool:
    return _TREASURY_RE.search(harness_body(solidity)[1]) is not None


def is_wei(unit: Any) -> bool:
    return not isinstance(unit, dict)


SYMBOL_RE = re.compile(r"[\w.\-]{1,16}")
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}")


def unit_symbol(unit: Any) -> str | None:
    """A token unit's printable name -- its symbol or its address -- or None (ether, no
    symbol, or anything else, such as a token expression an older result stored)."""
    if is_wei(unit):
        return None
    s = unit.get("token")
    return s if isinstance(s, str) and (SYMBOL_RE.fullmatch(s) or _ADDRESS_RE.fullmatch(s)) else None


def unit_name(unit: Any) -> str:
    return "ETH" if is_wei(unit) else unit_symbol(unit) or "token"


def format_amount(v: Any, unit: Any = WEI, *, zh: bool = False, name: bool = True) -> str:
    """'1.5 ETH', '5 HOOK'; a token whose decimals are unknown is shown in base units."""
    if v is None:
        return "?"
    v = int(v)
    if is_wei(unit):
        return f"{v / 1e18:g}" + (" ETH" if name else "")
    dec = unit.get("decimals")
    if isinstance(dec, int) and 0 <= dec <= 36:
        return f"{v / 10 ** dec:g}" + (f" {unit_name(unit)}" if name else "")
    if not name:
        return str(v)
    return (f"{v}（{unit_name(unit)} 最小單位）" if zh else
            f"{v} base units of {unit_name(unit)}")
