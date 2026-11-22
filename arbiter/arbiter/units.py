"""How an amount the harness measured is written for people: ether, or a token's units.

Every victim_loss environment carries `unit` (gate.json `abg.environments[].unit`):
"wei" -- the default, and every proof composed before token_expr was measured -- or
{"token": "<symbol, else the token expression>", "decimals": n or None}. Amounts stay
integers in the smallest unit everywhere; only display divides.
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


def token_of(solidity: str) -> str | None:
    """The token expression a victim_loss proof measures, or None for ether."""
    m = _ASSET_RE.search(solidity)
    if m:
        return None if m.group(1).strip() == "0" else m.group(1).strip()
    m = _LEGACY_TOKEN_RE.search(solidity)
    return m.group(1).strip() if m else None


def has_treasury(solidity: str) -> bool:
    return "function arbTreasuryExit()" in solidity


def is_wei(unit: Any) -> bool:
    return not isinstance(unit, dict)


def unit_name(unit: Any) -> str:
    return "ETH" if is_wei(unit) else str(unit.get("token") or "token")


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
