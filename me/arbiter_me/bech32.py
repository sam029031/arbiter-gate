"""0x <-> me1 address conversion (BIP-173 bech32), standard library only.

ME Network's EVM sender is an eth_secp256k1 account: the same 20 bytes as the 0x address,
written in bech32 with the human-readable part "me". The faucet and the Cosmos explorer show
the me1 form; Foundry and the EVM JSON-RPC use the 0x form.
"""
from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
HRP = "me"


def _polymod(values: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError("invalid data for bit conversion")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding")
    return ret


def bech32_encode(hrp: str, data20: bytes) -> str:
    data = _convertbits(data20, 8, 5, True)
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def bech32_decode(addr: str) -> tuple[str, bytes]:
    if addr.lower() != addr and addr.upper() != addr:
        raise ValueError("mixed case")
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr):
        raise ValueError("bad separator position")
    hrp, rest = addr[:pos], addr[pos + 1:]
    try:
        data = [CHARSET.index(c) for c in rest]
    except ValueError as exc:
        raise ValueError("invalid character") from exc
    if _polymod(_hrp_expand(hrp) + data) != 1:
        raise ValueError("bad checksum")
    return hrp, bytes(_convertbits(data[:-6], 5, 8, False))


def to_me1(eth_address: str) -> str:
    h = eth_address[2:] if eth_address.lower().startswith("0x") else eth_address
    raw = bytes.fromhex(h)
    if len(raw) != 20:
        raise ValueError("an EVM address has 20 bytes")
    return bech32_encode(HRP, raw)


def to_0x(me1_address: str) -> str:
    hrp, raw = bech32_decode(me1_address)
    if hrp != HRP or len(raw) != 20:
        raise ValueError("not a me1 account address")
    return "0x" + raw.hex()


if __name__ == "__main__":  # pragma: no cover - tiny CLI
    import sys

    for a in sys.argv[1:]:
        print(to_0x(a) if a.lower().startswith(HRP + "1") else to_me1(a))
