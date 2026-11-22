"""Keccak-256 and Solidity ABI encoding/decoding, standard library only.

Python's hashlib has SHA3-256, which pads differently from the Keccak-256 the EVM uses, so
the permutation is written out here. Together with the ABI codec below this lets anyone
read and check ME records with nothing but Python; Foundry is needed only to sign
transactions and to compile.

Supported ABI types: uint<N>, int<N>, address, bool, bytes<N>, bytes, string, T[] and
tuples "(T1,T2,...)". Decoded values: int, "0x…" lowercase hex (address, bytes<N>, bytes),
bool, str, list (arrays and tuples).
"""
from __future__ import annotations

_MASK = (1 << 64) - 1
_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
# rotation offsets r[x][y]
_ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56),
        (27, 20, 39, 8, 14))


def _rol(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v


def _permute(a: list[int]) -> list[int]:
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        a = [b[i] ^ (~b[(i + 1) % 5 + 5 * (i // 5)] & b[(i + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    msg = bytearray(data)
    msg.append(0x01)
    while len(msg) % rate:
        msg.append(0)
    msg[-1] |= 0x80
    state = [0] * 25
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            state[i] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
        state = _permute(state)
    return b"".join(state[i].to_bytes(8, "little") for i in range(4))


def hexbytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        return value
    v = value[2:] if value[:2] in ("0x", "0X") else value
    return bytes.fromhex(v)


def to_hex(b: bytes) -> str:
    return "0x" + b.hex()


def keccak_hex(value: str | bytes) -> str:
    """keccak256 of hex data (or raw bytes) as 0x-hex."""
    return to_hex(keccak256(hexbytes(value)))


def selector(signature: str) -> str:
    return to_hex(keccak256(signature.encode())[:4])


def topic(signature: str) -> str:
    return to_hex(keccak256(signature.encode()))


# ------------------------------------------------------------------ type parsing


def split_top(s: str) -> list[str]:
    """'a,(b,c),d' -> ['a', '(b,c)', 'd']"""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
            continue
        depth += ch == "("
        depth -= ch == ")"
        cur += ch
    if cur:
        out.append(cur)
    return [p.strip() for p in out]


def parse_type(t: str):
    t = t.strip()
    if t.endswith("[]"):
        return ("array", parse_type(t[:-2]))
    if t.startswith("("):
        return ("tuple", [parse_type(p) for p in split_top(t[1:-1])])
    return ("base", t)


def _dynamic(t) -> bool:
    kind, arg = t
    if kind == "base":
        return arg in ("bytes", "string")
    if kind == "array":
        return True
    return any(_dynamic(c) for c in arg)


def _static_size(t) -> int:
    return sum(_static_size(c) for c in t[1]) if t[0] == "tuple" else 32


# ------------------------------------------------------------------ encoding


def _pad_right(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 32)


def _enc_base(name: str, v) -> bytes:
    if name.startswith("uint"):
        return int(v).to_bytes(32, "big")
    if name.startswith("int"):
        return (int(v) % (1 << 256)).to_bytes(32, "big")
    if name == "address":
        raw = hexbytes(v)
        if len(raw) != 20:
            raise ValueError(f"bad address {v!r}")
        return raw.rjust(32, b"\x00")
    if name == "bool":
        return (1 if v else 0).to_bytes(32, "big")
    if name in ("bytes", "string"):
        raw = v.encode() if name == "string" else hexbytes(v)
        return len(raw).to_bytes(32, "big") + _pad_right(raw)
    if name.startswith("bytes"):
        n = int(name[5:])
        raw = hexbytes(v)
        if len(raw) != n:
            raise ValueError(f"{name} needs {n} bytes, got {len(raw)}")
        return raw.ljust(32, b"\x00")
    raise ValueError(f"unsupported ABI type {name}")


def _enc(t, v) -> bytes:
    kind, arg = t
    if kind == "base":
        return _enc_base(arg, v)
    if kind == "array":
        return len(v).to_bytes(32, "big") + _enc_tuple([arg] * len(v), list(v))
    return _enc_tuple(arg, list(v))


def _enc_tuple(types: list, values: list) -> bytes:
    if len(types) != len(values):
        raise ValueError(f"expected {len(types)} values, got {len(values)}")
    head_len = sum(32 if _dynamic(t) else _static_size(t) for t in types)
    heads, tails = b"", b""
    for t, v in zip(types, values):
        if _dynamic(t):
            heads += (head_len + len(tails)).to_bytes(32, "big")
            tails += _enc(t, v)
        else:
            heads += _enc(t, v)
    return heads + tails


def encode(types: list[str], values: list) -> bytes:
    return _enc_tuple([parse_type(t) for t in types], list(values))


def encode_call(signature: str, *values) -> str:
    """'f(uint256,bytes)' plus values -> 0x calldata."""
    name, args = signature.split("(", 1)
    types = split_top(args[:-1]) if args[:-1] else []
    return to_hex(hexbytes(selector(signature)) + encode(types, values))


# ------------------------------------------------------------------ decoding


def _word(data: bytes, pos: int) -> int:
    if pos + 32 > len(data):
        raise ValueError("ABI data too short")
    return int.from_bytes(data[pos:pos + 32], "big")


def _dec_base(name: str, data: bytes, pos: int):
    w = data[pos:pos + 32]
    if len(w) < 32:
        raise ValueError("ABI data too short")
    if name.startswith("uint"):
        return int.from_bytes(w, "big")
    if name.startswith("int"):
        n = int.from_bytes(w, "big")
        return n - (1 << 256) if n >> 255 else n
    if name == "address":
        return to_hex(w[12:])
    if name == "bool":
        return w[-1] == 1
    if name in ("bytes", "string"):
        n = _word(data, pos)
        raw = data[pos + 32:pos + 32 + n]
        return raw.decode("utf-8", "replace") if name == "string" else to_hex(raw)
    if name.startswith("bytes"):
        return to_hex(w[:int(name[5:])])
    raise ValueError(f"unsupported ABI type {name}")


def _dec(t, data: bytes, pos: int):
    kind, arg = t
    if kind == "base":
        return _dec_base(arg, data, pos)
    if kind == "array":
        n = _word(data, pos)
        return _dec_tuple([arg] * n, data, pos + 32)
    return _dec_tuple(arg, data, pos)


def _dec_tuple(types: list, data: bytes, base: int) -> list:
    out, pos = [], base
    for t in types:
        if _dynamic(t):
            out.append(_dec(t, data, base + _word(data, pos)))
            pos += 32
        else:
            out.append(_dec(t, data, pos))
            pos += _static_size(t)
    return out


def decode(types: list[str], data: str | bytes) -> list:
    return _dec_tuple([parse_type(t) for t in types], hexbytes(data), 0)
