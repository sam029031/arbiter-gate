"""Talking to ME Network (or a local anvil) from Python, standard library only.

Reads go straight to the EVM JSON-RPC with urllib; ABI encoding and Keccak live in abi.py.
Foundry's `cast` is used only to sign and send. Private keys never pass through this
module: on ME the transaction is signed by `cast` from a Foundry keystore, and the keystore
password is typed by the person running the command.

MEC units (measured 2026-11-21 against the testnet): the EVM balance of an account is its
bank balance in umec times 10^10, and the bank's denom metadata defines 1 MEC = 10^8 umec.
So 1 MEC = 10^18 of the EVM's smallest unit, the same 18 decimals as ether ("wei" below).
"""
from __future__ import annotations

import atexit
import dataclasses
import getpass
import json
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path

from . import abi
from .bech32 import to_me1

MEC_DECIMALS = 18
ZERO32 = "0x" + "00" * 32
# ME's node refuses eth_getLogs over more than 10,000 blocks ("maximum [from, to] blocks
# distance: 10000"), so every log query covers at most LOG_WINDOW blocks.
LOG_WINDOW = 10_000


class ChainError(RuntimeError):
    """An RPC call or a cast invocation failed."""


class RpcError(ChainError):
    """The node answered with a JSON-RPC error. `data` holds revert bytes when there are any."""

    def __init__(self, method: str, message: str, code: int | None = None, data: str | None = None):
        super().__init__(f"{method}: {message}")
        self.method, self.message, self.code, self.data = method, message, code, data


@dataclass(frozen=True)
class Network:
    name: str
    rpc: str
    chain_id: int
    explorer: str | None = None  # base URL, e.g. https://www.explorer-testnet.me
    rest: str | None = None  # Cosmos REST, used to find the Cosmos hash of an EVM tx
    faucet: str | None = None
    legacy: bool = False  # send type-0 transactions
    evm_version: str = "paris"  # ME testnet rejects PUSH0, so nothing newer than paris
    native_symbol: str = "MEC"
    # The explorer is a single-page app; these paths come from its router (/:lang/...). It
    # indexes Cosmos tx hashes and me1 addresses, not 0x forms.
    explorer_tx_path: str = "/zh-TW/transactions/{hash}?netType=hub"
    explorer_address_path: str = "/zh-TW/accountDetails/{me1}"
    extra_send_args: tuple[str, ...] = field(default_factory=tuple)

    def tx_url(self, tx_hash: str | None, cosmos_hash: str | None = None) -> str | None:
        """Explorer page of a transaction. The explorer indexes Cosmos transactions; an EVM
        transaction's Cosmos hash (Client.cosmos_tx_hash) is the only key it accepts; without
        one there is no working link (callers show the 0x hash and `cast receipt` instead)."""
        if not (self.explorer and cosmos_hash):
            return None
        return self.explorer + self.explorer_tx_path.format(hash=cosmos_hash.removeprefix("0x").upper())

    def address_url(self, address: str | None) -> str | None:
        if not (self.explorer and address):
            return None
        return self.explorer + self.explorer_address_path.format(me1=to_me1(address), address=address)


NETWORKS: dict[str, Network] = {
    "me-testnet": Network(
        name="me-testnet",
        rpc=os.environ.get("ME_RPC_URL", "https://beta-hub-8545.explorer-testnet.me"),
        chain_id=400,
        explorer="https://www.explorer-testnet.me",
        rest="https://beta-hub-1317.explorer-testnet.me",
        faucet="https://www.mec.me/zh-TW/faucet",
        legacy=os.environ.get("ME_LEGACY_TX") == "1",
    ),
    "anvil": Network(name="anvil", rpc=os.environ.get("ANVIL_RPC_URL", "http://127.0.0.1:8545"), chain_id=31337),
}


def network(name: str, rpc: str | None = None) -> Network:
    if name not in NETWORKS:
        raise ChainError(f"unknown network {name!r}; choose one of {', '.join(NETWORKS)}")
    net = NETWORKS[name]
    return dataclasses.replace(net, rpc=rpc) if rpc else net


# anvil's first two default accounts. Public test keys, published in Foundry's docs; only
# ever used when the connected chain id is 31337.
ANVIL_DEV_KEYS = (
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
)
ANVIL_DEV_KEY = ANVIL_DEV_KEYS[0]


# ------------------------------------------------------------------ MEC amounts


def format_mec(wei: int, symbol: str = "MEC") -> str:
    """18-decimal amount -> '0.0123 MEC' (exact, trailing zeros dropped)."""
    sign = "-" if wei < 0 else ""
    whole, frac = divmod(abs(int(wei)), 10**MEC_DECIMALS)
    text = f"{whole}.{frac:018d}".rstrip("0").rstrip(".")
    return f"{sign}{text} {symbol}"


def parse_mec(text: str) -> int:
    """'0.01' (MEC) -> 10**16. Rejects more than 18 decimals."""
    try:
        d = Decimal(text.strip().removesuffix("MEC").strip())
    except InvalidOperation as exc:
        raise ValueError(f"not an amount: {text!r}") from exc
    wei = d * (10**MEC_DECIMALS)
    if wei != wei.to_integral_value() or wei < 0:
        raise ValueError(f"not a valid MEC amount: {text!r}")
    return int(wei)


# ------------------------------------------------------------------ Foundry


def find_tool(name: str) -> str:
    path = shutil.which(name) or str(Path.home() / ".foundry" / "bin" / name)
    if not Path(path).exists():
        raise ChainError(f"{name} not found; install Foundry (https://getfoundry.sh)")
    return path


def _cast_error(out: str, err: str) -> str:
    # With --json, cast reports failures as {"success": false, "errors": [{message}]} on stdout.
    for line in reversed(out.splitlines()):
        try:
            env = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(env, dict) and env.get("errors"):
            return "; ".join(e.get("message", "") for e in env["errors"][:2])
    return err.strip() or out.strip()


def cast(*args: str, env: dict[str, str] | None = None, input_text: str | None = None, timeout: int = 180) -> str:
    proc = subprocess.run(
        [find_tool("cast"), *args],
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
        input=input_text,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise ChainError(f"cast {args[0]} failed: {_cast_error(proc.stdout, proc.stderr)}")
    return proc.stdout.strip()


# ------------------------------------------------------------------ JSON-RPC client


class Client:
    def __init__(self, network: Network, timeout: float = 30.0):
        self.network = network
        self.timeout = timeout
        self._id = 0

    def rpc(self, method: str, params: list | None = None):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or []}).encode()
        req = urllib.request.Request(self.network.rpc, data=body, headers={"content-type": "application/json"})
        last: Exception | None = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    payload = json.loads(resp.read().decode())
                break
            except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                last = exc
                time.sleep(1.5 * (attempt + 1))
        else:
            raise ChainError(f"{self.network.name} RPC unreachable ({method}): {last}")
        if payload.get("error"):
            err = payload["error"]
            data = err.get("data")
            if isinstance(data, dict):  # some nodes nest it
                data = data.get("data")
            raise RpcError(method, str(err.get("message", err)), err.get("code"),
                           data if isinstance(data, str) and data.startswith("0x") else None)
        return payload.get("result")

    def chain_id(self) -> int:
        return int(self.rpc("eth_chainId"), 16)

    def block_number(self) -> int:
        return int(self.rpc("eth_blockNumber"), 16)

    def get_code(self, address: str) -> str:
        return self.rpc("eth_getCode", [address, "latest"]) or "0x"

    def code_hash(self, address: str) -> str:
        """keccak256 of the runtime code, as EXTCODEHASH returns it (zero for no code)."""
        code = self.get_code(address)
        if code in ("0x", "0x0", ""):
            return ZERO32
        return abi.keccak_hex(code)

    def balance(self, address: str) -> int:
        return int(self.rpc("eth_getBalance", [address, "latest"]), 16)

    def receipt(self, tx_hash: str) -> dict | None:
        return self.rpc("eth_getTransactionReceipt", [tx_hash])

    def wait_receipt(self, tx_hash: str, timeout: float = 120.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            rec = self.receipt(tx_hash)
            if rec:
                return rec
            time.sleep(2)
        raise ChainError(f"no receipt for {tx_hash} after {timeout:.0f}s")

    def block_timestamp(self, block: int | str = "latest") -> int:
        tag = hex(block) if isinstance(block, int) else block
        return int(self.rpc("eth_getBlockByNumber", [tag, False])["timestamp"], 16)

    def call(self, to: str | None, data: str, sender: str | None = None, value: int = 0) -> str:
        tx: dict = {"data": data}
        if to:
            tx["to"] = to
        if sender:
            tx["from"] = sender
        if value:
            tx["value"] = hex(value)
        return self.rpc("eth_call", [tx, "latest"])

    def estimate_gas(self, to: str | None, data: str, sender: str | None = None, value: int = 0) -> int:
        tx: dict = {"data": data}
        if to:
            tx["to"] = to
        if sender:
            tx["from"] = sender
        if value:
            tx["value"] = hex(value)
        return int(self.rpc("eth_estimateGas", [tx]), 16)

    def gas_price(self) -> int:
        return int(self.rpc("eth_gasPrice"), 16)

    def get_logs(self, address: str, topics: list, from_block: int | str = 0,
                 to_block: int | str = "latest") -> list[dict]:
        def tag(b):
            return hex(b) if isinstance(b, int) else b
        return self.rpc("eth_getLogs", [{"address": address, "topics": topics,
                                         "fromBlock": tag(from_block), "toBlock": tag(to_block)}]) or []

    def block_at_timestamp(self, ts: int, lo: int = 0, hi: int | None = None) -> int:
        """First block in [lo, hi] whose timestamp is >= ts (hi when none is), by binary search
        over eth_getBlockByNumber. Block timestamps never decrease, so this is where a
        transaction mined at time `ts` can first appear."""
        hi = self.block_number() if hi is None else hi
        lo = max(0, min(lo, hi))
        while lo < hi:
            mid = (lo + hi) // 2
            if self.block_timestamp(mid) < ts:
                lo = mid + 1
            else:
                hi = mid
        return lo

    def find_logs(self, address: str, topics: list, start: int, end: int | None = None, *,
                  window: int = LOG_WINDOW, max_windows: int = 100, first: bool = True) -> list[dict]:
        """eth_getLogs from block `start` forward in windows of at most `window` blocks (ME's
        cap), stopping at the first window with a match when `first`. At most `max_windows`
        windows are read; a log further away is reported as not found."""
        end = self.block_number() if end is None else end
        window = max(1, min(window, LOG_WINDOW))
        out: list[dict] = []
        lo = max(0, start)
        for _ in range(max_windows):
            if lo > end:
                break
            hi = min(lo + window - 1, end)
            out += self.get_logs(address, topics, lo, hi)
            if out and first:
                break
            lo = hi + 1
        return out

    def check_network(self) -> None:
        got = self.chain_id()
        if got != self.network.chain_id:
            raise ChainError(f"{self.network.rpc} reports chain id {got}, expected {self.network.chain_id}")

    def increase_time(self, seconds: int) -> None:
        """anvil only: move block time forward and mine a block."""
        self.rpc("evm_increaseTime", [seconds])
        self.rpc("evm_mine", [])

    # -------------------------------------------------------------- typed helpers
    def view(self, to: str, signature: str, *args, out: list[str]) -> list:
        """Call a view function; `out` is the list of return types."""
        return abi.decode(out, self.call(to, abi.encode_call(signature, *args)))

    def read(self, to: str, signature: str, *args: str) -> list[str]:
        """Backwards-compatible: 'f(uint256)(bool)' with string args, decoded by cast."""
        data = calldata(signature.split("(")[0] + "(" + _inputs(signature) + ")", *args)
        raw = self.call(to, data)
        return decode_output(signature, raw)

    def cosmos_tx_hash(self, evm_hash: str) -> str | None:
        """The Cosmos transaction that carried an EVM transaction (what the explorer indexes)."""
        if not self.network.rest:
            return None
        q = urllib.parse.quote(f"ethereum_tx.ethereumTxHash='{evm_hash}'")
        try:
            with urllib.request.urlopen(f"{self.network.rest}/cosmos/tx/v1beta1/txs?events={q}",
                                        timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError):
            return None
        txs = data.get("tx_responses") or []
        return txs[0].get("txhash") if txs else None


def _inputs(signature: str) -> str:
    # "f(uint256,address)(bool)" -> "uint256,address"
    depth = 0
    start = signature.index("(")
    for i, ch in enumerate(signature[start:], start):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return signature[start + 1:i]
    raise ValueError(signature)


def calldata(signature: str, *args: str) -> str:
    return cast("calldata", signature, *args)


def decode_output(signature: str, raw: str) -> list[str]:
    out = cast("decode-abi", signature, raw)
    return [line for line in out.splitlines()]


def keccak(hex_data: str) -> str:
    return abi.keccak_hex(hex_data)


def abi_encode(signature: str, *args: str) -> str:
    return cast("abi-encode", signature, *args)


# ------------------------------------------------------------------ signing


class Signer:
    """Sends transactions through `cast send`. Subclasses decide how cast gets the key."""

    address: str

    def _key_args(self) -> list[str]:
        raise NotImplementedError

    def _env(self) -> dict[str, str]:
        return {}

    def send(self, client: Client, to: str | None, data: str, value: int = 0, gas_limit: int | None = None,
             allow_revert: bool = False) -> dict:
        """Send and wait for the receipt. `to=None` deploys `data` as creation bytecode.
        `allow_revert` with a `gas_limit` sends a transaction expected to revert (cast skips
        the gas estimate that would otherwise refuse it) and returns its status-0 receipt."""
        net = client.network
        args = ["send", "--rpc-url", net.rpc, "--chain", str(net.chain_id), "--json"]
        if net.legacy:
            args.append("--legacy")
        if value:
            args += ["--value", str(value)]
        if gas_limit:
            args += ["--gas-limit", str(gas_limit)]
        args += list(net.extra_send_args)
        args += self._key_args()
        if to is None:
            args += ["--create", data]
        else:
            args += [to, data]
        out = cast(*args, env=self._env(), timeout=300)
        try:
            receipt = json.loads(out.splitlines()[-1])
        except (json.JSONDecodeError, IndexError) as exc:
            raise ChainError(f"unexpected cast send output: {out[:300]}") from exc
        ok = str(receipt.get("status")) in ("0x1", "1", "true", "True")
        if not ok and not allow_revert:
            raise ChainError(f"transaction reverted: {receipt.get('transactionHash')}")
        return receipt

    def close(self) -> None:  # pragma: no cover - default no-op
        pass


class DevKeySigner(Signer):
    """anvil only: refuses to sign for any chain other than 31337."""

    def __init__(self, client: Client, key: str = ANVIL_DEV_KEY):
        if client.chain_id() != 31337:
            raise ChainError("the anvil development key is only allowed on chain id 31337")
        self._key = key
        self.address = cast("wallet", "address", "--private-key", key).lower()

    def _key_args(self) -> list[str]:
        return ["--private-key", self._key]


# Password files of the open KeystoreSigners (file -> its private directory). They are removed
# by close(), at interpreter exit (atexit), and when the process is told to stop (SIGTERM,
# SIGHUP when the terminal closes, SIGINT): a signal that ends the process skips `finally`
# blocks and __del__, which used to leave the keystore password on disk.
_PW_FILES: dict[str, str] = {}
_PREV_HANDLERS: dict[int, object] = {}
_cleanup_lock = threading.Lock()
_cleanup_ready = False


def _remove_pw(pwfile: str, directory: str | None) -> None:
    try:
        os.remove(pwfile)
    except OSError:
        pass
    if directory:
        try:
            os.rmdir(directory)
        except OSError:
            pass


def _cleanup_pw_files() -> None:
    while _PW_FILES:
        try:
            pwfile, directory = _PW_FILES.popitem()
        except KeyError:
            break
        _remove_pw(pwfile, directory)


def _on_stop_signal(signum, frame) -> None:
    _cleanup_pw_files()
    prev = _PREV_HANDLERS.get(signum)
    if callable(prev):
        prev(signum, frame)  # Python's own SIGINT handler raises KeyboardInterrupt
        return
    # The default action would end the process; end it the same way, but through
    # SystemExit so `finally` blocks and atexit run too.
    raise SystemExit(128 + signum)


def _install_pw_cleanup() -> None:
    global _cleanup_ready
    with _cleanup_lock:
        if _cleanup_ready:
            return
        _cleanup_ready = True
    atexit.register(_cleanup_pw_files)
    if threading.current_thread() is not threading.main_thread():
        return  # signal handlers can only be set from the main thread; atexit still applies
    for name in ("SIGTERM", "SIGHUP", "SIGINT"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            prev = signal.getsignal(sig)
            if prev == signal.SIG_IGN or prev is None:
                continue  # ignored on purpose (nohup): the process keeps running, keep the file
            _PREV_HANDLERS[sig] = prev if callable(prev) else None
            signal.signal(sig, _on_stop_signal)
        except (ValueError, OSError):
            continue


class KeystoreSigner(Signer):
    """A Foundry keystore (~/.foundry/keystores/<name>). The password is typed once, kept in a
    private temporary file for the lifetime of this object, and removed by close(), at exit,
    or when the process is stopped by SIGTERM / SIGHUP / SIGINT."""

    def __init__(self, account: str, address: str | None = None, prompt: str | None = None):
        self.account = account
        pw = getpass.getpass(prompt or f"keystore '{account}' 的密碼（輸入時不會顯示）: ")
        _install_pw_cleanup()
        self._dir = tempfile.mkdtemp(prefix="arbiter-me-")
        os.chmod(self._dir, 0o700)
        self._pwfile = os.path.join(self._dir, "pw")
        _PW_FILES[self._pwfile] = self._dir  # registered before the password is written
        fd = os.open(self._pwfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(pw)
        del pw
        try:
            self.address = (address or cast("wallet", "address", "--account", account,
                                            "--password-file", self._pwfile)).lower()
        except ChainError:
            self.close()
            raise ChainError(f"無法開啟 keystore '{account}'：密碼錯誤或 keystore 不存在") from None

    def _key_args(self) -> list[str]:
        return ["--account", self.account, "--password-file", self._pwfile]

    def close(self) -> None:
        pwfile, directory = getattr(self, "_pwfile", None), getattr(self, "_dir", None)
        if not pwfile:
            return
        _PW_FILES.pop(pwfile, None)
        _remove_pw(pwfile, directory)

    def __del__(self):  # pragma: no cover - best effort
        self.close()
