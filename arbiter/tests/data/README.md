# Test data

| file | source | sha256 | fetched |
|---|---|---|---|
| `sarif-schema-2.1.0.json` | OASIS SARIF 2.1.0 Errata 01, official JSON Schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` | 2026-10-29 |

Used by `scripts/sarif_validate.py` to check `arbiter/sarif.py` output. Kept unmodified.

| file | source | sha256 | made |
|---|---|---|---|
| `me_anvil_demo.me.json` | The ME sidecar (BRIEF 4.2, with `patched`) written by `me/me.py demo --dev --network anvil`, run by `me/scripts/me_registry_probe.py` at commit 50936ba on a local anvil (chainId 31337, the published anvil dev account). No ME testnet transaction. | `0692620434d1054a147538e2cad1a567ea5102e13dcb91139e0ed14596ed67c5` | 2026-11-22 |

Used by `scripts/webui_probe.py` (me_real) to render the result page card from a real sidecar.
