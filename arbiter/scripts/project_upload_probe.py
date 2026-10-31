#!/usr/bin/env python3
"""The project (.zip) upload, offline: what is refused, what is unpacked, what is picked.

  normal          one top folder named "examples" (a word triage skips): lifted out, the
                  root is always `project`, src/ is a candidate, test/ and lib/ are not
  pick_two        two deployable contracts: both listed, the one with more state-changing
                  entry points preselected; the selection page renders
  zip_slip        a member named ../evil.sol                      -> refused
  absolute        a member named /tmp/evil.sol                    -> refused
  symlink         a member that is a symlink                      -> refused
  too_many        more than MAX_ZIP_FILES members                 -> refused
  bomb            a member whose unpacked size is over the limit  -> refused (a few KB on
                                                                     the wire)
  not_zip         .zip bytes that are not a zip                   -> refused
  nothing         only an interface and a test                    -> no candidate

No model request, no forge.

    python3 scripts/project_upload_probe.py
"""

from __future__ import annotations

import io
import shutil
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from arbiter import web, webui  # noqa: E402
from arbiter.gate import pick_target  # noqa: E402

VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    mapping(address => uint256) public bal;
    function deposit() external payable { bal[msg.sender] += msg.value; }
    function withdraw() external { uint256 a = bal[msg.sender]; bal[msg.sender] = 0; payable(msg.sender).transfer(a); }
    function sweep(address to) external { payable(to).transfer(0); }
}
"""
TOKEN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Token {
    mapping(address => uint256) public balanceOf;
    function mint() external payable { balanceOf[msg.sender] += msg.value; }
}
"""
IFACE = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ninterface IVault { function deposit() external payable; }\n"
TEST = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport \"../src/Vault.sol\";\ncontract VaultTest { function test_x() public {} }\n"


def make_zip(entries: list[tuple[str, bytes]], links: list[tuple[str, str]] = ()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
        for name, target in links:
            info = zipfile.ZipInfo(name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            z.writestr(info, target)
    return buf.getvalue()


results: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str) -> None:
    results.append((name, ok, detail))
    print(f"  [{'OK  ' if ok else 'WRONG'}] {name:10s} {detail}")


def refused(tmp: Path, name: str, data: bytes, want: str) -> None:
    d = tmp / name
    root, err = web.extract_project_zip(data, d)
    escaped = (tmp / "evil.sol").exists() or Path("/tmp/evil.sol").exists()
    check(name, root is None and want in err and not escaped, err or "accepted")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="upload-probe-"))
    try:
        z = make_zip([("examples/foundry.toml", b"[profile.default]\n"),
                      ("examples/src/Vault.sol", VAULT.encode()),
                      ("examples/src/IVault.sol", IFACE.encode()),
                      ("examples/test/Vault.t.sol", TEST.encode()),
                      ("examples/lib/dep/src/Token.sol", TOKEN.encode()),
                      ("__MACOSX/examples/._Vault.sol", b"x")])
        root, err = web.extract_project_zip(z, tmp / "normal")
        first, cands = pick_target(root) if root else (None, [])
        keep = [c["rel"] for c in cands if not c.get("skipped")]
        check("normal", root is not None and root.name == "project" and first == "src/Vault.sol"
              and keep == ["src/Vault.sol"] and not (root / "__MACOSX").exists(),
              f"root={root.name if root else err} candidates={keep}")

        z2 = make_zip([("src/Vault.sol", VAULT.encode()), ("src/Token.sol", TOKEN.encode())])
        root2, _ = web.extract_project_zip(z2, tmp / "two")
        first2, cands2 = pick_target(root2)
        keep2 = [c["rel"] for c in cands2 if not c.get("skipped")]
        page = webui.render_pick("0123456789ab", "two.zip", cands2, first2).decode()
        check("pick_two", first2 == "src/Vault.sol" and len(keep2) == 2
              and "checked" in page and "src/Token.sol" in page,
              f"preselected={first2} candidates={keep2}")

        refused(tmp, "zip_slip", make_zip([("../evil.sol", b"x")]), "不安全的路徑")
        refused(tmp, "absolute", make_zip([("/tmp/evil.sol", b"x")]), "不安全的路徑")
        refused(tmp, "symlink", make_zip([("src/V.sol", b"x")], [("src/link.sol", "/etc/passwd")]),
                "符號連結")
        refused(tmp, "too_many", make_zip([(f"f{i}.txt", b"") for i in range(web.MAX_ZIP_FILES + 1)]),
                "太多")
        bomb = make_zip([("big.bin", b"\0" * (web.MAX_UNZIPPED + 1))])
        refused(tmp, "bomb", bomb, "太大")
        check("bomb_size", len(bomb) < 1_000_000, f"the archive itself is {len(bomb)} bytes")
        refused(tmp, "not_zip", b"PK not really", "不是有效")

        z3 = make_zip([("src/IVault.sol", IFACE.encode()), ("test/Vault.t.sol", TEST.encode())])
        root3, _ = web.extract_project_zip(z3, tmp / "nothing")
        first3, _ = pick_target(root3)
        check("nothing", first3 is None, f"first={first3}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    good = sum(ok for _, ok, _ in results)
    print(f"\n{good}/{len(results)} as expected")
    return 0 if good == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
