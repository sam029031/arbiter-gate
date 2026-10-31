#!/usr/bin/env python3
"""Validate SARIF from arbiter/sarif.py against the official SARIF 2.1.0 JSON Schema.

    <python with jsonschema> scripts/sarif_validate.py report.sarif [gate.json]

The schema is tests/data/sarif-schema-2.1.0.json (OASIS, errata 01; source and sha256 in
tests/data/README.md). jsonschema is not in the standard library, so this runs under the
tools venv (~/innoserve/venv-tools/bin/python), never inside arbiter/ itself. Given the
gate.json the SARIF came from, also checks error-level results == proven findings.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RIG = Path(__file__).resolve().parent.parent
SCHEMA = RIG / "tests" / "data" / "sarif-schema-2.1.0.json"
sys.path.insert(0, str(RIG))


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print(__doc__.strip().splitlines()[2].strip())
        return 64
    try:
        import jsonschema
    except ImportError:
        print("jsonschema not installed; run with ~/innoserve/venv-tools/bin/python")
        return 2
    sarif = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    cls = jsonschema.validators.validator_for(schema)
    errors = sorted(cls(schema).iter_errors(sarif), key=lambda e: list(e.path))
    for err in errors[:20]:
        print(f"  schema: {'/'.join(map(str, err.path)) or '<root>'}: {err.message[:200]}")
    levels = [r.get("level") for run in sarif.get("runs", []) for r in run.get("results", [])]
    ok = not errors
    print(f"{Path(sys.argv[1]).name}: {'valid' if not errors else 'INVALID'} SARIF "
          f"{sarif.get('version')} ({cls.__name__}); results: "
          f"error={levels.count('error')} warning={levels.count('warning')}; "
          f"executionSuccessful="
          f"{[i.get('executionSuccessful') for run in sarif['runs'] for i in run.get('invocations', [])]}")
    if len(sys.argv) == 3:
        from arbiter.sarif import proven_count
        want = proven_count(json.loads(Path(sys.argv[2]).read_text(encoding="utf-8")))
        same = levels.count("error") == want
        print(f"  error results {levels.count('error')} == proven findings in gate.json {want}: "
              f"{'yes' if same else 'NO'}")
        ok = ok and same
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
