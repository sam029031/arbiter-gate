#!/usr/bin/env python3
"""Look up and independently re-check an ARBITER Gate record on ME.
Same as `python3 me/me.py verify`; see arbiter_me/verify.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arbiter_me.verify import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
