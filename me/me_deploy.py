#!/usr/bin/env python3
"""Register an ARBITER Gate result on ME and deploy through the registry when allowed.
Same as `python3 me/me.py deploy`; see arbiter_me/deploy.py."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arbiter_me.deploy import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
