"""
Pytest bootstrap for the openagent-logger test suite.

These tests exercise the pure functions in ``src/security.py`` only — no
database, no network, no FastAPI app. We just need the package importable
when pytest is invoked from the repo root.

``src`` is a real package (it has ``__init__.py``), so adding the repo root
to ``sys.path`` lets us ``import src.security``. We also force the HMAC secret
to a known value at collection time so signature round-trip tests are
deterministic regardless of the developer's environment.
"""

import os
import sys
from pathlib import Path

# Repo root = parent of this tests/ directory.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Pin the HMAC secret BEFORE src.security is imported, since the module reads
# LOGGER_HMAC_SECRET into a module-level constant at import time.
os.environ.setdefault("LOGGER_HMAC_SECRET", "test-secret")
