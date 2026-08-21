#!/usr/bin/env python3
"""
ubipack.py (top-level launcher)
================================
Standalone entry point: run this directly with `python3 ubipack.py ...`
from any working directory, with no installation required. Mirrors the
sqpack top-level launcher: the package's PARENT directory is added to
sys.path so the inner package can be imported normally, avoiding
"attempted relative import with no known parent package" errors when
run from inside the ubi_toolkit/ directory.

The actual CLI logic lives in ubi_toolkit/ubipack.py and is shared
with the `ubipack` console-script entry point installed via pyproject.toml.
"""
import os
import sys

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from ubi_toolkit.ubipack import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
