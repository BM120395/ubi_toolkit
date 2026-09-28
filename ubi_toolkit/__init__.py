"""ubi_toolkit — deterministic UBI firmware analysis, extraction, and surgical repacking.

Mirror of the sqpack architecture (unified CLI dispatcher over a library package).
Submodules wrap the original UBI analysis/repacking scripts that ship under
``~/Scripts/UBI`` so they can be invoked through a single ``ubipack`` command
and installed via ``uv tool install .`` or ``pip install .``.
"""

from __future__ import annotations

__version__ = "1.10.0"

# Operations exposed by the unified CLI.
OPERATIONS = ("analyze", "extract", "repack", "compare", "verify", "self-test")

# Sidecar metadata schema. Stored next to an analysis directory so the tool can
# auto-detect which firmware an extraction was produced from.
METADATA_FILENAME = ".ubipack_meta.json"
METADATA_SCHEMA_VERSION = 1
