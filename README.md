# ubipack — UBI Firmware Analysis & Surgical Repacking Toolkit

A unified CLI that wraps the UBI analyst + surgical repacker scripts into
a single installable command. Mirrors the `sqpack` architecture: top-level
launcher + Python package + `pyproject.toml` console-script entry point.

## Install

Run from inside the project directory (the folder containing this README):

```bash
# Option A — uv (recommended; isolated tool venv)
uv tool install .

# Option B — pipx
pipx install .

# Option C — pip in a venv
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

No-install quickstart — run the top-level launcher directly:

```bash
python3 ubipack.py --help
```

After `uv tool install .` (or `pipx install .`), the `ubipack` command is on
`PATH` system-wide via `~/.local/bin/ubipack`.

## Operations

One operation per invocation, selected by a single short flag (sqpack style):

| Flag | Operation    | Purpose                                                 |
|------|--------------|---------------------------------------------------------|
| `-a` | `analyze`    | Scan firmware, detect NAND geometry, extract UBI regions|
| `-x` | `extract`    | Alias for `analyze` (always writes extraction)          |
| `-r` | `repack`     | Surgical clean-UBI replace of one or more volumes       |
| `-c` | `compare`    | Compare two analysis directories                        |
| `-V` | `verify`     | Re-audit analysis output (VID CRC + EC magic/CRC)       |
| `-t` | `self-test`  | Toolchain availability + submodule import sanity        |

## Examples

```bash
# Analyze a raw firmware blob and extract UBI regions + inner filesystems
ubipack -a -s firmware.bin -o analysis_out/

# Force NAND geometry when autodetect fails
ubipack -a -s firmware.bin -o analysis_out/ \
    --force-geometry --page-size 0x800 --oob-size 0x40 --peb-size 0x20000

# Surgical replace of one volume inside an analyzed clean UBI region
ubipack -r -n analysis_out/ \
    --replace region0:rootfs=/path/new_rootfs.squashfs \
    -o repacked/

# Preflight (validate capacities without writing)
ubipack -r -n analysis_out/ \
    --replace region0:rootfs=/path/new_rootfs.squashfs --dry-run

# Multi-region / multi-volume replacement
ubipack -r -n analysis_out/ \
    --replace region0:rootfs=/path/new_r0.squashfs \
    --replace region1:rootfs=/path/new_r1.squashfs \
    -o repacked/ --yes

# Compare two analyses (e.g. before vs after firmware mod)
ubipack -c --left before/ --right after/ -o diff.json

# Re-verify integrity of a previous analysis
ubipack -V -n analysis_out/

# Sanity-check your toolchain
ubipack -t
```

## Project Layout

```
ubi_toolkit/
├── .gitignore             # Python build/cache outputs
├── pyproject.toml         # setuptools, ubipack console-script entry
├── README.md              # this file
├── ubipack.py             # top-level launcher (run without install)
└── ubi_toolkit/           # installable package
    ├── __init__.py        # version, OPERATIONS, METADATA_FILENAME
    ├── ubipack.py         # unified CLI dispatcher
    ├── analyst.py         # UBI region detection + extract
    ├── repacker.py        # Surgical volume replacement
    └── ecc_runtime.py     # NAND ECC layout handling
```

## Submodules

The package vendors three UBI scripts unmodified. Drop in newer iterations
of those scripts by overwriting the corresponding file inside `ubi_toolkit/` —
the CLI dispatcher auto-uses whatever is there.

| Module         | Source                              |
|----------------|-------------------------------------|
| `analyst`      | `ubi_analyst.py`                    |
| `repacker`     | `clean_ubi_surgical_repacker.py`    |
| `ecc_runtime`  | `ecc_runtime_progressive.py`        |

## Iteration Discipline

This is **v1.0.0**. As in the `sqpack` workflow, each new iteration
(`v1.1.0`, `v1.2.0`, …) is a fresh directory copy; prior iterations stay
frozen and remain installed/usable. Within an iteration, the named scope
is the hard boundary — don't refactor across versions.

## License

All Rights Reserved. See `LICENSE` for terms.
