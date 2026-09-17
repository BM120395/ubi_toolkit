# ubipack — UBI Firmware Analysis & Surgical Repacking Toolkit

> **v1.3.0** — new in this iteration: volume-level `--reference`. Pass a
> known-good **volume** image (e.g. the FS image extracted from a sibling
> dump) and the pre-scan adjudicates the inline-ECC page layout by content
> matching (LEB prefixes must appear verbatim in the reference), then
> patches the extracted volumes against it (isolated single-bit rot only —
> evidence-gated, never blind). Size-matched references keep the existing
> whole-image bit-rot behavior. Also new: `strip_page_layout()` — with
> `--auto-fix`, an adjudicated layout is applied to the image
> (`<input>.layout.bin`) before analysis.
>
> **v1.2.0** — `ubi_toolkit/anomaly.py` and
> `ubipack --auto-fix/--reference` — a fail-fast anomaly pre-scan (exit 3 with
> an exact rerun hint) covering bit rot vs a reference image, inline-ECC page
> layouts, CRC-convention variants, and single-bit VID repair, generalized to
> any geometry. Plus `case_studies/`: a documented real-world NAND recovery as
> a self-contained reference module (`ubi_toolkit/case_studies/`). Read-only
> reference code for the anomaly engine; not wired into any CLI operation.
> See `case_studies/README.md`.

A unified CLI that wraps the UBI analyst + surgical repacker scripts into
a single installable command. Mirrors the `sqpack` architecture: top-level
launcher + Python package + `pyproject.toml` console-script entry point.

## Dependencies

The core `ubipack` CLI runs on the **Python standard library only** — no
required third-party packages.

| Dependency | Required? | Used for | Install command |
|---|---|---|---|
| Python 3.8+ | ✅ required | runtime | system Python |
| `tkinter` | ⚪ optional | GUI (file picker / dialogs in analyst) | `sudo apt install python3-tk` (Debian/Ubuntu) |
| `tqdm` | ⚪ optional | progress bars during long scans | `uv tool install --with tqdm .` or `pip install tqdm` |

Both optional modules are **guarded** — if absent, the tool falls back to a
no-GUI / no-progress mode and everything else works normally. Install them
only if you want the GUI or progress bars:

```sh
# uv — with both optional extras
uv tool install --with tqdm ./

# pip
pip install .[tqdm]

# tkinter (system package, Python 3.x)
sudo apt install python3-tk   # Debian / Ubuntu
# macOS ships with Tk bundled; Windows includes it by default
```

## Install

There are four ways to use it. Pick one.

### Option A — `uv tool install` (recommended, isolated)

Installs `ubipack` as a standalone command in its own virtual environment
(the same way this tool is installed on the author's machine):

```bash
# from the toolkit directory
uv tool install ./ubi_toolkit_v1.0

# or from anywhere, pointing at the directory
uv tool install /path/to/ubi_toolkit_v1.0

# or straight from the built wheel
uv tool install ./dist/ubi_toolkit-1.0.0-py3-none-any.whl
```

After install, `ubipack` is on `PATH` (via `~/.local/bin/ubipack`).
Include optional extras at install time:

```bash
uv tool install --with tqdm ./ubi_toolkit_v1.0   # + progress bars
```

### Option B — `pipx install`

```bash
# from the toolkit directory
pipx install ./ubi_toolkit_v1.0

# or from anywhere, pointing at the directory
pipx install /path/to/ubi_toolkit_v1.0

# or straight from the built wheel
pipx install ./dist/ubi_toolkit-1.0.0-py3-none-any.whl
```

Optional extras after install: `pipx inject ubipack tqdm` (progress bars).

### Option C — `pip` in a venv

```bash
python3 -m venv .venv && . .venv/bin/activate

# from inside the toolkit directory
pip install .

# or from anywhere, pointing at the directory
pip install /path/to/ubi_toolkit_v1.0

# or straight from the built wheel
pip install ./dist/ubi_toolkit-1.0.0-py3-none-any.whl

# editable install (live code changes, run from the toolkit directory)
pip install -e .

# with optional extras
pip install .[tqdm]
```

### Option D — install from the prebuilt distribution files

`dist/` contains both packaging formats, built from this exact tree:

```bash
uv tool install ./dist/ubi_toolkit-1.0.0-py3-none-any.whl   # wheel
pip install ./dist/ubi_toolkit-1.0.0-py3-none-any.whl
pip install ./dist/ubi_toolkit-1.0.0.tar.gz                 # sdist
```

### No-install quickstart

Run the top-level launcher directly (no install needed):

```bash
python3 ubipack.py --help
```

### Verifying the install

```bash
ubipack --version      # → 1.0.0
ubipack -t             # toolchain + submodule sanity check
```

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

Standard copyright notice, © 2026 Bharatiy, "All Rights Reserved".
See `LICENSE` for full terms.
