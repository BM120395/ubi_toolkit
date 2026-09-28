# ubipack — UBI Firmware Analysis & Surgical Repacking Toolkit

> **v1.10.0** — donor-based recovery, made honest. The anomaly pre-scan now
> runs on **every** analyze: an ECC-interleaved dump analyzed without
> `--auto-fix` exits 3 with the exact rerun hint instead of silently
> extracting page-shifted (corrupt) volumes. `--reference` accepts a full
> image, a volume, **or a vendor sysupgrade package** (its clean volume is
> extracted automatically). New `--restore-reference`: when an extracted
> volume differs from the trusted donor beyond single-bit rot (layout/
> reassembly/version drift), the donor's bytes are restored verbatim
> (size-clamped) instead of skipped. Reference-free `--auto-fix` still
> works (layout self-adjudicated from the image's own xz-checksummed
> metadata) but now prints an explicit note that residual single-bit rot
> may remain — donor references give byte-exact output.
>
> **v1.3.0** — volume-level `--reference` (layout adjudication by content
> matching + extracted-volume patching) and `strip_page_layout()`.
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

There are five ways to install it. Pick one.

### Option A — self-install (no pip/uv/venv needed, recommended)

Since v1.6.0 ubipack manages its own installation: it copies the pure-stdlib
package under `--prefix` and writes a `ubipack` shim, tracked by an uninstall
manifest. No pip, no uv, no virtualenv, no sudo (default prefix `~/.local`).

```bash
# from a release tarball or a git clone of this repo
python3 -m ubi_toolkit.ubipack --install     # or: ./ubipack.py --install
```

Lifecycle shortcuts:

| Command | Effect |
|---|---|
| `ubipack --install` (`-I`) | install / upgrade in place (idempotent) |
| `ubipack --upgrade` | fetch the latest tarball from GitHub and reinstall |
| `ubipack --upgrade-url URL` | upgrade from a custom tarball URL or local path |
| `ubipack --uninstall` (`-U`) | manifest-driven uninstall (removes only what it created) |
| `ubipack --uninstall --force` | also remove a foreign (non-lifecycle) shim |
| `ubipack -K DIR` (`--clean`) | list generated sidecars (`*.autofix.bin`, `*.layout.bin`) — dry run |
| `ubipack -K DIR --yes` | apply the cleanup |
| `ubipack ... --prefix DIR` | install location (default `~/.local`) |

A pre-existing non-lifecycle `ubipack` shim (uv/pipx/pip) is never silently
replaced — it is backed up to `ubipack.pre-lifecycle` first. GitHub-upgrade
works from the very first self-install:

```bash
python3 -m ubi_toolkit.ubipack --install   # once
ubipack --upgrade                          # every later version
```

### Option B — `uv tool install` (isolated, pre-built venv)

Installs `ubipack` as a standalone command in its own virtual environment:

```bash
# from the toolkit directory
uv tool install ./ubi_toolkit_v1.0

# or from anywhere, pointing at the directory
uv tool install /path/to/ubi_toolkit_v1.0

# or straight from the built wheel
uv tool install ./dist/ubi_toolkit-<version>-py3-none-any.whl
```

After install, `ubipack` is on `PATH` (via `~/.local/bin/ubipack`).
Include optional extras at install time:

```bash
uv tool install --with tqdm ./ubi_toolkit_v1.0   # + progress bars
```

### Option C — `pipx install`

```bash
# from the toolkit directory
pipx install ./ubi_toolkit_v1.0

# or from anywhere, pointing at the directory
pipx install /path/to/ubi_toolkit_v1.0

# or straight from the built wheel
pipx install ./dist/ubi_toolkit-<version>-py3-none-any.whl
```

Optional extras after install: `pipx inject ubipack tqdm` (progress bars).

### Option D — `pip` in a venv

```bash
python3 -m venv .venv && . .venv/bin/activate

# from inside the toolkit directory
pip install .

# or from anywhere, pointing at the directory
pip install /path/to/ubi_toolkit_v1.0

# or straight from the built wheel
pip install ./dist/ubi_toolkit-<version>-py3-none-any.whl

# editable install (live code changes, run from the toolkit directory)
pip install -e .

# with optional extras
pip install .[tqdm]
```

### Option E — install from the prebuilt distribution files

`dist/` contains both packaging formats, built from this exact tree:

```bash
uv tool install ./dist/ubi_toolkit-<version>-py3-none-any.whl   # wheel
pip install ./dist/ubi_toolkit-<version>-py3-none-any.whl
pip install ./dist/ubi_toolkit-<version>.tar.gz                 # sdist
```

### No-install quickstart

Run the top-level launcher directly (no install needed):

```bash
python3 ubipack.py --help
```

### Verifying the install

```bash
ubipack --version      # → ubipack 1.6.0
ubipack -t             # toolchain + submodules + lifecycle round-trip check
python3 -m unittest tests.test_lifecycle -v   # test suite (from the repo root)
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

Lifecycle (v1.6.0): `-I/--install` · `-U/--uninstall` · `--upgrade` ·
`-K/--clean PATH` — see *Installation, Option A*. The anomaly pre-scan runs
on every analyze. Repairable anomalies fail fast (exit 3) unless
`--auto-fix` is given; `--reference KNOWN_GOOD` enables bit-rot evidence
(image, volume, or vendor sysupgrade package) and `--restore-reference`
canonicalizes extracted volumes from the trusted donor.

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

# Verify integrity of a previously-produced analysis
ubipack -V -n analysis_out/

# Reference-free recovery of an ECC-interleaved dump (layout self-adjudicated;
# prints a note that residual single-bit rot may remain)
ubipack -a -s dump.bin -o out/ --auto-fix

# Byte-exact recovery with a trusted donor (full image, volume, or vendor
# sysupgrade package all work); --restore-reference additionally restores
# donor bytes verbatim when differences go beyond single-bit rot
ubipack -a -s dump.bin -o out/ --auto-fix \
    --reference sysupgrade.bin
ubipack -a -s dump.bin -o out/ --auto-fix \
    --reference donor_volume.squashfs --restore-reference

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
    ├── ecc_runtime.py     # NAND ECC layout handling
    ├── anomaly.py         # anomaly engine (ANOM-1..5) + --auto-fix
    ├── bootimg.py         # uImage / FIT payload extraction
    └── lifecycle.py       # self-install / uninstall / upgrade / clean
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

This is **v1.6.0**. As in the `sqpack` workflow, each new iteration
(`v1.1.0`, `v1.2.0`, …) is a fresh directory copy; prior iterations stay
frozen and remain installed/usable. Within an iteration, the named scope
is the hard boundary — don't refactor across versions.

## License

Standard copyright notice, © 2026 Bharatiy, "All Rights Reserved".
See `LICENSE` for full terms.
