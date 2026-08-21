"""
ubipack — unified UBI firmware analysis / extraction / repacking CLI.

Operations (one chosen per invocation, mirroring sqpack's flat-flag style):

    analyze     Scan a firmware blob, detect NAND geometry, locate UBI regions
                and inner filesystems (SquashFS/JFFS2/CramFS/UBIFS/DTB).
                Wraps analyst.FirmwareAnalyst (OpenWUI_upg-06).
    extract     Alias for analyze that always writes the extracted tree.
    repack      Surgical clean-UBI repack: replace one or more UBI volumes
                inside a previously-analyzed image without disturbing other
                regions or PEBs. Wraps repacker.main (itr04).
    compare     Compare two analysis directories (region/volume layout,
                filesystem layouts, sizes, hashes).
    verify      Re-load an analysis directory, re-run baseline VID+EC audits,
                and confirm structural integrity of the analyst output.
    self-test   Quick sanity check of toolchain availability (ubi tools on
                PATH, package importable, submodules loadable).

Sidecar: when analyze/extract runs, a ``.ubipack_meta.json`` file is written
in the analysis directory capturing the source image path + sha256, so
later ``repack`` and ``verify`` invocations can auto-detect provenance
(analogous to sqpack's ``.sqpack_meta.json``).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ubi_toolkit import METADATA_FILENAME, METADATA_SCHEMA_VERSION

log = logging.getLogger("ubipack")


# ═══════════════════════════════════════════════════════════════════════════
# Sidecar metadata
# ═══════════════════════════════════════════════════════════════════════════

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sidecar(analysis_dir: Path, source: Path, extra: Optional[dict] = None) -> Path:
    """Write ``.ubipack_meta.json`` next to the analysis output.

    Stores the source firmware path + sha256 so a later ``repack`` or
    ``verify`` invocation can auto-detect provenance. ``extra`` is merged
    into the sidecar for operation-specific notes (geometry, region count).
    """
    analysis_dir = Path(analysis_dir).resolve()
    analysis_dir.mkdir(parents=True, exist_ok=True)
    sidecar = {
        "schema_version": METADATA_SCHEMA_VERSION,
        "source_image": str(source.resolve()),
        "source_sha256": _sha256_file(source) if source.exists() else None,
        "ubipack_version": "1.0.0",
    }
    if extra:
        sidecar.update(extra)
    out = analysis_dir / METADATA_FILENAME
    out.write_text(json.dumps(sidecar, indent=2, sort_keys=True))
    return out


def read_sidecar(analysis_dir: Path) -> Optional[dict]:
    p = Path(analysis_dir) / METADATA_FILENAME
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


# ═══════════════════════════════════════════════════════════════════════════
# Tempdir / artifact lifecycle (mirror sqpack ArtifactManager)
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ArtifactManager:
    """Owns a single tempdir per invocation. Cleaned up unless keep=True."""
    keep: bool = False
    root: Optional[Path] = None

    def __enter__(self) -> "ArtifactManager":
        self.root = Path(tempfile.mkdtemp(prefix="ubipack_"))
        return self

    def __exit__(self, *exc) -> None:
        if self.root and self.root.exists() and not self.keep:
            shutil.rmtree(self.root, ignore_errors=True)
        elif self.root:
            log.info("[KEEP] tempdir preserved at %s", self.root)

    def path(self, *parts) -> Path:
        assert self.root is not None, "ArtifactManager not entered"
        p = self.root.joinpath(*parts)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p


# ═══════════════════════════════════════════════════════════════════════════
# Operations
# ═══════════════════════════════════════════════════════════════════════════

def _check_tool(name: str) -> Optional[str]:
    return shutil.which(name)


def op_self_test(_args: argparse.Namespace) -> int:
    print("ubipack self-test")
    print("=" * 50)
    # Python
    print(f"  python       : {sys.version.split()[0]}")
    # External tools used by analyst / repacker
    tools = ["ubireader_extract_images", "ubireader_extract_files",
             "ubinize", "ubiformat", "nandsim"]
    for t in tools:
        loc = _check_tool(t)
        print(f"  {t:<26}: {'OK ' + loc if loc else 'MISSING'}")
    # Submodule imports
    try:
        from ubi_toolkit import analyst, repacker, ecc_runtime  # noqa: F401
        print("  submodules   : OK (analyst, repacker, ecc_runtime)")
    except Exception as e:
        print(f"  submodules   : FAIL ({e})")
        return 1
    print("=" + "=" * 49)
    print("Self-test complete.")
    return 0


def _run_analyst(firmware: Path, output: Path, args: argparse.Namespace) -> int:
    """Invoke the analyst submodule against a firmware blob."""
    from ubi_toolkit.analyst import (
        AnalysisOptions, FirmwareAnalyst, build_parser as _unused,
    )
    mode = ("clean_ubi" if args.clean_ubi
            else "force_geometry" if args.force_geometry
            else "auto")
    opts = AnalysisOptions(
        firmware=str(firmware),
        output=str(output),
        mode=mode,
        verbose=args.verbose,
        report_only=args.report_only,
        page_size=args.page_size,
        oob_size=args.oob_size,
        peb_size=args.peb_size,
        leb_size=args.leb_size,
        gui=False,
    )
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    analyst = FirmwareAnalyst(
        opts.firmware, opts.output, opts.page_size, opts.oob_size,
        opts.peb_size, opts.leb_size, opts.report_only, opts.mode,
    )
    try:
        analyst.run()
    except Exception as e:
        log.exception("Analysis failed: %s", e)
        return 1
    return 0


def op_analyze(args: argparse.Namespace) -> int:
    if not args.firmware:
        print("error: -s/--source required for analyze", file=sys.stderr)
        return 2
    fw = Path(args.firmware).expanduser().resolve()
    if not fw.exists():
        print(f"error: firmware not found: {fw}", file=sys.stderr)
        return 2
    out = Path(args.output).expanduser().resolve()
    rc = _run_analyst(fw, out, args)
    if rc != 0:
        return rc
    # Sidecar — only if we actually produced an analysis tree
    if not args.report_only:
        # Detect region count by listing region_* subdirs
        regions = sorted(p for p in out.iterdir()
                         if p.is_dir() and p.name.startswith("region_"))
        write_sidecar(out, fw, extra={
            "operation": "analyze",
            "region_count": len(regions),
            "geometry": {
                "page_size": args.page_size,
                "oob_size": args.oob_size,
                "peb_size": args.peb_size,
                "leb_size": args.leb_size,
                "mode": ("clean_ubi" if args.clean_ubi
                         else "force_geometry" if args.force_geometry
                         else "auto"),
            },
        })
        print(f"[SIDECAR] wrote {out / METADATA_FILENAME}")
    print(f"[ANALYZE] done -> {out}")
    return 0


def op_extract(args: argparse.Namespace) -> int:
    # extract is analyze with extraction enabled (analyst default).
    args.report_only = False
    return op_analyze(args)


def op_repack(args: argparse.Namespace) -> int:
    if not args.analysis_dir or not args.replace:
        print("error: --analysis-dir and at least one --replace required for repack",
              file=sys.stderr)
        return 2
    # Delegate to repacker.main by synthesizing its argparse.Namespace
    from ubi_toolkit.repacker import build_parser as repack_build_parser, main as repack_main
    repack_parser = repack_build_parser()
    # Forward all --replace entries
    argv = ["--analysis-dir", str(args.analysis_dir),
            "--output-dir", str(args.output)]
    for r in args.replace:
        argv += ["--replace", r]
    if args.dry_run:
        argv.append("--dry-run")
    if args.yes:
        argv.append("--yes")
    if args.allow_roundtrip_skip:
        argv.append("--allow-roundtrip-skip")
    if args.peb_size is not None:
        argv += ["--peb-size", str(args.peb_size)]
    if args.verbose:
        argv.append("--verbose")
    repack_args = repack_parser.parse_args(argv)
    log.info("[REPACK] delegating to repacker (analysis=%s)", args.analysis_dir)
    return repack_main.__wrapped__(repack_args) if hasattr(repack_main, "__wrapped__") \
        else _call_repack_main(repack_args)


def _call_repack_main(repack_args) -> int:
    """Call repacker.main() bypassing its own parse_args."""
    from ubi_toolkit import repacker
    # repacker.main() calls build_parser().parse_args() internally; we need
    # to bypass that. Re-implement the entry by calling its inner logic via
    # sys.argv override — the safest non-invasive approach is to temporarily
    # replace sys.argv and call repacker.main().
    import sys as _sys
    saved = _sys.argv
    try:
        # Reconstruct argv from the parsed Namespace
        argv = ["ubirepack"]
        argv += ["--analysis-dir", str(repack_args.analysis_dir)]
        for r in repack_args.replace:
            argv += ["--replace", r]
        argv += ["--output-dir", str(repack_args.output_dir)]
        if repack_args.dry_run:
            argv.append("--dry-run")
        if repack_args.yes:
            argv.append("--yes")
        if getattr(repack_args, "allow_roundtrip_skip", False):
            argv.append("--allow-roundtrip-skip")
        if getattr(repack_args, "peb_size", None) is not None:
            argv += ["--peb-size", str(repack_args.peb_size)]
        if getattr(repack_args, "verbose", False):
            argv.append("--verbose")
        _sys.argv = argv
        return repacker.main()
    finally:
        _sys.argv = saved


def op_compare(args: argparse.Namespace) -> int:
    """Compare two analysis directories — region/volume layout, sizes, hashes."""
    if not args.left or not args.right:
        print("error: --left and --right required for compare", file=sys.stderr)
        return 2
    left = Path(args.left).expanduser().resolve()
    right = Path(args.right).expanduser().resolve()
    if not left.is_dir() or not right.is_dir():
        print(f"error: both --left and --right must be directories: {left}, {right}",
              file=sys.stderr)
        return 2

    def _inventory(d: Path) -> dict:
        inv = {"regions": {}, "sidecar": read_sidecar(d)}
        for r in sorted(p for p in d.iterdir()
                        if p.is_dir() and p.name.startswith("region_")):
            files = {}
            for f in sorted(r.rglob("*")):
                if f.is_file():
                    rel = f.relative_to(r).as_posix()
                    files[rel] = {
                        "size": f.stat().st_size,
                        "sha256": (_sha256_file(f) if f.stat().st_size < (1 << 24)
                                   else None),
                    }
            inv["regions"][r.name] = {
                "file_count": len(files),
                "files": files,
            }
        return inv

    a = _inventory(left)
    b = _inventory(right)
    diffs = []
    a_regions = set(a["regions"])
    b_regions = set(b["regions"])
    if a_regions != b_regions:
        diffs.append(f"region set differs: left={sorted(a_regions)} right={sorted(b_regions)}")
    for r in sorted(a_regions & b_regions):
        la, lb = a["regions"][r]["files"], b["regions"][r]["files"]
        if set(la) != set(lb):
            only_l = sorted(set(la) - set(lb))
            only_r = sorted(set(lb) - set(la))
            diffs.append(f"{r}: file set differs (only_left={only_l}, only_right={only_r})")
        for f in sorted(set(la) & set(lb)):
            if la[f]["size"] != lb[f]["size"]:
                diffs.append(f"{r}/{f}: size {la[f]['size']} != {lb[f]['size']}")
            elif la[f]["sha256"] and lb[f]["sha256"] and la[f]["sha256"] != lb[f]["sha256"]:
                diffs.append(f"{r}/{f}: sha256 differs")
    report = {
        "left": str(left),
        "right": str(right),
        "differences": diffs,
        "identical": not diffs,
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True))
    if diffs:
        print(f"[COMPARE] {len(diffs)} difference(s) -> {out_path}")
        for d in diffs:
            print(f"  - {d}")
        return 1
    print(f"[COMPARE] identical -> {out_path}")
    return 0


def op_verify(args: argparse.Namespace) -> int:
    """Re-load an analysis directory, re-run baseline audits, confirm integrity."""
    if not args.analysis_dir:
        print("error: --analysis-dir required for verify", file=sys.stderr)
        return 2
    a_dir = Path(args.analysis_dir).expanduser().resolve()
    if not a_dir.is_dir():
        print(f"error: not a directory: {a_dir}", file=sys.stderr)
        return 2
    sidecar = read_sidecar(a_dir)
    if sidecar:
        print(f"[SIDECAR] source={sidecar.get('source_image')}")
        print(f"[SIDECAR] sha256={sidecar.get('source_sha256')}")
    else:
        print(f"[WARN] no {METADATA_FILENAME} sidecar in {a_dir}")
    regions = sorted(p for p in a_dir.iterdir()
                     if p.is_dir() and p.name.startswith("region_"))
    if not regions:
        print(f"error: no region_* directories in {a_dir}", file=sys.stderr)
        return 2
    from ubi_toolkit.repacker import (
        load_region, audit_vid_crc_baseline, audit_ec_headers,
    )
    failures = []
    for r in regions:
        try:
            ri = int(r.name.split("_", 1)[1])
        except (IndexError, ValueError):
            print(f"[SKIP] {r.name}: cannot parse region index")
            continue
        try:
            model = load_region(a_dir, ri, args.peb_size)
        except Exception as e:
            print(f"[FAIL] region{ri}: cannot load model ({e})")
            failures.append((ri, str(e)))
            continue
        ec = audit_ec_headers(model.clean, model)
        vid = audit_vid_crc_baseline(model.clean, model)
        ec_status = "PASS" if ec["status"] == "PASS" else f"WARN({ec['status']})"
        vid_status = "PASS" if vid["status"] == "PASS" else f"WARN({vid['status']})"
        print(f"[VERIFY] region{ri}: PEB=0x{model.peb_size:x} "
              f"EC={ec_status} VID={vid_status}")
        if ec["status"] not in ("PASS",):
            failures.append((ri, f"EC: {ec}"))
        if vid["status"] not in ("PASS",):
            failures.append((ri, f"VID: {vid}"))
    if failures:
        print(f"[VERIFY] FAILED — {len(failures)} region(s) had issues")
        return 1
    print(f"[VERIFY] OK — {len(regions)} region(s) audited")
    return 0


# ═══════════════════════════════════════════════════════════════════════════
# Argument parser
# ═══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ubipack",
        description="Deterministic UBI firmware analysis, extraction, and surgical repacking toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
  # Analyze a raw firmware blob and extract regions/volumes
  ubipack -a analyze -s firmware.bin -o analysis_out/

  # Same as above (alias)
  ubipack -x -s firmware.bin -o analysis_out/

  # Surgical replace of a single volume inside a clean UBI region
  ubipack -r repack -n analysis_out/ \
      --replace region0:rootfs=/path/new_rootfs.squashfs -o repacked/

  # Preflight only (no write)
  ubipack -r repack -n analysis_out/ \
      --replace region0:rootfs=/path/new_rootfs.squashfs --dry-run

  # Compare two analyses
  ubipack -c compare --left before/ --right after/ -o diff.json

  # Verify integrity of a previously-produced analysis
  ubipack -V verify -n analysis_out/
""")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("-a", "--analyze", dest="op_analyze", action="store_true",
                      help="Analyze a firmware blob (scan + extract UBI regions)")
    mode.add_argument("-x", "--extract", dest="op_extract", action="store_true",
                      help="Alias for analyze (always writes extraction)")
    mode.add_argument("-r", "--repack", dest="op_repack", action="store_true",
                      help="Surgical clean-UBI repack of one or more volumes")
    mode.add_argument("-c", "--compare", dest="op_compare", action="store_true",
                      help="Compare two analysis directories")
    mode.add_argument("-V", "--verify", dest="op_verify", action="store_true",
                      help="Re-audit an analysis directory (VID CRC + EC magic/CRC)")
    mode.add_argument("-t", "--self-test", dest="op_self_test", action="store_true",
                      help="Verify toolchain availability and import sanity")

    # Common paths
    p.add_argument("-s", "--source", dest="firmware",
                   help="Input firmware binary (for analyze/extract)")
    p.add_argument("-o", "--output", dest="output", default="output",
                   help="Output directory or comparison report path")
    p.add_argument("-n", "--analysis-dir", dest="analysis_dir",
                   help="Existing ubipack analysis directory (for repack/verify)")

    # Geometry (forwarded to analyst)
    p.add_argument("--page-size", type=lambda x: int(x, 0),
                   help="NAND page size (bytes; supports 0xHEX)")
    p.add_argument("--oob-size", type=lambda x: int(x, 0),
                   help="NAND OOB size (bytes; supports 0xHEX)")
    p.add_argument("--peb-size", type=lambda x: int(x, 0),
                   help="PEB size override (bytes; supports 0xHEX)")
    p.add_argument("--leb-size", type=lambda x: int(x, 0),
                   help="LEB size override (bytes; supports 0xHEX)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--clean-ubi", action="store_true",
                   help="Treat input as already-clean UBI (no OOB stripping)")
    g.add_argument("--force-geometry", action="store_true",
                   help="Use --page/--oob/--peb/--leb as-is, no autodetect")
    p.add_argument("--report-only", action="store_true",
                   help="Analyze: scan only, do not extract (analyze-only)")

    # Repack-specific
    p.add_argument("--replace", action="append",
                   metavar="regionN:volume=FILE",
                   help="Repack: replacement target (repeat for multi-volume)")
    p.add_argument("--dry-run", action="store_true",
                   help="Repack: preflight only, write nothing")
    p.add_argument("--yes", action="store_true",
                   help="Repack: skip interactive confirmation")
    p.add_argument("--allow-roundtrip-skip", action="store_true",
                   help="Repack: allow mutation when no analyst .bin exists")

    # Compare-specific
    p.add_argument("--left", help="Compare: left analysis directory")
    p.add_argument("--right", help="Compare: right analysis directory")

    # Misc
    p.add_argument("-k", "--keep-temp", action="store_true",
                   help="Preserve tempdirs instead of cleaning them up")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable DEBUG logging")
    p.add_argument("--version", action="version",
                   version="ubipack 1.0.0")
    return p


# ═══════════════════════════════════════════════════════════════════════════
# Dispatcher
# ═══════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    else:
        logging.basicConfig(level=logging.INFO,
                            format="%(levelname)s: %(message)s")

    with ArtifactManager(keep=args.keep_temp):
        try:
            if args.op_self_test:
                return op_self_test(args)
            if args.op_analyze:
                return op_analyze(args)
            if args.op_extract:
                return op_extract(args)
            if args.op_repack:
                return op_repack(args)
            if args.op_compare:
                return op_compare(args)
            if args.op_verify:
                return op_verify(args)
        except KeyboardInterrupt:
            print("\ninterrupted", file=sys.stderr)
            return 130
        except Exception as e:
            log.exception("ubipack failed: %s", e)
            return 1
    # Should be unreachable — mutually_exclusive_group(required=True)
    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
