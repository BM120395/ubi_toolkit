"""
ubipack — unified UBI firmware analysis / extraction / repacking CLI.

Operations (one chosen per invocation, mirroring sqpack's flat-flag style):

    analyze     Scan a firmware blob, detect NAND geometry, locate UBI regions
                and inner filesystems (SquashFS/JFFS2/CramFS/UBIFS/DTB).
                Wraps analyst.FirmwareAnalyst.
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
from typing import Dict, Optional, Tuple

from ubi_toolkit import (METADATA_FILENAME, METADATA_SCHEMA_VERSION,
                         __version__)

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
        "ubipack_version": __version__,
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
        from ubi_toolkit import carve, fs_health  # noqa: F401  (v1.12.0)
        print("  submodules   : OK (analyst, repacker, ecc_runtime, "
              "carve, fs_health)")
    except Exception as e:
        print("  submodules   : FAIL (%s)" % e)
        return 1
    # Lifecycle round-trip (v1.6.0): temp prefix only, never touches ~/.local
    try:
        from ubi_toolkit import lifecycle
        ok, msg = lifecycle.self_test_roundtrip()
        print("  lifecycle    : %s (%s)" % ("OK" if ok else "FAIL", msg))
        if not ok:
            return 1
    except Exception as e:
        print("  lifecycle    : FAIL (%s)" % e)
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


def _patch_volumes_with_reference(out: Path, ref: bytes, verbose: bool,
                                  restore: bool = False) -> None:
    """v1.3.0: patch extracted volume images against a volume-level
    reference (evidence-gated: only isolated single-bit rot is repaired).

    v1.10.0: --restore-reference upgrades this to a canonical donor
    restore. When the donor is trustworthy (a vendor sysupgrade package or
    a known-good volume), structural differences are not necessarily rot —
    e.g. ECC-interleaved LEBs reassembled without the layout fix, LEB
    reordering, or an fs-version mismatch — so the honest repair is to
    restore the donor's bytes verbatim and size-clamp to the local
    volume. Single-bit rot (the ANOM-2 evidence gate) still repairs
    in place byte-by-byte; restore mode additionally lays the donor over
    the local volume without demanding the rot signature."""
    from ubi_toolkit.anomaly import bitrot_signature, repair_bitrot
    vols = sorted(p for p in out.glob("ubi/region_*/volumes/*") if p.is_file())
    if not vols:
        print("[AUTO-FIX] volume reference: no extracted volumes found")
        return
    for v in vols:
        data = v.read_bytes()
        sig = bitrot_signature(data, ref)
        if not sig["diff_bytes"]:
            print(f"[AUTO-FIX] {v.name}: already matches reference")
            continue
        if not sig["is_bitrot"]:
            if restore:
                n = min(len(data), len(ref))
                buf = bytearray(data)
                buf[:n] = ref[:n]
                v.write_bytes(bytes(buf))
                print(f"[AUTO-FIX] {v.name}: restored from reference "
                      f"({sig['diff_bytes']} bytes"
                      + (", scan capped" if sig.get("capped") else "")
                      + f", max run {sig['max_run']}) -> {v} "
                      f"[donor-trusted restore: verify structurally "
                      f"before flashing]")
            elif verbose:
                print(f"[AUTO-FIX] {v.name}: differences vs reference are "
                      f"not bit rot ({sig['diff_bytes']} bytes, max run "
                      f"{sig['max_run']}) — skipped (restore mode off)")
            continue
        buf = bytearray(data)
        repaired, multi = repair_bitrot(buf, ref)
        v.write_bytes(bytes(buf))
        residual = bitrot_signature(bytes(buf), ref)["diff_bytes"]
        print(f"[AUTO-FIX] {v.name}: repaired {repaired} bit-rot bytes vs "
              f"reference ({multi} multi-bit left, residual {residual})")


def _resolve_reference_volume(ref: bytes) -> bytes:
    """v1.4.0: --reference may be a raw UBI image (e.g. a vendor sysupgrade
    .bin). Extract its dominant data volume by VID lnum so volume-level
    adjudication/patching sees clean LEB-concatenated bytes. Non-UBI
    references (already a volume / squashfs) pass through unchanged."""
    from ubi_toolkit.anomaly import (
        VOL_ID_INTERNAL, assemble_leb, derive_geometry, detect_crc_convention,
        recover_vid, vid_fields, VID_HDR_SZ,
    )
    if b"UBI#" not in ref:
        return ref
    geo = derive_geometry(ref)
    grid = geo.get("ec_grid") or []
    vo = geo.get("vid_offset")
    ps, dp = geo.get("page_stride"), geo.get("data_pages")
    if not grid or vo is None or not ps or not dp:
        return ref
    invert = bool(detect_crc_convention(ref, grid, vo))
    vol_maps: dict = {}
    for peb_off in grid[:4096]:
        vid = recover_vid(ref[peb_off + vo:peb_off + vo + VID_HDR_SZ],
                          invert)
        if vid is None:
            continue
        vol_id = int.from_bytes(vid[8:12], "big")
        if vol_id >= VOL_ID_INTERNAL:
            continue
        lnum = vid_fields(vid)[0]
        vol_maps.setdefault(vol_id, {}).setdefault(lnum, peb_off)
    if not vol_maps:
        return ref
    # dominant volume = most mapped LEBs
    vol_id, m = max(vol_maps.items(), key=lambda kv: len(kv[1]))
    out = bytearray()
    for ln in range(max(m) + 1):
        p = m.get(ln)
        leb_bytes = dp * ps
        if p is None:
            out += b"\x00" * leb_bytes
        else:
            out += assemble_leb(ref, p, ps, dp, ((0, ps),),
                                min_bytes=leb_bytes)
    return bytes(out)


def op_analyze(args: argparse.Namespace) -> int:
    if not args.firmware:
        print("error: -s/--source required for analyze", file=sys.stderr)
        return 2
    fw = Path(args.firmware).expanduser().resolve()
    if not fw.exists():
        print(f"error: firmware not found: {fw}", file=sys.stderr)
        return 2
    out = Path(args.output).expanduser().resolve()
    layout_applied: Optional[str] = None

    # Anomaly pre-scan (v1.2.0): read-only, cheap, runs before the parse.
    # Repairable findings fail fast (exit 3) with a rerun hint unless
    # --auto-fix was given; --reference enables the bit-rot (ANOM-2) check.
    # v1.10.0: the pre-scan runs on EVERY analyze. Plain analyses of
    # ECC-interleaved dumps used to extract silently-shifted volumes
    # (real-world case: output volumes 10% multi-bit vs the donor, i.e.
    # corrupt) — now ANOM-1 fail-fasts with the exact rerun hint.
    reference_bytes: Optional[bytes] = None
    reference_volume: Optional[bytes] = None
    if getattr(args, "reference", None):
        ref_path = Path(args.reference).expanduser().resolve()
        if not ref_path.exists():
            print(f"error: reference image not found: {ref_path}", file=sys.stderr)
            return 2
        reference_bytes = ref_path.read_bytes()
        reference_volume = _resolve_reference_volume(reference_bytes)
        if reference_volume is not reference_bytes:
            print(f"[REFERENCE] UBI image detected — extracted clean "
                  f"volume ({len(reference_volume):,} B) from it for "
                  f"adjudication/patching")
    if True:  # v1.10.0: pre-scan is unconditional; the gates below decide
              # whether findings stop the run or repairs are applied.
        from ubi_toolkit.anomaly import (
            apply_repairs,
            fail_fast_message,
            scan_anomalies,
        )
        ctx = scan_anomalies(fw.read_bytes(), reference=reference_volume,
                             verbose=args.verbose)
        if ctx.findings:
            print("[ANOMALY-SCAN] " + ctx.summary())
            for f in ctx.findings:
                print(f"  {f}")
        if ctx.has_repairable and not args.auto_fix:
            msg = fail_fast_message(ctx, "ubipack")
            if msg:
                print(msg, file=sys.stderr)
            return 3
        if args.auto_fix:
            repaired, actions = apply_repairs(ctx, dry_run=args.dry_run)
            for a in actions:
                print(f"[AUTO-FIX] {a}")
            if args.dry_run:
                return 0
            if ctx.reference is None and ctx.page_layout is not None:
                print("[AUTO-FIX] note: no --reference given — layout was "
                      "adjudicated from the image's own squashfs metadata; "
                      "residual single-bit rot may remain in extracted "
                      "volumes. For byte-exact extraction, rerun with "
                      "--reference DONOR (a sysupgrade image or known-good "
                      "volume both work).")
            if repaired != fw.read_bytes():
                fixed_path = fw.with_suffix(".autofix.bin")
                fixed_path.write_bytes(repaired)
                print(f"[AUTO-FIX] repaired image written: {fixed_path}")
                fw = fixed_path  # continue the pipeline on the repaired image
            else:
                # No whole-image repair was possible. If layout adjudication
                # also failed, the assembled volumes are ECC-shifted: warn.
                if ctx.page_layout is None:
                    print("[AUTO-FIX] WARNING: no page layout could be "
                          "adjudicated — extracted volumes may be ECC-"
                          "shifted/corrupt (no reference or no matching "
                          "layout)")
                # ANOM-1 adjudicated layout (v1.3.0): deinterleave the image
            # page-by-page so the analyst sees clean FS pages. The scan ran
            # on the pre-fix image; its evidence probes already used the
            # bit-rot-repaired view, so layout adjudication is unaffected.
            if ctx.page_layout is not None and ctx.page_stride:
                _name, _pd, slices = ctx.page_layout[0], ctx.page_layout[1], \
                    ctx.page_layout[2]
                from ubi_toolkit.anomaly import strip_page_layout
                laid = strip_page_layout(fw.read_bytes(), ctx.page_stride,
                                         slices)
                laid_path = fw.with_suffix(".layout.bin")
                laid_path.write_bytes(laid)
                print(f"[AUTO-FIX] page layout '{_name}' applied: "
                      f"{len(repaired):,} → {len(laid):,} bytes "
                      f"({laid_path})")
                fw = laid_path  # analyst consumes the deinterleaved image
                layout_applied = _name
    # end anomaly pre-scan

    rc = _run_analyst(fw, out, args)
    if rc != 0:
        return rc
    # v1.3.0: volume-level reference patches the extracted volumes
    # (evidence-gated single-bit rot repair, post-extraction).
    # v1.10.0: --restore-reference additionally canonicalizes non-bit-rot
    # differences from the donor (see _patch_volumes_with_reference).
    if reference_volume is not None and not args.dry_run:
        _patch_volumes_with_reference(out, reference_volume, args.verbose,
                                      restore=args.restore_reference)
    # v1.5.0: boot-image discovery (uImage/FIT). When --auto-fix applied a
    # page layout, `fw` already points at the stripped image (flag set
    # above); otherwise scan the raw image. Catches kernel/U-Boot/DTB
    # images stored OUTSIDE the UBI region (raw NAND partitions);
    # UBI-hosted boot volumes are extracted by the analyst.
    try:
        from ubi_toolkit import bootimg
        view: bytes = fw.read_bytes()
        view_name = f"stripped:{layout_applied}" if layout_applied \
            else "raw"
        boot_dir = out / "boot_images"
        entries = bootimg.extract_all(view, boot_dir, layout_name=view_name)
        if not entries:
            print("[BOOT-IMG] no uImage/FIT images found")
    except Exception as exc:  # boot extraction must never kill analyze
        print(f"[BOOT-IMG] skipped ({exc})")
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
    rc = repack_main.__wrapped__(repack_args) if hasattr(repack_main, "__wrapped__") \
        else _call_repack_main(repack_args)

    # ── v1.12.0: dual output ────────────────────────────────────────────
    # When the analysis tree records healed volumes (the post-extraction
    # health gate repaired a damaged filesystem), the repack can emit a
    # SECOND region image built from the PRE-HEAL volume bytes: one
    # image carries the anomaly-fixed filesystem, the other preserves
    # the original anomaly exactly as the dump had it.
    if rc == 0 and getattr(args, "dual_output", False):
        rc = _repack_original_anomaly(args, repack_parser)
    elif rc == 0 and not getattr(args, "dual_output", False):
        from ubi_toolkit import fs_health
        from pathlib import Path as _P
        healed = fs_health.load_heal_manifest(_P(args.analysis_dir))
        if healed:
            names = ", ".join(r["file"] for r in healed)
            print(f"[REPACK] note: the analysis tree contains healed "
                  f"volume(s): {names}. Re-run with --dual-output to also "
                  f"build a second UBI image that preserves the ORIGINAL "
                  f"(pre-heal) volume bytes.")
    return rc


def _repack_original_anomaly(args: argparse.Namespace, repack_parser) -> int:
    """Second repack pass: substitute every healed volume with its
    pre-heal (.orig) bytes so the output image preserves the original
    anomaly verbatim. Written under <output>/as-original/ so the
    primary (fixed) images are never overwritten. User --replace
    targets win over recorded heals."""
    from ubi_toolkit import fs_health

    a_dir = Path(args.analysis_dir).expanduser().resolve()
    out_dir = Path(args.output).expanduser().resolve()
    orig_dir = out_dir / "as-original"
    orig_dir.mkdir(parents=True, exist_ok=True)

    # Collect (region_idx, vol_name, orig_path) candidates from:
    #   1. the heal manifest (health-gate repairs), and
    #   2. --replace targets whose file has a sibling .orig file.
    candidates: Dict[Tuple[str, str], Path] = {}
    for r in fs_health.load_heal_manifest(a_dir):
        if not r.get("orig_file"):
            continue
        orig = Path(r["vols_dir"]) / r["orig_file"]
        if not orig.exists():
            continue
        rdir = Path(r["vols_dir"]).parent.name      # region_N
        vol_name = r["file"].split("_", 2)[-1].rsplit(".", 1)[0] \
            if r["file"].startswith("vol_") else r["file"]
        candidates[(rdir, vol_name)] = orig
    for spec in (args.replace or []):
        if "=" not in spec or ":" not in spec:
            continue
        region_sel, target = spec.split(":", 1)
        vol_name, local = target.split("=", 1)
        p = Path(local).expanduser().resolve()
        orig = p.with_name(p.stem + ".orig" + p.suffix)
        if orig.exists() and orig.read_bytes() != p.read_bytes():
            sel_digits = "".join(c for c in region_sel if c.isdigit())
            candidates.setdefault((f"region_{sel_digits or '0'}", vol_name),
                                  orig)

    if not candidates:
        log.info("[REPACK] dual-output: no pre-heal volumes found; "
                 "the single image is already both")
        return 0

    for (region_idx, vol_name), orig in sorted(candidates.items()):
        argv = ["--analysis-dir", str(a_dir),
                "--output-dir", str(orig_dir)]
        # keep the user's replaces for OTHER volumes
        for spec in (args.replace or []):
            if ":" not in spec or "=" not in spec:
                continue
            sel, target = spec.split(":", 1)
            sel_digits = "".join(c for c in sel if c.isdigit())
            if sel_digits == region_idx.split("_")[-1] and \
                    target.split("=", 1)[0] == vol_name:
                continue  # this volume comes from the .orig file instead
            argv += ["--replace", spec]
        argv += ["--replace", f"region{region_idx.split('_')[-1]}:"
                              f"{vol_name}={orig}"]
        if args.yes:
            argv.append("--yes")
        if args.peb_size is not None:
            argv += ["--peb-size", str(args.peb_size)]
        if args.verbose:
            argv.append("--verbose")
        log.info("[REPACK] dual-output: %s volume '%s' from pre-heal "
                 "bytes %s (original anomaly preserved)",
                 region_idx, vol_name, orig)
        repack_args = repack_parser.parse_args(argv)
        rc2 = _call_repack_main(repack_args)
        if rc2 != 0:
            log.error("[REPACK] dual-output second pass failed for %s "
                      "(rc=%d); primary images are unaffected",
                      region_idx, rc2)
            return rc2
    print(f"[REPACK] dual-output OK: anomaly-preserving image(s) under "
          f"{orig_dir}")
    return 0


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
# Splice (v1.11.0): write repacked regions back into the interleaved dump
# ═══════════════════════════════════════════════════════════════════════════

def op_splice(args: argparse.Namespace) -> int:
    """Splice repacked clean region images into the ORIGINAL interleaved dump.

    The layout is re-derived from the dump itself (same anomaly scan the
    analyze path runs), cross-checked against the analysis directory the
    repack was built on, then FS slices of changed pages are replaced and
    non-FS (ECC/aux) slices are carried over verbatim."""
    from ubi_toolkit import splice as splice_mod
    from ubi_toolkit.anomaly import scan_anomalies

    dump_path = Path(args.firmware).expanduser().resolve()
    if not dump_path.exists():
        print(f"error: dump not found: {dump_path}", file=sys.stderr)
        return 2
    a_dir = Path(args.analysis_dir).expanduser().resolve()
    if not a_dir.is_dir():
        print(f"error: analysis directory not found: {a_dir}", file=sys.stderr)
        return 2
    repacked_root = Path(args.repacked).expanduser().resolve() \
        if args.repacked else a_dir
    out_path = (Path(args.output).expanduser().resolve()
                if args.output and args.output != "output"
                else dump_path.with_name(dump_path.stem + ".spliced.bin"))

    # 1) Re-derive the page layout from the dump (source of truth).
    print(f"[SPLICE] scanning dump for UBI geometry + page layout "
          f"({dump_path.name})...")
    ctx = scan_anomalies(dump_path.read_bytes(), verbose=args.verbose)
    if ctx.ubi_base is None or ctx.peb_stride is None \
            or ctx.page_stride is None or not ctx.page_layout:
        print("[SPLICE] ERROR: no UBI region / page layout could be "
              "adjudicated from this dump — nothing to splice",
              file=sys.stderr)
        return 3
    _lname, _pdata, slices, _gp, _gs = ctx.page_layout
    ps: int = ctx.page_stride
    peb_stride: int = ctx.peb_stride
    pp_peb = ctx.pages_per_peb or (peb_stride // ps)
    print(f"[SPLICE] layout '{_lname}' page={ps}B fs/page="
          f"{splice_mod.fs_per_page(slices)}B, regions: "
          f"{splice_mod.cluster_ec_offsets(ctx.ec_offsets, ctx.peb_stride)}")

    # 2) Discover repacked region images (CLI arg wins; else -o of the repack).
    by_region: "dict[int, Path]" = {}
    for cand in sorted(repacked_root.rglob(f"*{splice_mod.REPACKED_SUFFIX}")):
        parts = cand.relative_to(repacked_root).parts
        for part in parts:
            if part.startswith("region_"):
                try:
                    by_region[int(part.split("_", 1)[1])] = cand
                except ValueError:
                    pass
    if not by_region:
        print(f"[SPLICE] ERROR: no *_ubi_repacked.img found under "
              f"{repacked_root} (expected <...>/region_N/<...>_ubi_repacked."
              f"img)", file=sys.stderr)
        return 2

    # 3) Cross-check against the analysis the repack was built on.
    a_ubi = a_dir / "ubi"
    if a_ubi.is_dir():
        a_regions = sorted(p for p in a_ubi.glob("region_*") if p.is_dir())
    else:
        a_regions = []
    if not a_regions:
        print(f"[SPLICE] WARN: analysis dir has no ubi/region_* subdirs "
              f"({a_dir}) — region-count cross-check skipped")
        a_region_count = None
    else:
        a_region_count = len(a_regions)
        if a_region_count != len(by_region):
            print(f"[SPLICE] ERROR: analysis has {a_region_count} region(s) "
                  f"but {len(by_region)} repacked image(s) found — refusing "
                  f"partial splice", file=sys.stderr)
            return 3

    dump = dump_path.read_bytes()
    orders = sorted(by_region)
    report_all = []
    out = bytearray(dump)
    any_change = False
    for ri in orders:
        repacked_path = by_region[ri]
        repacked = repacked_path.read_bytes()
        # Region base: Nth contiguous EC run (dump order), sanity-checked
        # against the analysis's clean_ubi.img size.
        runs = splice_mod.cluster_ec_offsets(ctx.ec_offsets, peb_stride)
        if ri >= len(runs):
            print(f"[SPLICE] ERROR: repacked region{ri} has no matching EC "
                  f"run in the dump", file=sys.stderr)
            return 3
        base, peb_count = runs[ri]
        # Cross-check PEB count against the analysis image. The analysis's
        # clean_ubi.img is DEINTERLEAVED (its PEB = pages_per_peb * fs/page),
        # not stride-sized like the dump region.
        clean = a_dir / "ubi" / f"region_{ri}" / "clean_ubi.img"
        clean_peb = pp_peb * splice_mod.fs_per_page(slices)
        if clean.exists() and clean.stat().st_size != peb_count * clean_peb:
            print(f"[SPLICE] ERROR: region{ri}: dump run has {peb_count} "
                  f"PEBs but analysis clean_ubi.img implies "
                  f"{clean.stat().st_size // clean_peb} — "
                  f"analysis/dump mismatch", file=sys.stderr)
            return 3
        plan = splice_mod.plan_region(dump, repacked, base, ps, pp_peb,
                                      slices, f"region_{ri}")
        print(f"[SPLICE] region_{ri} @ {base:#x}: {plan.pages_changed}/"
              f"{plan.pages} pages differ ({plan.pebs_changed} PEBs, "
              f"range {plan.first_peb}..{plan.last_peb})")
        if plan.pages_changed:
            new, report = splice_mod.splice_bytes(dump, [repacked], [base],
                                                  ps, pp_peb, slices)
            errs = splice_mod.verify_splice(new, dump, repacked, base, ps,
                                            pp_peb, slices)
            if errs:
                for e in errs[:10]:
                    print(f"[SPLICE] VERIFY: {e}", file=sys.stderr)
                print(f"[SPLICE] FAILED — {len(errs)} verification "
                      f"violation(s); nothing written", file=sys.stderr)
                return 4
            drift = splice_mod.verify_no_aux_drift(new, dump, base, ps,
                                                   pp_peb, slices)
            if drift:
                print(f"[SPLICE] VERIFY: aux drift on {drift} pages",
                      file=sys.stderr)
                return 4
            out = bytearray(new)
            dump = bytes(out)
            any_change = True
            report.source = str(dump_path)
            report.output = str(out_path)
            report.layout_name = _lname
            report_all.append(report)
        else:
            print(f"[SPLICE] region_{ri}: FS content identical — nothing to "
                  f"splice")

    if not any_change:
        print("[SPLICE] all regions identical to the repacked source — "
              "nothing written")
        return 0
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(out))
    print(f"[SPLICE] wrote {out_path} ({len(out):,} bytes)")
    for report in report_all:
        print(report.summary())
    return 0


# ═══════════════════════════════════════════════════════════════════════════
# Argument parser
# ═══════════════════════════════════════════════════════════════════════════

def op_carve(args: argparse.Namespace) -> int:
    """--carve (v1.12.0): raw NAND/UBI flash dump -> SquashFS volume.

    The dump is not treated as an image: interleaved NAND OOB/spare
    bytes are stripped, the UBI partition is located and walked, the
    volume table is decoded, and the target volume is rebuilt in LEB
    order and trimmed to the exact SquashFS size. Anomalies found on
    the way (real wear, bit-flipped headers, redundant image copies,
    erased blocks) are detected and reported -- they shape how the
    volume is rebuilt, and none of them abort the run unless nothing
    usable can be carved at all. The carved volume is then validated
    with the toolkit's own FsValidator; no external squashfs tool is
    needed.
    """
    from ubi_toolkit import carve as carve_mod
    from ubi_toolkit.analyst import FsValidator

    if not args.firmware:
        print("error: -s/--source required for carve", file=sys.stderr)
        return 2
    fw = Path(args.firmware).expanduser().resolve()
    if not fw.exists():
        print(f"error: firmware not found: {fw}", file=sys.stderr)
        return 2

    out_dir = Path(args.output).expanduser().resolve() \
        if args.output != "output" else fw.parent / (fw.stem + "_carve")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "carved.squashfs"

    print(f"[CARVE] reading {fw} ...")
    raw = fw.read_bytes()
    print(f"[CARVE] {len(raw):,} bytes")

    try:
        rep = carve_mod.carve(
            raw, out_path,
            volume=getattr(args, "volume", None),
            page_size=getattr(args, "page_size", None),
            oob_size=getattr(args, "oob_size", None),
            peb_size=getattr(args, "peb_size", None),
        )
    except carve_mod.CarveError as e:
        print(f"[CARVE] ERROR: {e}", file=sys.stderr)
        return 1

    geom = rep["geometry"]
    print(f"[CARVE] geometry : page={geom['page_size']} "
          f"oob={geom['oob_size']} PEB={geom['peb_size']} "
          f"(UBI at {geom['ubi_start']:#x}, {geom['ubi_pebs']} PEBs)")
    print(f"[CARVE] volumes  : " + (", ".join(
        f"{v['name']!r}(id={v['vol_id']}, {v['lebs_found']} LEBs"
        + (f", {v['copies']} copies" if v.get("copies", 0) > 1 else "")
        + ")" for v in rep["volumes"]) or "none"))
    print(f"[CARVE] target   : {rep['target_name']!r} "
          f"(vol_id {rep['target_vol_id']})")
    sb = rep["superblock"]
    if sb:
        print(f"[CARVE] squashfs : v{sb['s_major']}.{sb['s_minor']} "
              f"{sb['compression_name']}, {sb['inode_count']} inodes, "
              f"bytes_used={sb['bytes_used']:,}")
        print(f"[CARVE] carved   : {rep['carved_size']:,} B "
              f"(raw volume {rep['raw_volume_size']:,} B) -> {out_path}")
    else:
        print(f"[CARVE] carved   : {rep['carved_size']:,} B "
              f"(no SquashFS superblock -- raw volume kept)")
    if rep["anomalies"]:
        print(f"[CARVE] anomalies: {len(rep['anomalies'])}")
        for a in rep["anomalies"]:
            print(f"  - {a}")

    # ---- validate the carved image with the toolkit's own validator ----
    vol_bytes = Path(out_path).read_bytes()
    if rep["superblock"]:
        validation = FsValidator.validate("SquashFS", vol_bytes)
        if validation.get("valid"):
            print(f"[CARVE] validation: OK ({len(vol_bytes):,} B squashfs)")
        else:
            print(f"[CARVE] validation: FAILED ({validation.get('reason', 'unknown')})",
                  file=sys.stderr)
            return 1
    print(f"[CARVE] OK: volume written to {out_path} "
          f"(raw copy at {rep['raw_volume_path']})")
    return 0


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
  # -n = the ANALYSIS directory (the one with ubi/region_0/clean_ubi.img),
  #     NOT the output directory; -o = where the repacked images go
  ubipack -r repack -n analysis_out/ \
      --replace region0:rootfs=/path/new_rootfs.squashfs -o repacked/

  # Full real-world sequence: recover a dump, modify its fs, repack
  ubipack -a analyze -s dump.bin -o out/ --auto-fix \
      --reference sysupgrade.bin          # byte-exact recovery
  # ... edit out/ubi/region_0/volumes/vol_0_squashfs.squashfs ...
  ubipack -r -n out/ \
      --replace region0:squashfs=out/ubi/region_0/volumes/vol_0_squashfs_mod.squashfs \
      -o repacked/ --yes

  # Preflight only (no write)
  ubipack -r repack -n analysis_out/ \
      --replace region0:rootfs=/path/new_rootfs.squashfs --dry-run

  # Compare two analyses
  ubipack -c compare --left before/ --right after/ -o diff.json

  # Verify integrity of a previously-produced analysis
  ubipack -V verify -n analysis_out/

  # Byte-exact recovery of an ECC-interleaved dump with a trusted donor
  # (a sysupgrade package, full image, or bare volume all work)
  ubipack -a analyze -s dump.bin -o out/ --auto-fix \
      --reference sysupgrade.bin

  # Same, plus verbatim donor restore when volumes differ beyond bit rot
  ubipack -a analyze -s dump.bin -o out/ --auto-fix \
      --reference donor_volume.squashfs --restore-reference

  # Write the repacked regions back into the ORIGINAL interleaved dump
  # (page-faithful: only FS slices change; ECC/aux bytes carried verbatim)
  ubipack --splice -s dump.bin -n out/ --repacked repacked/ -o dump.spliced.bin
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

    # Splice (v1.11.0): write repacked regions back into the source dump
    mode.add_argument("--splice", dest="op_splice", action="store_true",
                      help="Splice previously repacked regions back into the "
                           "ORIGINAL interleaved dump (page-faithful: only FS "
                           "slices change; ECC/aux bytes carried verbatim). "
                           "Dump via -s, repacked tree via --repacked (or -n); "
                           "output via -o")

    # Carve (v1.12.0): raw NAND/UBI dump -> SquashFS volume
    mode.add_argument("--carve", dest="op_carve", action="store_true",
                      help="Treat -s IMAGE as a RAW NAND/UBI flash dump: "
                           "strip interleaved OOB/spare bytes, locate the "
                           "UBI partition, decode the volume table, rebuild "
                           "the target volume in LEB order and trim it to "
                           "the exact SquashFS size. Anomalies (wear, "
                           "bit-flips, redundant copies, gaps) are detected "
                           "and reported, never silently ignored. Output "
                           "via -o; volume via --volume")

    # Lifecycle (v1.6.0): self-managed install/uninstall/upgrade/clean
    mode.add_argument("-I", "--install", dest="op_install", action="store_true",
                      help="Install/upgrade this tool under --prefix "
                           "(default ~/.local): package copy + shim in "
                           "<prefix>/bin + uninstall manifest")
    mode.add_argument("-U", "--uninstall", dest="op_uninstall", action="store_true",
                      help="Remove a lifecycle install (manifest-driven; "
                           "cleans the shim from <prefix>/bin)")
    mode.add_argument("--upgrade", dest="op_upgrade", action="store_true",
                      help="Fetch the latest toolkit tarball from the "
                           "repository and reinstall it")
    mode.add_argument("-K", "--clean", dest="clean", nargs="+", metavar="PATH",
                      help="List (dry-run) generated artifacts under PATH "
                           "(<fw>.autofix.bin / <fw>.layout.bin); --yes applies")

    # Common paths
    p.add_argument("-s", "--source", dest="firmware",
                   help="Input firmware binary (for analyze/extract)")
    p.add_argument("-o", "--output", dest="output", default="output",
                   help="Output directory or comparison report path "
                        "(repack: where repacked images are written)")
    p.add_argument("-n", "--analysis-dir", dest="analysis_dir",
                   help="Existing ubipack ANALYSIS directory (for repack/"
                        "verify/splice): the one containing ubi/region_N/"
                        "clean_ubi.img — NOT the repack output directory")
    p.add_argument("--repacked", dest="repacked", metavar="DIR",
                   help="Splice: directory holding the repack output "
                        "(<...>/region_N/*_ubi_repacked.img); default: the "
                        "repack output you passed with -o, i.e. search from "
                        "-n if unset")

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

    # Anomaly scan / auto-fix (v1.2.0)
    p.add_argument("--auto-fix", dest="auto_fix", action="store_true",
                   help="Analyze/extract: detect + repair anomalies (bit rot, "
                        "inline-ECC page layouts, single-bit VID damage) and "
                        "continue. Without it, repairable anomalies fail fast "
                        "with a rerun hint")
    p.add_argument("--reference", dest="reference",
                   help="Known-good image for bit-rot detection/repair "
                        "(enables ANOM-2 evidence). May be a full image, a "
                        "volume, or a vendor sysupgrade package")
    p.add_argument("--restore-reference", dest="restore_reference",
                   action="store_true",
                   help="Analyze with --reference: when extracted volumes "
                        "differ from the donor beyond single-bit rot "
                        "(layout/reassembly/version drift), restore the "
                        "donor's bytes verbatim instead of skipping. The "
                        "donor is trusted as-is; verify structurally "
                        "before flashing")

    # Repack-specific
    p.add_argument("--replace", action="append",
                   metavar="regionN:volume=FILE",
                   help="Repack: replacement target (repeat for multi-volume)")
    p.add_argument("--volume", dest="volume", metavar="NAME",
                   help="Carve: volume name to extract (default: the first "
                        "volume whose LEB 0 starts with a SquashFS magic)")
    p.add_argument("--dual-output", dest="dual_output", action="store_true",
                   help="Repack: also build a second UBI image from the "
                        "PRE-HEAL volume bytes recorded by the post-"
                        "extraction health gate, so you get one image with "
                        "the anomaly FIXED and one preserving the ORIGINAL "
                        "anomaly verbatim")
    p.add_argument("--dry-run", action="store_true",
                   help="Repack: preflight only, write nothing")
    p.add_argument("--yes", action="store_true",
                   help="Repack/upgrade: skip interactive confirmation")
    p.add_argument("--force", action="store_true",
                   help="Lifecycle: overwrite/replace even when the existing "
                        "shim or target is not lifecycle-managed")
    p.add_argument("--prefix", metavar="DIR",
                   help="Lifecycle: install prefix (default ~/.local)")
    p.add_argument("--upgrade-url", dest="upgrade_url", metavar="URL",
                   help="Upgrade: tarball URL or local tarball path "
                        "(default: repository default branch)")
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
                   version="ubipack 1.12.0")
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
            if getattr(args, "op_install", False):
                from ubi_toolkit import lifecycle
                return lifecycle.op_install(args)
            if getattr(args, "op_uninstall", False):
                from ubi_toolkit import lifecycle
                return lifecycle.op_uninstall(args)
            if getattr(args, "op_upgrade", False):
                from ubi_toolkit import lifecycle
                return lifecycle.op_upgrade(args)
            if getattr(args, "clean", None):
                from ubi_toolkit import lifecycle
                return lifecycle.op_clean(args)
            if args.op_analyze:
                return op_analyze(args)
            if args.op_extract:
                return op_extract(args)
            if args.op_repack:
                return op_repack(args)
            if getattr(args, "op_splice", False):
                return op_splice(args)
            if getattr(args, "op_carve", False):
                return op_carve(args)
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
