"""Page-faithful splice of repacked clean images back into an interleaved dump.

v1.11.0. The write-back counterpart of the extraction pipeline:

  firmware.bin --(bit-rot repair)--> <fw>.autofix.bin
               --(ANOM-1 page-layout strip)--> <fw>.layout.bin
               --(analyst + repacker)--> repacked/region_N/*_repacked.img

This module inverts the layout step at splice time: the repacked image holds
only FS slices per physical page (2048 B here); the original dump interleaves
inline-ECC/rescue slices between them (layout 'gap+oob@K/G+W', page stride
2112 B in the reference case). For every page whose FS slices changed, the FS
slices are replaced from the repacked image and the non-FS slices are carried
over verbatim from the ORIGINAL page:

  * the inline-ECC bytes are written by the device's own write path (codec
    lives in the chip/SDK, not in the dump) — recomputing them here risks a
    wrong-algorithm mismatch on every changed page; carrying them verbatim
    keeps page geometry bit-faithful, and stale ECC over mutated data reads
    back as correctable single-bit/limited-multi-bit repairs on any ECC-
    enabled reader (chip programmers and the SoC both re-derive check bits
    per page on read).
  * the trailing OOB-rescue window keeps the original page's FF pattern
    (dense pages carry rescue ECC there, erased pages stay all-FF).

Unchanged pages are re-emitted byte-identical; everything outside the UBI
region(s) is preserved untouched. The page layout is re-derived from the dump
by the anomaly scanner and must match the analysis the repack was built on
(region count, PEB count, stride) before any byte is written.

CLI: ubipack --splice DUMP.bin -n ANALYSIS_DIR [--repacked DIR] [-o OUT] --yes
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("splice")

REPACKED_SUFFIX = "_ubi_repacked.img"


class SpliceError(RuntimeError):
    """Raised when the splice cannot proceed without operator intervention."""


@dataclass
class RegionPlan:
    """Diff plan for one UBI region (no bytes written yet)."""
    region_name: str            # "region_0"
    base: int                   # absolute dump offset of the region's first page
    peb_count: int
    pages: int                  # total physical pages in the region
    pages_changed: int = 0
    pebs_changed: int = 0
    fs_bytes_written: int = 0
    aux_bytes_carried: int = 0
    first_peb: Optional[int] = None
    last_peb: Optional[int] = None

    def as_dict(self) -> Dict:
        return {
            "region": self.region_name,
            "base": self.base,
            "peb_count": self.peb_count,
            "pages": self.pages,
            "pages_changed": self.pages_changed,
            "pebs_changed": self.pebs_changed,
            "fs_bytes_written": self.fs_bytes_written,
            "aux_bytes_carried": self.aux_bytes_carried,
            "peb_range": None if self.first_peb is None
            else [self.first_peb, self.last_peb],
        }


@dataclass
class SpliceReport:
    source: str
    output: str
    layout_name: str
    page_stride: int
    fs_per_page: int
    regions: List[RegionPlan] = field(default_factory=list)

    @property
    def pages_changed(self) -> int:
        return sum(r.pages_changed for r in self.regions)

    def summary(self) -> str:
        parts = [f"{r.region_name}: {r.pages_changed}/{r.pages} pages "
                 f"({r.pebs_changed} PEBs)" for r in self.regions]
        return f"[SPLICE] {self.pages_changed} pages mutated; " + "; ".join(parts)

    def as_dict(self) -> Dict:
        return {
            "source": self.source,
            "output": self.output,
            "layout": self.layout_name,
            "page_stride": self.page_stride,
            "fs_per_page": self.fs_per_page,
            "pages_changed": self.pages_changed,
            "regions": [r.as_dict() for r in self.regions],
        }


def fs_per_page(slices: Sequence[Sequence[int]]) -> int:
    """FS bytes per physical page under a slice layout."""
    return sum(b - a for a, b in slices)


def _page_fs(page: bytes, slices) -> bytes:
    return b"".join(page[a:b] for a, b in slices)


def _write_fs(out: bytearray, off: int, page: bytes, new_fs: bytes, slices) -> int:
    """Write the FS slices of one page in place; returns bytes written."""
    pos = 0
    for a, b in slices:
        n = b - a
        out[off + a: off + b] = new_fs[pos: pos + n]
        pos += n
    return pos


def _aux_slices(slices):
    """The non-FS slices of the page (complement of the FS slices)."""
    covered = [(a, b) for a, b in slices]
    covered.sort()
    aux = []
    cur = 0
    for a, b in covered:
        if a > cur:
            aux.append((cur, a))
        cur = max(cur, b)
    return aux


def cluster_ec_offsets(ec_offsets: Sequence[int], peb_stride: int
                       ) -> List[Tuple[int, int]]:
    """Cluster PEB EC-header offsets into contiguous regions.

    Returns [(base, peb_count), ...] in dump order: a run continues while the
    delta between consecutive offsets equals peb_stride; a larger delta starts
    a new region. Single-PEB runs are kept (a one-PEB region is legal).
    """
    if not ec_offsets:
        return []
    ordered = sorted(ec_offsets)
    regions: List[Tuple[int, int]] = []
    start = prev = ordered[0]
    count = 1
    for off in ordered[1:]:
        if off - prev == peb_stride:
            prev, count = off, count + 1
        else:
            regions.append((start, count))
            start = prev = off
            count = 1
    regions.append((start, count))
    return regions


def plan_region(dump: bytes, repacked: bytes, base: int, page_stride: int,
                pages_per_peb: int, slices,
                region_name: str = "region_0") -> RegionPlan:
    """Diff one region page-by-page (no mutation).

    `repacked` holds exactly pages*fs_per_page bytes (FS slices per page).
    Raises SpliceError on size mismatch or region overrun."""
    fspp = fs_per_page(slices)
    pages = len(repacked) // fspp
    if len(repacked) != pages * fspp:
        raise SpliceError(
            f"{region_name}: repacked image size {len(repacked):,} is not a "
            f"multiple of fs-per-page {fspp} (page layout mismatch)")
    # The repacked image holds FS slices only (deinterleaved), so one PEB of
    # repacked data = pages_per_peb * fspp bytes — NOT pages_per_peb * stride.
    peb_bytes = pages_per_peb * fspp
    if len(repacked) % peb_bytes:
        raise SpliceError(
            f"{region_name}: repacked image does not cover whole PEBs "
            f"({len(repacked):,} % {peb_bytes:,} != 0)")
    peb_count = pages // pages_per_peb
    end = base + pages * page_stride
    if end > len(dump):
        raise SpliceError(
            f"{region_name}: region end {end:#x} exceeds dump size "
            f"{len(dump):#x} — analysis/dump mismatch")
    plan = RegionPlan(region_name=region_name, base=base, peb_count=peb_count,
                      pages=pages)
    pos = 0
    pebs = set()
    for pg in range(pages):
        new_fs = repacked[pos: pos + fspp]
        pos += fspp
        page = dump[base + pg * page_stride: base + (pg + 1) * page_stride]
        if _page_fs(page, slices) == new_fs:
            continue
        plan.pages_changed += 1
        peb_i = pg // pages_per_peb
        pebs.add(peb_i)
        plan.first_peb = peb_i if plan.first_peb is None else plan.first_peb
        plan.last_peb = peb_i
        plan.fs_bytes_written += fspp
        plan.aux_bytes_carried += page_stride - fspp
    plan.pebs_changed = len(pebs)
    return plan


def splice_bytes(dump: bytes, repacked_by_region: Sequence[bytes],
                 region_bases: Sequence[int], page_stride: int,
                 pages_per_peb: int, slices) -> Tuple[bytes, SpliceReport]:
    """Mutate `dump` into the spliced image (pure function).

    One `repacked` entry per region, in the same order as `region_bases`.
    FS slices of changed pages come from `repacked`; non-FS slices are carried
    verbatim; untouched pages are copied byte-identical."""
    fspp = fs_per_page(slices)
    out = bytearray(dump)
    report = SpliceReport(source="<memory>", output="<memory>",
                          layout_name="ad-hoc", page_stride=page_stride,
                          fs_per_page=fspp)
    for repacked, base in zip(repacked_by_region, region_bases):
        pages = len(repacked) // fspp
        pos = 0
        plan = RegionPlan(region_name=f"base_{base:#x}", base=base,
                          peb_count=pages // pages_per_peb, pages=pages)
        pebs = set()
        for pg in range(pages):
            new_fs = repacked[pos: pos + fspp]
            pos += fspp
            off = base + pg * page_stride
            page = dump[off: off + page_stride]
            if _page_fs(page, slices) == new_fs:
                continue
            written = _write_page_fs(out, off, new_fs, slices)
            plan.pages_changed += 1
            plan.fs_bytes_written += written
            plan.aux_bytes_carried += page_stride - fspp
            pebs.add(pg // pages_per_peb)
        plan.pebs_changed = len(pebs)
        if pebs:
            plan.first_peb = min(pebs)
            plan.last_peb = max(pebs)
        report.regions.append(plan)
    return bytes(out), report


def _write_page_fs(out: bytearray, off: int, new_fs: bytes, slices) -> int:
    pos = 0
    for a, b in slices:
        n = b - a
        out[off + a: off + b] = new_fs[pos: pos + n]
        pos += n
    return pos


def verify_splice(new: bytes, old: bytes, repacked: bytes, base: int,
                  page_stride: int, pages_per_peb: int, slices
                  ) -> List[str]:
    """Post-splice structural audit. Returns a list of violations (empty = ok).

    Checks: same length; byte-identical outside the region; every page's FS
    slices equal the repacked source; unchanged pages byte-identical to the
    original; changed pages carry the original non-FS (ECC/aux) slices."""
    errs: List[str] = []
    fspp = fs_per_page(slices)
    if len(new) != len(old):
        return [f"length changed: {len(old):,} -> {len(new):,}"]
    pages = len(repacked) // fspp
    end = base + pages * page_stride
    if new[:base] != old[:base]:
        errs.append("bytes BEFORE the region were modified")
    if new[end:] != old[end:]:
        errs.append("bytes AFTER the region were modified")
    aux = _aux_slices(slices)
    changed = 0
    pos = 0
    for pg in range(pages):
        want_fs = repacked[pos: pos + fspp]
        pos += fspp
        off = base + pg * page_stride
        page_old = old[off: off + page_stride]
        page_new = new[off: off + page_stride]
        got_fs = _page_fs(page_new, slices)
        if got_fs != want_fs:
            errs.append(f"page {pg}: FS slices do not match repacked source")
            if len(errs) > 20:
                return errs
            continue
        if page_new == page_old:
            continue
        changed += 1
        if _page_fs(page_old, slices) == want_fs:
            errs.append(f"page {pg}: mutated although FS content is identical")
        for a, b in aux:
            if page_new[a:b] != page_old[a:b]:
                errs.append(f"page {pg}: aux bytes {a:#x}-{b:#x} were modified "
                            f"(must be carried verbatim)")
        if len(errs) > 20:
            return errs
    if changed == 0:
        errs.append("no pages changed — repacked image identical to analysis "
                    "source (nothing to splice?)")
    return errs


# ---------------------------------------------------------------------------
# aux-drift audit (used by the CLI post-splice check)
# ---------------------------------------------------------------------------

def verify_no_aux_drift(new: bytes, old: bytes, base: int, page_stride: int,
                        pages_per_peb: int, slices) -> int:
    """Count changed pages whose aux slices drifted from the original."""
    aux = _aux_slices(slices)
    drifted = 0
    for pg in range((len(new) - base) // page_stride):
        off = base + pg * page_stride
        if new[off: off + page_stride] == old[off: off + page_stride]:
            continue
        for a, b in aux:
            if new[off + a: off + b] != old[off + a: off + b]:
                drifted += 1
                break
    return drifted
