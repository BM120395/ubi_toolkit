"""anomaly.py — generalized NAND/UBI anomaly detection & repair (v1.2.0).

Detects and (optionally) repairs the anomaly family seen in real-world vendor
NAND dumps, generalized to any geometry — nothing is hardcoded to
512B/2048B pages. Region, strides, header offsets, page layout, and CRC
convention are all probed from the binary's own evidence.

Anomaly catalog (see case_studies/README.md for the full write-up):

  ANOM-1  Raw-NAND page layout with inline ECC — filesystem bytes are
          interleaved with hidden ECC bytes; naive page concatenation
          shifts every page after the first (data_crc pass rate 0/N).
          Detected by scoring candidate layouts, including a GENERIC
          single-gap search (any gap size in {8,12,14,16} at any offset).
  ANOM-2  Aged-NAND single-bit flips (bit rot): every differing byte at
          Hamming distance 1 vs a reference image, <=2 flips per 512B
          block, total << 1%.
  ANOM-3  CRC convention mismatch: stored CRCs are ~crc32 (one's
          complement) rather than plain crc32.
  ANOM-4  Geometry ambiguity: UBI region base, PEB stride, page stride,
          and VID offset derived from magic-hit grids (median deltas),
          not assumptions.
  ANOM-5  VID headers failing hdr_crc: CRC-guided single-bit repair
          (bounded); multi-bit damage is reported, never guessed.

Usage:
  from ubi_toolkit.anomaly import scan_anomalies, apply_repairs
  ctx = scan_anomalies(data)                    # read-only, cheap
  repaired, log = apply_repairs(ctx, data)      # explicit repair step

Design rules:
  - Detection is read-only and runs before any parse.
  - Nothing is modified without --auto-fix; dry-run reports only.
  - Every repair is evidence-backed with counts in the report.
"""

from __future__ import annotations

import lzma
import zlib
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ------------------------------------------------------------------ constants

EC_MAGIC = b"UBI#"
VID_MAGIC = b"UBI!"
EC_HDR_SZ = 64
VID_HDR_SZ = 64
VID_BODY = 60                      # hdr_crc covers VID bytes [0:60)
XZ_MAGIC = b"\xfd7zXZ\x00"

MAX_MAGIC_HITS = 8192              # cap for the magic-grid scan
MIN_GRID_HITS = 4                  # minimum EC hits to trust a stride
BITROT_MAX_CHUNK = 1 << 20         # 1 MiB chunks for the int-XOR diff
BITROT_BIT_CAP = 4_000_000         # bail out if more bits differ than this
GAP_SIZES = (8, 12, 14, 16)        # candidate inline-ECC widths (bytes)
# chunked inline-ECC shapes (data_bytes, ecc_bytes): page split as
# [data c][ecc e] repeated k times, k*c == fs page size (e.g. 2112 B
# physical page = 4 x (512+16) — ECC interleaved per 512 B sub-chunk)
CHUNK_ECC_SHAPES = ((256, 8), (512, 8), (512, 16), (512, 24), (1024, 32))
GAP_SEARCH_ALIGN = 2               # gap-position search granularity
GAP_SEARCH_MIN = 64                # ECC never sits in the first bytes
MIN_XZ_SAMPLES = 2                 # min xz headers for a meaningful rate
MIN_XZ_PEBS = 2                    # min xz-bearing PEBs to run the probe
LAYOUT_MIN_RATE = 0.80             # winner must pass this many data_crcs
LAYOUT_MARGIN = 0.20               # and beat the baseline by this much
SAMPLE_PEB_LIMIT = 32              # PEBs sampled for scoring
SELF_CENSUS_MIN_RATE = 0.10        # ref-free: min squashfs xz-decode rate
SELF_CENSUS_MIN_BLOCKS = 8         # min metadata blocks for a census verdict
SELF_CENSUS_MAX_BLOCKS = 200       # census walk cap per layout hypothesis
VOL_ID_INTERNAL = 0x7FFFEFFF       # UBI internal-volume id marker


# ------------------------------------------------------------------- helpers

def _u32(b: bytes, o: int) -> int:
    return int.from_bytes(b[o:o + 4], "big")


def crc_matches(stored: int, data: bytes, invert: bool) -> bool:
    """True if stored equals crc32(data), or its complement when invert."""
    c = zlib.crc32(data) & 0xFFFFFFFF
    return stored == c or (invert and stored == (~c & 0xFFFFFFFF))


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


# ------------------------------------------------------------ anomaly context

@dataclass
class Finding:
    kind: str                      # ANOM-1..5 id
    severity: str                  # "info" | "repairable" | "fatal"
    detail: str
    evidence: Dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.kind}] {self.severity}: {self.detail}"


@dataclass
class AnomalyContext:
    data: bytes
    findings: List[Finding] = field(default_factory=list)
    # ANOM-4 evidence-derived geometry
    ubi_base: Optional[int] = None          # first grid-consistent EC offset
    peb_stride: Optional[int] = None        # median delta between EC headers
    page_stride: Optional[int] = None       # median EC->VID delta (1 page in)
    vid_offset: Optional[int] = None        # EC -> VID delta within a PEB
    pages_per_peb: Optional[int] = None
    data_pages: Optional[int] = None        # pages carrying LEB payload
    ec_offsets: List[int] = field(default_factory=list)
    vid_offsets: List[int] = field(default_factory=list)
    # ANOM-3
    crc_inverted: Optional[bool] = None
    # ANOM-1 winner: (name, page_data, slices, gap_pos, gap_size)
    page_layout: Optional[Tuple[str, int, Tuple[Tuple[int, int], ...],
                                Optional[int], Optional[int]]] = None
    # ANOM-2
    reference: Optional[bytes] = None
    # Repair plan / stats
    repair_plan: List[str] = field(default_factory=list)
    stats: Dict = field(default_factory=dict)
    # In-memory bit-rot-repaired view used for evidence probes (None = data)
    working: Optional[bytes] = None

    @property
    def has_repairable(self) -> bool:
        return any(f.severity == "repairable" for f in self.findings)

    @property
    def has_fatal(self) -> bool:
        return any(f.severity == "fatal" for f in self.findings)

    def summary(self) -> str:
        if not self.findings:
            return "no anomalies detected"
        return "; ".join(f"{f.kind}({f.severity})" for f in self.findings)


# ------------------------------------------------- ANOM-4: magic-grid geometry

def magic_grid(data: bytes, magic: bytes, max_hits: int = MAX_MAGIC_HITS
               ) -> List[int]:
    """All offsets of `magic` in data (C-speed find loop, capped)."""
    hits = []
    pos = 0
    while len(hits) < max_hits:
        i = data.find(magic, pos)
        if i < 0:
            break
        hits.append(i)
        pos = i + 1
    return hits


def _dominant_delta(hits: List[int]) -> Optional[int]:
    """Most common spacing between consecutive hits (the true grid pitch)."""
    if len(hits) < MIN_GRID_HITS:
        return None
    deltas = Counter(b - a for a, b in zip(hits, hits[1:]))
    if not deltas:
        return None
    delta, _count = deltas.most_common(1)[0]
    return delta if delta > 0 else None


def _grid_consistent(hits: List[int], base: int, stride: int,
                     tolerance: int = 8) -> List[int]:
    """Hits that sit on the arithmetic grid base + k*stride."""
    out = []
    for h in hits:
        k, rem = divmod(h - base, stride)
        if k >= 0 and (rem <= tolerance or stride - rem <= tolerance):
            out.append(h)
    return out


def derive_geometry(data: bytes) -> Dict:
    """Derive UBI base / PEB stride / page stride / VID offset from magic
    grids. Works for clean UBI images AND raw-NAND dumps with OOB: the EC
    magic marks PEB starts, the EC->VID delta marks one page stride."""
    ec_hits = magic_grid(data, EC_MAGIC)
    vid_hits = magic_grid(data, VID_MAGIC)
    g: Dict = {"ec_hits": ec_hits, "vid_hits": vid_hits}
    if len(ec_hits) < MIN_GRID_HITS:
        return g

    peb_stride = _dominant_delta(ec_hits)
    if not peb_stride:
        return g
    base = ec_hits[0]
    # Re-anchor: prefer the most common (hit mod stride) residue so a
    # stray early magic doesn't skew the base.
    residues = Counter(h % peb_stride for h in ec_hits)
    residue, _n = residues.most_common(1)[0]
    g["peb_stride"] = peb_stride
    g["ubi_base"] = base
    g["ec_grid"] = _grid_consistent(ec_hits, residue, peb_stride)

    # Page stride: median EC->VID delta (VID within the same PEB).
    ec_set = sorted(g["ec_grid"])
    diffs = []
    for v in vid_hits:
        # greatest EC hit <= v within one PEB
        lo, hi = 0, len(ec_set)
        while lo < hi:
            mid = (lo + hi) // 2
            if ec_set[mid] <= v:
                lo = mid + 1
            else:
                hi = mid
        if lo:
            d = v - ec_set[lo - 1]
            if 0 < d < peb_stride:
                diffs.append(d)
    if diffs:
        diffs.sort()
        vid_off = diffs[len(diffs) // 2]
        g["vid_offset"] = vid_off
        if vid_off >= 512:
            # VID sits one full page in -> that delta IS the page stride.
            g["page_stride"] = vid_off
        else:
            # small-page NAND: VID in second min-I/O unit of page 0.
            g["page_stride"] = None
    if g.get("page_stride") is not None:
        ps: int = g["page_stride"]  # type: ignore[assignment]
        g["pages_per_peb"] = peb_stride // ps
        g["data_pages"] = g["pages_per_peb"] - 2  # EC page + VID page
    return g


# ------------------------------------------------- VID / EC header utilities

def vid_crc_ok(vid: bytes, invert: bool) -> bool:
    return len(vid) >= VID_HDR_SZ and crc_matches(
        _u32(vid, 0x3C), vid[:VID_BODY], invert)


def vid_fields(vid: bytes) -> Tuple[int, int, int]:
    """(lnum, data_size, data_crc) — big-endian per UBI on-wire layout."""
    return _u32(vid, 0x0C), _u32(vid, 0x14), _u32(vid, 0x20)


def repair_vid_single_bit(vid: bytes, invert: bool) -> Optional[bytes]:
    """All 480 single-bit flips of the VID body; first CRC-valid variant.
    Bounded and evidence-guided — never guesses multi-bit damage."""
    for pos in range(VID_BODY):
        for bit in range(8):
            w = bytearray(vid)
            w[pos] ^= 1 << bit
            if vid_crc_ok(bytes(w), invert):
                return bytes(w)
    return None


def recover_vid(vid: bytes, invert: bool) -> Optional[bytes]:
    """VID as-is if CRC-valid, else single-bit repair, else None."""
    if vid[:4] != VID_MAGIC:
        return None
    if vid_crc_ok(vid, invert):
        return vid
    return repair_vid_single_bit(vid, invert)


# ------------------------------------------------- ANOM-1: page-layout probe

def _slice_map(slices: Tuple[Tuple[int, int], ...]):
    """(fs_bytes_per_page, mapping) for raw-page-offset → FS-offset."""
    fs = 0
    m = []
    for a, b in slices:
        m.append((a, b, fs))
        fs += b - a
    return fs, m


def _raw_to_fs(mapping, r: int) -> Optional[int]:
    for a, b, fs in mapping:
        if a <= r < b:
            return fs + (r - a)
    return None          # magic fell inside an ECC gap (not FS data)


def scan_xz_magics(data: bytes, ec_grid: List[int], page_stride: int,
                   data_pages: int, max_per_peb: int = 4,
                   peb_limit: int = 32) -> List[Tuple[int, List]]:
    """Locate xz magics in RAW physical data pages (layout-independent —
    the magic survives any slicing). Returns [(peb_off, [(page, raw_off)])]."""
    out = []
    for peb_off in ec_grid:
        hits = []
        base = peb_off + 2 * page_stride
        seg = data[base: base + data_pages * page_stride]
        pos = 0
        while len(hits) < max_per_peb:
            i = seg.find(XZ_MAGIC, pos)
            if i < 0:
                break
            # absolute page index within the PEB (EC hdr = page 0, VID = 1)
            hits.append((i // page_stride + 2, i % page_stride))
            pos = i + 1
        if hits:
            out.append((peb_off, hits))
        if len(out) >= peb_limit:
            break
    return out


def score_layout_xz(data: bytes, peb_magics: List[Tuple[int, List]],
                    page_stride: int,
                    slices: Tuple[Tuple[int, int], ...],
                    sample_limit: int = 32) -> Tuple[int, int]:
    """(valid, total) xz block-header CRC pass counts under a layout
    hypothesis. Each raw magic at (page k, raw off r) maps to an FS offset
    via the slice layout; the header is validated on a 3-page FS window
    assembled around it. Wrong layouts shift the stream and break header
    CRCs even though the magic itself is found."""
    fs_per_page, mapping = _slice_map(slices)
    valid = total = 0
    for peb_off, hits in peb_magics[:sample_limit]:
        for k, r in hits:
            fs_r = _raw_to_fs(mapping, r)
            if fs_r is None:
                continue
            # 3-page FS window starting at page k
            blob = b"".join(
                b"".join(data[peb_off + (k + j) * page_stride + a:
                              peb_off + (k + j) * page_stride + b]
                         for a, b in slices)
                for j in range(3))
            hb = fs_r + 12                 # block header after stream header
            if hb + 8 > len(blob):
                continue
            hsz = (blob[hb] + 1) * 4
            if hsz < 8 or hb + hsz > len(blob):
                total += 1                 # malformed under this layout
                continue
            stored = int.from_bytes(blob[hb + hsz - 4:hb + hsz], "little")
            calc = zlib.crc32(blob[hb:hb + hsz - 4]) & 0xFFFFFFFF
            total += 1
            if stored == calc:
                valid += 1
    return valid, total


def assemble_leb(data: bytes, peb_off: int, page_stride: int, data_pages: int,
                 slices: Tuple[Tuple[int, int], ...],
                 first_page: int = 2, min_bytes: int = 0) -> bytes:
    """LEB payload of one PEB under a slice layout (first `min_bytes` only
    when min_bytes>0, to keep CRC checks cheap)."""
    out = []
    need = min_bytes
    for k in range(first_page, first_page + data_pages):
        s = peb_off + k * page_stride
        page = data[s:s + page_stride]
        piece = b"".join(page[a:b] for a, b in slices)
        out.append(piece)
        need -= len(piece)
        if need <= 0:
            break
    return b"".join(out)


def collect_vids(data: bytes, ec_grid: List[int], vid_offset: int,
                 invert: bool, sample_limit: int = SAMPLE_PEB_LIMIT
                 ) -> List[Tuple[int, int, int]]:
    """[(peb_off, data_size, data_crc)] for recoverable VID headers.
    Layout-independent — compute once, reuse across layout scoring."""
    out = []
    for peb_off in ec_grid[:sample_limit]:
        vid = recover_vid(data[peb_off + vid_offset:
                               peb_off + vid_offset + VID_HDR_SZ], invert)
        if vid is None:
            continue
        _lnum, dsz, dcrc = vid_fields(vid)
        if dsz:
            out.append((peb_off, dsz, dcrc))
    return out


def score_layout(data: bytes, ec_grid: List[int], vid_offset: int,
                 page_stride: int, data_pages: int,
                 slices: Tuple[Tuple[int, int], ...], invert: bool,
                 sample_limit: int = SAMPLE_PEB_LIMIT,
                 vids: Optional[List[Tuple[int, int, int]]] = None
                 ) -> Tuple[int, int]:
    """(ok, bad) VID data_crc pass counts under a layout hypothesis.
    `vids` = precomputed collect_vids() output (recommended: VID recovery
    is layout-independent and slow)."""
    ok = bad = 0
    entries = vids if vids is not None else collect_vids(
        data, ec_grid, vid_offset, invert,
        sample_limit=sample_limit)[:sample_limit]
    for peb_off, dsz, dcrc in entries[:sample_limit]:
        leb = assemble_leb(data, peb_off, page_stride, data_pages, slices,
                           min_bytes=dsz)
        if len(leb) < dsz:
            continue
        c = zlib.crc32(leb[:dsz]) & 0xFFFFFFFF
        if c == dcrc or (c ^ 0xFFFFFFFF) == dcrc:
            ok += 1
        else:
            bad += 1
    return ok, bad


def probe_page_layouts(data: bytes, ec_grid: List[int], vid_offset: int,
                       page_stride: int, data_pages: int, invert: bool
                       ) -> List[Dict]:
    """Score layout hypotheses by xz block-header CRC pass rate:
      1. 'full-page'   — whole physical page treated as data (naive)
      2. 'data-only'   — largest 2^n <= page_stride (2048 for 2112)
      3. 'gap@k/g'     — GENERIC inline-ECC gap search (gap width g at
                         offset k), two-stage screen then confirm
      4. 'gap+oob@...' — gap plus trailing OOB-rescue slice of width w
    Returns scored candidates sorted best-first."""
    candidates: List[Dict] = []
    if page_stride <= 0:
        return candidates

    # 1. naive full-page
    candidates.append(dict(name="full-page", page_data=page_stride,
                           slices=((0, page_stride),), gap_pos=None,
                           gap_size=None))

    # 2. data-only (largest power of two fitting the page)
    page_data = 1 << (page_stride - 1).bit_length()
    if page_data > page_stride:
        page_data >>= 1
    if page_data != page_stride:
        candidates.append(dict(name=f"data-only({page_data})",
                               page_data=page_data,
                               slices=((0, page_data),), gap_pos=None,
                               gap_size=None))

    SCREEN_PEBS = 4
    VID_SCREEN_PEBS = 6

    # Prefilter: locate xz magics in RAW data pages (layout-independent —
    # the magic survives any slicing). Volume tables and non-xz volumes
    # contribute nothing and are skipped.
    peb_magics = scan_xz_magics(data, ec_grid, page_stride, data_pages)

    # Precompute recoverable VID headers once (layout-independent, slow):
    # reused by every data_crc screen below. Keep only LEBs spanning more
    # than one page's worth of data — single-page LEBs (UBI layout volume)
    # are layout-insensitive and would vote for the naive contiguous view.
    vids_all = collect_vids(data, ec_grid, vid_offset, invert,
                            sample_limit=SAMPLE_PEB_LIMIT)
    vids = [v for v in vids_all if v[1] > page_data] or vids_all

    # 3. generic single-gap search (inline ECC hidden inside the data area).
    # Screened by VID data_crc — the only layout-exact metric (xz header
    # CRCs pass under several layouts because they span too few bytes).
    # One-VID early-exit screens the position sweep; the winner is then
    # confirmed on up to VID_SCREEN_PEBS VIDs.
    def _vid1_ok(slices):
        # any of the first 3 recoverable VIDs passing is evidence enough
        # (CRC false-positive odds ~2^-32 per try)
        for peb_off, dsz, dcrc in vids[:3]:
            leb = assemble_leb(data, peb_off, page_stride, data_pages,
                               slices, min_bytes=dsz)
            if len(leb) < dsz:
                continue
            c = zlib.crc32(leb[:dsz]) & 0xFFFFFFFF
            if c == dcrc or (c ^ 0xFFFFFFFF) == dcrc:
                return True
        return False

    if page_data >= GAP_SEARCH_MIN + 64 and vids:
        best: Optional[Tuple[int, int]] = None  # (k, g)
        for g in GAP_SIZES:
            if GAP_SEARCH_MIN + g >= page_data:
                continue
            for k in range(GAP_SEARCH_MIN, page_data - g, GAP_SEARCH_ALIGN):
                if _vid1_ok(((0, k), (k + g, page_data))):
                    best = (k, g)
                    break
            if best:
                break
        if best is not None:
            k, g = best
            win_slices: Tuple[Tuple[int, int], ...] = ((0, k), (k + g, page_data))
            candidates.append(dict(name=f"gap@{k}/{g}", page_data=page_data,
                                   slices=win_slices, gap_pos=k, gap_size=g))

    # 4. gap + OOB-rescue variants: some vendor layouts hide ECC inline AND
    # take extra FS bytes from the OOB area. Probe the family generically:
    # gap search + trailing OOB slice width w, tried LEFT-aligned right
    # after the 2-byte bad-block marker and RIGHT-aligned at the page end
    # (one-VID early-exit sweep).
    if page_stride > page_data + 8 and page_data >= GAP_SEARCH_MIN + 64 \
            and vids:
        oob_w = page_stride - page_data
        best2: Optional[Tuple[int, int, int, int]] = None  # (k, g, w, start)
        for g in GAP_SIZES:
            if GAP_SEARCH_MIN + g >= page_data:
                continue
            for w in range(8, min(17, oob_w - 2), 2):
                starts = (page_data + 2, page_stride - w)
                for start in starts:
                    for k in range(GAP_SEARCH_MIN, page_data - g,
                                   GAP_SEARCH_ALIGN):
                        slices = ((0, k), (k + g, page_data),
                                  (start, start + w))
                        if _vid1_ok(slices):
                            best2 = (k, g, w, start)
                            break
                    if best2:
                        break
                if best2:
                    break
            if best2:
                break
        if best2 is not None:
            k, g, w, start = best2
            win2: Tuple[Tuple[int, int], ...] = (
                (0, k), (k + g, page_data), (start, start + w))
            candidates.append(dict(name=f"gap+oob@{k}/{g}+{w}",
                                   page_data=page_data, slices=win2,
                                   gap_pos=k, gap_size=g))

    # 5. chunked inline-ECC: page split as [data c][ecc e] repeated k
    # times (k*c == page_data). Common on small-page NAND with per-chunk
    # hardware ECC (e.g. 2112 = 4 x (512+16)). Screened by the same VID
    # data_crc oracle; runs only when the single-gap families found
    # nothing (cheap: ≤10 shapes).
    if vids and page_data >= GAP_SEARCH_MIN:
        for c, e in CHUNK_ECC_SHAPES:
            if page_data % c or page_data // c * (c + e) != page_stride:
                continue
            sl: List[Tuple[int, int]] = []
            off_c = 0
            for _ in range(page_data // c):
                sl.append((off_c, off_c + c))
                off_c += c + e
            slices5: Tuple[Tuple[int, int], ...] = tuple(sl)
            if _vid1_ok(slices5):
                candidates.append(dict(
                    name=f"chunked-ecc {c}+{e}x{page_data // c}",
                    page_data=page_data, slices=slices5, gap_pos=None,
                    gap_size=None))
                break

    # Score the non-gap candidates too, then tie-break with VID data_crc:
    # xz header CRCs only exercise ~130 B around each container start, so
    # several layouts can pass them all. The VID data_crc covers the whole
    # assembled LEB (data_size bytes), which separates layout hypotheses
    # decisively (0/N vs N/N in real dumps).
    for c in candidates:
        if "ok" not in c:
            v, t = score_layout_xz(data, peb_magics, page_stride,
                                   c["slices"], sample_limit=SAMPLE_PEB_LIMIT)
            c["ok"], c["bad"] = v, t - v
        vid_ok, vid_bad = score_layout(data, ec_grid, vid_offset,
                                       page_stride, data_pages,
                                       c["slices"], invert,
                                       sample_limit=SAMPLE_PEB_LIMIT,
                                       vids=vids)
        c["vid_ok"], c["vid_bad"] = vid_ok, vid_bad
        c["vid_total"] = vid_ok + vid_bad
        c["vid_rate"] = (vid_ok / c["vid_total"]) if c["vid_total"] else None
    total = [c for c in candidates
             if c["ok"] + c["bad"] > 0
             or c["vid_ok"] + c["vid_total"] > 0]
    for c in total:
        c["rate"] = (c["ok"] / (c["ok"] + c["bad"])) if (c["ok"] + c["bad"]) \
            else 0.0
        # Adjudicated rate: VID data_crc when any VIDs were readable,
        # else the xz-header rate.
        c["arate"] = c["vid_rate"] if c["vid_rate"] is not None \
            else c["rate"]
    return sorted(total, key=lambda c: (-c["arate"], -c["vid_ok"],
                                        -c["rate"], -(c["ok"] + c["bad"])))


# ------------------------------------------------- ANOM-2: bit-rot signature

def bitrot_signature(volume: bytes, reference: bytes, block: int = 512
                     ) -> Dict:
    """Classify volume-vs-reference differences as bit rot (ANOM-2) or a
    layout bug. Chunked int-XOR: C-speed for the common all-zero chunks.

    Healthy rot: total rate << 1%, overwhelmingly single-bit bytes, and no
    long contiguous runs of differing bytes (a layout shift produces runs;
    bit rot produces isolated single-byte hits)."""
    n = min(len(volume), len(reference))
    diff_bytes = 0
    flip_bits = 0
    multi_bit_bytes = 0
    max_run = 0
    run = 0
    for base in range(0, n, BITROT_MAX_CHUNK):
        chunk_v = volume[base:base + BITROT_MAX_CHUNK]
        # reference may be longer than the volume (e.g. tail padding):
        # slice per-chunk so the int-XOR lengths always match
        chunk_r = reference[base:base + len(chunk_v)]
        xi = int.from_bytes(chunk_v, "little") ^ int.from_bytes(chunk_r,
                                                                "little")
        if xi == 0:
            run = 0
            continue
        cb = xi.to_bytes(len(chunk_v), "little")
        for i, d in enumerate(cb):
            if d:
                diff_bytes += 1
                h = d.bit_count()
                flip_bits += h
                if h > 1:
                    multi_bit_bytes += 1
                run += 1
                max_run = max(max_run, run)
            else:
                run = 0
        if flip_bits > BITROT_BIT_CAP:
            break
    rate = diff_bytes / n if n else 0.0
    multi_frac = (multi_bit_bytes / diff_bytes) if diff_bytes else 0.0
    return {
        "diff_bytes": diff_bytes,
        "flip_bits": flip_bits,
        "multi_bit_bytes": multi_bit_bytes,
        "max_run": max_run,
        "rate": rate,
        "is_bitrot": (diff_bytes > 0 and rate < 0.01
                      and multi_frac <= 0.05 and max_run <= 8),
        "capped": flip_bits > BITROT_BIT_CAP,
    }


def bitrot_diff_positions(volume: bytes, reference: bytes) -> List[int]:
    """Byte positions where volume and reference differ (chunked int-XOR)."""
    n = min(len(volume), len(reference))
    pos = []
    for base in range(0, n, BITROT_MAX_CHUNK):
        chunk_v = volume[base:base + BITROT_MAX_CHUNK]
        # reference may be longer than the volume: slice per-chunk
        chunk_r = reference[base:base + len(chunk_v)]
        xi = int.from_bytes(chunk_v, "little") ^ int.from_bytes(chunk_r,
                                                                "little")
        if xi == 0:
            continue
        cb = xi.to_bytes(len(chunk_v), "little")
        pos.extend(base + i for i, d in enumerate(cb) if d)
    return pos


def repair_bitrot(volume: bytearray, reference: bytes) -> Tuple[int, int]:
    """Correct single-bit-flip bytes against the reference. Returns
    (repaired, skipped_multi_bit). Multi-bit bytes are NOT touched."""
    positions = bitrot_diff_positions(bytes(volume), reference)
    repaired = skipped = 0
    for i in positions:
        if hamming(volume[i], reference[i]) == 1:
            volume[i] = reference[i]
            repaired += 1
        else:
            skipped += 1
    return repaired, skipped


# ------------------------------------------------- ANOM-3: CRC convention

def detect_crc_convention(data: bytes, ec_grid: List[int], vid_offset: int
                          ) -> Optional[bool]:
    """Majority vote: are stored EC/VID CRCs plain crc32 (False) or ~crc32
    (True)? None when no header yields a decisive vote."""
    votes: List[bool] = []
    for eco in ec_grid[:64]:
        ec = data[eco:eco + EC_HDR_SZ]
        if ec[:4] == EC_MAGIC:
            stored = _u32(ec, 0x3C)
            calc = zlib.crc32(ec[:60]) & 0xFFFFFFFF
            if stored == calc:
                votes.append(False)
            elif stored == (~calc & 0xFFFFFFFF):
                votes.append(True)
        if vid_offset is not None:
            vo = eco + vid_offset
            vid = data[vo:vo + VID_HDR_SZ]
            if len(vid) == VID_HDR_SZ and vid[:4] == VID_MAGIC:
                stored = _u32(vid, 0x3C)
                calc = zlib.crc32(vid[:VID_BODY]) & 0xFFFFFFFF
                if stored == calc:
                    votes.append(False)
                elif stored == (~calc & 0xFFFFFFFF):
                    votes.append(True)
    if not votes:
        return None
    return votes.count(True) > votes.count(False)


# ------------------------------------------------------------- main scanner

def scan_anomalies(data: bytes, reference: Optional[bytes] = None,
                   verbose: bool = False) -> AnomalyContext:
    """Read-only anomaly scan over a raw firmware/dump image. Cheap enough
    to run before every parse; populates ctx.findings + repair plan."""
    ctx = AnomalyContext(data=data)
    if reference is not None:
        ctx.reference = reference

    # ANOM-4: derive geometry from magic grids.
    geo = derive_geometry(data)
    ctx.ec_offsets = geo.get("ec_grid", geo.get("ec_hits", []))
    ctx.vid_offsets = [eco + geo["vid_offset"] for eco in ctx.ec_offsets] \
        if geo.get("vid_offset") is not None else []
    ctx.ubi_base = geo.get("ubi_base")
    ctx.peb_stride = geo.get("peb_stride")
    ctx.page_stride = geo.get("page_stride")
    ctx.vid_offset = geo.get("vid_offset")
    ctx.pages_per_peb = geo.get("pages_per_peb")
    ctx.data_pages = geo.get("data_pages")

    if not ctx.ec_offsets:
        ctx.findings.append(Finding(
            "ANOM-4", "fatal",
            "no UBI EC-header grid found (magic 'UBI#' hits: "
            f"{len(geo.get('ec_hits', []))}) — not a UBI-containing image?"))
        return ctx

    ctx.stats["ec_grid_size"] = len(ctx.ec_offsets)
    ctx.findings.append(Finding(
        "ANOM-4", "info",
        f"UBI grid: base {ctx.ubi_base:#x}, PEB stride {ctx.peb_stride}, "
        f"page stride {ctx.page_stride}, VID offset {ctx.vid_offset}, "
        f"{len(ctx.ec_offsets)} EC headers",
        {k: geo.get(k) for k in ("ubi_base", "peb_stride", "page_stride",
                                 "vid_offset", "pages_per_peb")}))

    # ANOM-3: CRC convention.
    ctx.crc_inverted = detect_crc_convention(data, ctx.ec_offsets,
                                             ctx.vid_offset)
    if ctx.crc_inverted is not None:
        ctx.findings.append(Finding(
            "ANOM-3", "info",
            "CRC convention: " +
            ("~crc32 (inverted)" if ctx.crc_inverted else "plain crc32"),
            {"inverted": ctx.crc_inverted}))
    invert = bool(ctx.crc_inverted)

    # ANOM-2 FIRST (probe prerequisite): when a reference image is given,
    # detect bit rot and repair an in-memory view. All downstream evidence
    # probes (VID health, page layout) run on the repaired view — otherwise
    # 12k flipped bits mask the layout signal (data_crc fails everywhere).
    probe_data: bytes = data
    if ctx.reference is not None:
        if len(ctx.reference) != len(data):
            # Volume-level reference (v1.3.0): a known-good VOLUME image
            # (smaller than the dump) cannot patch raw pages, but it does
            # adjudicate the page layout by content matching — skip the
            # byte-level ANOM-2 path instead of aborting the scan.
            _adjudicate_layout_volume_ref(ctx, data)
            return ctx
        sig = bitrot_signature(data, ctx.reference)
        ctx.stats["bitrot"] = sig
        if sig["diff_bytes"]:
            if sig["is_bitrot"]:
                ctx.findings.append(Finding(
                    "ANOM-2", "repairable",
                    f"{sig['diff_bytes']} differing bytes, "
                    f"{sig['multi_bit_bytes']} multi-bit (max run "
                    f"{sig['max_run']}, rate {sig['rate']:.4%}) — aged "
                    f"NAND bit rot, ECC-correctable",
                    sig))
                ctx.repair_plan.append(
                    f"repair {sig['diff_bytes']} single-bit flips vs "
                    f"reference")
                if not sig.get("capped"):
                    buf = bytearray(data)
                    repair_bitrot(buf, ctx.reference)
                    probe_data = bytes(buf)
                    ctx.working = probe_data
            else:
                ctx.findings.append(Finding(
                    "ANOM-2", "fatal",
                    f"{sig['diff_bytes']} differing bytes, "
                    f"{sig['multi_bit_bytes']} multi-bit (max run "
                    f"{sig['max_run']}, rate {sig['rate']:.4%}) — NOT "
                    f"plain bit rot; blind repair refused",
                    sig))

    # ANOM-5: VID hdr_crc health (single-bit repairability).
    bad_vid = []
    for vo in ctx.vid_offsets[:4096]:
        vid = probe_data[vo:vo + VID_HDR_SZ]
        if vid[:4] == VID_MAGIC and not vid_crc_ok(vid, invert):
            bad_vid.append(vo)
    ctx.stats["vid_bad"] = len(bad_vid)
    if bad_vid:
        repairable = sum(1 for vo in bad_vid
                         if repair_vid_single_bit(probe_data[vo:vo + VID_HDR_SZ],
                                                  invert) is not None)
        sev = "repairable" if repairable else "fatal"
        ctx.findings.append(Finding(
            "ANOM-5", sev,
            f"{len(bad_vid)} VID header(s) fail hdr_crc "
            f"({repairable} single-bit repairable)",
            {"offsets_sample": [hex(v) for v in bad_vid[:8]]}))
        if repairable:
            ctx.repair_plan.append(
                f"single-bit repair {repairable} VID header(s)")

    # ANOM-1: page-layout probe (needs page geometry; runs on the
    # bit-rot-repaired view when available).
    if ctx.page_stride and ctx.data_pages and ctx.data_pages > 0 \
            and ctx.vid_offset is not None:
        layout_cands = probe_page_layouts(
            probe_data, ctx.ec_offsets, ctx.vid_offset, ctx.page_stride,
            ctx.data_pages, invert)
        ctx.stats["layout_candidates"] = [
            {k: c.get(k) for k in ("name", "arate", "rate", "vid_ok",
                                   "vid_total", "ok", "bad")}
            for c in layout_cands[:6]]
        if layout_cands:
            best = layout_cands[0]
            full = next((c for c in layout_cands
                         if c["name"] == "full-page"), None)
            full_rate = full["arate"] if full else None
            if best["arate"] >= LAYOUT_MIN_RATE and \
               (full_rate is None or best["arate"] > full_rate + LAYOUT_MARGIN):
                ctx.page_layout = (best["name"], best["page_data"],
                                   best["slices"], best["gap_pos"],
                                   best["gap_size"])
                metric = ("VID data_crc" if best["vid_total"]
                          else "xz header CRC")
                ctx.findings.append(Finding(
                    "ANOM-1", "repairable",
                    f"page layout '{best['name']}' {metric} rate "
                    f"{best['arate']:.2f} vs full-page "
                    f"{full_rate if full_rate is not None else 'n/a'} — "
                    f"data area is ECC-interleaved; naive assembly shifts "
                    f"pages",
                    {"winner": best["name"], "gap_pos": best["gap_pos"],
                     "gap_size": best["gap_size"]}))
                ctx.repair_plan.append(
                    f"assemble LEBs with layout '{best['name']}' "
                    f"(skip gap {best['gap_size']}B at "
                    f"{best['gap_pos']})")
            elif full_rate is not None and full_rate < 0.5 and \
                    best["arate"] < LAYOUT_MIN_RATE:
                if ctx.reference is None:
                    hint = ("if a known-good image/volume exists, rerun with "
                            "--reference KNOWN_GOOD — bit rot may be present "
                            "but is undetectable (and layout adjudication "
                            "masks data_crc) without it; otherwise inspect "
                            "OOB/ECC placement manually")
                    note = (f"no layout hypothesis passes data_crc (best "
                            f"{best['name']} {best['arate']:.2f}) — {hint}")
                else:
                    note = (f"no layout hypothesis passes data_crc (best "
                            f"{best['name']} {best['arate']:.2f}) — damage "
                            "beyond page-layout shift")
                # v1.4.0: reference-free self-adjudication — when VID
                # data_crc evidence is masked (bit rot) and no reference is
                # available, the image's own squashfs metadata (xz-
                # checksummed blocks) adjudicates the layout.
                if not _self_adjudicate_layout(ctx, layout_cands):
                    ctx.findings.append(Finding("ANOM-1", "fatal", note))

    return ctx


def apply_repairs(ctx: AnomalyContext,
                  dry_run: bool = False) -> Tuple[bytes, List[str]]:
    """Execute the repair plan. Returns (repaired_bytes, action_log).
    Repairs only what evidence supports; never guesses."""
    log: List[str] = []
    out = bytearray(ctx.data)
    invert = bool(ctx.crc_inverted)

    # ANOM-5: single-bit VID header repair.
    fixed = skipped = 0
    for vo in ctx.vid_offsets[:4096]:
        vid = bytes(out[vo:vo + VID_HDR_SZ])
        if vid[:4] != VID_MAGIC or vid_crc_ok(vid, invert):
            continue
        rep = repair_vid_single_bit(vid, invert)
        if rep is not None:
            if not dry_run:
                out[vo:vo + VID_HDR_SZ] = rep
            fixed += 1
        else:
            skipped += 1
    if fixed or skipped:
        verb = "[dry-run] would repair" if dry_run else "repaired"
        log.append(f"{verb} {fixed} VID header(s) single-bit "
                   f"({skipped} multi-bit left untouched)")

    # ANOM-2: bit rot vs reference (byte patch).
    if ctx.reference is not None and any(
            f.kind == "ANOM-2" and f.severity == "repairable"
            for f in ctx.findings):
        if dry_run:
            sig = bitrot_signature(bytes(out), ctx.reference)
            log.append(f"[dry-run] would repair {sig['diff_bytes']} "
                       f"bit-rot bytes vs reference")
        else:
            repaired, multi = repair_bitrot(out, ctx.reference)
            log.append(f"repaired {repaired} bit-rot bytes vs reference "
                       f"({multi} multi-bit bytes left untouched)")

    if not log:
        log.append("nothing to repair (layout findings are assembly hints, "
                   "not byte patches)")
    return (bytes(out) if not dry_run else ctx.data), log


# ---------------------------------------------- page-layout deinterleaving
# ANOM-1's byte-level remedy: rewrite the image so every physical page
# keeps only the FS slices (the inline-ECC gap and trailing OOB-rescue
# bytes are dropped). Everything downstream (OOB strip, UBI scanner,
# volume assembly, extraction) then works on a clean, contiguous image.

def strip_page_layout(data: bytes, page_stride: int,
                      slices: Tuple[Tuple[int, int], ...]) -> bytes:
    """Rewrite image page-by-page keeping only FS slices per page.

    Every `page_stride` bytes of `data` is a physical page; output is the
    concatenation of its FS slices (from a layout hypothesis adjudicated by
    ANOM-1). Padding at the tail beyond the last full page is dropped."""
    if page_stride <= 0:
        return data
    fs_len = sum(b - a for a, b in slices)
    out = bytearray()
    for pos in range(0, len(data) - page_stride + 1, page_stride):
        page = data[pos:pos + page_stride]
        for a, b in slices:
            out += page[a:b]
    return bytes(out)


def adjudicated_layout(ctx: "AnomalyContext"
                       ) -> Optional[Tuple[str, int, Tuple[Tuple[int, int], ...],
                                           Optional[int], Optional[int]]]:
    """The ANOM-1 layout finding packaged for consumers (None = full-page)."""
    return ctx.page_layout


# ---------------------------------------------- volume-reference adjudication
# A known-good VOLUME image (e.g. the FS image from a sibling dump of the
# same firmware) identifies the page layout by content matching: under the
# true layout, LEB prefixes appear verbatim in the reference; under any
# wrong layout the bytes are ECC-shifted and match nothing. This works even
# when uncorrected bit rot masks VID data_crc probing, and the reference
# then patches the extracted volumes (post-extraction, evidence-gated).

def _adjudicate_layout_volume_ref(ctx: "AnomalyContext", data: bytes) -> None:
    """Set ctx.page_layout from a volume reference, if one matches."""
    ps, dp = ctx.page_stride, ctx.data_pages
    if not ps or not dp or ctx.vid_offset is None or not ctx.ec_offsets:
        return
    ref = ctx.reference
    if ref is None:
        return
    vo = ctx.vid_offset
    invert = bool(ctx.crc_inverted)
    vids = collect_vids(data, ctx.ec_offsets, ctx.vid_offset, invert,
                        sample_limit=SAMPLE_PEB_LIMIT)
    vids = [v for v in vids if v[1] > 512] or vids
    if not vids:
        return
    page_data = 1 << (ps - 1).bit_length()
    if page_data > ps:
        page_data >>= 1

    def _windows_ok(slices, fs_per_page):
        """>=2 of the first 3 multi-page LEBs: a 64 KB window at the LEB's
        reference position is isolated-single-bit vs the reference. Under
        the true layout this is aged bit rot; under any wrong layout the
        bytes are ECC-shifted and diff wholesale (rate >> 1%)."""
        wins = tried = 0
        for peb_off, _dsz, _dcrc in vids[:3]:
            vid = recover_vid(data[peb_off + vo:peb_off + vo + VID_HDR_SZ],
                              invert)
            if vid is None:
                continue
            lnum = vid_fields(vid)[0]
            leb = assemble_leb(data, peb_off, ps, dp, slices, min_bytes=1 << 16)
            rpos = lnum * (dp * fs_per_page)
            if rpos < 0 or rpos >= len(ref) or len(leb) < (1 << 16):
                continue
            rend = min(rpos + (1 << 16), len(ref))
            tried += 1
            sig = bitrot_signature(leb[:rend - rpos], ref[rpos:rend])
            if sig["is_bitrot"]:
                wins += 1
        return wins >= 2 and tried >= 2, wins

    def _probe_ok(slices, fs_per_page):
        """Whole-page XOR probe (cheap pre-screen for the sweep): the first
        data page of the first recoverable LEB must match the reference at
        the lnum-derived offset within a small byte budget (bit rot). A
        wrong gap position/width shifts most bytes past the knee and fails."""
        peb_off = vids[0][0]
        vid = recover_vid(data[peb_off + vo:peb_off + vo + VID_HDR_SZ],
                          invert)
        if vid is None:
            return False
        lnum = vid_fields(vid)[0]
        page = data[peb_off + 2 * ps:peb_off + 3 * ps]
        fs_page = b"".join(page[a:b] for a, b in slices)
        rpos = lnum * (dp * fs_per_page)
        if rpos < 0 or rpos + len(fs_page) > len(ref):
            return False
        x = int.from_bytes(fs_page, "little") ^ \
            int.from_bytes(ref[rpos:rpos + len(fs_page)], "little")
        diff = sum(1 for b in x.to_bytes(len(fs_page), "little") if b)
        return diff <= 48

    win: Optional[Tuple[str, int, Tuple, Optional[int], Optional[int]]] = None
    if _windows_ok(((0, ps),), ps)[0]:
        win = ("full-page", ps, ((0, ps),), None, None)
    if win is None and _windows_ok(((0, page_data),), page_data)[0]:
        win = (f"data-only({page_data})", page_data,
               ((0, page_data),), None, None)
    if win is None and page_data >= GAP_SEARCH_MIN + 64:
        for g in GAP_SIZES:
            if GAP_SEARCH_MIN + g >= page_data:
                continue
            for k in range(GAP_SEARCH_MIN, page_data - g, GAP_SEARCH_ALIGN):
                sl = ((0, k), (k + g, page_data))
                if _probe_ok(sl, page_data) and _windows_ok(sl, page_data)[0]:
                    win = (f"gap@{k}/{g}", page_data, sl, k, g)
                    break
            if win:
                break
    if win is None and ps > page_data + 8 and page_data >= GAP_SEARCH_MIN + 64:
        # Sweep cost control: cheap positional 512-byte probe (VID lnum gives
        # the exact reference offset — no haystack search) across the full
        # grid, then confirm the winners with the 64 KB window signature.
        oob_w = ps - page_data
        for g in GAP_SIZES:
            if GAP_SEARCH_MIN + g >= page_data:
                continue
            confirmed = None
            for w in range(8, min(17, oob_w - 2), 2):
                for start in (page_data + 2, ps - w):
                    for k in range(GAP_SEARCH_MIN, page_data - g,
                                   GAP_SEARCH_ALIGN):
                        sl = ((0, k), (k + g, page_data), (start, start + w))
                        if _probe_ok(sl, page_data) and \
                                _windows_ok(sl, page_data)[0]:
                            confirmed = (k, g, w, start)
                            break
                    if confirmed:
                        break
                if confirmed:
                    break
            if confirmed:
                k, g2, w2, start = confirmed
                win = (f"gap+oob@{k}/{g2}+{w2}", page_data,
                       ((0, k), (k + g2, page_data), (start, start + w2)),
                       k, g2)
                break
    if win is None:
        return
    name, pd, slices, gap_pos, gap_size = win
    hits = _windows_ok(slices, pd)[1]
    ctx.page_layout = (name, pd, slices, gap_pos, gap_size)
    ctx.findings.append(Finding(
        "ANOM-1", "repairable",
        f"page layout '{name}' adjudicated by volume reference "
        f"({hits}/3 LEB 64KB-windows pass bit-rot signature) — "
        f"data area is ECC-interleaved; naive assembly shifts pages",
        {"winner": name, "gap_pos": gap_pos, "gap_size": gap_size}))
    plan = f"assemble with layout '{name}'"
    if gap_pos is not None:
        plan += f" (skip gap {gap_size}B at {gap_pos:#x})"
    ctx.repair_plan.append(plan)
    ctx.stats["volume_reference"] = {"bytes": len(ref), "window_hits": hits}


def _sqfs_metadata_census(vol: bytes,
                          max_blocks: int = SELF_CENSUS_MAX_BLOCKS
                          ) -> Tuple[int, int]:
    """(decoded, tried) squashfs metadata blocks under an assembled volume.
    Walks the inode table named by the superblock; every metadata block is
    an independently checksummed xz stream, so the true page layout decodes
    a healthy fraction even under bit rot, while any wrong layout yields
    ECC-shifted garbage (measured 15.8% vs 0.0% on real dumps)."""
    if len(vol) < 0x50 or vol[:4] != b"hsqs":
        return 0, 0
    ino = int.from_bytes(vol[0x40:0x48], "little")
    if not (0 < ino < len(vol) - 2):
        return 0, 0
    ok = tried = 0
    pos = ino
    while tried < max_blocks and pos + 2 <= len(vol):
        h = int.from_bytes(vol[pos:pos + 2], "little")
        ln = h & 0x7FFF
        if ln <= 0 or pos + 2 + ln > len(vol):
            break
        blk = vol[pos + 2:pos + 2 + ln]
        tried += 1
        if not (h & 0x8000) and blk[:6] == XZ_MAGIC:
            try:
                lzma.decompress(blk, format=lzma.FORMAT_XZ)
                ok += 1
            except Exception:
                pass
        pos += 2 + ln
    return ok, tried


def _self_adjudicate_layout(ctx: "AnomalyContext",
                            layout_cands: List[Dict]) -> bool:
    """v1.4.0 reference-free ANOM-1 adjudication. When no external
    reference exists and VID data_crc evidence is masked (e.g. by bit rot —
    a single flip anywhere in an LEB breaks its data_crc), score layout
    hypotheses by how much of the image's OWN squashfs metadata decodes:
    the superblock names the inode table, and each metadata block is an
    independently checksummed xz stream. The true layout decodes a healthy
    fraction even with heavy rot; any wrong layout yields ECC-shifted
    garbage (measured 15.8% vs 0.0% on real dumps). Screens the full
    gap/gap+oob sweep cheaply by censusing only the volume tail LEBs that
    hold the metadata table."""
    ps, dp = ctx.page_stride, ctx.data_pages
    if not ps or not dp or ctx.vid_offset is None or not ctx.ec_offsets:
        return False
    invert = bool(ctx.crc_inverted)
    page_data = 1 << (ps - 1).bit_length()
    if page_data > ps:
        page_data >>= 1

    # Layout-independent: map the dominant volume's PEBs by VID lnum.
    # PEBs with unreadable VIDs fill the gaps in grid order (the common
    # real-world case: rot damaged exactly those VID headers).
    lnum_map: Dict[int, int] = {}
    for peb_off in ctx.ec_offsets[:1024]:
        vid = recover_vid(ctx.data[peb_off + ctx.vid_offset:
                                   peb_off + ctx.vid_offset + VID_HDR_SZ],
                          invert)
        if vid is None:
            continue
        vol_id = int.from_bytes(vid[8:12], "big")
        if vol_id >= VOL_ID_INTERNAL:
            continue
        lnum = vid_fields(vid)[0]
        lnum_map.setdefault(lnum, peb_off)
    if 0 not in lnum_map:
        return False                       # no readable superblock volume
    used = set(lnum_map.values())
    fill_q = [p for p in ctx.ec_offsets[:1024] if p not in used]
    hi = max(lnum_map) + 1
    peb_order: List[Optional[int]] = []
    fi = 0
    for ln in range(hi):
        p = lnum_map.get(ln)
        if p is None and fi < len(fill_q):
            p = fill_q[fi]
            fi += 1
        peb_order.append(p)

    leb_sz = dp * page_data
    # Superblock fields are identical under every hypothesis that keeps the
    # page-0 prefix intact — parse once from a plain data-only page 0.
    p0 = peb_order[0]
    if p0 is None:
        return False
    vol0 = assemble_leb(ctx.data, p0, ps, dp,
                        ((0, page_data),), min_bytes=0x50)
    if len(vol0) < 0x50 or vol0[:4] != b"hsqs":
        return False
    ino = int.from_bytes(vol0[0x40:0x48], "little")
    if not (0 < ino < hi * leb_sz - 2):
        return False

    def _census(slices, max_blocks):
        # fs bytes per LEB under THIS hypothesis (oob-rescue widens it)
        fs_leb = dp * sum(b - a for a, b in slices)
        tail_lo = max(0, ino // fs_leb - 1)
        vol = []
        for ln in range(tail_lo, hi):
            p = peb_order[ln]
            if p is None:
                return 0, 0                # metadata LEB unrecoverable
            vol.append(assemble_leb(ctx.data, p, ps, dp, slices,
                                    min_bytes=fs_leb))
        vol = b"".join(vol)
        pos = ino - tail_lo * fs_leb
        ok = tried = 0
        while tried < max_blocks and pos + 2 <= len(vol):
            h = int.from_bytes(vol[pos:pos + 2], "little")
            ln2 = h & 0x7FFF
            if ln2 <= 0 or pos + 2 + ln2 > len(vol):
                break
            blk = vol[pos + 2:pos + 2 + ln2]
            tried += 1
            if not (h & 0x8000) and blk[:6] == XZ_MAGIC:
                try:
                    lzma.decompress(blk, format=lzma.FORMAT_XZ)
                    ok += 1
                except Exception:
                    pass
            pos += 2 + ln2
        return ok, tried

    def _hypotheses():
        yield "full-page", ps, ((0, ps),), None, None
        if page_data != ps:
            yield (f"data-only({page_data})", page_data,
                   ((0, page_data),), None, None)
        for cand in layout_cands[:6]:
            yield (cand["name"], cand["page_data"], cand["slices"],
                   cand["gap_pos"], cand["gap_size"])
        if page_data >= GAP_SEARCH_MIN + 64:
            for c, e in CHUNK_ECC_SHAPES:
                if page_data % c or page_data // c * (c + e) != ps:
                    continue
                sl: List[Tuple[int, int]] = []
                off_c = 0
                for _ in range(page_data // c):
                    sl.append((off_c, off_c + c))
                    off_c += c + e
                yield (f"chunked-ecc {c}+{e}x{page_data // c}", page_data,
                       tuple(sl), None, None)
            for g in GAP_SIZES:
                if GAP_SEARCH_MIN + g >= page_data:
                    continue
                for k in range(GAP_SEARCH_MIN, page_data - g,
                               GAP_SEARCH_ALIGN):
                    yield (f"gap@{k}/{g}", page_data,
                           ((0, k), (k + g, page_data)), k, g)
            oob_w = ps - page_data
            if ps > page_data + 8:
                for g in GAP_SIZES:
                    if GAP_SEARCH_MIN + g >= page_data:
                        continue
                    for w in range(8, min(17, oob_w - 2), 2):
                        for start in (page_data + 2, ps - w):
                            for k in range(GAP_SEARCH_MIN, page_data - g,
                                           GAP_SEARCH_ALIGN):
                                yield (f"gap+oob@{k}/{g}+{w}", page_data,
                                       ((0, k), (k + g, page_data),
                                        (start, start + w)), k, g)

    best: Optional[Tuple[float, int, int, str, int, Tuple,
                         Optional[int], Optional[int]]] = None
    for name, pd, slices, gap_pos, gap_size in _hypotheses():
        ok, tried = _census(slices, 16)
        if tried < SELF_CENSUS_MIN_BLOCKS:
            continue
        rate = ok / tried
        if rate < SELF_CENSUS_MIN_RATE or ok < 2:
            continue
        ok, tried = _census(slices, SELF_CENSUS_MAX_BLOCKS)
        rate = ok / tried if tried else 0.0
        if best is None or rate > best[0]:
            best = (rate, ok, tried, name, pd, slices, gap_pos, gap_size)
    if best is None:
        return False
    rate, ok, tried, name, pd, slices, gap_pos, gap_size = best
    ctx.page_layout = (name, pd, slices, gap_pos, gap_size)
    ctx.findings.append(Finding(
        "ANOM-1", "repairable",
        f"page layout '{name}' adjudicated reference-free by in-image "
        f"squashfs metadata (xz decode {ok}/{tried} blocks, {rate:.0%}) — "
        f"data area is ECC-interleaved; naive assembly shifts pages",
        {"winner": name, "gap_pos": gap_pos, "gap_size": gap_size,
         "census": f"{ok}/{tried}"}))
    plan = f"assemble with layout '{name}'"
    if gap_pos is not None:
        plan += f" (skip gap {gap_size}B at {gap_pos:#x})"
    ctx.repair_plan.append(plan)
    ctx.stats["self_adjudication"] = {"xz_ok": ok, "xz_tried": tried}
    return True


def fail_fast_message(ctx: AnomalyContext, tool: str) -> Optional[str]:
    """The fail-fast banner (rerun hint) when repairable anomalies exist."""
    if not ctx.has_repairable:
        return None
    bar = "=" * 64
    lines = [bar, "ANOMALIES DETECTED — repair available", bar]
    for f in ctx.findings:
        if f.severity in ("repairable", "fatal"):
            lines.append(f"  {f}")
    lines += ["",
              "Rerun with auto-fix to repair and continue:",
              f"  {tool} --analyze <image> --auto-fix",
              "  (preview first: add --dry-run; byte-exact bit-rot repair:",
              "   add --reference KNOWN_GOOD — a vendor sysupgrade image or",
              "   a known-good volume both work)"]
    lines.append(bar)
    return "\n".join(lines)
