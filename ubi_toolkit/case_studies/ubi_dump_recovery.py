"""Case study: raw NAND UBI dump recovery techniques (generic).

Self-contained, stdlib-only reference implementation of the lessons in
case_studies/README.md. NOT imported by any ubipack code path — read or run it
against a similar dump:

    python -m ubi_toolkit.case_studies.ubi_dump_recovery firmware.bin

Functions are deliberately independent of the analyst/repacker internals so
future releases can lift them without coupling.

Key techniques demonstrated:
  assemble_volume()        — vendor page layout with inline ECC (1040-skip)
  repair_vid_single_bit()  — CRC-guided 1-bit VID header repair
  lnum_bijection_check()   — sanity: each lnum claimed exactly once
  datacrc_audit()          — layout-bug detector (0/N pass = geometry wrong)
  diff_against_reference() — reference-image differential repair (bit flips)
"""

from __future__ import annotations

import zlib
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------- geometry

PEB_STRIDE = 0x21000
LEB_SIZE = 0x1F000
DATA_PAGES = 62
PAGE_DATA = 2048
PAGE_STRIDE = 2112

# Vendor page layout: 14 B ECC inline at data offset 1040, second 14 B ECC
# block taken from the OOB area (page offset 2050 = 2048 + 2).
FS_SLICES = ((0, 1040), (1054, 2048), (2050, 2064))

VID_OFFSET = 0x840
VID_BODY = 60


def page_fs_bytes(page: bytes) -> bytes:
    """Filesystem bytes of one 2112 B physical page (layout with inline ECC)."""
    return b"".join(page[a:b] for a, b in FS_SLICES)


def peb_data(fw: bytes, base: int, peb: int) -> bytes:
    """LEB data of one physical erase block (pages 2..63)."""
    o = base + peb * PEB_STRIDE
    out = []
    for k in range(DATA_PAGES):
        s = o + (2 + k) * PAGE_STRIDE
        out.append(page_fs_bytes(fw[s:s + PAGE_STRIDE]))
    return b"".join(out)


def assemble_volume(fw: bytes, base: int, first_peb: int, count: int,
                    vid_lnum_of: Optional[Dict[int, int]] = None) -> bytes:
    """Concatenate LEBs in lnum order. Pass vid_lnum_of (PEB -> lnum) to order
    by repaired VID map; default assumes the physical map PEB p -> lnum p-2."""
    if vid_lnum_of is None:
        return b"".join(peb_data(fw, base, first_peb + i) for i in range(count))
    by_lnum = {ln: peb_data(fw, base, p) for p, ln in vid_lnum_of.items()}
    return b"".join(by_lnum[ln] for ln in range(count))


# ------------------------------------------------------------- VID repair

def vid_crc_ok(vid: bytes) -> bool:
    stored = int.from_bytes(vid[0x3C:0x40], "big")
    return (zlib.crc32(vid[:VID_BODY]) ^ 0xFFFFFFFF) == stored


def vid_field(vid: bytes, off: int) -> int:
    return int.from_bytes(vid[off:off + 4], "big")


def repair_vid_single_bit(vid: bytes) -> Optional[bytes]:
    """Try all 480 single-bit flips of the VID body; return the first repaired
    header whose CRC validates. Caller must still sanity-check the fields."""
    for pos in range(VID_BODY):
        for bit in range(8):
            w = bytearray(vid)
            w[pos] ^= 1 << bit
            if vid_crc_ok(bytes(w)):
                return bytes(w)
    return None


def build_lnum_map(fw: bytes, base: int, pebs: range,
                   max_lnum: int) -> Tuple[Dict[int, int], List[int], List[int]]:
    """CRC-guided VID lnum map. Returns (map, multi_bit_pebs, unrepaired).

    - natural CRC pass -> use as-is
    - 1-bit repairable -> repaired lnum (sanity-checked)
    - else -> multi-bit damage; caller derives lnum from PEB position
    """
    amap: Dict[int, int] = {}
    multi: List[int] = []
    dead: List[int] = []
    for p in pebs:
        vid = fw[base + p * PEB_STRIDE + VID_OFFSET:
                 base + p * PEB_STRIDE + VID_OFFSET + 64]
        if vid[:4] != b"UBI!":
            dead.append(p)
            continue
        if not vid_crc_ok(vid):
            fixed = repair_vid_single_bit(vid)
            if fixed is None:
                multi.append(p)
                continue
            vid = fixed
        lnum = vid_field(vid, 0x0C)
        if lnum <= max_lnum:
            amap[lnum] = p
        else:
            dead.append(p)
    return amap, multi, dead


def lnum_bijection_check(amap: Dict[int, int], n_expected: int,
                         multi: List[int],
                         pos_lnum=None) -> Tuple[bool, List[int]]:
    """Sanity check on the repaired lnum map. With pos_lnum (PEB -> lnum for
    multi-bit-damaged PEBs, e.g. lambda p: p - 2), True requires: no lnum
    claimed twice, every gap 0..n-1 covered by exactly one multi-bit PEB.
    Without pos_lnum, True requires: no duplicates and no gaps."""
    if len(set(amap.values())) != len(amap):
        return False, []
    gaps = sorted(set(range(n_expected)) - set(amap))
    if pos_lnum is None:
        return not gaps and not multi, gaps
    derived = sorted(pos_lnum(p) for p in multi)
    return sorted(derived) == gaps, gaps


# ------------------------------------------------------------ data_crc audit

def datacrc_audit(fw: bytes, base: int, volume: bytes, pebs: range,
                  max_lnum: int) -> Tuple[int, int]:
    """Compare VID data_crc against the assembled volume. A 0/N pass rate with
    correct geometry is a PAGE LAYOUT bug signal, not a vendor convention."""
    ok = bad = 0
    leb = len(volume) // max(max_lnum + 1, 1)
    for p in pebs:
        vid = fw[base + p * PEB_STRIDE + VID_OFFSET:
                 base + p * PEB_STRIDE + VID_OFFSET + 64]
        if vid[:4] != b"UBI!":
            continue
        if not vid_crc_ok(vid):
            fixed = repair_vid_single_bit(vid)
            if fixed is None:
                continue
            vid = fixed
        lnum = vid_field(vid, 0x0C)
        dsz = vid_field(vid, 0x14)
        dcrc = vid_field(vid, 0x20)
        if lnum > max_lnum or dsz == 0 or dsz > leb:
            continue
        c = zlib.crc32(volume[lnum * leb:lnum * leb + dsz])
        if dcrc == c or dcrc == (~c & 0xFFFFFFFF):
            ok += 1
        else:
            bad += 1
    return ok, bad


# ------------------------------------------------- reference diff (bit flips)

def diff_against_reference(volume: bytearray, reference: bytes,
                           limit: Optional[int] = None) -> int:
    """Correct single-bit flip sites against a known-good image of the same
    firmware. Returns the number of bytes corrected. A healthy NAND dump
    differs from the reference by <<1% with every byte at hamming distance 1;
    larger distances indicate a layout/assembly bug, not ECC damage."""
    n = len(reference) if limit is None else min(limit, len(reference), len(volume))
    fixed = 0
    for i in range(n):
        a, b = volume[i], reference[i]
        if a != b:
            volume[i] = b
            fixed += 1
    return fixed


def flip_stats(volume: bytes, reference: bytes) -> Dict[int, int]:
    """Histogram of hamming distance per differing byte (diagnostic)."""
    hist: Dict[int, int] = {}
    for a, b in zip(volume, reference):
        if a != b:
            d = (a ^ b).bit_count()
            hist[d] = hist.get(d, 0) + 1
    return hist


if __name__ == "__main__":  # minimal smoke demo
    import sys
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    data = open(sys.argv[1], "rb").read()
    # Example from a real dump: the UBI region starts at 0x1ef0000;
    # bank A = PEBs 2..119.
    BASE = 0x1EF0000
    amap, multi, dead = build_lnum_map(data, BASE, range(2, 120), 117)
    ok, gaps = lnum_bijection_check(amap, 118, multi, pos_lnum=lambda p: p - 2)
    print(f"lnum map: {len(amap)} CRC-valid claims, bijection={ok}, gaps={gaps}")
    print(f"multi-bit-damage PEBs: {multi}, unusable: {dead}")
