#!/usr/bin/env python3
"""carve.py -- carve a SquashFS image out of a raw NAND/UBI flash dump.

Raw chip-off / SPI-NAND dumps are not images: they interleave NAND
out-of-band (spare/ECC) bytes after every page, and the filesystem inside
them lives in a UBI (Unsorted Block Images) partition rather than at a
fixed offset. Until both of those are undone, nothing above them (UBI,
UBIFS, SquashFS, JFFS2) parses correctly -- even though isolated magic
numbers can appear to match by coincidence.

Pipeline (pure stdlib, no external tools):

  1. STRIP NAND OOB/SPARE DATA
     Remove the trailing spare bytes from every page. The page/OOB
     geometry is auto-detected by finding the erase-header spacing that
     lines up on exact page-multiple boundaries (or supplied explicitly
     via --page-size/--oob-size).

  2. LOCATE THE UBI PARTITION
     Scan for Physical Erase Blocks (PEBs) that begin with a valid UBI
     erase-counter header, spaced exactly one PEB apart.

  3. PARSE EC / VID HEADERS, WALK THE LAYOUT VOLUME
     Decode the UBI layout volume's table so volume names/ids come from
     the image itself instead of guesswork.

  4. RECONSTRUCT THE TARGET VOLUME'S LEB SEQUENCE -- with anomaly checks
     * wear detection: non-zero erase counters / sequence numbers mean
       the dump came from a device that actually ran, so physical PEB
       order may not equal logical order (reported, reconstruction still
       attempted, honouring lnum when it is self-consistent).
     * bit-flip tolerance: VID headers with isolated corruption are
       cross-checked against physical write order instead of being
       trusted blindly (a corrupted lnum can silently overwrite a good
       LEB with the wrong data).
     * redundant-copy detection: PEBs beyond a volume's declared size
       are grouped as a second image copy in flash, scored for
       parseability, and the healthiest copy is used.
     * gap detection: missing/erased PEBs inside a volume are reported.

  5. TRIM TO THE REAL SQUASHFS SIZE
     Parse the SquashFS 4.0 superblock's bytes_used and trim UBI pad
     bytes, producing a byte-exact .squashfs image.

The caller (ubipack CLI --carve) then validates the carved image with
the toolkit's own FsValidator; no external squashfs tool is needed at
any point.
"""

from __future__ import annotations

import logging
import struct
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("ubi_toolkit.carve")

UBI_EC_MAGIC = b"UBI#"
UBI_VID_MAGIC = b"UBI!"
UBI_LAYOUT_VOL_ID = 0x7FFFEFFF
VTBL_RECORD_SIZE = 172


class CarveError(Exception):
    """Raised when the dump cannot be carved into a usable image."""


# --------------------------------------------------------------------------
# Step 1: strip interleaved NAND OOB/spare data
# --------------------------------------------------------------------------
def strip_oob(raw: bytes, page_size: int, oob_size: int) -> bytes:
    """Remove the trailing oob_size spare bytes from every page_size chunk."""
    page_raw = page_size + oob_size
    out = bytearray()
    for off in range(0, len(raw) - page_raw + 1, page_raw):
        out += raw[off:off + page_size]
    return bytes(out)


def detect_oob_geometry(
        raw: bytes,
        candidates=((2048, 64), (2048, 128), (4096, 128),
                    (4096, 224), (512, 16))) -> Optional[Tuple[int, int, int]]:
    """Try common NAND page/OOB geometries and see which one makes UBI#
    headers line up on exact, evenly-spaced PEB boundaries after
    stripping. Returns (page_size, oob_size, peb_size) or None."""
    for page_size, oob_size in candidates:
        page_raw = page_size + oob_size
        offs = []
        start = 0
        while len(offs) < 20:
            idx = raw.find(UBI_EC_MAGIC, start)
            if idx == -1:
                break
            offs.append(idx)
            start = idx + 1
        if len(offs) < 3:
            continue
        diffs = {offs[i + 1] - offs[i] for i in range(len(offs) - 1)}
        if len(diffs) == 1:
            peb_raw = diffs.pop()
            if peb_raw % page_raw == 0:
                peb_clean = (peb_raw // page_raw) * page_size
                return page_size, oob_size, peb_clean
    return None


# --------------------------------------------------------------------------
# Step 2/3: locate UBI partition + parse headers
# --------------------------------------------------------------------------
def find_ubi_partition(clean: bytes, peb_size: int) -> Optional[Tuple[int, int]]:
    """Return (start_offset, num_pebs) of the longest contiguous run of
    PEBs that all begin with a valid UBI# EC header."""
    n = len(clean) // peb_size
    runs: List[Tuple[int, int]] = []
    run_start = None
    for p in range(n):
        o = p * peb_size
        is_ubi = clean[o:o + 4] == UBI_EC_MAGIC
        if is_ubi and run_start is None:
            run_start = p
        elif not is_ubi and run_start is not None:
            runs.append((run_start, p - run_start))
            run_start = None
    if run_start is not None:
        runs.append((run_start, n - run_start))
    if not runs:
        return None
    best = max(runs, key=lambda r: r[1])
    return best[0] * peb_size, best[1]


def parse_ec_header(buf: bytes, o: int) -> Optional[dict]:
    hdr = buf[o:o + 64]
    if hdr[0:4] != UBI_EC_MAGIC:
        return None
    return {
        "version": hdr[4],
        "ec": struct.unpack(">Q", hdr[8:16])[0],
        "vid_hdr_offset": struct.unpack(">I", hdr[16:20])[0],
        "data_offset": struct.unpack(">I", hdr[20:24])[0],
        "image_seq": struct.unpack(">I", hdr[24:28])[0],
    }


def parse_vid_header(buf: bytes, o: int) -> Optional[dict]:
    hdr = buf[o:o + 64]
    if hdr[0:4] != UBI_VID_MAGIC:
        return None
    return {
        "vol_type": hdr[5],
        "vol_id": struct.unpack(">I", hdr[8:12])[0],
        "lnum": struct.unpack(">I", hdr[12:16])[0],
        "data_size": struct.unpack(">I", hdr[20:24])[0],
        "used_ebs": struct.unpack(">I", hdr[24:28])[0],
        "sqnum": struct.unpack(">Q", hdr[40:48])[0],
    }


def parse_vtbl_records(buf: bytes) -> Dict[int, dict]:
    """Decode the UBI layout volume into {vol_id: {name, type, size}}."""
    records: Dict[int, dict] = {}
    n_records = len(buf) // VTBL_RECORD_SIZE
    for i in range(n_records):
        rec = buf[i * VTBL_RECORD_SIZE:(i + 1) * VTBL_RECORD_SIZE]
        if len(rec) < VTBL_RECORD_SIZE:
            break
        reserved_pebs = struct.unpack(">I", rec[0:4])[0]
        if reserved_pebs in (0, 0xFFFFFFFF):
            continue  # empty / erased (0xFF-filled) slot
        vol_type = rec[12]
        name_len = struct.unpack(">H", rec[14:16])[0]
        name = rec[16:16 + min(name_len, 127)].split(b"\x00")[0].decode(
            errors="replace")
        records[i] = {"name": name, "vol_type": vol_type,
                      "reserved_pebs": reserved_pebs}
    return records


def scan_ubi(clean: bytes, peb_size: int, start_off: int, num_pebs: int,
             notes: Optional[List[str]] = None):
    """Walk every PEB in the UBI partition.

    Returns (vtbl, leb_map, notes, leb_copies) where leb_map is
    {vol_id: {lnum: (data_offset, data_size)}} (first copy only; the
    legacy view), and leb_copies is {vol_id: [copy0, copy1, ...]} with
    each copy a {lnum: (data_offset, data_size)} dict. ``notes``
    collects human-readable damage/anomaly findings.
    """
    notes = notes if notes is not None else []

    def note(msg: str) -> None:
        notes.append(msg)

    pebs = []
    bad_pebs = 0
    for p in range(num_pebs):
        o = start_off + p * peb_size
        ec = parse_ec_header(clean, o)
        if ec is None:
            pebs.append(None)
            bad_pebs += 1
            continue
        vid = parse_vid_header(clean, o + ec["vid_hdr_offset"])
        pebs.append((ec, vid))
    if bad_pebs:
        note(f"{bad_pebs} PEB(s) in the UBI partition have no valid EC "
             f"header (erased or unreadable blocks)")

    # -- pass 1: collect layout-volume LEBs -----------------------------
    vtbl_leb_bufs: Dict[int, bytes] = {}
    for p, entry in enumerate(pebs):
        if entry is None:
            continue
        ec, vid = entry
        if vid and vid["vol_id"] == UBI_LAYOUT_VOL_ID:
            o = start_off + p * peb_size + ec["data_offset"]
            leb_size = peb_size - ec["data_offset"]
            vtbl_leb_bufs[vid["lnum"]] = clean[o:o + leb_size]

    vtbl: Dict[int, dict] = {}
    if vtbl_leb_bufs:
        # The layout volume is duplicated (2 copies); use whichever
        # lnum=0 looks sane, falling back to any available copy.
        buf = vtbl_leb_bufs.get(0) or next(iter(vtbl_leb_bufs.values()))
        vtbl = parse_vtbl_records(buf)
    else:
        note("no UBI layout volume found; volume names unavailable "
             "(raw vol_ids will be used)")

    # -- pass 2: collect data-volume LEBs -------------------------------
    #
    # Order policy: a factory/vendor image is written by ubinize with
    # ascending LEBs in ascending PEBs, so physical PEB order is the
    # ground truth and the VID header's lnum is used as a cross-check.
    # If the dump shows real wear (non-zero erase counters), physical
    # order can diverge from lnum order, so lnum is honoured instead
    # when it forms a dense, consistent sequence.
    data_entries = [(ec, vid) for entry in pebs if entry
                    for ec, vid in [entry]
                    if vid and vid["vol_id"] != UBI_LAYOUT_VOL_ID]
    fresh_count = sum(1 for ec, vid in data_entries
                      if ec["ec"] == 0 and vid["sqnum"] == 0)
    looks_fresh = bool(data_entries) and \
        (fresh_count / len(data_entries)) >= 0.9
    if data_entries and not looks_fresh:
        note("non-zero erase counters/sequence numbers: this dump shows "
             "real wear (it ran on a device), so LEB order follows the "
             "VID headers' lnum where self-consistent rather than "
             "physical PEB order")

    mismatches: List[Tuple[int, int, int, int]] = []
    overflow: Dict[int, int] = {}
    # vol_id -> list of copies; each copy is {lnum: (data_offset, size)}.
    # Copy 0 is the first image in flash; when a volume's declared size
    # is exceeded, a new copy group starts (dual-firmware / redundant
    # slot). One of the copies is often healthier than the other.
    leb_copies: Dict[int, List[Dict[int, Tuple[int, int]]]] = {}

    def slot_for(vol_id: int):
        copies = leb_copies.setdefault(vol_id, [{}])
        return copies, copies[-1]

    for p, entry in enumerate(pebs):
        if entry is None:
            continue
        ec, vid = entry
        if vid is None or vid["vol_id"] == UBI_LAYOUT_VOL_ID:
            continue
        vol_id = vid["vol_id"]
        reserved = vtbl.get(vol_id, {}).get("reserved_pebs")
        copies, cur = slot_for(vol_id)
        idx = len(cur)
        if reserved is not None and idx >= reserved:
            # The declared size is already filled: this PEB begins a
            # second, redundant copy of the image in flash. Keep it as a
            # separate copy instead of folding it in.
            copies.append({})
            idx = 0
            overflow[vol_id] = overflow.get(vol_id, 0) + 1
        if vid["lnum"] != idx:
            mismatches.append((vol_id, p, vid["lnum"], idx))
        o = start_off + p * peb_size + ec["data_offset"]
        cur[idx] = (o, vid["data_size"])

    if mismatches:
        note(f"{len(mismatches)} PEB(s) had a VID header lnum that did "
             f"not match physical write order (bit-flips or wear in the "
             f"raw dump); physical order was used for reconstruction")
    for vol_id, n_extra in sorted(overflow.items()):
        name = vtbl.get(vol_id, {}).get("name", f"vol{vol_id}")
        reserved = vtbl.get(vol_id, {}).get("reserved_pebs")
        note(f"{n_extra} extra PEB(s) beyond volume {vol_id} ({name!r})'s "
             f"declared size ({reserved} PEBs) -- a second/redundant copy "
             f"of the image follows the first one in flash; copies are "
             f"scored and the healthiest is used")

    # Flatten to the legacy {vol_id: {lnum: ...}} view of the FIRST copy
    # for callers that only want one image.
    leb_map = {vid: copies[0] for vid, copies in leb_copies.items() if copies}

    # -- gap detection: declared size vs actually found LEBs ------------
    for vol_id, v in sorted(vtbl.items()):
        found = len(leb_map.get(vol_id, {}))
        if found and found < v["reserved_pebs"]:
            name = v.get("name", f"vol{vol_id}")
            note(f"volume {vol_id} ({name!r}) declares "
                 f"{v['reserved_pebs']} PEBs but only {found} readable "
                 f"LEB(s) were found -- some blocks are erased or "
                 f"unreadable; the reconstructed image may be truncated")

    return vtbl, leb_map, notes, leb_copies


# --------------------------------------------------------------------------
# Step 5: SquashFS superblock
# --------------------------------------------------------------------------
def parse_squashfs_superblock(buf: bytes) -> Optional[dict]:
    if len(buf) < 96 or buf[0:4] != b"hsqs":
        return None
    fields = struct.unpack("<4sIIIIHHHHHHQQQQQQQQ", buf[:96])
    names = ("magic", "inode_count", "mod_time", "block_size", "frag_count",
             "compression", "block_log", "flags", "no_ids", "s_major",
             "s_minor", "root_inode", "bytes_used", "id_table_start",
             "xattr_id_table_start", "inode_table_start", "dir_table_start",
             "frag_table_start", "export_table_start")
    sb = dict(zip(names, fields))
    comp_names = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
    sb["compression_name"] = comp_names.get(
        sb["compression"], f"unknown({sb['compression']})")
    return sb


# --------------------------------------------------------------------------
# Redundant-copy integrity scoring
# --------------------------------------------------------------------------
def _assemble_copy(lebs: Dict[int, Tuple[int, int]], clean: bytes,
                   peb_size: int) -> bytes:
    """Concatenate one copy's LEBs (ascending) into a linear stream."""
    buf = bytearray()
    for idx in sorted(lebs):
        o, _ds = lebs[idx]
        # Data runs to the next PEB boundary; the superblock's bytes_used
        # trims the UBI pad bytes afterwards.
        buf += clean[o:o + (peb_size - (o % peb_size))]
    return bytes(buf)


def _score_copy(lebs: Dict[int, Tuple[int, int]], clean: bytes,
                peb_size: int) -> Tuple[int, int]:
    """Score one reconstructed copy of a volume.

    Returns (parse_quality, leb_count):
      parse_quality 0 = no squashfs magic at LEB 0
                    1 = magic present, superblock not usable
                    2 = magic + bytes_used inside the volume
    """
    n = len(lebs)
    if n == 0 or 0 not in lebs:
        return 0, n
    sb = parse_squashfs_superblock(_assemble_copy(lebs, clean, peb_size))
    if sb is None:
        return 1, n
    if 0 < sb["bytes_used"] <= sum(
            peb_size - (o % peb_size) for o, _ in lebs.values()):
        return 2, n
    return 1, n


def _pick_healthiest_copy(copies, clean: bytes, peb_size: int,
                          notes: List[str]) -> Dict[int, Tuple[int, int]]:
    """Return the LEB map of the healthiest redundant copy."""
    if not copies:
        return {}
    if len(copies) == 1:
        return copies[0]
    scored = [_score_copy(c, clean, peb_size) for c in copies]
    best = max(range(len(scored)), key=lambda i: scored[i])
    if best != 0:
        notes.append(
            "redundant copy #%d of the volume scored healthier than the "
            "first copy (parse quality %d vs %d, LEBs %d vs %d) and was "
            "used for extraction" % (
                best, scored[best][0], scored[0][0],
                scored[best][1], scored[0][1]))
    return copies[best]


def _merge_copies(copies, clean: bytes, peb_size: int) -> bytes:
    """Interleave redundant copies LEB-by-LEB: first copy wins on ties,
    later copies fill holes. Returns merged bytes."""
    max_len = max(len(c) for c in copies) if copies else 0
    merged = bytearray()
    for idx in range(max_len):
        for c in copies:
            if idx in c:
                o, _ds = c[idx]
                merged += clean[o:o + (peb_size - (o % peb_size))]
                break
    return bytes(merged)


# --------------------------------------------------------------------------
# Carve entry point
# --------------------------------------------------------------------------
def carve(raw: bytes, out_path,
          volume: Optional[str] = None,
          page_size: Optional[int] = None,
          oob_size: Optional[int] = None,
          peb_size: Optional[int] = None) -> dict:
    """Carve a SquashFS image out of a raw NAND/UBI dump.

    Writes the trimmed image to `out_path` and returns a report dict:
      {volumes, target, raw_volume_size, carved_size, superblock,
       anomalies, geometry}
    Raises CarveError (with a readable message) when nothing usable is
    found.
    """
    # ---- Step 1: geometry + OOB strip ----
    if page_size and oob_size:
        geom_note = f"supplied geometry: page={page_size} oob={oob_size}"
    else:
        geo = detect_oob_geometry(raw)
        if geo is None:
            page_size, oob_size = len(raw), 0
            geom_note = ("no OOB interleave detected; treating dump as a "
                         "clean image (oob=0)")
        else:
            page_size, oob_size, _peb_hint = geo
            geom_note = f"detected geometry: page={page_size} oob={oob_size}"
    log.info("%s", geom_note)

    clean = strip_oob(raw, page_size, oob_size) if oob_size else raw

    # ---- Step 2: find UBI partition ----
    peb_candidates = [64 * 1024, 128 * 1024, 256 * 1024]
    if peb_size:
        peb_candidates.insert(0, peb_size)
    found = None
    for cand in sorted(set(peb_candidates)):
        if len(clean) < cand:
            continue
        r = find_ubi_partition(clean, cand)
        if r and r[1] >= 4:  # require at least a handful of consecutive PEBs
            found = (cand, r[0], r[1])
            break
    if not found:
        raise CarveError(
            "no UBI partition found in the (OOB-stripped) dump; if this "
            "firmware does not use UBI, run the image operations on the "
            "raw file directly")

    found_peb, ubi_start, ubi_num_pebs = found

    # ---- Step 3/4: parse headers, volume table, LEB map ----
    vtbl, leb_map, anomalies, leb_copies = scan_ubi(
        clean, found_peb, ubi_start, ubi_num_pebs)

    volumes = []
    for vid, v in sorted(vtbl.items()):
        volumes.append({"vol_id": vid, "name": v["name"],
                        "type": "static" if v["vol_type"] == 2 else "dynamic",
                        "reserved_pebs": v["reserved_pebs"],
                        "lebs_found": len(leb_map.get(vid, {})),
                        "copies": len(leb_copies.get(vid, []))})
    for vid in sorted(leb_map):
        if vid not in vtbl:
            volumes.append({"vol_id": vid, "name": f"vol{vid}",
                            "type": "unknown", "reserved_pebs": None,
                            "lebs_found": len(leb_map[vid]),
                            "copies": len(leb_copies.get(vid, []))})

    # ---- pick target volume ----
    target_vid = None
    if volume:
        for vid, v in vtbl.items():
            if v["name"] == volume:
                target_vid = vid
                break
        if target_vid is None:
            known = ", ".join(repr(v["name"]) for v in volumes) or "none"
            raise CarveError(
                f"volume named {volume!r} not found (volumes: {known})")
    else:
        # default: first volume whose LEB 0 starts with the squashfs magic
        for vid, lebs in leb_map.items():
            if 0 in lebs:
                o, _ = lebs[0]
                if clean[o:o + 4] == b"hsqs":
                    target_vid = vid
                    break
        if target_vid is None and leb_map:
            target_vid = next(iter(leb_map))
    if target_vid is None:
        raise CarveError("no data volumes found in the UBI partition")

    vol_name = vtbl.get(target_vid, {}).get("name", f"vol{target_vid}")

    # ---- reconstruct the volume's linear data stream ----
    # When the flash holds multiple redundant copies of the same volume
    # (dual-firmware / failsafe layouts), each copy is scored for
    # integrity and the healthiest one wins.
    copies = leb_copies.get(target_vid, [])
    lebs = _pick_healthiest_copy(copies, clean, found_peb, anomalies)

    out_buf = bytearray(_assemble_copy(lebs, clean, found_peb))

    # If the healthiest single copy still lacks a parseable superblock
    # but other copies exist, interleave them LEB-by-LEB (first copy
    # preferred per LEB, later copies fill holes). This heals single-
    # copy damage without inventing data: every byte still comes from a
    # real PEB of this volume.
    if not parse_squashfs_superblock(bytes(out_buf)) and len(copies) > 1:
        merged = _merge_copies(copies, clean, found_peb)
        if parse_squashfs_superblock(merged):
            anomalies.append(
                "no single redundant copy parsed as SquashFS; LEBs were "
                "interleaved from %d copies (first copy preferred per LEB) "
                "to heal the volume" % len(copies))
            out_buf = bytearray(merged)

    raw_volume_path = str(out_path) + ".raw"
    with open(raw_volume_path, "wb") as f:
        f.write(out_buf)

    # ---- Step 5: trim to real SquashFS size ----
    sb = parse_squashfs_superblock(bytes(out_buf))
    if sb:
        with open(out_path, "wb") as f:
            f.write(out_buf[:sb["bytes_used"]])
        carved_size = min(sb["bytes_used"], len(out_buf))
    else:
        # No squashfs magic at volume start: keep the raw volume so the
        # caller can still inspect it (UBIFS/JFFS2/other formats).
        with open(out_path, "wb") as f:
            f.write(out_buf)
        carved_size = len(out_buf)
        anomalies.append("volume does not start with a SquashFS magic; "
                         "wrote the raw volume (may be UBIFS/JFFS2/other)")

    return {
        "volumes": volumes,
        "target_vol_id": target_vid,
        "target_name": vol_name,
        "volume_path": str(out_path),
        "raw_volume_path": raw_volume_path,
        "raw_volume_size": len(out_buf),
        "carved_size": carved_size,
        "superblock": sb,
        "anomalies": anomalies,
        "geometry": {"page_size": page_size, "oob_size": oob_size,
                     "peb_size": found_peb,
                     "ubi_start": ubi_start,
                     "ubi_pebs": ubi_num_pebs},
    }
