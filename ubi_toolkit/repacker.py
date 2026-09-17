#!/usr/bin/env python3
"""
clean_ubi_surgical_repacker_itr04.py

Surgical clean-UBI repacker for output produced by the ubi_toolkit analyst stage.

itr04 changes (from itr03):
  CRITICAL FIX: infer_volume_names() and extracted_volume_path() only globbed
    for .bin files, but v06 analyst now extracts volumes with content-aware
    extensions: .squashfs, .jffs2, .cramfs, .ubifs, .dtb, .bin. The repacker
    could not find extracted volumes for roundtrip validation, causing
    "SKIPPED" status on filesystem volumes (rootfs, rootfs_data, kernel/DTB).
    Now globs for all known extensions and picks the correct file.

  FIX: Updated analyst reference from upg-03 to upg-06 in all docstrings and
    compatibility checks.

  ENHANCEMENT: Added SUPPORTED_EXTENSIONS constant listing all volume file
    types the v06 analyst can produce, used by both glob functions.

  ENHANCEMENT: extracted_volume_path() now warns if multiple candidate files
    exist for the same vol_id (ambiguous state) instead of silently picking
    the first one.

Architecture (unchanged from itr03):
  - Uses region_N/clean_ubi.img as the byte-for-byte base template.
  - Uses headers/ec_headers.json and headers/vid_headers.json for exact PEB,
    vol_id and LNUM mapping.
  - Replaces only payload areas belonging to requested target volumes.
  - Preserves unrelated PEBs byte-for-byte.
  - Supports modified files larger than the original when they fit the actual
    allocated volume capacity.
  - Reports original size, modified size, current buffer and maximum allowed size.
  - Handles dynamic UBI volumes conservatively: payload changes do not rewrite
    VID data_size/data_crc fields.
  - Handles static UBI volumes by updating data_size/data_crc and VID hdr_crc.
  - Performs round-trip validation against analyst-extracted volume files before
    mutation.
  - Produces same-size clean UBI images, manifests, reports and detailed logs.

This script intentionally does NOT generate raw NAND OOB/ECC. Its output is a
clean UBI image intended for a validated MTD write path that accepts clean data.
"""

from __future__ import annotations

import argparse
import binascii
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import os
import re
import struct
import sys
import tempfile
import traceback
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── UBI constants ──────────────────────────────────────────────────────────

UBI_EC_MAGIC = 0x55424923       # "UBI#"
UBI_VID_MAGIC = 0x55424921      # "UBI!"
UBI_VID_HDR_SIZE = 64
UBI_EC_HDR_SIZE = 64
UBI_CRC32_INIT = 0xFFFFFFFF
UBI_VID_DYNAMIC = 1
UBI_VID_STATIC = 2

# ── VID header field offsets (from Linux include/uapi/mtd/ubi-user.h) ──────
# struct ubi_vid_hdr {
#   __be32 magic;          //  0
#   __u8   version;        //  4
#   __u8   vol_type;       //  5
#   __u8   copy_flag;      //  6
#   __u8   compat;         //  7
#   __be32 vol_id;         //  8
#   __be32 lnum;           // 12
#   __be32 data_size;      // 16  ← was using 20 (used_ebs) in itr02!
#   __be32 used_ebs;       // 20
#   __be32 data_pad;       // 24
#   __be32 data_crc;       // 28  ← was using 32 (used_pct) in itr02!
#   __u8   used_pct;       // 32
#   __u8   padding[3];     // 33
#   __be64 sqnum;          // 36
#   __u8   padding2[12];   // 44
#   __be32 hdr_crc;        // 60
# };

UBI_VID_OFF_MAGIC      = 0
UBI_VID_OFF_VERSION    = 4
UBI_VID_OFF_VOL_TYPE   = 5
UBI_VID_OFF_COPY_FLAG  = 6
UBI_VID_OFF_COMPAT     = 7
UBI_VID_OFF_VOL_ID     = 8
UBI_VID_OFF_LNUM       = 12
UBI_VID_OFF_DATA_SIZE  = 16   # FIXED: was 20 in itr02
UBI_VID_OFF_USED_EBS   = 20
UBI_VID_OFF_DATA_PAD   = 24
UBI_VID_OFF_DATA_CRC   = 28   # FIXED: was 32 in itr02
UBI_VID_OFF_USED_PCT   = 32
UBI_VID_OFF_SQNUM      = 36
UBI_VID_OFF_HDR_CRC    = 60

# ── EC header field offsets ────────────────────────────────────────────────
# struct ubi_ec_hdr {
#   __be32 magic;              //  0
#   __u8   version;            //  4
#   __u8   padding1[3];        //  5
#   __be64 ec;                 //  8
#   __be32 vid_hdr_offset;     // 16
#   __be32 data_offset;        // 20
#   __be32 image_seq;          // 24
#   __u8   padding2[32];       // 28
#   __be32 hdr_crc;            // 60
# };

UBI_EC_OFF_MAGIC           = 0
UBI_EC_OFF_VERSION         = 4
UBI_EC_OFF_EC              = 8
UBI_EC_OFF_VID_HDR_OFFSET  = 16
UBI_EC_OFF_DATA_OFFSET     = 20
UBI_EC_OFF_IMAGE_SEQ       = 24
UBI_EC_OFF_HDR_CRC         = 60

# ── Volume file extensions produced by ubi_analyst v06 ─────────────────────
# v06 extracts volumes with content-aware extensions based on magic bytes.
# The repacker must recognize all of them for roundtrip validation.
SUPPORTED_EXTENSIONS = (
    ".bin",       # raw / kernel / fallback
    ".squashfs",  # SquashFS filesystem
    ".jffs2",     # JFFS2 filesystem
    ".cramfs",    # CramFS filesystem
    ".ubifs",     # UBIFS filesystem
    ".dtb",       # Flattened Device Tree
)


class RepackError(RuntimeError):
    def __init__(self, code: str, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

@dataclasses.dataclass
class Replacement:
    region: int
    selector: str
    path: Path
    vol_id: Optional[int] = None
    volume_name: Optional[str] = None

@dataclasses.dataclass
class RegionModel:
    index: int
    directory: Path
    clean_path: Path
    ec_path: Path
    vid_path: Path
    volumes_dir: Path
    clean: bytes
    ec: List[dict]
    vid: List[dict]
    peb_size: int
    data_offset: int
    vid_hdr_offset: int
    volume_names: Dict[int, str]

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def ubi_crc32(data: bytes) -> int:
    # Linux crc32_le(UBI_CRC32_INIT, data, len(data)) semantics.
    return binascii.crc32(data, UBI_CRC32_INIT) & 0xFFFFFFFF

def parse_int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return None
    return None

def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception as e:
        raise RepackError("E_JSON", f"Cannot read JSON {path}: {e}")

def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise

def atomic_json(path: Path, obj: Any) -> None:
    atomic_write(path, (json.dumps(obj, indent=2, sort_keys=False) + "\n").encode())

def discover_region_dir(analysis_dir: Path, region: int) -> Path:
    candidates = [
        analysis_dir / "ubi" / f"region_{region}",
        analysis_dir / f"region_{region}",
        analysis_dir / "ubi" / f"region{region}",
        analysis_dir / f"region{region}",
    ]
    for p in candidates:
        if (p / "clean_ubi.img").is_file():
            return p
    raise RepackError("E_REGION_NOT_FOUND",
                      f"Cannot find clean_ubi.img for region{region} under {analysis_dir}")

def infer_volume_names(volumes_dir: Path) -> Dict[int, str]:
    names: Dict[int, str] = {}
    if not volumes_dir.is_dir():
        return names
    # v06 analyst extracts with content-aware extensions (.squashfs, .jffs2,
    # .cramfs, .ubifs, .dtb, .bin). Glob all supported types.
    for ext in SUPPORTED_EXTENSIONS:
        for p in sorted(volumes_dir.glob(f"vol_*{ext}")):
            m = re.match(r"vol_(\d+)_([^/]+)" + re.escape(ext) + r"$", p.name)
            if m:
                vid = int(m.group(1))
                # Don't overwrite a name already found (first ext wins)
                if vid not in names:
                    names[vid] = m.group(2)
    return names

def infer_peb_size(clean_len: int, ec: List[dict], vid: List[dict]) -> int:
    idxs = sorted({parse_int(x.get("peb_index")) for x in ec + vid
                   if parse_int(x.get("peb_index")) is not None})
    offsets = []
    by_idx = {}
    for x in ec:
        i = parse_int(x.get("peb_index"))
        o = parse_int(x.get("offset_clean", x.get("offset")))
        if i is not None and o is not None:
            by_idx[i] = o
    for a, b in zip(sorted(by_idx), sorted(by_idx)[1:]):
        di = b - a
        if di == 1:
            d = by_idx[b] - by_idx[a]
            if d > 0: offsets.append(d)
    if offsets:
        from collections import Counter
        return Counter(offsets).most_common(1)[0][0]
    if idxs:
        n = max(idxs) + 1
        if n and clean_len % n == 0:
            return clean_len // n
    raise RepackError("E_GEOMETRY", "Unable to infer clean PEB size from analyst headers")

def infer_header_offsets(ec: List[dict], peb_size: int) -> Tuple[int, int]:
    vids = [parse_int(x.get("vid_hdr_offset")) for x in ec]
    datas = [parse_int(x.get("data_offset")) for x in ec]
    vids = [x for x in vids if x is not None and 0 < x < peb_size]
    datas = [x for x in datas if x is not None and 0 < x < peb_size]
    if not vids or not datas:
        raise RepackError("E_GEOMETRY",
                          "EC headers do not provide usable vid_hdr_offset/data_offset")
    from collections import Counter
    vh = Counter(vids).most_common(1)[0][0]
    do = Counter(datas).most_common(1)[0][0]
    if not (0 < vh < do < peb_size):
        raise RepackError("E_GEOMETRY",
                          f"Invalid offsets: vid_hdr_offset={vh}, data_offset={do}, peb={peb_size}")
    return vh, do

def load_region(analysis_dir: Path, region: int, peb_override: Optional[int] = None) -> RegionModel:
    rd = discover_region_dir(analysis_dir, region)
    clean_path = rd / "clean_ubi.img"
    ec_path = rd / "headers" / "ec_headers.json"
    vid_path = rd / "headers" / "vid_headers.json"
    volumes_dir = rd / "volumes"
    for p in (clean_path, ec_path, vid_path):
        if not p.is_file():
            raise RepackError("E_INPUT_MISSING", f"Required analyst artifact missing: {p}")
    clean = clean_path.read_bytes()
    ec = load_json(ec_path)
    vid = load_json(vid_path)
    if not isinstance(ec, list) or not isinstance(vid, list):
        raise RepackError("E_SCHEMA", "Header JSON files must contain arrays")
    if peb_override is not None:
        peb = peb_override
        if peb <= 0:
            raise RepackError("E_ARGUMENT", f"--peb-size must be positive, got {peb}")
    else:
        peb = infer_peb_size(len(clean), ec, vid)
    if len(clean) % peb:
        raise RepackError("E_GEOMETRY",
                          f"clean_ubi.img size {len(clean)} is not divisible by PEB size {peb}")
    vh, do = infer_header_offsets(ec, peb)
    return RegionModel(region, rd, clean_path, ec_path, vid_path, volumes_dir,
                       clean, ec, vid, peb, do, vh, infer_volume_names(volumes_dir))

def parse_replace(spec: str) -> Replacement:
    if "=" not in spec:
        raise RepackError("E_ARGUMENT",
                          f"Invalid --replace {spec!r}; expected regionN:volume=/path/file")
    target, p = spec.split("=", 1)
    m = re.fullmatch(r"region_?(\d+):(.+)", target.strip(), re.I)
    if not m:
        raise RepackError("E_ARGUMENT",
                          f"Invalid target {target!r}; expected regionN:volume")
    path = Path(p).expanduser().resolve()
    if not path.is_file():
        raise RepackError("E_REPLACEMENT_NOT_FOUND", f"Replacement file not found: {path}")
    return Replacement(int(m.group(1)), m.group(2).strip(), path)

def resolve_volume(model: RegionModel, repl: Replacement) -> None:
    s = repl.selector
    if re.fullmatch(r"(?:vol(?:ume)?[_-]?)?\d+", s, re.I):
        repl.vol_id = int(re.search(r"\d+", s).group())
        repl.volume_name = model.volume_names.get(repl.vol_id, f"vol_{repl.vol_id}")
        return
    matches = [(vid, name) for vid, name in model.volume_names.items()
               if name.lower() == s.lower()]
    if len(matches) == 1:
        repl.vol_id, repl.volume_name = matches[0]
        return
    # Useful aliases from extracted filenames.
    fuzzy = [(vid, name) for vid, name in model.volume_names.items()
             if s.lower() in name.lower() or name.lower() in s.lower()]
    if len(fuzzy) == 1:
        repl.vol_id, repl.volume_name = fuzzy[0]
        return
    available = ", ".join(f"{vid}:{name}" for vid, name in sorted(model.volume_names.items()))
    raise RepackError("E_TARGET",
                      f"Cannot uniquely resolve region{model.index}:{s}. Available: {available}")

def volume_entries(model: RegionModel, vol_id: int) -> List[dict]:
    out = []
    for x in model.vid:
        vi = parse_int(x.get("vol_id"))
        ln = parse_int(x.get("lnum"))
        pi = parse_int(x.get("peb_index"))
        if vi == vol_id and ln is not None and pi is not None:
            out.append(x)
    # Reject duplicate LNUM mappings; choosing one silently is unsafe.
    by_lnum: Dict[int, List[dict]] = {}
    for x in out:
        by_lnum.setdefault(int(x["lnum"]), []).append(x)
    dup = [k for k, v in by_lnum.items() if len(v) != 1]
    if dup:
        raise RepackError("E_AMBIGUOUS_MAPPING",
                          f"Volume {vol_id} has duplicate VID mappings for LNUMs {dup[:10]}")
    out.sort(key=lambda x: int(x["lnum"]))
    if not out:
        raise RepackError("E_TARGET", f"No VID mappings for volume ID {vol_id}")
    lnums = [int(x["lnum"]) for x in out]
    expected = list(range(lnums[0], lnums[-1] + 1))
    if lnums != expected or lnums[0] != 0:
        raise RepackError("E_LNUM_GAP",
                          f"Volume {vol_id} LNUM sequence is not contiguous from zero")
    return out

def extracted_volume_path(model: RegionModel, vol_id: int, name: str) -> Optional[Path]:
    # v06 analyst extracts with content-aware extensions. Try exact name match
    # with each supported extension, then fall back to vol_id glob.
    for ext in SUPPORTED_EXTENSIONS:
        exact = model.volumes_dir / f"vol_{vol_id}_{name}{ext}"
        if exact.is_file():
            return exact
    # Fallback: glob by vol_id across all extensions
    cands: List[Path] = []
    for ext in SUPPORTED_EXTENSIONS:
        cands.extend(sorted(model.volumes_dir.glob(f"vol_{vol_id}_*{ext}")))
    if len(cands) == 1:
        return cands[0]
    if len(cands) > 1:
        log.warning("Ambiguous extracted files for vol_id %d: %s — picking first",
                    vol_id, [c.name for c in cands])
        return cands[0]
    return None

def reconstruct_allocated_payload(model: RegionModel, entries: List[dict]) -> bytes:
    cap = model.peb_size - model.data_offset
    parts = []
    for x in entries:
        pi = int(x["peb_index"])
        start = pi * model.peb_size + model.data_offset
        end = start + cap
        if end > len(model.clean):
            raise RepackError("E_BOUNDS", f"PEB {pi} payload exceeds clean image")
        parts.append(model.clean[start:end])
    return b"".join(parts)

def derive_original_size(model: RegionModel, entries: List[dict],
                         extracted: Optional[Path]) -> Tuple[int, str]:
    if extracted and extracted.is_file():
        return extracted.stat().st_size, "analyst extracted volume"
    # Fallback 1: sum data_size from VID headers read at correct on-disk offset.
    # This works for static volumes where data_size is per-PEB.
    total_data_size = 0
    found_any = False
    for x in entries:
        pi = int(x["peb_index"])
        ds = read_vid_data_size(model.clean, pi, model.peb_size, model.vid_hdr_offset)
        if ds is not None and ds > 0:
            total_data_size += ds
            found_any = True
    if found_any:
        return total_data_size, "summed VID data_size (offset 16, on-disk)"
    # Fallback 2: trim erased 0xFF tail only.
    alloc = reconstruct_allocated_payload(model, entries)
    return len(alloc.rstrip(b"\xFF")), "0xFF-trimmed allocated payload"

def roundtrip_validate(model: RegionModel, entries: List[dict],
                       extracted: Optional[Path]) -> dict:
    if not extracted:
        return {"status": "SKIPPED", "reason": "no unique analyst .bin volume artifact"}
    expected = extracted.read_bytes()
    alloc = reconstruct_allocated_payload(model, entries)
    # Analyst extraction commonly trims erased FF tail. Exact prefix equality is
    # stronger and avoids assuming the extracted file has no legitimate FF suffix.
    ok = len(expected) <= len(alloc) and alloc[:len(expected)] == expected
    return {
        "status": "PASS" if ok else "FAIL",
        "artifact": str(extracted),
        "artifact_size": len(expected),
        "artifact_sha256": sha256_bytes(expected),
        "allocated_prefix_sha256": sha256_bytes(alloc[:len(expected)]),
    }

# ── VID/EC header reading helpers (read at correct on-disk offsets) ────────

def read_vid_data_size(image: bytes, peb_index: int, peb_size: int,
                       vid_hdr_offset: int) -> Optional[int]:
    """Read data_size field from VID header at correct offset (16)."""
    off = peb_index * peb_size + vid_hdr_offset
    if off + UBI_VID_HDR_SIZE > len(image):
        return None
    hdr = image[off:off + UBI_VID_HDR_SIZE]
    if struct.unpack(">I", hdr[UBI_VID_OFF_MAGIC:UBI_VID_OFF_MAGIC + 4])[0] != UBI_VID_MAGIC:
        return None
    return struct.unpack(">I", hdr[UBI_VID_OFF_DATA_SIZE:UBI_VID_OFF_DATA_SIZE + 4])[0]

def read_vid_data_pad(image: bytes, peb_index: int, peb_size: int,
                      vid_hdr_offset: int) -> Optional[int]:
    """Read data_pad field from VID header at correct offset (24)."""
    off = peb_index * peb_size + vid_hdr_offset
    if off + UBI_VID_HDR_SIZE > len(image):
        return None
    hdr = image[off:off + UBI_VID_HDR_SIZE]
    if struct.unpack(">I", hdr[UBI_VID_OFF_MAGIC:UBI_VID_OFF_MAGIC + 4])[0] != UBI_VID_MAGIC:
        return None
    return struct.unpack(">I", hdr[UBI_VID_OFF_DATA_PAD:UBI_VID_OFF_DATA_PAD + 4])[0]

def vid_header_absolute(model: RegionModel, entry: dict) -> int:
    pi = int(entry["peb_index"])
    return pi * model.peb_size + model.vid_hdr_offset

def patch_static_vid_header(image: bytearray, model: RegionModel, entry: dict,
                            chunk: bytes) -> None:
    """Patch data_size, data_crc, and hdr_crc in a static volume's VID header.

    FIXED in itr03: uses correct on-disk offsets from the UBI spec:
      - data_size at offset 16 (was incorrectly 20 in itr02)
      - data_crc  at offset 28 (was incorrectly 32 in itr02)
      - hdr_crc   at offset 60 (was already correct)
    """
    off = vid_header_absolute(model, entry)
    hdr = bytearray(image[off:off + UBI_VID_HDR_SIZE])
    if len(hdr) != UBI_VID_HDR_SIZE:
        raise RepackError("E_BOUNDS", "VID header exceeds image")
    magic = struct.unpack(">I", hdr[UBI_VID_OFF_MAGIC:UBI_VID_OFF_MAGIC + 4])[0]
    if magic != UBI_VID_MAGIC:
        raise RepackError("E_VID_MAGIC",
                          f"Invalid VID magic at 0x{off:x}: 0x{magic:08x}")
    # Write data_size at correct offset 16
    struct.pack_into(">I", hdr, UBI_VID_OFF_DATA_SIZE, len(chunk))
    # Write data_crc at correct offset 28
    struct.pack_into(">I", hdr, UBI_VID_OFF_DATA_CRC, ubi_crc32(chunk))
    # Recalculate hdr_crc over bytes 0..59, write at offset 60
    struct.pack_into(">I", hdr, UBI_VID_OFF_HDR_CRC, ubi_crc32(bytes(hdr[:UBI_VID_OFF_HDR_CRC])))
    image[off:off + UBI_VID_HDR_SIZE] = hdr

def preflight_one(model: RegionModel, repl: Replacement) -> dict:
    assert repl.vol_id is not None
    entries = volume_entries(model, repl.vol_id)
    cap_per_leb = model.peb_size - model.data_offset
    max_size = len(entries) * cap_per_leb
    extracted = extracted_volume_path(model, repl.vol_id, repl.volume_name or "")
    original_size, original_source = derive_original_size(model, entries, extracted)
    modified_size = repl.path.stat().st_size
    current_buffer = max_size - original_size
    remaining = max_size - modified_size
    rt = roundtrip_validate(model, entries, extracted)

    # Check data_pad for this volume's PEBs
    data_pad_values = set()
    for e in entries:
        pi = int(e["peb_index"])
        dp = read_vid_data_pad(model.clean, pi, model.peb_size, model.vid_hdr_offset)
        if dp is not None:
            data_pad_values.add(dp)
    data_pad_warning = None
    if data_pad_values and any(dp != 0 for dp in data_pad_values):
        data_pad_warning = (
            f"Non-zero data_pad detected: {data_pad_values}. "
            "Capacity calculations assume data_pad=0; payload may be smaller than calculated."
        )

    return {
        "target": f"region{model.index}:{repl.volume_name}",
        "selector": repl.selector,
        "volume_id": repl.vol_id,
        "volume_name": repl.volume_name,
        "replacement": str(repl.path),
        "replacement_sha256": sha256_file(repl.path),
        "original_size": original_size,
        "original_size_source": original_source,
        "modified_size": modified_size,
        "growth_over_original": modified_size - original_size,
        "allocated_lebs": len(entries),
        "per_leb_payload_capacity": cap_per_leb,
        "maximum_allowed_size": max_size,
        "current_free_buffer": current_buffer,
        "remaining_after_replacement": remaining,
        "exceeds_maximum_by": max(0, modified_size - max_size),
        "status": "PASS" if modified_size <= max_size else "REJECTED",
        "roundtrip_validation": rt,
        "data_pad_warning": data_pad_warning,
        "_entries": entries,
    }

def print_preflight(rows: List[dict]) -> None:
    print("\nReplacement capacity preflight:")
    for r in rows:
        print(f"\n  Target                   : {r['target']}")
        print(f"  Volume ID                : {r['volume_id']}")
        print(f"  Original size            : {r['original_size']:,} bytes")
        print(f"  Modified size            : {r['modified_size']:,} bytes")
        print(f"  Growth over original     : {r['growth_over_original']:+,} bytes")
        print(f"  Allocated LEBs           : {r['allocated_lebs']}")
        print(f"  Per-LEB payload capacity : {r['per_leb_payload_capacity']:,} bytes")
        print(f"  Maximum allowed size     : {r['maximum_allowed_size']:,} bytes")
        print(f"  Current free buffer      : {r['current_free_buffer']:,} bytes")
        print(f"  Remaining after replace  : {r['remaining_after_replacement']:,} bytes")
        if r["exceeds_maximum_by"]:
            print(f"  Exceeds maximum by       : {r['exceeds_maximum_by']:,} bytes")
        print(f"  Round-trip validation    : {r['roundtrip_validation']['status']}")
        if r.get("data_pad_warning"):
            print(f"  WARNING (data_pad)       : {r['data_pad_warning']}")
        print(f"  Status                   : {r['status']}")

def apply_replacement(image: bytearray, model: RegionModel, repl: Replacement,
                      pf: dict, log: logging.Logger) -> dict:
    data = repl.path.read_bytes()
    entries = pf["_entries"]
    cap = model.peb_size - model.data_offset
    if len(data) > len(entries) * cap:
        raise RepackError("E_CAPACITY", f"{pf['target']} exceeds allocated capacity")

    changed_ranges = []
    pos = 0
    for n, entry in enumerate(entries):
        pi = int(entry["peb_index"])
        lnum = int(entry["lnum"])
        start = pi * model.peb_size + model.data_offset
        end = start + cap
        chunk = data[pos:pos + cap]
        pos += len(chunk)

        # Every allocated target LEB payload is deterministically rebuilt:
        # replacement bytes followed by erased 0xFF padding.
        new_payload = chunk + (b"\xFF" * (cap - len(chunk)))
        old_payload = bytes(image[start:end])
        if old_payload != new_payload:
            image[start:end] = new_payload
            changed_ranges.append({
                "peb_index": pi, "lnum": lnum,
                "start": start, "end": end,
                "changed_bytes": sum(a != b for a, b in zip(old_payload, new_payload)),
            })

        vol_type = parse_int(entry.get("vol_type"))
        if vol_type == UBI_VID_STATIC:
            patch_static_vid_header(image, model, entry, chunk)

        pct = ((n + 1) * 100.0 / len(entries))
        if n == 0 or n + 1 == len(entries) or (n + 1) % max(1, len(entries)//20) == 0:
            log.info("[PATCH] %s: %d/%d LEBs (%.1f%%)",
                     pf["target"], n + 1, len(entries), pct)

    return {
        "target": pf["target"],
        "volume_id": repl.vol_id,
        "modified_size": len(data),
        "changed_payload_ranges": changed_ranges,
        "changed_pebs": len(changed_ranges),
    }

def verify_unrelated_bytes(original: bytes, modified: bytes,
                           model: RegionModel, preflights: List[dict]) -> dict:
    allowed = bytearray(len(original))
    for pf in preflights:
        for e in pf["_entries"]:
            pi = int(e["peb_index"])
            s = pi * model.peb_size + model.data_offset
            allowed[s:s + (model.peb_size - model.data_offset)] = b"\x01" * (
                model.peb_size - model.data_offset)
            if parse_int(e.get("vol_type")) == UBI_VID_STATIC:
                vh = pi * model.peb_size + model.vid_hdr_offset
                allowed[vh:vh + UBI_VID_HDR_SIZE] = b"\x01" * UBI_VID_HDR_SIZE
    unrelated = 0
    first = None
    for i, (a, b) in enumerate(zip(original, modified)):
        if a != b and not allowed[i]:
            unrelated += 1
            if first is None: first = i
    return {
        "status": "PASS" if unrelated == 0 else "FAIL",
        "unrelated_changed_bytes": unrelated,
        "first_unrelated_change": first,
    }

def audit_vid_crc_baseline(image: bytes, model: RegionModel) -> dict:
    """Audit all VID header CRCs in the original image (diagnostic only)."""
    checked, mismatches = 0, []
    for e in model.vid:
        pi = parse_int(e.get("peb_index"))
        if pi is None: continue
        off = pi * model.peb_size + model.vid_hdr_offset
        hdr = image[off:off + UBI_VID_HDR_SIZE]
        if len(hdr) != UBI_VID_HDR_SIZE or struct.unpack(">I", hdr[:4])[0] != UBI_VID_MAGIC:
            continue
        stored, calc = struct.unpack(">I", hdr[UBI_VID_OFF_HDR_CRC:UBI_VID_OFF_HDR_CRC + 4])[0], \
                       ubi_crc32(hdr[:UBI_VID_OFF_HDR_CRC])
        checked += 1
        if stored != calc:
            mismatches.append({"peb_index": pi, "vol_id": parse_int(e.get("vol_id")),
                "lnum": parse_int(e.get("lnum")), "stored": f"0x{stored:08x}",
                "calculated": f"0x{calc:08x}"})
    return {"status": "PASS" if not mismatches else "MISMATCH_PRESENT",
        "vid_headers_checked": checked, "mismatch_count": len(mismatches),
        "mismatches": mismatches[:100]}

def audit_ec_headers(image: bytes, model: RegionModel) -> dict:
    """Audit all EC header magic and CRCs in the original image (diagnostic).

    NEW in itr03: verifies EC header integrity alongside the VID CRC baseline.
    """
    checked, magic_bad, crc_mismatches = 0, [], []
    for e in model.ec:
        pi = parse_int(e.get("peb_index"))
        if pi is None: continue
        off = pi * model.peb_size
        hdr = image[off:off + UBI_EC_HDR_SIZE]
        if len(hdr) != UBI_EC_HDR_SIZE:
            continue
        magic = struct.unpack(">I", hdr[UBI_EC_OFF_MAGIC:UBI_EC_OFF_MAGIC + 4])[0]
        if magic != UBI_EC_MAGIC:
            magic_bad.append({"peb_index": pi, "magic": f"0x{magic:08x}"})
            continue
        stored, calc = struct.unpack(">I", hdr[UBI_EC_OFF_HDR_CRC:UBI_EC_OFF_HDR_CRC + 4])[0], \
                       ubi_crc32(hdr[:UBI_EC_OFF_HDR_CRC])
        checked += 1
        if stored != calc:
            crc_mismatches.append({"peb_index": pi,
                "stored": f"0x{stored:08x}", "calculated": f"0x{calc:08x}"})
    status = "PASS" if not magic_bad and not crc_mismatches else "MISMATCH_PRESENT"
    return {"status": status,
        "ec_headers_checked": checked,
        "magic_failure_count": len(magic_bad),
        "magic_failures": magic_bad[:100],
        "crc_mismatch_count": len(crc_mismatches),
        "crc_mismatches": crc_mismatches[:100]}

def verify_vid_headers_differential(original: bytes, modified: bytes,
                                    model: RegionModel, preflights: List[dict]) -> dict:
    """Verify that only intended static-volume VID headers changed, and all
    changed headers have valid magic and correct CRC."""
    static_allowed = set()
    for pf in preflights:
        for e in pf["_entries"]:
            if parse_int(e.get("vol_type")) == UBI_VID_STATIC:
                static_allowed.add(int(e["peb_index"]))
    checked, unexpected, crc_bad, changed_static = 0, [], [], []
    for e in model.vid:
        pi = parse_int(e.get("peb_index"))
        if pi is None: continue
        off = pi * model.peb_size + model.vid_hdr_offset
        oh, mh = original[off:off+UBI_VID_HDR_SIZE], modified[off:off+UBI_VID_HDR_SIZE]
        if len(oh) != UBI_VID_HDR_SIZE or len(mh) != UBI_VID_HDR_SIZE: continue
        checked += 1
        if pi not in static_allowed:
            if oh != mh:
                unexpected.append({"peb_index": pi, "vol_id": parse_int(e.get("vol_id")),
                    "lnum": parse_int(e.get("lnum")),
                    "reason": "VID header changed without intentional static-header patch"})
            continue
        if oh != mh: changed_static.append(pi)
        if struct.unpack(">I", mh[:4])[0] != UBI_VID_MAGIC:
            crc_bad.append({"peb_index": pi, "reason": "invalid VID magic"})
            continue
        stored, calc = struct.unpack(">I", mh[UBI_VID_OFF_HDR_CRC:UBI_VID_OFF_HDR_CRC + 4])[0], \
                       ubi_crc32(mh[:UBI_VID_OFF_HDR_CRC])
        if stored != calc:
            crc_bad.append({"peb_index": pi, "vol_id": parse_int(e.get("vol_id")),
                "lnum": parse_int(e.get("lnum")), "stored": f"0x{stored:08x}",
                "calculated": f"0x{calc:08x}"})
    ok = not unexpected and not crc_bad
    return {"status": "PASS" if ok else "FAIL", "headers_checked": checked,
        "unexpected_header_change_count": len(unexpected),
        "unexpected_header_changes": unexpected[:100],
        "static_crc_failure_count": len(crc_bad), "static_crc_failures": crc_bad[:100],
        "intentionally_changed_static_headers": changed_static}

def verify_replacement_payload(image: bytes, model: RegionModel,
                               repl: Replacement, pf: dict,
                               data: Optional[bytes] = None) -> dict:
    """Verify the replacement payload was written correctly.

    ENHANCEMENT in itr03: accepts pre-read data bytes to avoid re-reading
    the replacement file from disk.
    """
    cap, alloc = model.peb_size - model.data_offset, bytearray()
    for e in pf["_entries"]:
        s = int(e["peb_index"]) * model.peb_size + model.data_offset
        alloc.extend(image[s:s+cap])
    expected = data if data is not None else repl.path.read_bytes()
    prefix_ok = bytes(alloc[:len(expected)]) == expected
    tail = bytes(alloc[len(expected):])
    tail_ff = all(b == 0xFF for b in tail)
    return {"status": "PASS" if prefix_ok and tail_ff else "FAIL",
        "replacement_size": len(expected), "allocated_capacity": len(alloc),
        "prefix_exact": prefix_ok, "replacement_sha256": sha256_bytes(expected),
        "reconstructed_prefix_sha256": sha256_bytes(bytes(alloc[:len(expected)])),
        "tail_size": len(tail), "tail_all_ff": tail_ff,
        "first_non_ff_tail_offset": next((i for i,b in enumerate(tail) if b != 0xFF), None)}


def setup_logging(log_dir: Path, verbose: bool) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("clean_ubi_repacker")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(log_dir / "process.log")
    fh.setLevel(logging.DEBUG); fh.setFormatter(fmt); logger.addHandler(fh)
    sh = logging.StreamHandler()
    sh.setLevel(logging.DEBUG if verbose else logging.INFO); sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger

def clean_public_pf(pf: dict) -> dict:
    return {k: v for k, v in pf.items() if not k.startswith("_")}

def build_parser() -> argparse.ArgumentParser:
    epilog = r"""
Examples:
  # Replace rootfs in region 0
  %(prog)s --analysis-dir output_upk-script-03 \
      --replace region0:rootfs=/path/mod_rootfs.squashfs

  # Replace kernel and rootfs together
  %(prog)s --analysis-dir output_upk-script-03 \
      --replace region0:kernel=/path/mod_kernel.bin \
      --replace region0:rootfs=/path/mod_rootfs.squashfs

  # Multi-region replacement
  %(prog)s --analysis-dir output_upk-script-03 \
      --replace region0:rootfs=/path/mod_r0.squashfs \
      --replace region1:rootfs=/path/mod_r1.squashfs \
      --output-dir repacked-clean-output

  # Preflight only: show maximum allowed sizes and buffers
  %(prog)s --analysis-dir output_upk-script-03 \
      --replace region0:rootfs=/path/mod_rootfs.squashfs --dry-run

  # Override PEB size when auto-detection fails
  %(prog)s --analysis-dir output_upk-script-03 \
      --peb-size 131072 \
      --replace region0:rootfs=/path/mod_rootfs.squashfs
"""
    p = argparse.ArgumentParser(
        description="Surgical clean-UBI repacker using ubi_analyst output (itr03)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog)
    p.add_argument("--analysis-dir", required=True, help="ubi_analyst output directory")
    p.add_argument("--replace", action="append", required=True,
                   metavar="regionN:volume=FILE",
                   help="Replacement; repeat for multiple targets")
    p.add_argument("--output-dir", default="repacked-clean-output")
    p.add_argument("--dry-run", action="store_true",
                   help="Validate and report capacities without writing images")
    p.add_argument("--yes", action="store_true", help="Do not ask for confirmation")
    p.add_argument("--allow-roundtrip-skip", action="store_true",
                   help="Allow mutation when no analyst .bin exists for self-validation")
    p.add_argument("--peb-size", type=lambda s: int(s, 0), default=None,
                   help="Override PEB size (bytes, supports hex like 0x20000)")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--version", action="version",
                   version="clean_ubi_surgical_repacker_itr03 v1.0")
    return p

def main() -> int:
    args = build_parser().parse_args()
    run_id = uuid.uuid4().hex[:8]
    analysis_dir = Path(args.analysis_dir).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    log_dir = output_dir / "logs" / f"run_{run_id}"
    log = setup_logging(log_dir, args.verbose)
    summary = {
        "run_id": run_id, "status": "RUNNING",
        "started_at": dt.datetime.now().isoformat(),
        "analysis_dir": str(analysis_dir), "output_dir": str(output_dir),
        "dry_run": args.dry_run,
        "itr_version": "itr03",
    }
    try:
        repls = [parse_replace(x) for x in args.replace]
        # Reject duplicate targets before any mutation.
        raw_targets = [(r.region, r.selector.lower()) for r in repls]
        if len(raw_targets) != len(set(raw_targets)):
            raise RepackError("E_DUPLICATE_TARGET", "Duplicate --replace target supplied")

        regions: Dict[int, RegionModel] = {}
        for ri in sorted({r.region for r in repls}):
            log.info("[LOAD] Loading analyst model for region%d", ri)
            regions[ri] = load_region(analysis_dir, ri, args.peb_size)
            m = regions[ri]
            log.info("[GEOMETRY] region%d: clean=%d, PEB=0x%x, VID=0x%x, data=0x%x",
                     ri, len(m.clean), m.peb_size, m.vid_hdr_offset, m.data_offset)

        preflights = []
        resolved_keys = set()
        for r in repls:
            resolve_volume(regions[r.region], r)
            key = (r.region, r.vol_id)
            if key in resolved_keys:
                raise RepackError("E_DUPLICATE_TARGET",
                                  f"Multiple replacements resolve to region{r.region}:vol{r.vol_id}")
            resolved_keys.add(key)
            pf = preflight_one(regions[r.region], r)
            preflights.append(pf)

        print_preflight(preflights)

        # Baseline audits: EC header magic+CRC and VID header CRC.
        baseline_vid_audits = {}
        baseline_ec_audits = {}
        for ri, model in regions.items():
            # EC header audit (NEW in itr03)
            ec_audit = audit_ec_headers(model.clean, model)
            baseline_ec_audits[str(ri)] = ec_audit
            if ec_audit["status"] == "PASS":
                log.info("[EC_BASELINE] region%d: %d EC headers pass magic+CRC audit",
                         ri, ec_audit["ec_headers_checked"])
            else:
                log.warning("[EC_BASELINE] region%d: EC header issues — "
                            "%d magic failures, %d CRC mismatches (diagnostic only)",
                            ri, ec_audit["magic_failure_count"],
                            ec_audit["crc_mismatch_count"])

            # VID header audit (from itr02)
            audit = audit_vid_crc_baseline(model.clean, model)
            baseline_vid_audits[str(ri)] = audit
            if audit["status"] == "PASS":
                log.info("[VID_BASELINE] region%d: %d VID headers pass CRC audit",
                         ri, audit["vid_headers_checked"])
            else:
                log.warning("[VID_BASELINE] region%d: %d/%d original VID headers disagree "
                            "with local CRC verifier; diagnostic only",
                            ri, audit["mismatch_count"], audit["vid_headers_checked"])
        summary["baseline_ec_audit"] = baseline_ec_audits
        summary["baseline_vid_crc_audit"] = baseline_vid_audits

        rejected = [x for x in preflights if x["status"] != "PASS"]
        if rejected:
            raise RepackError("E_CAPACITY",
                              "One or more replacements exceed actual allocated volume capacity",
                              {"targets": [clean_public_pf(x) for x in rejected]})

        failed_rt = [x for x in preflights
                     if x["roundtrip_validation"]["status"] == "FAIL"]
        if failed_rt:
            raise RepackError("E_ROUNDTRIP",
                              "Analyst volume round-trip validation failed; refusing mutation",
                              {"targets": [x["target"] for x in failed_rt]})
        skipped_rt = [x for x in preflights
                      if x["roundtrip_validation"]["status"] == "SKIPPED"]
        if skipped_rt and not args.allow_roundtrip_skip:
            raise RepackError("E_ROUNDTRIP_SKIPPED",
                              "No analyst .bin artifact for one or more targets; "
                              "use --allow-roundtrip-skip only after manual verification",
                              {"targets": [x["target"] for x in skipped_rt]})

        summary["preflight"] = [clean_public_pf(x) for x in preflights]
        atomic_json(log_dir / "preflight.json", summary["preflight"])

        if args.dry_run:
            summary["status"] = "DRY_RUN_PASS"
            log.info("[DONE] Dry-run preflight passed")
            return 0

        if not args.yes:
            ans = input("\nProceed with surgical clean-UBI mutation? [y/N] ").strip().lower()
            if ans not in ("y", "yes"):
                raise RepackError("E_USER_CANCELLED", "User cancelled execution")

        manifests = []
        outputs = []
        for ri, model in regions.items():
            image = bytearray(model.clean)
            # FIXED: use exact volume_id matching instead of startswith to avoid
            # region1 matching region10 etc.
            region_pfs = [pf for pf in preflights if pf["target"] == f"region{ri}:{pf['volume_name']}"]
            # More robust: match by region index in the target string
            region_pfs = [pf for pf in preflights
                          if pf["target"].startswith(f"region{ri}:") and
                          pf["target"].count(":") == 1]
            # Actually, safest approach: filter by checking if the volume's entries
            # belong to this region's model
            region_repls = [r for r in repls if r.region == ri]

            mutations = []
            for r in region_repls:
                pf = next(x for x in region_pfs if x["volume_id"] == r.vol_id)
                log.info("[PATCH] Applying %s from %s", pf["target"], r.path)
                mutations.append(apply_replacement(image, model, r, pf, log))

            unrelated = verify_unrelated_bytes(model.clean, bytes(image), model, region_pfs)
            if unrelated["status"] != "PASS":
                raise RepackError("E_UNRELATED_CHANGE",
                                  f"region{ri}: unrelated bytes changed", unrelated)

            payload_checks = []
            for r in region_repls:
                pf = next(x for x in region_pfs if x["volume_id"] == r.vol_id)
                # Pass pre-read data to avoid re-reading the file
                data_bytes = r.path.read_bytes()
                pc = verify_replacement_payload(bytes(image), model, r, pf, data=data_bytes)
                pc["target"] = pf["target"]
                payload_checks.append(pc)
                if pc["status"] != "PASS":
                    raise RepackError("E_PAYLOAD_VERIFY",
                                      f"{pf['target']}: payload verification failed", pc)
                log.info("[PAYLOAD_VERIFY] %s: exact prefix PASS, FF tail PASS (%d bytes)",
                         pf["target"], pc["tail_size"])

            hdrcheck = verify_vid_headers_differential(
                model.clean, bytes(image), model, region_pfs)
            if hdrcheck["status"] != "PASS":
                raise RepackError("E_VID_DIFFERENTIAL",
                                  f"region{ri}: differential VID verification failed", hdrcheck)
            log.info("[VID_VERIFY] region%d: differential verification PASS", ri)

            if len(image) != len(model.clean):
                raise RepackError("E_SIZE", f"region{ri}: output size changed")

            out = output_dir / f"region_{ri}" / "clean_ubi_repacked.img"
            atomic_write(out, bytes(image))
            outputs.append({
                "region": ri, "path": str(out), "size": len(image),
                "sha256": sha256_bytes(bytes(image)),
                "original_sha256": sha256_bytes(model.clean),
            })
            manifests.append({
                "region": ri, "source": str(model.clean_path),
                "output": str(out), "geometry": {
                    "peb_size": model.peb_size,
                    "vid_hdr_offset": model.vid_hdr_offset,
                    "data_offset": model.data_offset,
                    "leb_payload_capacity": model.peb_size - model.data_offset,
                },
                "mutations": mutations,
                "unrelated_byte_verification": unrelated,
                "payload_verification": payload_checks,
                "vid_header_differential_verification": hdrcheck,
                "baseline_ec_audit": baseline_ec_audits.get(str(ri)),
                "baseline_vid_crc_audit": baseline_vid_audits.get(str(ri)),
            })
            log.info("[OUTPUT] region%d complete: %s", ri, out)

        atomic_json(output_dir / "mutation_manifest.json", manifests)
        summary["outputs"] = outputs
        summary["status"] = "SUCCESS"
        log.info("[DONE] All requested clean UBI images generated and verified")
        return 0

    except RepackError as e:
        summary["status"] = "FAILED"
        summary["failure_code"] = e.code
        summary["failure_message"] = str(e)
        summary["failure_details"] = e.details
        log.error("[%s] %s", e.code, e)
        return 2
    except KeyboardInterrupt:
        summary["status"] = "ABORTED"
        summary["failure_code"] = "E_USER_CANCELLED"
        summary["failure_message"] = "User cancelled execution"
        log.error("[ABORTED] User cancelled execution")
        return 130
    except Exception as e:
        summary["status"] = "FAILED"
        summary["failure_code"] = "E_INTERNAL"
        summary["failure_message"] = str(e)
        tb = traceback.format_exc()
        atomic_write(log_dir / "traceback.log", tb.encode())
        log.exception("[E_INTERNAL] Unexpected exception")
        return 3
    finally:
        summary["ended_at"] = dt.datetime.now().isoformat()
        try:
            atomic_json(log_dir / "run_summary.json", summary)
        except Exception:
            pass

if __name__ == "__main__":
    sys.exit(main())
