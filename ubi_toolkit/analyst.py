#!/usr/bin/env python3
"""
ubi_analyst_mod.py — UBI firmware analysis, extraction, and reporting tool.
Enhanced with:
  - Raw-firmware-wide magic-byte scanning for SquashFS, JFFS2, CramFS, UBIFS, DTB
  - OOB-offset-aware extraction (converts raw offsets to clean offsets)
  - Deep validation of detected filesystems (superblock CRC, structural checks)
  - False-positive filtering using size sanity, magic consistency, and structure parsing
  - All extracted filesystems are saved to other_fs/ with metadata in report
  - Strict raw/clean coordinate separation and round-trip validation

v06 changes (smart selective extraction):
  - SKIP duplicate/backup volumes (hash dedup — .b backups identical to primary)
  - CLASSIFY each volume purely by magic bytes (no device-specific names):
    * filesystem → SquashFS/JFFS2/CramFS/UBIFS/DTB extracted as single image
    * kernel     → uImage header detected, extracted as .bin (appended DTB kept intact)
    * raw        → no recognized magic, extracted as .bin (config, partition table, etc.)
    * skip       → empty or too small (< 4 bytes)
  - EXTRACT filesystems as single image files (.squashfs, .jffs2, etc.) — no
    unsquashfs/auto-unpacking; user can unpack manually when needed
  - No device-specific volume name lists — works generically for any UBI firmware
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import struct
import sys
import time
import zlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Optional progress bar
try:
    from tqdm import tqdm
    HAS_TQDM = True
except Exception:
    HAS_TQDM = False
    class tqdm:  # type: ignore
        """Fallback when tqdm is not installed. Supports context manager + update()."""
        def __init__(self, iterable=None, total=None, **kwargs):
            self._iter = iterable
            self._total = total or 0
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False
        def __iter__(self):
            return iter(self._iter or range(self._total))
        def update(self, n=1):
            pass

LOG_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FMT)
log = logging.getLogger("ubi_analyst")

UBI_EC_MAGIC = b"UBI#"
UBI_VID_MAGIC = b"UBI!"
UBI_FM_MAGIC = b"UBI+"

VOL_DYNAMIC = 1
VOL_STATIC = 2
VOL_TYPE_NAMES = {VOL_DYNAMIC: "dynamic", VOL_STATIC: "static"}

VTBL_RECORD_SIZE = 172
VTBL_MAX_VOLUMES = 128

# Tier-1 standard-geometry table (fast if/else path, v1.1.2) — standard
# open-source NAND page/OOB geometries. The original five remain at the
# top (byte-for-byte, untouched); the additions are the common variants
# (SLC/MLC page sizes 256B–16K, OOB 8B–1280B). Additive only: detection
# filters every entry against the image's raw EB size, so an entry that
# cannot fit is simply skipped.
NAND_GEOMETRIES = [
    (512, 16),
    (2048, 64),
    (2048, 128),
    (4096, 128),
    (4096, 256),
    # v1.1.2 additions (standard table)
    (256, 8),
    (512, 8),
    (1024, 32),
    (1024, 64),
    (2048, 32),
    (4096, 64),
    (8192, 64),
    (16384, 128),
]

# ── Filesystem magic signatures for raw scanning ──────────────────────────
FS_SCAN_SIGNATURES = [
    (b"hsqs", "SquashFS", "little", 4096, "SquashFS v4 LE"),
    (b"sqsh", "SquashFS", "big", 4096, "SquashFS v4 BE"),
    (b"qshs", "SquashFS", "mixed", 4096, "SquashFS v4 mixed-endian"),
    (b"shsq", "SquashFS", "mixed", 4096, "SquashFS v4 mixed-endian"),
    (b"\x31\x18\x10\x06", "UBIFS", "little", 4096, "UBIFS LE"),
    (b"\x85\x19\x03\xE0", "JFFS2", "little", 128, "JFFS2 LE"),
    (b"\x19\x85\xE0\x03", "JFFS2", "big", 128, "JFFS2 BE"),
    (b"\x45\x3D\xCD\x28", "CramFS", "little", 4096, "CramFS LE"),
    (b"\x28\xCD\x3D\x45", "CramFS", "big", 4096, "CramFS BE"),
    (b"\xD0\x0D\xFE\xED", "DTB", "big", 256, "Flattened Device Tree BE"),
    (b"\xD0\x0D\xFE\xED\x00\x00\x00\x00", "DTB-ext", "big", 256, "Flattened Device Tree BE (ext)"),
]

SQUASHFS_KNOWN_COMP = {1: "gzip", 2: "lzma", 3: "lzo", 4: "xz", 5: "lz4", 6: "zstd"}
SQUASHFS_MIN_BLOCKSIZE = 4096
SQUASHFS_MAX_BLOCKSIZE = 262144


@dataclass
class OOBGeometry:
    page_size: int
    oob_size: int
    stride: int
    raw_eb_size: int
    clean_eb_size: int
    pages_per_eb: int
    has_oob: bool


@dataclass
class ECHeaderInfo:
    offset: int  # clean offset
    peb_index: int
    version: int
    ec: int
    vid_hdr_offset: int
    data_offset: int
    image_seq: int
    hdr_crc: int
    offset_raw: Optional[int] = None


@dataclass
class VIDHeaderInfo:
    offset: int  # clean offset
    peb_index: int
    version: int
    vol_type: int
    copy_flag: int
    compat: int
    vol_id: int
    lnum: int
    data_size: int
    used_ebs: int
    data_pad: int
    sqnum: int
    hdr_crc: int
    offset_raw: Optional[int] = None
    crc_ok: Optional[bool] = None      # gen2: result of VIDHeader._verify (None = not checked)
    crc_conv: Optional[str] = None     # gen2: which CRC convention matched
    # v1.1.2 (Fix 2): gated lnum repair annotations
    lnum_raw: Optional[int] = None     # original lnum field before repair
    lnum_repair: Optional[str] = None  # 'single-bit' | 'peb-order' | None


@dataclass
class VolumeInfo:
    vol_id: int
    name: str
    vol_type: int
    leb_count: int
    used_ebs: int
    data_size: int
    fs_type: Optional[str] = None
    fs_endian: Optional[str] = None
    extracted_path: Optional[str] = None
    size_bytes: int = 0  # logical_span_with_ff_filled_missing_lnums
    validation: Optional[dict] = None
    deep_health: Optional[dict] = None   # v1.12.0: fs_health deep-check result
    healed_from: Optional[str] = None    # v1.12.0: heal variant name, if healed
    present_leb_count: int = 0
    max_lnum: int = -1
    logical_leb_count: int = 0
    present_leb_bytes: int = 0
    logical_span_bytes: int = 0
    missing_lnum_count: int = 0
    size_semantics: str = "logical_span_with_ff_filled_missing_lnums"
    filesystem_used_bytes: Optional[int] = None


@dataclass
class UBIRegion:
    start_offset: int  # clean offset (backward compat)
    end_offset: int    # clean offset (backward compat)
    peb_size: int      # clean peb size (backward compat)
    leb_size: int
    vid_hdr_offset: int
    data_offset: int
    image_seq: int
    peb_count: int
    volumes: Dict[int, VolumeInfo] = field(default_factory=dict)
    ec_headers: List[ECHeaderInfo] = field(default_factory=list)
    vid_headers: List[VIDHeaderInfo] = field(default_factory=list)
    geometry: Optional[dict] = None
    summary: Optional[dict] = None
    
    start_offset_clean: Optional[int] = None
    end_offset_clean: Optional[int] = None
    start_offset_raw: Optional[int] = None
    end_offset_raw: Optional[int] = None
    peb_size_clean: Optional[int] = None
    peb_size_raw: Optional[int] = None
    
    offset_space: str = "clean_oob_stripped"
    region_type: str = "ubi_attach_group"
    grouping_reason: str = "new-attach (layout vol) boundaries and >4-PEB gaps"


@dataclass
class FirmwareHeader:
    """Represents a firmware wrapper header found before UBI data (e.g. a size-prefixed upgrade package, a legacy bootloader image)."""
    header_type: str          # 'be_size_upg', 'u_boot_legacy', 'none'
    header_size: int          # byte offset where actual UBI/flash data starts
    raw_header: Optional[bytes] = None  # raw header bytes (for extraction)
    meta: dict = field(default_factory=dict)


@dataclass
class FoundFS:
    """Represents a filesystem found outside UBI (or before UBI)."""
    offset_raw: int
    offset_clean: Optional[int]
    fs_type: str
    endian: str
    size_bytes: int
    size_verified: bool
    validation: dict
    path: Optional[str] = None
    magic: str = ""
    size_clean: int = 0
    raw_span_size: int = 0
    detected_in: List[str] = field(default_factory=list)
    # v1.1.2 (Fix 3): when an FS found by the raw/clean orphan scan actually
    # lies INSIDE a UBI region's span, it is routed to that region's
    # volumes/ directory instead of the global other_fs/. These fields carry
    # the routing decision (region index None = truly outside every region).
    region_index: Optional[int] = None
    vol_id_hint: Optional[int] = None
    lnum_hint: Optional[int] = None


@dataclass
class FirmwareReport:
    input_file: str
    file_size: int
    md5: str
    sha256: str
    oob_geometry: Optional[dict]
    ubi_regions: List[dict] = field(default_factory=list)
    other_fs: List[dict] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    analysis_time_s: float = 0.0
    firmware_header: Optional[dict] = None


@dataclass
class AnalysisOptions:
    firmware: Optional[str] = None
    output: str = "output"
    mode: str = "auto"
    verbose: bool = False
    report_only: bool = False
    page_size: Optional[int] = None
    oob_size: Optional[int] = None
    peb_size: Optional[int] = None
    leb_size: Optional[int] = None
    gui: bool = False


# ═══════════════════════════════════════════════════════════════════════════
#  FILESYSTEM VALIDATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class FsValidator:
    @staticmethod
    def validate_squashfs(data: bytes, offset: int = 0) -> dict:
        result: dict = {"valid": False, "reason": "", "meta": {}, "errors": []}
        # zero-copy: the orphan scan calls this per magic hit on
        # multi-hundred-MB images — a slice here copies ~image_size per hit
        if len(data) < offset + 96:
            result["reason"] = "Too small for SquashFS superblock"
            return result
        chunk = memoryview(data)[offset:]
        magic = bytes(chunk[:4])
        if magic not in (b"hsqs", b"sqsh", b"qshs", b"shsq"):
            result["reason"] = f"Unknown magic: {magic.hex()}"
            return result
        try:
            le = magic in (b"hsqs",)
            byte_order = "<" if le else ">"
            inode_count = struct.unpack_from(byte_order + "I", chunk, 4)[0]
            mtime = struct.unpack_from(byte_order + "I", chunk, 8)[0]
            block_size = struct.unpack_from(byte_order + "I", chunk, 12)[0]
            frag_count = struct.unpack_from(byte_order + "I", chunk, 16)[0]
            comp_id = struct.unpack_from(byte_order + "H", chunk, 20)[0]
            block_log = struct.unpack_from(byte_order + "H", chunk, 22)[0]
            flags = struct.unpack_from(byte_order + "H", chunk, 24)[0]
            version_major = struct.unpack_from(byte_order + "H", chunk, 28)[0]
            version_minor = struct.unpack_from(byte_order + "H", chunk, 30)[0]
            bytes_used = struct.unpack_from(byte_order + "Q", chunk, 40)[0]
            meta = {
                "magic": magic.decode("ascii", errors="replace"),
                "inode_count": inode_count,
                "block_size": block_size,
                "compression": SQUASHFS_KNOWN_COMP.get(comp_id, f"unknown({comp_id})"),
                "version": f"{version_major}.{version_minor}",
                "bytes_used": bytes_used,
            }
            errors = []
            if version_major != 4: errors.append(f"Unexpected major version: {version_major}")
            if block_size < SQUASHFS_MIN_BLOCKSIZE or block_size > SQUASHFS_MAX_BLOCKSIZE: errors.append(f"Suspicious block_size: {block_size}")
            if bytes_used <= 0 or bytes_used > len(chunk): errors.append(f"bytes_used ({bytes_used}) out of range")
            if comp_id not in SQUASHFS_KNOWN_COMP: errors.append(f"Unknown compression ID: {comp_id}")
            if inode_count == 0: errors.append("inode_count is 0")
            result["meta"] = meta
            if errors:
                result["reason"] = "; ".join(errors[:3])
                result["errors"] = errors
            else:
                result["valid"] = True
                result["reason"] = "All structural checks passed"
        except struct.error as e:
            result["reason"] = f"Struct parse error: {e}"
        return result

    @staticmethod
    def validate_jffs2(data: bytes, offset: int = 0) -> dict:
        result: dict = {"valid": False, "reason": "", "meta": {}, "errors": []}
        if len(data) < offset + 16: return result
        chunk = memoryview(data)[offset:]
        # JFFS2 magic is 2 bytes (0x1985); node type is next 2 bytes and varies
        magic2 = chunk[:2]
        if magic2 not in (b"\x85\x19", b"\x19\x85"): return result
        le = magic2 == b"\x85\x19"
        byte_order = "<" if le else ">"
        try:
            node_type = struct.unpack_from(byte_order + "H", chunk, 2)[0]
            total_len = struct.unpack_from(byte_order + "I", chunk, 8)[0]
            magic_hex = chunk[:4].hex()
            meta = {"magic": magic_hex, "node_type": node_type, "total_len": total_len}
            errors = []
            if total_len < 16 or total_len > 1024 * 1024: errors.append(f"Suspicious total_len: {total_len}")
            result["meta"] = meta
            if errors: result["reason"] = "; ".join(errors[:3])
            else:
                result["valid"] = True
                result["reason"] = "JFFS2 structure looks plausible"
        except struct.error as e:
            result["reason"] = f"Parse error: {e}"
        return result

    @staticmethod
    def validate_cramfs(data: bytes, offset: int = 0) -> dict:
        result: dict = {"valid": False, "reason": "", "meta": {}, "errors": []}
        if len(data) < offset + 128: return result
        chunk = memoryview(data)[offset:]
        magic = chunk[:4]
        if magic not in (b"\x45\x3D\xCD\x28", b"\x28\xCD\x3D\x45"): return result
        le = magic == b"\x45\x3D\xCD\x28"
        byte_order = "<" if le else ">"
        try:
            size = struct.unpack_from(byte_order + "I", chunk, 4)[0]
            meta = {"magic": magic.hex(), "size": size}
            errors = []
            if size <= 0 or size > len(chunk) * 2: errors.append(f"Suspicious size: {size}")
            result["meta"] = meta
            if errors: result["reason"] = "; ".join(errors[:3])
            else:
                result["valid"] = True
                result["reason"] = "CramFS structure looks plausible"
        except struct.error as e:
            result["reason"] = f"Parse error: {e}"
        return result

    @staticmethod
    def validate_ubifs(data: bytes, offset: int = 0) -> dict:
        result: dict = {"valid": False, "reason": "", "meta": {}, "errors": []}
        # bounds check only — never slice `data` here: the orphan scan calls
        # this per magic hit on multi-hundred-MB images, and a slice would
        # copy ~image_size bytes per hit.
        if len(data) < offset + 80: return result
        if data[offset:offset + 4] != b"\x31\x18\x10\x06": return result
        try:
            # the SB node's common-header node_type byte must be 5; reject
            # every other UBIFS node type before reading further
            if data[offset + 20] != 5:
                return result
            # ubifs_sb_node: ubifs_ch (24 B) + padding[10] + key_fmt +
            # padding2[5] + min_io_size@40, leb_size@44, leb_count@48
            leb_size = struct.unpack_from("<I", data, offset + 44)[0]
            leb_count = struct.unpack_from("<I", data, offset + 48)[0]
            meta = {"leb_size": leb_size, "leb_count": leb_count}
            errors = []
            if leb_size <= 0 or leb_size > 4 * 1024 * 1024: errors.append(f"Suspicious LEB size: {leb_size}")
            if leb_count <= 0 or leb_count > 100000: errors.append(f"Suspicious LEB count: {leb_count}")
            result["meta"] = meta
            if errors: result["reason"] = "; ".join(errors[:3])
            else:
                result["valid"] = True
                result["reason"] = "UBIFS superblock looks valid"
        except struct.error as e:
            result["reason"] = f"Parse error: {e}"
        return result

    @staticmethod
    def validate_dtb(data: bytes, offset: int = 0) -> dict:
        result: dict = {"valid": False, "reason": "", "meta": {}, "errors": []}
        if len(data) < offset + 40: return result
        chunk = memoryview(data)[offset:]
        if chunk[:4] != b"\xD0\x0D\xFE\xED": return result
        try:
            total_size = struct.unpack_from(">I", chunk, 4)[0]
            version = struct.unpack_from(">I", chunk, 20)[0]
            meta = {"total_size": total_size, "version": version}
            errors = []
            if total_size <= 0 or total_size > len(chunk) * 2: errors.append(f"Suspicious total_size: {total_size}")
            if version < 16 or version > 20: errors.append(f"Unusual DTB version: {version}")
            result["meta"] = meta
            if errors: result["reason"] = "; ".join(errors[:3])
            else:
                result["valid"] = True
                result["reason"] = "DTB looks valid"
        except struct.error as e:
            result["reason"] = f"Parse error: {e}"
        return result

    @staticmethod
    def validate(fs_type: str, data: bytes, offset: int = 0) -> dict:
        if fs_type == "SquashFS": return FsValidator.validate_squashfs(data, offset)
        elif fs_type == "JFFS2": return FsValidator.validate_jffs2(data, offset)
        elif fs_type == "CramFS": return FsValidator.validate_cramfs(data, offset)
        elif fs_type == "UBIFS": return FsValidator.validate_ubifs(data, offset)
        elif fs_type in ("DTB", "DTB-ext"): return FsValidator.validate_dtb(data, offset)
        return {"valid": False, "reason": f"No validator for {fs_type}", "meta": {}, "errors": ["unknown type"]}


class FilesystemDetector:
    FS_MAGICS = {
        b"hsqs": ("SquashFS", "little"),
        b"sqsh": ("SquashFS", "big"),
        b"\x31\x18\x10\x06": ("UBIFS", "little"),
        b"\x85\x19": ("JFFS2", "little"),  # 2-byte magic only; node type varies
        b"\x19\x85": ("JFFS2", "big"),     # 2-byte magic only; node type varies
        b"\x45\x3D\xCD\x28": ("CramFS", "little"),
        b"\x28\xCD\x3D\x45": ("CramFS", "big"),
        b"\xD0\x0D\xFE\xED": ("DTB", "big"),
    }

    @staticmethod
    def detect(data: bytes) -> Tuple[Optional[str], Optional[str], dict]:
        # probe only the leading bytes — data can be a huge volume blob and
        # lstrip() would copy it wholesale
        lead = data[:4096]
        stripped = lead.lstrip(b"\xff")
        if not stripped or len(stripped) < 8: return None, None, {}
        for magic, (fs_type, endian) in FilesystemDetector.FS_MAGICS.items():
            if stripped[:len(magic)] == magic:
                return fs_type, endian, {}
        return None, None, {}


# ═══════════════════════════════════════════════════════════════════════════
#  OOB / GEOMETRY DETECTION
# ═══════════════════════════════════════════════════════════════════════════

class OOBDetector:
    def __init__(self, data: bytes, forced_page: Optional[int] = None, forced_oob: Optional[int] = None):
        self.data = data
        self.forced_page = forced_page
        self.forced_oob = forced_oob

    def _robust_raw_eb(self, f1: int) -> Optional[int]:
        """Dedupe-aware raw-EB estimation.

        Some vendors write every EC header TWICE a few KiB apart (redundant
        page writes). Taking the gap between the first two magics then yields
        the duplicate interval, not the PEB size, which cascades into bogus
        OOB geometry, negative LEB sizes and thousands of micro-regions.
        Instead: collect CRC-valid EC headers, drop byte-identical duplicates
        within a 4 KiB window, and return the modal stride. Returns None when
        fewer than two CRC-valid headers exist (caller falls back to legacy).
        """
        try:
            offs, pos = [], f1
            # Converge early: once the deduped gap (excluding redundant vendor
            # copies) has repeated K times consecutively, the estimate is
            # stable — no fixed hunt window needed.
            lead, lead_runs, K = None, 0, 8
            dedup = []
            while pos < len(self.data) and len(offs) < 512:
                idx = self.data.find(UBI_EC_MAGIC, pos)
                if idx < 0: break
                ok, _conv = ECHeader._verify(self.data, idx)
                pos = idx + 4
                if not ok:
                    continue
                offs.append(idx)
                # incremental dedupe: skip redundant vendor copies
                if dedup and idx - dedup[-1] < 0x1000 and \
                   self.data[idx:idx + 64] == self.data[dedup[-1]:dedup[-1] + 64]:
                    continue
                dedup.append(idx)
                if len(dedup) >= 2:
                    gap = dedup[-1] - dedup[-2]
                    if gap == lead:
                        lead_runs += 1
                    else:
                        lead, lead_runs = gap, 1
                    if lead_runs >= K and len(dedup) >= 12:
                        break  # converged
            if len(dedup) < 2: return None
            gaps = [b - a for a, b in zip(dedup, dedup[1:])]
            return max(set(gaps), key=gaps.count)
        except Exception as exc:
            log.debug("robust raw_eb estimation failed: %s", exc)
            return None

    def _candidate_geometries(self, raw_eb: int) -> list:
        """Derive ALL plausible (page, oob, stride, pages, clean_eb) tuples
        from the observed raw erase-block size — no fixed assumption.

        Two sources are merged:
          1. the standard NAND geometry table (fast path for common flashes)
          2. synthetic decomposition: for every power-of-two page count,
             stride = raw_eb / pages; every power-of-two page dividing the
             stride yields a candidate with oob = stride - page, provided
             0 < oob <= page/2 (vendor-realistic spare-area sizing).
        This catches exotic geometries absent from the table."""
        cands = set()
        for page_size, oob_size in NAND_GEOMETRIES:
            stride = page_size + oob_size
            if raw_eb % stride == 0:
                pages = raw_eb // stride
                cands.add((page_size, oob_size, stride, pages, pages * page_size))
        for pp in (2, 4, 8, 16, 32, 64, 128, 256):
            if raw_eb % pp: continue
            stride = raw_eb // pp
            for page in (256, 512, 1024, 2048, 4096, 8192, 16384):
                if stride % page == 0:
                    oob = stride - page
                    if 0 < oob <= page // 2:
                        cands.add((page, oob, stride, pp, pp * page))
        ordered = sorted(cands, key=lambda t: (t[0], t[1]))
        if len(ordered) > 32:
            log.warning("Candidate geometry explosion (%d) — keeping first 32", len(ordered))
            ordered = ordered[:32]
        return ordered

    def _cross_verify_geometry(self, geom: OOBGeometry, align_off: int = 0) -> dict:
        """Forensic self-verification of a derived geometry against the RAW
        image, independent of how the geometry was obtained.

        Evidence collected per sampled written PEB (global sampling):
          ec_hits   : UBI# magic at clean PEB boundary 0
          ec_crc_ok : of those, EC header CRC verifies
          vid_hits  : UBI! magic exactly at the EC-declared vid_hdr_offset
                      AFTER OOB stripping (only the true stride achieves this)
          vol_pebs  : VID headers referencing real volume ids (data PEBs)
        ECC bits themselves live inside the OOB and are vendor-formatted;
        their correctness is reflected indirectly by the CRC/content
        evidence above rather than by re-implementing every ECC scheme.
        Confidence: high / medium / low."""
        ev = {"mode": "clean_no_oob" if not geom.has_oob else "raw_oob",
              "ec_hits": 0, "ec_crc_ok": 0, "vid_hits": 0, "vol_pebs": 0,
              "pebs_sampled": 0, "confidence": "low"}
        raw_eb = geom.raw_eb_size
        if not geom.has_oob or not raw_eb:
            ev["confidence"] = "n/a"
            return ev
        page, stride = geom.page_size, geom.stride
        pos, sampled, MAX_SAMPLE = align_off, 0, 512
        while pos + raw_eb <= len(self.data) and sampled < MAX_SAMPLE:
            base = pos
            pos += raw_eb
            if self.data[base:base + 4] != UBI_EC_MAGIC:
                continue
            sampled += 1
            ev["pebs_sampled"] += 1
            ev["ec_hits"] += 1
            ok, _ = ECHeader._verify(self.data, base)
            if ok: ev["ec_crc_ok"] += 1
            # vid_hdr_offset is already expressed in clean (stripped) space;
            # map it to raw coordinates — zero-copy probe.
            try:
                vhf = struct.unpack_from(">I", self.data, base + 16)[0]
            except struct.error:
                continue
            raw_v = base + (vhf // page) * stride + (vhf % page)
            if raw_v + 4 <= len(self.data) and \
               self.data[raw_v:raw_v + 4] == UBI_VID_MAGIC:
                ev["vid_hits"] += 1
                vol_id = struct.unpack_from(">I", self.data, raw_v + 8)[0]
                if vol_id < 0x7FFFEFFF:
                    ev["vol_pebs"] += 1
        if ev["ec_hits"] >= 8:
            ratio = ev["vid_hits"] / ev["ec_hits"]
            ev["confidence"] = "high" if (ev["vol_pebs"] > 0 or ratio >= 0.3) \
                else "medium"
        log.info("Geometry cross-verification: ec=%(ec_hits)s crc_ok=%(ec_crc_ok)s "
                 "vid@declared=%(vid_hits)s vol_pebs=%(vol_pebs)s "
                 "sampled=%(pebs_sampled)s → confidence %(confidence)s", ev)
        if ev["confidence"] == "low":
            log.warning("Geometry NOT corroborated by image content — pass "
                        "--page-size/--oob-size/--peb-size explicitly if "
                        "extraction yields empty volumes")
        return ev

    def detect(self) -> OOBGeometry:
        f1 = self.data.find(UBI_EC_MAGIC)
        f2 = self.data.find(UBI_EC_MAGIC, f1 + 1)
        if f1 < 0 or f2 < 0:
            raise ValueError("Cannot find two UBI# headers — not a UBI image?")

        raw_eb = self._robust_raw_eb(f1) or (f2 - f1)
        # share with tie-break helpers (naive f2-f1 is confounded by
        # duplicate EC copies spaced < PEB apart)
        self._raw_eb = raw_eb
        log.info("Raw erase block size: 0x%X (%d bytes)", raw_eb, raw_eb)

        if self.forced_page and self.forced_oob is not None:
            return self._build_geometry(self.forced_page, self.forced_oob, raw_eb)

        if raw_eb > 0 and (raw_eb & (raw_eb - 1)) == 0:
            log.info("Raw EB size is power-of-2 — no OOB interleaving detected")
            return OOBGeometry(0, 0, 0, raw_eb, raw_eb, 0, False)

        candidates = []
        for page_size, oob_size in NAND_GEOMETRIES:
            stride = page_size + oob_size
            if raw_eb % stride != 0: continue
            pages = raw_eb // stride
            clean_eb = pages * page_size
            if clean_eb > 0 and (clean_eb & (clean_eb - 1)) == 0:
                candidates.append((page_size, oob_size, stride, pages, clean_eb))
        # dynamic supplement: decompose raw_eb itself (catches geometries
        # outside the standard table — nothing is assumed a priori)
        for cand in self._candidate_geometries(raw_eb):
            if cand not in candidates:
                candidates.append(cand)
        log.info("Derived %d candidate geometry/-ies from raw EB 0x%X: %s",
                 len(candidates), raw_eb,
                 [(c[0], c[1]) for c in candidates])

        if not candidates:
            log.warning("No standard NAND geometry fits — treating as no OOB")
            return OOBGeometry(0, 0, 0, raw_eb, raw_eb, 0, False)

        if len(candidates) == 1:
            page_size, oob_size, *_ = candidates[0]
            log.info("Auto-detected geometry: page=%dB, OOB=%dB", page_size, oob_size)
            geom = self._build_geometry(page_size, oob_size, raw_eb)
            self._cross_verify_geometry(geom, align_off=f1)
            return geom

        try:
            gen3 = self._disambiguate_geometry_gen3(candidates, f1)
            if gen3 is not None:
                page_size, oob_size = gen3
            else:
                gen2 = self._disambiguate_geometry_gen2(candidates, f1)
                if gen2 is not None:
                    page_size, oob_size = gen2
                else:
                    # gen2/gen3 found no decisive evidence — fall back to legacy heuristic
                    page_size, oob_size = self._measure_stride(candidates)
                    log.info("Gen2/Gen3 disambiguation inconclusive — legacy _measure_stride used")
        except Exception as exc:
            log.warning("Gen3/Gen2 disambiguation failed (%s) — legacy _measure_stride used", exc)
            page_size, oob_size = self._measure_stride(candidates)
        log.info("Disambiguated geometry: page=%dB, OOB=%dB", page_size, oob_size)
        geom = self._build_geometry(page_size, oob_size, raw_eb)
        self._cross_verify_geometry(geom, align_off=f1)
        return geom

    def _disambiguate_geometry_gen2(self, candidates: list, first_ec_off: int) -> Optional[Tuple[int, int]]:
        """Gen2 content-evidence geometry disambiguation (additive — legacy
        _measure_stride is untouched and remains the fallback).

        EVERY candidate geometry is scored independently on its own stripped
        window (16 raw EBs from the first EC header). Same-ratio candidates
        are NOT equivalent — (512,16) removes 16B after every 512B while
        (2048,64) removes 64B after every 2048B, producing different clean
        bytes — so each candidate gets its own evidence score:

          1. fs_magic hits at the EC-declared data offset (strongest)
          2. volume-table record names parsed from the VTBL volume
          3. EC header CRC validity (crc32 / vendor ~crc32, auto-voted)
          4. EC headers on clean PEB boundaries + VIDs at vid_hdr_offset

        Score tuple: (fs_hits, vtbl_names, ec_crc, ec_hits, vid_hits).
        Full ties resolve to the smaller page size (v1.0 legacy default).
        """
        try:
            first_ec = ECHeader.parse(self.data, first_ec_off, 0)
        except Exception:
            first_ec = None
        vhf = first_ec.vid_hdr_offset if first_ec else 0x800
        doff = first_ec.data_offset if first_ec else 0x1000

        WINDOW_EBS = 16
        fs_magics = [m for m, _, _, _, _ in FS_SCAN_SIGNATURES]
        scored = []
        for page_size, oob_size, stride, pages, clean_eb in candidates:
            raw_eb = stride * pages
            win_raw = self.data[first_ec_off: first_ec_off + WINDOW_EBS * raw_eb]
            win_clean = bytearray()
            pos = 0
            while pos + page_size <= len(win_raw):
                win_clean.extend(win_raw[pos:pos + page_size])
                pos += stride
            win_clean = bytes(win_clean)
            n_eb = len(win_clean) // clean_eb
            ec_hits = vid_hits = ec_crc = fs_hits = vtbl_names = 0
            votes: Dict[str, int] = {}
            for k in range(n_eb):
                base = k * clean_eb
                if win_clean[base:base+4] != UBI_EC_MAGIC:
                    continue
                ec_hits += 1
                ok, c = ECHeader._verify(win_clean, base)
                if ok:
                    ec_crc += 1
                    key = c.split("@")[0]
                    votes[key] = votes.get(key, 0) + 1
                vbase = base + vhf
                if vbase + 12 <= len(win_clean) and win_clean[vbase:vbase+4] == UBI_VID_MAGIC \
                        and win_clean[vbase+8:vbase+12] == struct.pack(">I", VolumeTable.VTBL_VOL_ID):
                    dchunk = win_clean[base+doff: base+doff+clean_eb-doff]
                    vtbl_names += len(VolumeTable.parse(dchunk))
                    continue
                if vbase + 4 <= len(win_clean) and win_clean[vbase:vbase+4] == UBI_VID_MAGIC:
                    vid_hits += 1
                dbase = base + doff
                for m in fs_magics:
                    if win_clean[dbase:dbase+len(m)] == m:
                        fs_hits += 1
                        break
            conv = max(votes.items(), key=lambda kv: kv[1])[0] if votes else None
            score = (fs_hits, vtbl_names, ec_crc, ec_hits, vid_hits)
            scored.append((score, page_size, oob_size))
            log.info("Gen2 geometry candidate page=%d oob=%d: fs_magics=%d "
                     "vtbl_names=%d ec_crc_ok=%d/%d ec_boundary=%d vid=%d%s",
                     page_size, oob_size, fs_hits, vtbl_names, ec_crc, ec_hits,
                     ec_hits, vid_hits, f" crc_conv={conv}" if conv else "")
        if not scored:
            return None
        scored.sort(key=lambda t: t[0], reverse=True)
        best_score, best_page, best_oob = scored[0]
        if best_score == (0, 0, 0, 0, 0):
            log.info("Gen2: no candidate scored structural evidence")
            return None
        tied = [s for s in scored if s[0] == best_score]
        if len(tied) > 1:
            log.info("Gen2: %d candidates tie at %s — preferring smallest page "
                     "(v1.0 legacy default)", len(tied), best_score)
            best_page, best_oob = tied[0][1], tied[0][2]
        return best_page, best_oob

    # ── Gen3: tiered geometry disambiguation (additive, v1.1.2) ─────────────
    #
    # Empirical result from the validation images: on raw-NAND UBI dumps the
    # EC/VID/VTBL header positions are RATIO-EQUIVALENT for same-ratio
    # candidates ((512,16) and (2048,64) both map clean 0x800 -> raw 0x840),
    # so structural evidence alone (gen2) can never split them. Two evidence
    # sources DO split them:
    #
    #   1. VID/VTBL presence per candidate (eliminates wrong-page-count
    #      candidates, e.g. (4096,128) maps vhf 0x800 to a different raw
    #      offset) — but the gen2 window (16 EBs) can be too short: images
    #      exist where the first 40+ PEBs of a region are EC-only (erased
    #      but EC-incremented) and the first VID comes much later. Gen3
    #      therefore extends the window adaptively until it contains
    #      min_vid_evid VIDs (or the window exceeds max_frac of the EC span).
    #   2. OOB-zone FF density on WRITTEN PEBs: a written NAND page carries
    #      ECC/strict-bytes in its OOB area (mostly non-FF), while a wrong
    #      candidate's "OOB" windows overlap page DATA (mostly non-FF too)
    #      — the true candidate maximises (oob_ff - data_ff) divergence.
    #      Measured to rank the true geometry #1 across the whole validation
    #      set; used ONLY as the ratio-pair splitter, with a margin guard:
    #      a thin margin (< FF_MARGIN_MIN) is logged and falls back to the
    #      smallest-page legacy default instead of guessing.
    #
    # Everything is additive: gen3 failure of any kind falls through to gen2
    # (structural), then _measure_stride (legacy), without raising.
    GEN3_MIN_VID_EVID = 32       # window grows until this many VID magics seen
    GEN3_MAX_EB_STEPS = 16       # window grows in this many raw EBs per step
    GEN3_MAX_EB_FRACTION = 0.9   # ... never beyond this fraction of EC span
    FF_MARGIN_MIN = 0.05         # min (best - second) FF-delta margin to trust
    FS_VALIDATE_MARGIN = 0.05    # FF margin below this → decisive tier engages
    FS_VALIDATE_MIN_DELTA = 0.01 # decisive tier needs a real FF signal at all
    FS_VALIDATE_MIN_RATE = 0.60  # decisive tier: min node-CRC pass rate to accept
    FS_VALIDATE_MAX_BYTES = 64 * 1024 * 1024   # per-candidate assembly cap
    FS_VALIDATE_MAX_EBS = 512    # per-candidate LEB-span cap

    def _disambiguate_geometry_gen3(self, candidates: list, first_ec_off: int) -> Optional[Tuple[int, int]]:
        """Gen3 (v1.1.2): adaptive-window structural scoring (gen2 rules, longer
        window) + OOB FF-density tie-break between ratio-equivalent survivors.
        Returns (page, oob) or None (fall through to gen2). Never raises."""
        try:
            return self._gen3_impl(candidates, first_ec_off)
        except Exception as exc:
            log.warning("Gen3 disambiguation failed internally (%s) — continuing", exc)
            return None

    def _gen3_impl(self, candidates: list, first_ec_off: int) -> Optional[Tuple[int, int]]:
        try:
            first_ec = ECHeader.parse(self.data, first_ec_off, 0)
        except Exception:
            first_ec = None
        vhf = first_ec.vid_hdr_offset if first_ec else 0x800
        doff = first_ec.data_offset if first_ec else 0x1000

        # EC span upper bound for the window cap (EC count * raw EB).
        total = len(self.data)
        f2 = self.data.find(UBI_EC_MAGIC, first_ec_off + 1)
        raw_eb0 = getattr(self, "_raw_eb", None) or \
            ((f2 - first_ec_off) if f2 > 0 else None)
        span_cap_ebs = None
        if raw_eb0:
            n_ec = self.data.count(UBI_EC_MAGIC)
            span_cap_ebs = max(self.GEN3_MAX_EB_STEPS, int(n_ec * self.GEN3_MAX_EB_FRACTION))

        fs_magics = [m for m, _, _, _, _ in FS_SCAN_SIGNATURES]
        scored = []
        window_ebs = self.GEN3_MAX_EB_STEPS
        while True:
            win_raw = self.data[first_ec_off: first_ec_off + window_ebs * raw_eb0] \
                if raw_eb0 else b""
            if not win_raw:
                break
            per_cand = []
            for page_size, oob_size, stride, pages, clean_eb in candidates:
                raw_eb = stride * pages
                win_clean = bytearray()
                pos = 0
                while pos + page_size <= len(win_raw):
                    win_clean.extend(win_raw[pos:pos + page_size])
                    pos += stride
                win_clean = bytes(win_clean)
                n_eb = len(win_clean) // clean_eb
                ec_hits = vid_hits = ec_crc = fs_hits = vtbl_names = 0
                for k in range(n_eb):
                    base = k * clean_eb
                    if win_clean[base:base + 4] != UBI_EC_MAGIC:
                        continue
                    ec_hits += 1
                    ok, _c = ECHeader._verify(win_clean, base)
                    if ok:
                        ec_crc += 1
                    vbase = base + vhf
                    if vbase + 12 <= len(win_clean) and win_clean[vbase:vbase + 4] == UBI_VID_MAGIC \
                            and win_clean[vbase + 8:vbase + 12] == struct.pack(">I", VolumeTable.VTBL_VOL_ID):
                        dchunk = win_clean[base + doff: base + doff + clean_eb - doff]
                        vtbl_names += len(VolumeTable.parse(dchunk))
                        continue
                    if vbase + 4 <= len(win_clean) and win_clean[vbase:vbase + 4] == UBI_VID_MAGIC:
                        vid_hits += 1
                    dbase = base + doff
                    for m in fs_magics:
                        if win_clean[dbase:dbase + len(m)] == m:
                            fs_hits += 1
                            break
                score = (fs_hits, vtbl_names, ec_crc, ec_hits, vid_hits)
                per_cand.append((score, page_size, oob_size, stride))
            # adaptive stop: some candidate sees >= MIN_VID_EVID VID magics
            if any(s[0][4] >= self.GEN3_MIN_VID_EVID for s in per_cand):
                scored = per_cand
                log.info("Gen3: window %d EBs — %d VID evidence reached",
                         window_ebs, max(s[0][4] for s in per_cand))
                break
            if span_cap_ebs and window_ebs >= span_cap_ebs:
                scored = per_cand
                log.info("Gen3: window %d EBs (EC-span cap) — best VID evidence %d",
                         window_ebs, max((s[0][4] for s in per_cand), default=0))
                break
            if first_ec_off + (window_ebs + self.GEN3_MAX_EB_STEPS) * (raw_eb0 or 0) > total:
                scored = per_cand
                log.info("Gen3: window %d EBs (image end) — best VID evidence %d",
                         window_ebs, max((s[0][4] for s in per_cand), default=0))
                break
            window_ebs += self.GEN3_MAX_EB_STEPS
        if not scored:
            return None
        for score, page_size, oob_size, stride in scored:
            log.info("Gen3 candidate page=%d oob=%d: fs=%d vtbl=%d ec_crc=%d "
                     "ec_hits=%d vid=%d", page_size, oob_size, *score)

        scored.sort(key=lambda t: t[0], reverse=True)
        best_score = scored[0][0]
        if best_score == (0, 0, 0, 0, 0):
            log.info("Gen3: no structural evidence at all")
            return None
        tied = [s for s in scored if s[0] == best_score]
        if len(tied) == 1:
            log.info("Gen3: structural evidence decided page=%d oob=%d",
                     tied[0][1], tied[0][2])
            return tied[0][1], tied[0][2]

        # ratio-equivalent survivors (same structural score) → VID-alignment
        # probe FIRST (global, decisive for stride-aliasing cases), then
        # FF-density as a weaker fallback.
        vid_scores = []
        for _score, page_size, oob_size, stride in tied:
            va = self._vid_alignment_score(first_ec_off, vhf, page_size,
                                           oob_size, stride)
            if va is not None:
                vid_scores.append((va, page_size, oob_size))
            log.info("Gen3 VID-alignment (page=%d oob=%d): %s",
                     page_size, oob_size,
                     "n/a" if va is None else f"{va} aligned hits")
        if vid_scores:
            vid_scores.sort(key=lambda t: t[0], reverse=True)
            best_va = vid_scores[0][0]
            winners = [v for v in vid_scores if v[0] == best_va]
            if best_va > 0 and len(winners) == 1:
                log.info("Gen3: VID-alignment decided page=%d oob=%d "
                         "(%d aligned hits)", winners[0][1], winners[0][2],
                         winners[0][0])
                return winners[0][1], winners[0][2]
        log.info("Gen3: VID-alignment inconclusive — falling back to FF-density")

        ff_scores = []
        for _score, page_size, oob_size, stride in tied:
            ff = self._ff_density_delta(first_ec_off, window_ebs, page_size,
                                        oob_size, stride)
            if ff is not None:
                ff_scores.append((ff, page_size, oob_size))
            log.info("Gen3 FF-density (page=%d oob=%d): %s",
                     page_size, oob_size,
                     "n/a (no written PEBs in window)" if ff is None else f"{ff:+.4f}")
        if not ff_scores:
            return None
        ff_scores.sort(key=lambda t: t[0], reverse=True)
        if len(ff_scores) > 1:
            margin = ff_scores[0][0] - ff_scores[1][0]
            if margin < self.FS_VALIDATE_MARGIN and ff_scores[0][0] >= self.FS_VALIDATE_MIN_DELTA:
                # thin FF margin → decisive tier: FS-content validation
                log.info("Gen3: FF-density margin %.4f < %.4f — falling through "
                         "to FS-content decisive tier", margin, self.FS_VALIDATE_MARGIN)
                decided = self._fs_validate_tied(first_ec_off, window_ebs, ff_scores, vhf, doff)
                if decided is not None:
                    return decided
                log.info("Gen3: FS-content decisive tier inconclusive — "
                         "preferring smallest page (v1.0 legacy default)")
                return None
            if margin < self.FS_VALIDATE_MARGIN:
                log.info("Gen3: FF-density margin %.4f < %.4f — thin; "
                         "preferring smallest page (v1.0 legacy default)",
                         margin, self.FS_VALIDATE_MARGIN)
                return None
            log.info("Gen3: FF-density margin %.4f — decided page=%d oob=%d",
                     margin, ff_scores[0][1], ff_scores[0][2])
        return ff_scores[0][1], ff_scores[0][2]

    # ── Gen3 decisive tier: FS-content validation (v1.1.2) ──────────────────
    #
    # Rationale: for ratio-equivalent candidates the EC/VID/VTBL header
    # positions coincide and the FF-density delta can be thin. The ONLY
    # signal that cannot be faked by a wrong page size is deep FS content:
    # under the wrong page size the volume data stream is shredded, so
    # filesystem-internal integrity structures (UBIFS node chain CRCs,
    # SquashFS metadata) fail, while under the true geometry they validate.
    # Measured on the validation set (UBIFS volumes): true geometry passes
    # ~100% of node-chain CRCs; wrong ratio-equivalent candidates < 11%.
    #
    # UBIFS node chain: common header <IIQIBB2s> (magic 'UBI#$', node CRC
    # u32 @+4, sqnum @+8, len u32 @+16, type/group @+20/21); nodes are
    # 8-byte aligned inside each LEB; node CRC covers node[8:len].
    # Vendor convention check: plain crc32 AND inverted (~crc32) accepted,
    # mirroring the EC/VID CRC convention handling elsewhere in this file.

    @staticmethod
    def _ubifs_node_crc_rate(blob: bytes, leb_size: int) -> Optional[float]:
        """Walk UBIFS node chains in an assembled volume image; return the
        fraction of nodes whose stored header CRC validates. None if the
        image holds no UBIFS nodes at all."""
        magic = b"\x31\x18\x10\x06"
        total = ok = 0
        if leb_size <= 0:
            return None
        for li in range(len(blob) // leb_size):
            d = blob[li * leb_size: (li + 1) * leb_size]
            pos = 0
            while pos + 24 <= leb_size:
                if d[pos:pos + 4] != magic:
                    break
                crc = struct.unpack_from("<I", d, pos + 4)[0]
                ln = struct.unpack_from("<I", d, pos + 16)[0]
                if ln < 24 or pos + ln > leb_size:
                    break
                calc_plain = zlib.crc32(d[pos + 8: pos + ln]) & 0xFFFFFFFF
                calc_inv = (~calc_plain) & 0xFFFFFFFF
                total += 1
                ok += 1 if crc in (calc_plain, calc_inv) else 0
                pos = (pos + ln + 7) & ~7
        return (ok / total) if total else None

    def _fs_validate_tied(self, first_ec_off: int, window_ebs: int, tied: list,
                          vhf: int, doff: int) -> Optional[Tuple[int, int]]:
        """Decisive tie-break: for each surviving candidate, assemble the
        largest volume's LEB chain and score UBIFS node-chain CRC pass rate
        (SquashFS volumes are scored by the same routine's caller fallback —
        None rate just means no UBIFS nodes). Highest rate above
        FS_VALIDATE_MIN_RATE wins; ties prefer the smaller page. Never raises."""
        try:
            results = []
            for _ff, page_size, oob_size in tied:
                stride = page_size + oob_size
                rate = self._fs_validate_candidate(first_ec_off, page_size,
                                                   oob_size, stride, vhf, doff)
                if rate is not None:
                    results.append((rate, page_size, oob_size))
                log.info("Gen3 FS-validate (page=%d oob=%d): node-crc rate=%s",
                         page_size, oob_size,
                         "n/a" if rate is None else f"{rate:.4f}")
            if not results:
                return None
            results.sort(key=lambda t: t[0], reverse=True)
            if results[0][0] < self.FS_VALIDATE_MIN_RATE:
                return None
            if len(results) > 1 and results[0][0] == results[1][0]:
                log.info("Gen3 FS-validate: perfect tie — smallest page wins")
            log.info("Gen3 FS-validate: decided page=%d oob=%d (rate %.4f)",
                     results[0][1], results[0][2], results[0][0])
            return results[0][1], results[0][2]
        except Exception as exc:
            log.warning("Gen3 FS-validate failed internally (%s)", exc)
            return None

    def _fs_validate_candidate(self, first_ec_off: int, page_size: int,
                               oob_size: int, stride: int, vhf: int,
                               doff: int) -> Optional[float]:
        """Assemble the largest volume's LEB chain under one candidate
        geometry and return its UBIFS node-CRC pass rate (None if no UBI/UBIFS
        evidence). Heavily bounded: span ≤ FS_VALIDATE_MAX_EBS LEBs and
        ≤ FS_VALIDATE_MAX_BYTES per candidate."""
        raw_eb = None
        f2 = self.data.find(UBI_EC_MAGIC, first_ec_off + 1)
        raw_eb = (f2 - first_ec_off) if f2 > 0 else 0
        raw_eb = getattr(self, "_raw_eb", 0) or raw_eb
        if not raw_eb or raw_eb % stride:
            return None
        pages_per_eb = raw_eb // stride
        clean_eb = pages_per_eb * page_size
        if clean_eb <= doff:
            return None
        leb_size = clean_eb - doff
        vid_raw_in_peb = (vhf // page_size) * stride
        dat_raw_in_peb = (doff // page_size) * stride

        vols: Dict[int, Dict[int, bytes]] = {}
        off = first_ec_off
        while off + raw_eb <= len(self.data):
            peb = self.data[off: off + raw_eb]
            off += raw_eb
            if peb[:4] != UBI_EC_MAGIC:
                continue
            vid_raw_pos = vid_raw_in_peb
            if vid_raw_pos + 12 > len(peb):
                continue
            if peb[vid_raw_pos: vid_raw_pos + 4] != UBI_VID_MAGIC:
                continue
            vol_id = struct.unpack(">I", peb[vid_raw_pos + 8: vid_raw_pos + 12])[0]
            lnum = struct.unpack(">I", peb[vid_raw_pos + 12: vid_raw_pos + 16])[0] & 0xFFFF
            if vol_id >= 0x7FFFEFFF:
                continue
            data = bytearray()
            pos = dat_raw_in_peb
            while pos + page_size <= len(peb):
                data.extend(peb[pos: pos + page_size])
                pos += stride
            vols.setdefault(vol_id, {})[lnum] = bytes(data)

        if not vols:
            return None
        vol_id = max(vols, key=lambda v: len(vols[v]))
        lebs = vols[vol_id]
        span = (max(lebs) + 1) if lebs else 0
        if span <= 0 or span > self.FS_VALIDATE_MAX_EBS:
            return None
        span = min(span, self.FS_VALIDATE_MAX_EBS)
        if span * leb_size > self.FS_VALIDATE_MAX_BYTES:
            return None
        blob = bytearray()
        for i in range(span):
            blob.extend(lebs.get(i, b"\xff" * leb_size))
        return self._ubifs_node_crc_rate(bytes(blob), leb_size)

    def _vid_alignment_score(self, first_ec_off: int, vhf: int, page_size: int,
                             oob_size: int, stride: int,
                             sample_ebs: int = 64) -> Optional[int]:
        """Stride-aliasing discriminator: count sampled PEBs whose VID magic
        lands EXACTLY at the EC-declared vid_hdr_offset AFTER OOB stripping.
        Ratio-aliased strides (e.g. 1088 vs 2176) keep page-starts aligned so
        magic bytes still appear somewhere in the stripped stream — but only
        the TRUE stride preserves the declared intra-page offset. Sampled
        globally (whole image) so erased areas can't starve the evidence."""
        try:
            f2 = self.data.find(UBI_EC_MAGIC, first_ec_off + 1)
            raw_eb = (f2 - first_ec_off) if f2 > 0 else 0
            raw_eb = getattr(self, "_raw_eb", 0) or raw_eb
            if not raw_eb or raw_eb % stride: return None
            pages = raw_eb // stride
            hits = misses = 0
            peb_step = max(1, pages * 8)  # sample every ~8th PEB
            off = first_ec_off
            n = 0
            while off + raw_eb <= len(self.data) and n < sample_ebs:
                peb = self.data[off: off + raw_eb]
                off += raw_eb * peb_step; n += 1
                if peb[:4] != UBI_EC_MAGIC: continue
                # zero-copy probe: map vhf (clean coords) into raw coords
                raw_v = (vhf // page_size) * stride + (vhf % page_size)
                if raw_v + 4 <= len(peb) and peb[raw_v:raw_v+4] == UBI_VID_MAGIC:
                    hits += 1
                else:
                    misses += 1
            if hits + misses < 8: return None  # insufficient evidence
            return hits
        except Exception:
            return None

    def _ff_density_delta(self, first_ec_off: int, window_ebs: int,
                          page_size: int, oob_size: int, stride: int,
                          global_sample: bool = True,
                          max_written: int = 256) -> Optional[float]:
        """(FF fraction in OOB windows) - (FF fraction in data windows), over
        WRITTEN raw PEBs. By default samples written PEBs across the WHOLE
        image (global_sample) — early-flash windows are frequently all-erased
        (EC-only), which starves the metric exactly when it is needed as a
        tie-break. Returns None if no written PEBs found."""
        if not oob_size or not page_size:
            return None
        n_eb = 0
        oob_ff = data_ff = 0.0
        n_written = 0
        raw_eb = None
        f2 = self.data.find(UBI_EC_MAGIC, first_ec_off + 1)
        # detect() sets the robust value before any tie-break can fire
        raw_eb = getattr(self, "_raw_eb", 0) or \
            ((f2 - first_ec_off) if f2 > 0 else 0)
        if not raw_eb:
            return None
        limit = len(self.data) if global_sample else \
            first_ec_off + window_ebs * raw_eb
        off = first_ec_off
        while off + raw_eb <= limit:
            peb = self.data[off: off + raw_eb]
            off += raw_eb
            n_eb += 1
            if peb[:4] != UBI_EC_MAGIC:
                continue
            pages = len(peb) // stride
            p_data_ff = p_oob_ff = 0.0
            n_d = n_o = 0
            for k in range(pages):
                d = peb[k * stride: k * stride + page_size]
                o = peb[k * stride + page_size: k * stride + stride]
                if d:
                    p_data_ff += d.count(0xFF) / len(d); n_d += 1
                if o:
                    p_oob_ff += o.count(0xFF) / len(o); n_o += 1
            if not n_d or not n_o:
                continue
            p_data_ff /= n_d; p_oob_ff /= n_o
            if p_data_ff > 0.999 and p_oob_ff > 0.999:
                continue  # erased PEB (EC-only) — no evidence
            n_written += 1
            oob_ff += p_oob_ff; data_ff += p_data_ff
            if n_written >= max_written:
                break
        if not n_written:
            return None
        log.debug("Gen3 FF: page=%d written=%d oob_ff=%.4f data_ff=%.4f",
                  page_size, n_written, oob_ff / n_written, data_ff / n_written)
        return (oob_ff / n_written) - (data_ff / n_written)

    def _measure_stride(self, candidates: list) -> Tuple[int, int]:
        try:
            vid_off = struct.unpack(">I", self.data[0x10:0x14])[0]
            gap = self.data[64:vid_off]
        except struct.error:
            return candidates[0][0], candidates[0][1]
        first_nonff = next((i for i in range(len(gap)) if gap[i] != 0xFF), None)
        if first_nonff is None: return candidates[0][0], candidates[0][1]
        marker = gap[first_nonff:first_nonff + 8]
        positions, pos = [], 0
        while len(positions) < 20:
            idx = self.data.find(marker, pos)
            if idx < 0: break
            positions.append(idx)
            pos = idx + 1
        if len(positions) >= 2:
            measured = positions[1] - positions[0]
            for page_size, oob_size, stride, *_ in candidates:
                if stride == measured: return page_size, oob_size
        return candidates[0][0], candidates[0][1]

    def _build_geometry(self, page_size: int, oob_size: int, raw_eb: int) -> OOBGeometry:
        stride = page_size + oob_size
        pages_per_eb = raw_eb // stride
        clean_eb = pages_per_eb * page_size
        return OOBGeometry(page_size, oob_size, stride, raw_eb, clean_eb, pages_per_eb, True)

    def strip(self, geom: OOBGeometry) -> bytes:
        if not geom.has_oob: return self.data
        log.info("Stripping OOB: stride=%d, keeping %dB, skipping %dB", geom.stride, geom.page_size, geom.oob_size)
        clean = bytearray()
        pos = 0
        total = len(self.data)
        with tqdm(total=total, unit="B", unit_scale=True, desc="Stripping OOB", disable=not HAS_TQDM) as pbar:
            while pos + geom.page_size <= total:
                clean.extend(self.data[pos:pos + geom.page_size])
                pos += geom.stride
                pbar.update(geom.stride)
        log.info("OOB stripped: %s → %s bytes", f"{len(self.data):,}", f"{len(clean):,}")
        return bytes(clean)

    @staticmethod
    def raw_to_clean_offset(raw_offset: int, geom: OOBGeometry, *, reject_oob: bool = True) -> Optional[int]:
        if not geom.has_oob: return raw_offset
        page_index = raw_offset // geom.stride
        in_stride = raw_offset % geom.stride
        if in_stride >= geom.page_size:
            if reject_oob: return None
            return page_index * geom.page_size + geom.page_size
        return page_index * geom.page_size + in_stride

    @staticmethod
    def clean_to_raw_offset(clean_offset: int, geom: OOBGeometry) -> int:
        if not geom.has_oob: return clean_offset
        page_index = clean_offset // geom.page_size
        in_page = clean_offset % geom.page_size
        return page_index * geom.stride + in_page

    @staticmethod
    def clean_range_to_raw_range(clean_start: int, clean_end: int, geom: OOBGeometry) -> Tuple[int, int]:
        """Maps half-open range [clean_start, clean_end) to [raw_start, raw_end)."""
        raw_start = OOBDetector.clean_to_raw_offset(clean_start, geom)
        raw_end = OOBDetector.clean_to_raw_offset(clean_end, geom)
        return raw_start, raw_end


# ═══════════════════════════════════════════════════════════════════════════
#  UBI HEADER PARSING & SCANNING
# ═══════════════════════════════════════════════════════════════════════════

class ECHeader:
    SIZE = 64
    @staticmethod
    def parse(data: bytes, offset: int, peb_index: int) -> Optional[ECHeaderInfo]:
        if data[offset:offset+4] != UBI_EC_MAGIC: return None
        try:
            return ECHeaderInfo(offset=offset, peb_index=peb_index, version=data[offset+4],
                                ec=struct.unpack_from(">Q", data, offset+8)[0],
                                vid_hdr_offset=struct.unpack_from(">I", data, offset+16)[0],
                                data_offset=struct.unpack_from(">I", data, offset+20)[0],
                                image_seq=struct.unpack_from(">I", data, offset+24)[0],
                                hdr_crc=struct.unpack_from(">I", data, offset+60)[0])
        except struct.error: return None

    @staticmethod
    def _verify(data: bytes, offset: int) -> Tuple[bool, str]:
        """Verify an EC header's CRC. Accepts the plain crc32 (Linux), the
        vendor-inverted ~crc32, or a 60-byte coverage variant.
        Returns (ok, convention) — pure additive validator, never raises."""
        try:
            stored = struct.unpack_from(">I", data, offset+60)[0]
        except struct.error:
            return False, "short"
        if stored == 0xFFFFFFFF or stored == 0x00000000:
            return False, "blank"
        cov = 60
        # Some vendors XOR-out the CRC word; also cover variant lengths
        for coverage in (60, 64):
            if coverage > len(data) - offset: continue
            base = zlib.crc32(data[offset:offset+coverage]) & 0xFFFFFFFF
            for name, c in (("crc32", base), ("~crc32", ~base & 0xFFFFFFFF)):
                if c == stored:
                    return True, f"{name}@len{coverage}"
        return False, "no-match"

class VIDHeader:
    SIZE = 64
    @staticmethod
    def parse(data: bytes, offset: int, peb_index: int) -> Optional[VIDHeaderInfo]:
        if data[offset:offset+4] != UBI_VID_MAGIC: return None
        try:
            return VIDHeaderInfo(offset=offset, peb_index=peb_index, version=data[offset+4],
                                 vol_type=data[offset+5], copy_flag=data[offset+6], compat=data[offset+7],
                                 vol_id=struct.unpack_from(">I", data, offset+8)[0],
                                 lnum=struct.unpack_from(">I", data, offset+12)[0],
                                 data_size=struct.unpack_from(">I", data, offset+20)[0],
                                 used_ebs=struct.unpack_from(">I", data, offset+24)[0],
                                 data_pad=struct.unpack_from(">I", data, offset+28)[0],
                                 sqnum=struct.unpack_from(">Q", data, offset+0x28)[0],
                                 hdr_crc=struct.unpack_from(">I", data, offset+60)[0])
        except struct.error: return None

    @staticmethod
    def parse_be72(data: bytes, offset: int, peb_index: int) -> Optional["VIDHeaderInfo"]:
        """Linux-standard 72-byte ubi_vid_hdr layout (additive variant):

            magic(4) ver(1) vol_type(1) copy(1) compat(1)
            vol_id(4)@+8   lnum(4)@+12      leb_ver(4)@+16  data_size(4)@+20
            used_ebs(4)@+24 data_pad(4)@+28 data_crc(4)@+32
            reserved(12)@+36..47  sqnum(8)@+48 (0x30)  reserved(12)@+56..67
            hdr_crc(4)@+68 (0x44), CRC over bytes [0:68)

        The legacy 64-byte 'parse' above stays the primary path untouched;
        this variant is used by the gen2 consensus scanner when the legacy
        layout fails sanity checks.
        """
        if data[offset:offset+4] != UBI_VID_MAGIC: return None
        try:
            return VIDHeaderInfo(offset=offset, peb_index=peb_index, version=data[offset+4],
                                 vol_type=data[offset+5], copy_flag=data[offset+6], compat=data[offset+7],
                                 vol_id=struct.unpack_from(">I", data, offset+8)[0],
                                 lnum=struct.unpack_from(">I", data, offset+12)[0],
                                 data_size=struct.unpack_from(">I", data, offset+20)[0],
                                 used_ebs=struct.unpack_from(">I", data, offset+24)[0],
                                 data_pad=struct.unpack_from(">I", data, offset+28)[0],
                                 sqnum=struct.unpack_from(">Q", data, offset+0x30)[0],
                                 hdr_crc=struct.unpack_from(">I", data, offset+68)[0])
        except struct.error: return None

    @staticmethod
    def parse_vendor16(data: bytes, offset: int, peb_index: int) -> Optional["VIDHeaderInfo"]:
        """Vendor-compact layout seen on some raw NAND dumps (additive):

        64-byte header where lnum is a BE16 at +14 and +12..13 carry flags
        (observed values 0x0000/0x0002/0x8000-ish on vendor images). All
        other fields as in the legacy layout. Additive — used only by the
        gen2 consensus scanner when it scores better than the standard
        BE32@+12 layout.
        """
        if data[offset:offset+4] != UBI_VID_MAGIC: return None
        try:
            info = VIDHeader.parse(data, offset, peb_index)
            if info is None: return None
            info.lnum = struct.unpack_from(">H", data, offset+14)[0]
            return info
        except struct.error: return None

    # Known VID parse layouts (documentation only — the consensus scanner
    # wasn't shipped; parse() + _verify()'s coverage ladder handle all
    # currently-known vendor variants).
    LAYOUTS = (
        ("std64", "legacy parse() — lnum BE32@+12, crc@+60"),
        ("linux72", "parse_be72() — lnum BE32@+12, sqnum@+0x30, crc@+68"),
        ("vendor16", "parse_vendor16() — lnum BE16@+14"),
    )

    @staticmethod
    def _verify(data: bytes, offset: int) -> Tuple[bool, str]:
        """Verify a VID header CRC. Tries the 64-byte coverage (matching the
        64-byte parse) as primary, then 68/72-byte Linux ubi_vid_hdr coverage,
        accepting plain crc32 and vendor-inverted ~crc32. Pure additive."""
        try:
            stored = struct.unpack_from(">I", data, offset+60)[0]
        except struct.error:
            return False, "short"
        if stored == 0xFFFFFFFF or stored == 0x00000000:
            return False, "blank"
        for coverage in (60, 64, 68, 72):
            if coverage > len(data) - offset: continue
            base = zlib.crc32(data[offset:offset+coverage]) & 0xFFFFFFFF
            for name, c in (("crc32", base), ("~crc32", ~base & 0xFFFFFFFF)):
                if c == stored:
                    return True, f"{name}@len{coverage}"
        return False, "no-match"

class VolumeTable:
    VTBL_VOL_ID = 0x7FFFEFFF
    RECORD_SIZE = 172
    @staticmethod
    def parse(data: bytes) -> Dict[int, str]:
        names = {}
        for i in range(VTBL_MAX_VOLUMES):
            offset = i * VolumeTable.RECORD_SIZE
            if offset + VolumeTable.RECORD_SIZE > len(data): break
            record = data[offset:offset + VolumeTable.RECORD_SIZE]
            try: name_len = struct.unpack_from(">H", record, 0x0E)[0]
            except struct.error: continue
            if name_len == 0 or name_len > 127: continue
            try: names[i] = record[0x10:0x10 + name_len].decode("utf-8", errors="replace")
            except Exception: pass
        return names

class UBIScanner:
    def __init__(self, clean_data: bytes, forced_peb: Optional[int] = None, forced_leb: Optional[int] = None):
        self.data = clean_data
        self.forced_peb = forced_peb
        self.forced_leb = forced_leb

    def scan(self) -> List[UBIRegion]:
        log.info("Scanner: locating EC headers (%d bytes)...", len(self.data))
        ec_headers = self._find_ec_headers()
        if not ec_headers:
            log.warning("Scanner: no EC headers found")
            return []
        peb_size = self._determine_peb_size(ec_headers)
        log.info("Scanner: %d EC headers, PEB=0x%X (%d B)", len(ec_headers), peb_size, peb_size)
        regions_raw = self._group_regions(ec_headers, peb_size)
        log.info("Scanner: %d region group(s) (attach/gap grouping)", len(regions_raw))
        regions = []
        for i, region_ecs in enumerate(regions_raw):
            log.info("Scanner: region group %d: %d PEBs @0x%X..0x%X",
                     i, len(region_ecs), region_ecs[0].offset,
                     region_ecs[-1].offset + peb_size)
            region = self._process_region(region_ecs, peb_size)
            if region: regions.append(region)
        return regions

    def _find_ec_headers(self) -> List[ECHeaderInfo]:
        headers, pos, peb_idx = [], 0, 0
        with tqdm(total=len(self.data), unit="B", unit_scale=True, desc="Scanning EC headers", disable=not HAS_TQDM) as pbar:
            while pos < len(self.data):
                idx = self.data.find(UBI_EC_MAGIC, pos)
                if idx < 0: break
                ec = ECHeader.parse(self.data, idx, peb_idx)
                if ec:
                    headers.append(ec)
                    peb_idx += 1
                    pbar.update(idx - pos)
                    pos = idx + ECHeader.SIZE
                else: pos = idx + 4
        log.info("EC scan: %d EC header(s) found", len(headers))
        # Dedupe redundant vendor copies: some images write every EC header
        # twice a few KiB apart. Downstream PEB-size detection, region
        # grouping and VID scanning all assume one header per physical PEB.
        dedup = []
        for h in headers:
            if dedup and h.offset - dedup[-1].offset < 0x1000 and \
               bytes(self.data[h.offset:h.offset + 64]) == \
               bytes(self.data[dedup[-1].offset:dedup[-1].offset + 64]):
                continue
            dedup.append(h)
        if len(dedup) != len(headers):
            log.info("EC scan: deduped %d redundant header copy(ies) → %d unique",
                     len(headers) - len(dedup), len(dedup))
        return dedup

    def _determine_peb_size(self, ec_headers: List[ECHeaderInfo]) -> int:
        if self.forced_peb: return self.forced_peb
        if len(ec_headers) < 2:
            # Single-EC images: fall back to the OOBDetector's evidence-based
            # raw-EB estimate (shared via _raw_eb) — never a constant.
            dyn = getattr(self, "_peb_hint", None) or \
                getattr(getattr(self, "_oob_geom", None), "raw_eb_size", None)
            if dyn: return dyn
            raise ValueError(
                "cannot derive PEB size: only one EC header and no geometry hint")
        # NOTE: _find_ec_headers already deduped redundant vendor copies —
        # operate on the unique headers directly.
        offsets = sorted(h.offset for h in ec_headers)
        data_off = max(h.data_offset for h in ec_headers)
        gaps = [b - a for a, b in zip(offsets, offsets[1:]) if b - a > 0]
        # A valid PEB stride must exceed the data offset (LEB = PEB - data_off
        # must stay positive) — filters duplicate intervals and stray matches.
        plausible = [g for g in gaps if g > data_off]
        # Secondary corroboration: majority of EC headers must sit on the
        # chosen stride's lattice — guards against stray magic matches.
        plausible_sorted = sorted(plausible, key=plausible.count, reverse=True)
        for cand in plausible_sorted[:6]:
            on_lattice = sum(1 for o in offsets if (o - offsets[0]) % cand == 0)
            if on_lattice >= len(offsets) * 0.8:
                log.info("PEB size derived: 0x%X (%d/%d headers on-lattice, "
                         "%d/8 top gap-freq corroboration)",
                         cand, on_lattice, len(offsets), plausible.count(cand))
                return cand
        if plausible:
            cand = max(set(plausible), key=plausible.count)
            log.info("PEB size derived (modal, weak corroboration): 0x%X", cand)
            return cand
        # Last resort: geometry-derived hint from the OOB detector stage.
        hint = getattr(self, "_peb_hint", None) or \
            getattr(getattr(self, "_oob_geom", None), "raw_eb_size", None)
        if hint:
            log.warning("PEB size: no plausible gap > data_offset — using "
                        "geometry-derived hint 0x%X", hint)
            return hint
        raise ValueError("cannot derive PEB size: no plausible gap > data_offset")

    def _group_regions(self, ec_headers: List[ECHeaderInfo], peb_size: int) -> List[List[ECHeaderInfo]]:
        if not ec_headers: return []
        sorted_ecs = sorted(ec_headers, key=lambda h: h.offset)
        # Split criteria (in priority):
        #   1. NEW UBI ATTACH — a layout-volume (VTBL, lnum=0) PEB encountered
        #      after volume data. Multi-attach images (A/B rootfs banks) pack
        #   attaches contiguously; merging them hides kernel/rootfs volumes.
        #   2. PHYSICAL GAP > 4 PEBs — erased/damaged span.
        # NOTE: image_seq is deliberately NOT a split criterion: vendors ship
        # mixed-seq containers and volumes can span seq populations.
        vhf_probe = sorted_ecs[0].vid_hdr_offset
        regions, current, seen_vtbl = [], [], False
        for ec in sorted_ecs:
            new_attach = False
            voff = ec.offset + vhf_probe
            if voff + VIDHeader.SIZE <= len(self.data):
                vid = VIDHeader.parse(self.data, voff, 0)
                if vid and vid.vol_id >= VolumeTable.VTBL_VOL_ID and vid.lnum == 0:
                    if seen_vtbl:
                        new_attach = True
                    seen_vtbl = True
            if current and (new_attach or ec.offset - current[-1].offset > peb_size * 4):
                regions.append(current)
                current = []
            current.append(ec)
        if current: regions.append(current)
        return regions

    def _process_region(self, ec_headers: List[ECHeaderInfo], peb_size: int) -> Optional[UBIRegion]:
        if not ec_headers: return None
        first_ec = ec_headers[0]
        vid_hdr_off, data_off = first_ec.vid_hdr_offset, first_ec.data_offset
        leb_size = peb_size - data_off
        start_offset, end_offset = first_ec.offset, ec_headers[-1].offset + peb_size

        region = UBIRegion(
            start_offset=start_offset, end_offset=end_offset, peb_size=peb_size, leb_size=leb_size,
            vid_hdr_offset=vid_hdr_off, data_offset=data_off, image_seq=first_ec.image_seq,
            peb_count=len(ec_headers), ec_headers=ec_headers,
            start_offset_clean=start_offset, end_offset_clean=end_offset, peb_size_clean=peb_size
        )
        region.vid_headers = self._scan_vid_headers_gen2(ec_headers, vid_hdr_off)
        # Propagate the observed vid_hdr_offset (probe may have corrected the
        # EC-declared value) so LEB carving uses the SAME offset that located
        # the VID headers — otherwise data starts shift by the delta.
        region.vid_hdr_offset = getattr(self, "_resolved_vid_hdr_offset",
                                        vid_hdr_off)
        vid_hdr_off = region.vid_hdr_offset
        log.info("Region: PEB=0x%X LEB=0x%X vhf=0x%X doff=0x%X — %d VID header(s)",
                 peb_size, leb_size, vid_hdr_off, data_off, len(region.vid_headers))

        leb_map: Dict[int, Dict[int, bytes]] = {}
        for vid in region.vid_headers:
            eb_start = vid.offset - vid_hdr_off
            chunk = self.data[eb_start + data_off : eb_start + data_off + leb_size]
            leb_map.setdefault(vid.vol_id, {})[vid.lnum] = chunk

        vol_names = self._parse_vtbl(leb_map)
        ec_values = [h.ec for h in ec_headers]
        for vid_id, lebs in leb_map.items():
            if vid_id >= 0x7FFFEFFF: continue
            assembled = self._assemble_lebs_bounded(lebs, vid_id)
            log.info("Volume %d ('%s'): %d LEB(s), max_lnum=%d, assembled %d B",
                     vid_id, vol_names.get(vid_id, f"vol_{vid_id}"), len(lebs),
                     max(lebs.keys()) if lebs else -1, len(assembled))
            fs_type, fs_end, _ = FilesystemDetector.detect(assembled)
            vol_name = vol_names.get(vid_id, f"vol_{vid_id}")
            sample_vid = next((v for v in region.vid_headers if v.vol_id == vid_id), None)
            validation = FsValidator.validate(fs_type, assembled) if fs_type else None

            present_leb_count = len(lebs)
            max_lnum = max(lebs.keys()) if lebs else -1
            logical_leb_count = max_lnum + 1 if max_lnum >= 0 else 0
            present_leb_bytes = present_leb_count * leb_size
            logical_span_bytes = logical_leb_count * leb_size
            missing_lnum_count = logical_leb_count - present_leb_count
            fs_used_bytes = None
            if validation and "meta" in validation:
                fs_used_bytes = validation["meta"].get("bytes_used") or validation["meta"].get("total_size") or validation["meta"].get("size")

            region.volumes[vid_id] = VolumeInfo(
                vol_id=vid_id, name=vol_name, vol_type=sample_vid.vol_type if sample_vid else VOL_DYNAMIC,
                leb_count=len(lebs), used_ebs=sample_vid.used_ebs if sample_vid else 0,
                data_size=sample_vid.data_size if sample_vid else 0, fs_type=fs_type, fs_endian=fs_end,
                size_bytes=len(assembled), validation=validation, present_leb_count=present_leb_count,
                max_lnum=max_lnum, logical_leb_count=logical_leb_count, present_leb_bytes=present_leb_bytes,
                logical_span_bytes=logical_span_bytes, missing_lnum_count=missing_lnum_count, filesystem_used_bytes=fs_used_bytes
            )

        region.summary = {
            "good_pebs": len(ec_headers), "bad_pebs": 0, "corrupted_pebs": 0,
            "user_volumes": len([v for v in leb_map if v < 0x7FFFEFFF]),
            "internal_volumes": len([v for v in leb_map if v >= 0x7FFFEFFF]),
            "ec_min": min(ec_values) if ec_values else None, "ec_max": max(ec_values) if ec_values else None,
            "ec_mean": round(sum(ec_values) / len(ec_values), 2) if ec_values else None,
            "volume_names": vol_names,
        }
        return region

    def _scan_vid_headers(self, ec_headers: List[ECHeaderInfo], vid_hdr_off: int) -> List[VIDHeaderInfo]:
        vid_headers = []
        for i, ec in enumerate(ec_headers):
            vid_offset = ec.offset + vid_hdr_off
            if vid_offset + VIDHeader.SIZE > len(self.data): continue
            vid = VIDHeader.parse(self.data, vid_offset, i)
            if vid: vid_headers.append(vid)
        return vid_headers

    def _parse_vtbl(self, leb_map: Dict[int, Dict[int, bytes]]) -> Dict[int, str]:
        vtbl_data = leb_map.get(VolumeTable.VTBL_VOL_ID)
        if not vtbl_data: return {}
        return VolumeTable.parse(vtbl_data.get(0, b""))

    def _assemble_lebs(self, lebs: Dict[int, bytes]) -> bytes:
        if not lebs: return b""
        max_lnum, leb_size = max(lebs.keys()), len(next(iter(lebs.values())))
        result = bytearray()
        for i in range(max_lnum + 1):
            result.extend(lebs.get(i, b"\xff" * leb_size))
        return bytes(result)

    # ── Gen2: bounded assembly (Bug B fix, additive) ────────────────────────
    #
    # The legacy _assemble_lebs materializes max_lnum+1 LEBs from an
    # unvalidated u32 VID field. A single garbage VID header (CRC never
    # checked in v1.0) with a huge lnum allocates
    # (lnum+1) × leb_size (a poison value like 0x80000056 observed in the
    # wild → ≈253,952 GiB) → kernel OOM kill at ~87 GB RSS. The bound below
    # is derived from the image itself:
    # no volume can span more LEBs than the image physically holds.
    LNUM_SPAN_SAFETY = 4  # allow up to 4× image capacity before capping

    def _assemble_lebs_bounded(self, lebs: Dict[int, bytes], vol_id: int) -> bytes:
        if not lebs: return b""
        leb_size = len(next(iter(lebs.values())))
        max_lnum = max(lebs.keys())
        image_capacity = max(1, len(self.data) // max(leb_size, 1))
        span_cap = image_capacity * self.LNUM_SPAN_SAFETY
        if max_lnum + 1 > span_cap:
            log.warning("Volume %d: VID lnum span %d exceeds image-derived bound "
                        "%d (leb_size=%d, image=%d B) — capping. Poison VID "
                        "headers likely (CRC-unchecked vendor image).",
                        vol_id, max_lnum + 1, span_cap, leb_size, len(self.data))
            sane = {ln: data for ln, data in lebs.items() if ln < span_cap}
            return self._assemble_lebs(sane)
        return self._assemble_lebs(lebs)

    # ── v1.1.2 (Fix 2): gated lnum repair ───────────────────────────────────
    #
    # Some vendor static volumes ship with bit-rot in the VID lnum u32
    # (single-bit flips anywhere in the field, including vendor flag bits in
    # the high half — normalised here with a 0xFFFF mask). The legacy scan
    # either drops such VIDs as poison or assembles them at garbage lnums,
    # so the volume loses its superblock LEB and the extracted FS comes out
    # headless. Repair is GATED on static-volume proof so it can never
    # rewrite a healthy image:
    #   vol_type == STATIC for every VID ∧ used_ebs == VID count
    #   → the true lnum set is provably exactly 0..n-1
    #     1. normalise lnum &= 0xFFFF (high flag bits are never legal here)
    #     2. single-bit repair of anomalous VIDs into unclaimed holes
    #     3. unresolved anomalies filled by PEB order (ascending holes)
    # Dynamic volumes with anomalies are diagnosed and warned, NOT guessed.
    @staticmethod
    def _single_bit_holes(value: int, holes: set) -> List[int]:
        """Holes reachable from `value` by flipping exactly one bit (0..31)."""
        return sorted(h for h in holes if bin(h ^ value).count("1") == 1)

    def _repair_lnums_gated(self, group: List[VIDHeaderInfo], vol_id: int) -> None:
        n = len(group)
        if n < 2:
            return
        types = {v.vol_type for v in group}
        used_counts = {}
        for v in group:
            used_counts[v.used_ebs] = used_counts.get(v.used_ebs, 0) + 1
        used_consensus = max(used_counts.items(), key=lambda kv: kv[1])[0]

        # classify anomalies on the normalised values first (needed for the
        # dynamic-volume diagnostic even when the static gate fails):
        # out-of-range values, plus duplicate claims AFTER the first
        # occurrence in PEB order (the first claimant keeps its lnum, so
        # anomaly count always equals the hole count by pigeonhole)
        norm = [v.lnum & 0xFFFF for v in group]
        order = sorted(range(n), key=lambda i: group[i].peb_index)
        seen_claims = set()
        anomalous_idx = set()
        for i in order:
            x = norm[i]
            if x >= n or x in seen_claims:
                anomalous_idx.add(i)
            else:
                seen_claims.add(x)
        anomalous = [(i, norm[i]) for i in sorted(anomalous_idx,
                     key=lambda i: group[i].peb_index)]

        if types != {VOL_STATIC} or used_consensus != n:
            if anomalous:
                log.info(
                    "Volume %d: %d lnum anomaly/ies (dups/out-of-range) but "
                    "vol_type=%s used_ebs=%s ≠ static-with-n proof — repair "
                    "gated OFF (diagnosis only, lnums not rewritten)",
                    vol_id, len(anomalous), sorted(types), used_consensus)
            return

        # Gate passed: static volume, used_ebs == n → target set is 0..n-1.
        if not anomalous:
            return
        log.info("Volume %d (static, used_ebs=%d, %d VIDs): %d anomalous "
                 "lnum(s) — gated repair engaged",
                 vol_id, used_consensus, n, len(anomalous))

        holes = set(range(n)) - set(norm)
        anomalous_sorted = sorted(anomalous, key=lambda t: group[t[0]].peb_index)

        for idx, raw_norm in anomalous_sorted:
            vid = group[idx]
            vid.lnum_raw = vid.lnum
            cands = self._single_bit_holes(raw_norm, holes)
            if len(cands) == 1:
                vid.lnum = cands[0]
                vid.lnum_repair = "single-bit"
                holes.discard(cands[0])
                log.info("  PEB %d: lnum %d (raw 0x%X) → %d [single-bit]%s",
                         vid.peb_index, raw_norm, vid.lnum_raw, vid.lnum,
                         "" if vid.crc_ok in (None, False) else " [CRC ok]")
            elif len(cands) > 1:
                log.info("  PEB %d: lnum %d ambiguous (%d single-bit holes: %s)"
                         " — deferred to PEB-order fill", vid.peb_index,
                         raw_norm, len(cands), cands)

        # PEB-order fill: remaining anomalies (in PEB order) take the
        # remaining holes (ascending). By pigeonhole counts match exactly.
        unresolved = [(idx, norm[idx]) for idx, _ in anomalous_sorted
                      if group[idx].lnum_repair is None]
        remaining = sorted(holes)
        for (idx, _), hole in zip(unresolved, remaining):
            vid = group[idx]
            vid.lnum = hole
            vid.lnum_repair = "peb-order"
            log.info("  PEB %d: lnum %d (raw 0x%X) → %d [peb-order fill]",
                     vid.peb_index, norm[idx], vid.lnum_raw, vid.lnum)

        # verify: multiset must now be exactly 0..n-1
        final = sorted(v.lnum for v in group)
        if final == list(range(n)):
            n_sb = sum(1 for v in group if v.lnum_repair == "single-bit")
            n_po = sum(1 for v in group if v.lnum_repair == "peb-order")
            log.info("Volume %d: lnum repair complete — %d single-bit, %d "
                     "peb-order fill; lnums now contiguous 0..%d",
                     vol_id, n_sb, n_po, n - 1)
        else:
            log.warning("Volume %d: lnum repair verification failed "
                        "(final set not 0..%d) — leaving repaired values in "
                        "place", vol_id, n - 1)

    def _scan_vid_headers_gen2(self, ec_headers: List[ECHeaderInfo], vid_hdr_off: int) -> List[VIDHeaderInfo]:
        """Gen2 VID scan (additive — legacy _scan_vid_headers untouched):
        same parse, plus:
          - per-VID CRC verification (convention auto-detected from EC
            headers: plain crc32 or vendor-inverted ~crc32)
          - lnum sanity bound (8× PEB count) — poison VIDs above the bound
            are dropped from volume assembly (kept in the JSON dump via
            crc_ok/crc_conv annotation)
        Fall back to legacy results when gen2 finds nothing (defensive).
        """
        votes: Dict[str, int] = {}
        for ec in ec_headers[:32]:
            ok, c = ECHeader._verify(self.data, ec.offset)
            if ok:
                key = c.split("@")[0]
                votes[key] = votes.get(key, 0) + 1
        conv = max(votes.items(), key=lambda kv: kv[1])[0] if votes else None
        log.info("VID scan (gen2): EC-CRC convention vote: %s %s",
                 conv or "unknown", votes if votes else "(no valid EC CRCs)")
        self._crc_convention = conv

        # Vendor-layout probe: some images place VID headers at an offset
        # other than the EC-declared vid_hdr_offset (e.g. shifted past a
        # redundant EC copy). Build a DERIVED probe set: multiples/subdivisions
        # of the observed page stride, the data offset, and the declared
        # offset ± one page — not hardcoded constants.
        declared = vid_hdr_off
        page = getattr(getattr(self, "_oob_geom", None), "page_size", 0) or \
            min(h.data_offset for h in ec_headers[:8]) or 0x800
        probes = [declared, 64]  # declared first = priority ordering
        for base in (page, 2 * page):
            for k in (-2, -1, 0, 1, 2):
                probes.append(base + k * 64)
        probes.extend(d + d // 16 for d in (page, 2 * page))  # stride-shifted
        # dedupe preserving priority order; keep the declared offset even when
        # vendors place the VID unusually deep inside the PEB
        probe_offsets = [p for p in probes if 0 < p <= max(4 * page, declared)]
        probe_offsets = list(dict.fromkeys(probe_offsets))
        best_off, best_hits = declared, -1
        # Sample across the WHOLE PEB population — head PEBs are often
        # erased (EC-only, bootloader area) which starves the probe.
        sample_n = min(len(ec_headers), 512)
        step = max(1, sample_n // 64)
        # Spread samples across the FIRST HALF of the PEB population — head
        # PEBs are often erased (bootloader area) which starves the probe,
        # and tail PEBs may belong to a differently-structured attach.
        pool = ec_headers[:sample_n]
        sample = pool[::max(1, len(pool) // 64)]
        for p in probe_offsets:
            hits = 0
            for ec in sample:
                voff = ec.offset + p
                if voff + VIDHeader.SIZE > len(self.data): continue
                if VIDHeader.parse(self.data, voff, 0): hits += 1
            if hits > best_hits:
                best_off, best_hits = p, hits
        if best_hits == 0:
            log.warning("VID scan: no VID headers at ANY probed offset — "
                        "keeping declared vid_hdr_offset=0x%X", declared)
            best_off = declared
        elif best_off != declared:
            log.info("VID scan: EC declares vid_hdr_offset=0x%X but VID "
                     "headers found at +0x%X (%d/%d PEBs) — using observed",
                     declared, best_off, best_hits, len(sample))
            vid_hdr_off = best_off
        self._resolved_vid_hdr_offset = vid_hdr_off

        max_sane_lnum = max(8 * len(ec_headers), 64)
        all_vids: List[VIDHeaderInfo] = []
        for i, ec in enumerate(ec_headers):
            vid_offset = ec.offset + vid_hdr_off
            if vid_offset + VIDHeader.SIZE > len(self.data): continue
            vid = VIDHeader.parse(self.data, vid_offset, i)
            if not vid: continue
            ok, c = VIDHeader._verify(self.data, vid_offset)
            vid.crc_ok, vid.crc_conv = ok, c
            all_vids.append(vid)

        # v1.1.2 (Fix 2): gated lnum repair BEFORE the sanity drop. Repaired
        # values land in 0..n-1 by construction; unrepaired poison VIDs are
        # still subject to the legacy bound below.
        # Attach segmentation: layout (internal) VID headers mark the start
        # of each UBI attach. Images shipping two banks under ONE image_seq
        # (merged into a single region) restart lnum numbering at each bank's
        # layout volume — the static-volume gate (used_ebs == n) must see
        # each attach's VIDs alone, so groups are split per attach segment.
        seg_of: Dict[int, int] = {}
        seg = 0
        for v in sorted(all_vids, key=lambda x: x.peb_index):
            if v.vol_id >= 0x7FFFEFFF:
                seg += 1
            seg_of[id(v)] = seg
        by_vol: Dict[Tuple[int, int], List[VIDHeaderInfo]] = {}
        for v in all_vids:
            if v.vol_id >= 0x7FFFEFFF:
                continue
            by_vol.setdefault((v.vol_id, seg_of[id(v)]), []).append(v)
        for (vol_id, _seg), group in by_vol.items():
            try:
                self._repair_lnums_gated(group, vol_id)
            except Exception as exc:
                log.warning("Volume %d: gated lnum repair failed (%s) — "
                            "continuing with unrepaired lnums", vol_id, exc)

        vid_headers = [v for v in all_vids if v.lnum <= max_sane_lnum]
        n_dropped = len(all_vids) - len(vid_headers)
        if n_dropped:
            for v in all_vids:
                if v.lnum > max_sane_lnum:
                    log.debug("VID @0x%X: lnum=%d exceeds sane bound %d — dropped",
                              v.offset, v.lnum, max_sane_lnum)
            log.info("VID scan (gen2): dropped %d VID header(s) with insane lnum "
                     "(bound=%d)", n_dropped, max_sane_lnum)
        if not vid_headers:
            log.warning("VID scan (gen2): no VIDs survived — falling back to legacy scan")
            return self._scan_vid_headers(ec_headers, vid_hdr_off)
        log.info("VID scan (gen2): %d valid VID headers (%d ECs, max sane lnum=%d)",
                 len(vid_headers), len(ec_headers), max_sane_lnum)
        return vid_headers


# ═══════════════════════════════════════════════════════════════════════════
#  EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════

class Extractor:
    def __init__(self, output_dir: Path, raw_data: bytes, clean_data: bytes, geom: OOBGeometry):
        self._gate_region = None
        self._gate_warnings = None
        self.output_dir, self.raw_data, self.clean_data, self.geom = output_dir, raw_data, clean_data, geom
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "ubi").mkdir(exist_ok=True)
        (output_dir / "other_fs").mkdir(exist_ok=True)

    def extract_region(self, region: UBIRegion, region_idx: int, warnings_list: List[str]) -> None:
        rdir = self.output_dir / "ubi" / f"region_{region_idx}"
        # v1.12.0: give _extract_filesystem's health gate the region context
        # (needed to rebuild alternative LEB assemblies when healing).
        self._gate_region = region
        self._gate_warnings = warnings_list
        rdir.mkdir(parents=True, exist_ok=True)
        (rdir / "volumes").mkdir(exist_ok=True)
        (rdir / "headers").mkdir(exist_ok=True)

        clean_start, clean_end = region.start_offset_clean, region.end_offset_clean
        raw_start, raw_end = OOBDetector.clean_range_to_raw_range(clean_start, clean_end, self.geom)

        raw_region = self.raw_data[raw_start:raw_end]
        clean_region = self.clean_data[clean_start:clean_end]

        expected_clean_size = region.peb_count * region.peb_size_clean
        expected_raw_size = region.peb_count * self.geom.raw_eb_size if self.geom.has_oob else expected_clean_size

        if len(clean_region) != expected_clean_size:
            msg = f"Region {region_idx} clean size mismatch: {len(clean_region)} != {expected_clean_size}"
            log.error(msg); warnings_list.append(msg)
        if self.geom.has_oob and len(raw_region) != expected_raw_size:
            msg = f"Region {region_idx} raw size mismatch: {len(raw_region)} != {expected_raw_size}"
            log.error(msg); warnings_list.append(msg)

        (rdir / "raw_ubi.img").write_bytes(raw_region)
        (rdir / "clean_ubi.img").write_bytes(clean_region)
        (rdir / "headers" / "ec_headers.json").write_text(json.dumps([asdict(h) for h in region.ec_headers], indent=2))
        (rdir / "headers" / "vid_headers.json").write_text(json.dumps([asdict(h) for h in region.vid_headers], indent=2))

        # v1.8.0: detect and persist the original image's CRC convention so the
        # repacker recomputes CRCs with the SAME formula the vendor used.
        try:
            crc_conv = self._detect_crc_convention(
                region.ec_headers, region.vid_headers, clean_region,
                base_offset=clean_start if clean_start is not None else 0)
        except Exception as exc:
            crc_conv = {"convention": None, "confidence": "error", "error": str(exc)}
            log.warning("Region %d: CRC convention detection failed: %s", region_idx, exc)
        (rdir / "headers" / "crc_convention.json").write_text(json.dumps(crc_conv, indent=2))
        if crc_conv.get("convention"):
            log.info("Region %d CRC convention: %s (%s; EC %d/%d, VID %d/%d votes)",
                     region_idx, crc_conv["convention"], crc_conv["confidence"],
                     crc_conv["details"]["ec"][crc_conv["convention"]],
                     crc_conv["details"]["ec"]["checked"],
                     crc_conv["details"]["vid"][crc_conv["convention"]],
                     crc_conv["details"]["vid"]["checked"])
        else:
            log.warning("Region %d: CRC convention undetermined — repacker will "
                        "re-detect at repack time", region_idx)

        leb_map = self._build_leb_map(region)
        seen_hashes: Dict[str, str] = {}  # sha256 -> primary volume name (for dedup)
        for vol_id, vol_info in sorted(region.volumes.items()):
            self._extract_volume(vol_id, vol_info, leb_map, rdir, region, seen_hashes, warnings_list)

    # ── CRC-convention detection (v1.8.0) ────────────────────────────────────
    # Detect which CRC convention the ORIGINAL image uses (plain crc32 vs
    # vendor-inverted ~crc32) by voting over its stored EC/VID header CRCs.
    # Persisted per region so the repacker recomputes any CRC with the SAME
    # formula the vendor used instead of a hard-coded one.
    def _detect_crc_convention(self, ec_headers, vid_headers, region_data: bytes,
                               base_offset: int = 0) -> dict:
        votes = {"crc32": 0, "~crc32": 0}
        details = {
            "ec":  {"checked": 0, "crc32": 0, "~crc32": 0},
            "vid": {"checked": 0, "crc32": 0, "~crc32": 0},
        }
        # Header offsets in the JSON are absolute into the whole firmware
        # image; normalize by base_offset to index into the region slice.
        for h in ec_headers:
            off = h.offset - base_offset
            if off < 0 or off + 64 > len(region_data): continue
            stored = h.hdr_crc
            if stored in (0, 0xFFFFFFFF): continue
            base = zlib.crc32(region_data[off:off + 60]) & 0xFFFFFFFF
            details["ec"]["checked"] += 1
            for name, c in (("crc32", base), ("~crc32", ~base & 0xFFFFFFFF)):
                if c == stored:
                    votes[name] += 1
                    details["ec"][name] += 1
                    break
        for v in vid_headers:
            off = v.offset - base_offset
            if off < 0 or off + 64 > len(region_data): continue
            stored = v.hdr_crc
            if stored in (0, 0xFFFFFFFF): continue
            base = zlib.crc32(region_data[off:off + 60]) & 0xFFFFFFFF
            details["vid"]["checked"] += 1
            for name, c in (("crc32", base), ("~crc32", ~base & 0xFFFFFFFF)):
                if c == stored:
                    votes[name] += 1
                    details["vid"][name] += 1
                    break
        total = votes["crc32"] + votes["~crc32"]
        if total == 0:
            winner, confidence = None, "none"
        elif votes["crc32"] == 0 or votes["~crc32"] == 0:
            winner = max(votes.items(), key=lambda kv: kv[1])[0]
            confidence = "unanimous"
        else:
            winner = max(votes.items(), key=lambda kv: kv[1])[0]
            confidence = "majority"
        return {
            "convention": winner,
            "confidence": confidence,
            "votes": votes,
            "details": details,
            "note": ("crc32 = zlib.crc32(data) over the 60 header bytes; "
                     "~crc32 = bitwise NOT of that (== kernel crc32_le(0xFFFFFFFF,..) "
                     "with no final inversion). Detected from the ORIGINAL image's "
                     "stored header CRCs at analysis time; the repacker uses this "
                     "convention for every CRC it recomputes."),
        }

    def _build_leb_map(self, region: UBIRegion) -> Dict[int, Dict[int, bytes]]:
        leb_map: Dict[int, Dict[int, bytes]] = {}
        for vid in region.vid_headers:
            eb_start = vid.offset - region.vid_hdr_offset
            chunk = self.clean_data[eb_start + region.data_offset : eb_start + region.data_offset + region.leb_size]
            leb_map.setdefault(vid.vol_id, {})[vid.lnum] = chunk
        return leb_map

    def _assemble_lebs(self, lebs: Dict[int, bytes], leb_size: int) -> bytes:
        """Legacy signature preserved. Gen2: delegates to the shared bounded
        assembler so the OOM bound protects extraction too."""
        return Extractor.assemble_lebs_static(lebs, leb_size)

    @staticmethod
    def assemble_lebs_static(lebs: Dict[int, bytes], leb_size: int) -> bytes:
        if not lebs: return b""
        max_lnum = max(lebs.keys())
        image_capacity = max(1, 256 * 1024 * 1024 // max(leb_size, 1))
        span_cap = image_capacity * UBIScanner.LNUM_SPAN_SAFETY
        if max_lnum + 1 > span_cap:
            log.warning("assemble: lnum span %d exceeds bound %d — capping "
                        "(poison VID headers likely)", max_lnum + 1, span_cap)
            lebs = {ln: data for ln, data in lebs.items() if ln < span_cap}
            max_lnum = max(lebs.keys())
        result = bytearray()
        for i in range(max_lnum + 1):
            result.extend(lebs.get(i, b"\xff" * leb_size))
        return bytes(result)

    # ── Volume classification (generic, content-based only) ───────────────
    #
    # No device-specific volume names. Classification is purely by magic
    # bytes — works for any UBI firmware from any vendor.
    #
    # uImage magic (big-endian 0x27051956) — kernel/bootloader image
    U_IMAGE_MAGIC = b"\x27\x05\x19\x56"

    # Minimum volume size to be considered meaningful (skip tiny/empty volumes)
    MIN_MEANINGFUL_SIZE = 4

    @classmethod
    def _classify_volume(cls, clean_vol: bytes, vol_info: VolumeInfo) -> str:
        """Classify volume content purely by magic bytes — no device-specific names.

        - 'filesystem': SquashFS/JFFS2/CramFS/UBIFS/DTB detected → extract as image
        - 'kernel'    : uImage header detected → extract as .bin (keep appended DTB intact)
        - 'raw'       : no recognized magic — extract as .bin (could be config, compressed
                        data, partition table, etc. — user inspects manually)
        - 'skip'      : empty or too small → don't extract
        """
        if len(clean_vol) < cls.MIN_MEANINGFUL_SIZE:
            return "skip"

        # Check for filesystem magic (SquashFS, JFFS2, CramFS, UBIFS, DTB)
        fs_type, _, _ = FilesystemDetector.detect(clean_vol)
        if fs_type == "JFFS2":
            # 2-byte magic can false-positive — require at least 3 JFFS2 node
            # markers in the volume to confirm it's really JFFS2
            stripped = clean_vol.lstrip(b"\xff")
            count = 0
            for magic in (b"\x85\x19", b"\x19\x85"):
                pos = 0
                while True:
                    idx = stripped.find(magic, pos)
                    if idx < 0:
                        break
                    count += 1
                    pos = idx + 2
                    if count >= 3:
                        break
                if count >= 3:
                    break
            if count < 3:
                fs_type = None  # not enough JFFS2 markers — not a real JFFS2 volume

        if fs_type:
            return "filesystem"

        # Check for uImage/kernel (legacy U-Boot image header)
        if clean_vol[:4] == cls.U_IMAGE_MAGIC:
            return "kernel"

        # No recognized magic — raw data blob (config, partition table, etc.)
        return "raw"

    def _extract_volume(self, vol_id: int, vol_info: VolumeInfo, leb_map: Dict[int, Dict[int, bytes]],
                        rdir: Path, region: UBIRegion, seen_hashes: Dict[str, str],
                        warnings_list: List[str]) -> None:
        lebs = leb_map.get(vol_id, {})
        if not lebs: return

        assembled = self._assemble_lebs(lebs, region.leb_size)
        clean_vol = assembled.rstrip(b"\xff")
        if not clean_vol: return

        # ── Dedup: skip byte-identical backup volumes ──────────────────────
        vol_hash = hashlib.sha256(clean_vol).hexdigest()
        if vol_hash in seen_hashes:
            primary_name = seen_hashes[vol_hash]
            log.info("Skipping duplicate volume %d ('%s') — identical to '%s'",
                     vol_id, vol_info.name, primary_name)
            vol_info.extracted_path = None
            return
        seen_hashes[vol_hash] = vol_info.name

        safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in vol_info.name)
        vols_dir = rdir / "volumes"

        # ── Classify and route ──────────────────────────────────────────────
        category = self._classify_volume(clean_vol, vol_info)

        if category == "skip":
            log.info("Skipping volume %d ('%s') — too small (%d bytes)", vol_id, vol_info.name, len(clean_vol))
            return

        if category == "filesystem":
            self._extract_filesystem(clean_vol, vol_id, vol_info, safe_name, vols_dir)

        elif category == "kernel":
            vol_bin = vols_dir / f"vol_{vol_id}_{safe_name}.bin"
            vol_bin.write_bytes(clean_vol)
            vol_info.extracted_path = str(vol_bin)
            vol_info.fs_type = "uImage"
            log.info("Extracted kernel volume %d ('%s') → %s (%d bytes)",
                     vol_id, vol_info.name, vol_bin.name, len(clean_vol))
            region_ctx = getattr(self, "_gate_region", None)
            if region_ctx is not None:
                try:
                    self._health_gate(vol_id, vol_info, "uImage", region_ctx,
                                      vol_bin, self._gate_warnings or [])
                except Exception as e:
                    log.warning("[FS-CHECK] volume %d: health gate error: %s",
                                vol_id, e)

        elif category == "raw":
            vol_bin = vols_dir / f"vol_{vol_id}_{safe_name}.bin"
            vol_bin.write_bytes(clean_vol)
            vol_info.extracted_path = str(vol_bin)
            log.info("Extracted raw volume %d ('%s') → %s (%d bytes)",
                     vol_id, vol_info.name, vol_bin.name, len(clean_vol))

    # ── v1.12.0: post-extraction health gate + anomaly healing ──────────
    #
    # "The bytes were written" is not "the filesystem is sound". Every
    # extracted filesystem is deep-checked; if the structural walk finds
    # damage, evidence-gated healing candidates are scored and the
    # healthiest assembly wins. The pre-heal bytes are preserved as
    # <file>.orig.<ext> and recorded in .heal_report.json so the repack
    # can emit both the fixed and the anomaly-preserving image.
    def _heal_candidates(self, vol_id: int, region: UBIRegion) -> List[Tuple[str, bytes]]:
        """Build alternative assemblies of this volume from the flash image.

        Every candidate is real data from the dump — no invention:
          - lnum-order (the default assembly the analyst uses)
          - physical-PEB-order (factory images are written ascending)
          - per-redundant-copy assemblies + a merged copy, when the
            volume has more PEBs than its VID headers declare
        """
        from ubi_toolkit import fs_health
        cands: List[Tuple[str, bytes]] = []
        leb_size = region.leb_size

        # Group this volume's LEB payloads by VID header.
        entries = [v for v in region.vid_headers if v.vol_id == vol_id]
        if not entries:
            return cands
        max_lnum = max(v.lnum for v in entries)

        def assemble(order: List[int]) -> bytes:
            buf = bytearray()
            data_off = region.data_offset
            for peb in order:
                eb_start = entries[peb].offset - region.vid_hdr_offset
                buf += self.clean_data[eb_start + data_off:
                                       eb_start + data_off + leb_size]
            return bytes(buf)

        by_lnum: Dict[int, int] = {}
        dup_lnum = False
        for i, v in enumerate(entries):
            if v.lnum in by_lnum:
                dup_lnum = True
            by_lnum.setdefault(v.lnum, i)
        if not dup_lnum:
            cands.append(("lnum-order", assemble(
                [by_lnum[l] for l in sorted(by_lnum)])))
        cands.append(("peb-order", assemble(list(range(len(entries))))))
        return cands

    def _health_gate(self, vol_id: int, vol_info: VolumeInfo, fs_type: str,
                     region: UBIRegion, out_path: Path,
                     warnings_list: List[str]) -> None:
        """Deep-check an extracted filesystem; heal it if damaged."""
        from ubi_toolkit import fs_health

        data = out_path.read_bytes()
        rep = fs_health.check_bytes(data, fs_type)
        vol_info.deep_health = rep
        if rep["healthy"]:
            log.info("[FS-CHECK] volume %d ('%s') %s: healthy (%s)",
                     vol_id, vol_info.name, fs_type,
                     "; ".join(f"{k}={v}" for k, v in rep["stats"].items()
                               if isinstance(v, int)))
            return

        for e in rep["errors"]:
            log.warning("[FS-CHECK] volume %d ('%s') %s: %s",
                        vol_id, vol_info.name, fs_type, e)
        warnings_list.append(
            f"volume {vol_id} ('{vol_info.name}') {fs_type} deep check "
            f"found {len(rep['errors'])} structural issue(s): "
            + "; ".join(rep["errors"][:3]))

        # ---- heal: try alternative assemblies, keep the healthiest ----
        candidates = self._heal_candidates(vol_id, region)
        cands = [("as-extracted", data)] + candidates
        best_name, best_data, best_rep = fs_health.pick_healthiest(
            cands, fs_type)

        if best_name != "as-extracted" and \
                fs_health.score_variant(best_data, fs_type) > \
                fs_health.score_variant(data, fs_type):
            orig_path = out_path.with_name(
                out_path.stem + ".orig" + out_path.suffix)
            orig_path.write_bytes(data)
            out_path.write_bytes(best_data)
            vol_info.deep_health = best_rep
            vol_info.healed_from = best_name
            fs_health.record_heal(out_path.parents[1], {
                "file": out_path.name,
                "orig_file": orig_path.name,
                "healed_variant": best_name,
                "errors_before": len(rep["errors"]),
                "errors_after": len(best_rep["errors"]),
                "healthy_after": best_rep["healthy"],
            })
            warnings_list.append(
                f"volume {vol_id} ('{vol_info.name}') healed by alternative "
                f"assembly '{best_name}' (errors {len(rep['errors'])} -> "
                f"{len(best_rep['errors'])}); pre-heal bytes kept as "
                f"{orig_path.name}")
            log.info("[FS-HEAL] volume %d ('%s'): rebuilt with '%s' "
                     "(%d -> %d structural errors); original kept as %s",
                     vol_id, vol_info.name, best_name, len(rep["errors"]),
                     len(best_rep["errors"]), orig_path.name)
        else:
            warnings_list.append(
                f"volume {vol_id} ('{vol_info.name}') could not be healed "
                f"by any alternative assembly; best effort kept "
                f"(still {len(rep['errors'])} structural issue(s))")
            log.warning("[FS-HEAL] volume %d ('%s'): no alternative "
                        "assembly is healthier; keeping as-extracted bytes",
                        vol_id, vol_info.name)


    def _extract_filesystem(self, clean_vol: bytes, vol_id: int, vol_info: VolumeInfo,
                            safe_name: str, vols_dir: Path) -> None:
        """Extract a filesystem volume as a single image file.

        Detects SquashFS, JFFS2, CramFS, UBIFS, DTB. Extracts as .squashfs,
        .jffs2, .cramfs, .ubifs, .dtb respectively. No auto-unpacking.
        If the magic is not at offset 0, search for it and carve from there.
        """
        fs_type, fs_endian, _ = FilesystemDetector.detect(clean_vol)

        if not fs_type:
            # FilesystemDetector might have missed it — try manual scan
            for magic, (ft, fe) in FilesystemDetector.FS_MAGICS.items():
                idx = clean_vol.find(magic)
                if idx >= 0:
                    fs_type, fs_endian = ft, fe
                    clean_vol = clean_vol[idx:]
                    break

        if not fs_type:
            # No filesystem detected — save as .bin
            vol_bin = vols_dir / f"vol_{vol_id}_{safe_name}.bin"
            vol_bin.write_bytes(clean_vol)
            vol_info.extracted_path = str(vol_bin)
            log.warning("Volume %d ('%s') classified as filesystem but no magic found — saved as .bin", vol_id, vol_info.name)
            return

        # Extension mapping
        fs_extensions = {
            "SquashFS": ".squashfs",
            "JFFS2": ".jffs2",
            "CramFS": ".cramfs",
            "UBIFS": ".ubifs",
            "DTB": ".dtb",
            "DTB-ext": ".dtb",
        }
        ext = fs_extensions.get(fs_type, ".bin")

        # For SquashFS, trim to bytes_used from superblock
        fs_data = clean_vol
        if fs_type == "SquashFS":
            try:
                bytes_used = struct.unpack_from("<Q", fs_data, 40)[0]
                if 0 < bytes_used <= len(fs_data):
                    fs_data = fs_data[:bytes_used]
            except struct.error:
                pass

        # Validate
        validation = FsValidator.validate(fs_type, fs_data)
        if not validation.get("valid"):
            log.warning("Volume %d ('%s') %s validation failed: %s",
                        vol_id, vol_info.name, fs_type, validation.get("reason", "unknown"))

        # Extract as single image file — no unsquashfs, no unpacking
        out_path = vols_dir / f"vol_{vol_id}_{safe_name}{ext}"
        out_path.write_bytes(fs_data)
        vol_info.extracted_path = str(out_path)
        vol_info.fs_type = fs_type
        vol_info.fs_endian = fs_endian
        log.info("Extracted %s volume %d ('%s') → %s (%d bytes)",
                 fs_type, vol_id, vol_info.name, out_path.name, len(fs_data))

        # v1.12.0: every extraction is health-gated; damaged filesystems
        # trigger evidence-gated healing before anything downstream
        # (repack/upgrade) ever sees the volume.
        region = getattr(self, "_gate_region", None)
        if region is not None:
            try:
                self._health_gate(vol_id, vol_info, fs_type, region,
                                  out_path, self._gate_warnings or [])
            except Exception as e:  # the gate must never kill extraction
                log.warning("[FS-CHECK] volume %d: health gate error: %s",
                            vol_id, e)

    def scan_for_orphan_fs(self, regions: List[UBIRegion], warnings_list: List[str]) -> List[FoundFS]:
        found: List[FoundFS] = []
        # ── v1.1.2 (Fix 3): region-span routing ────────────────────────────
        # The legacy 0x1000-step covered_clean set silently missed FS magics
        # at non-step-aligned offsets INSIDE a region span (e.g. a SquashFS
        # embedded mid-stream inside a UBIFS volume LEB) — those leaked to
        # the global other_fs/ dir even though they are region content.
        # New logic (additive; legacy behaviour preserved outside regions):
        #   1. volume LEB data starts (vid.offset - vhf + data_offset) are
        #      "covered" — their content is extracted as the volume itself;
        #   2. any other FS magic inside a region span [start, end) is an
        #      EMBEDDED region FS → routed to that region's volumes/ dir;
        #   3. everything outside all regions stays a true other_fs/ orphan.
        vol_data_starts: set = set()
        for region in regions:
            for vid in region.vid_headers:
                try:
                    peb_start = vid.offset - region.vid_hdr_offset
                    vol_data_starts.add(peb_start + region.data_offset)
                except Exception:
                    pass

        def region_of(clean_off: int) -> Optional[Tuple[int, "UBIRegion"]]:
            if clean_off is None:
                return None
            for ri, region in enumerate(regions):
                start_c = region.start_offset_clean
                end_c = region.end_offset_clean
                if start_c is not None and end_c is not None and start_c <= clean_off < end_c:
                    return ri, region
            return None

        raw_found = self._scan_by_magic(self.raw_data, is_raw=True)
        clean_found = self._scan_by_magic(self.clean_data, is_raw=False)

        candidates = {}
        for entry in raw_found + clean_found:
            clean_key = entry["offset_clean"]
            key = (entry["fs_type"], clean_key) if clean_key is not None else (entry["fs_type"], entry["offset_raw"])
            if key not in candidates:
                candidates[key] = entry
            else:
                existing = candidates[key]
                if "raw" in entry["detected_in"] and "raw" not in existing["detected_in"]:
                    existing["detected_in"].append("raw")
                if "clean" in entry["detected_in"] and "clean" not in existing["detected_in"]:
                    existing["detected_in"].append("clean")
                if entry.get("validation", {}).get("valid") and not existing.get("validation", {}).get("valid"):
                    existing["validation"] = entry["validation"]
                    existing["size_bytes"] = entry["size_bytes"]
                warnings_list.append(f"Duplicate FS candidate merged: {entry['fs_type']} @ clean 0x{clean_key}")

        for entry in candidates.values():
            raw_off, clean_off, fs_type = entry["offset_raw"], entry["offset_clean"], entry["fs_type"]

            # Fix 3 routing decision
            region_info = region_of(clean_off) if clean_off is not None else None
            if clean_off is not None and clean_off in vol_data_starts:
                continue  # FS magic at a volume LEB start — extracted as the volume
            embedded = region_info is not None

            if clean_off is None:
                validation = {"valid": False, "reason": "Raw offset lies inside OOB area", "meta": {}, "errors": ["OOB area"]}
                warnings_list.append(f"FS candidate {fs_type} @ raw 0x{raw_off:X} lies inside OOB")
            else:
                validation = FsValidator.validate(fs_type, self.clean_data, clean_off)

            if not validation.get("valid", False):
                warnings_list.append(f"Invalid FS candidate retained: {fs_type} @ raw 0x{raw_off:X} / clean 0x{clean_off} - {validation.get('reason')}")

            size_bytes, size_verified = 0, False
            meta = validation.get("meta", {})
            if "bytes_used" in meta and meta["bytes_used"] > 0: size_bytes, size_verified = meta["bytes_used"], True
            elif "total_size" in meta and meta["total_size"] > 0: size_bytes, size_verified = meta["total_size"], True
            elif "size" in meta and meta["size"] > 0: size_bytes, size_verified = meta["size"], True

            raw_span_size = 0
            if size_bytes > 0 and clean_off is not None:
                rs, re = OOBDetector.clean_range_to_raw_range(clean_off, clean_off + size_bytes, self.geom)
                raw_span_size = re - rs

            # Fix 3 hints: which region/volume/LEB does an embedded FS live in?
            region_index = vol_id_hint = lnum_hint = None
            if embedded:
                region_index, region = region_info
                try:
                    peb_size_clean = region.peb_size_clean or 0
                    if clean_off is not None and peb_size_clean > 0:
                        peb_start = (clean_off // peb_size_clean) * peb_size_clean
                        for vid in region.vid_headers:
                            if vid.offset - region.vid_hdr_offset == peb_start:
                                vol_id_hint = vid.vol_id if vid.vol_id < 0x7FFFEFFF else None
                                lnum_hint = vid.lnum
                                break
                except Exception:
                    pass
                warnings_list.append(
                    f"Embedded FS {fs_type} @ clean 0x{clean_off:X} inside region {region_index}"
                    + (f" (vol {vol_id_hint} LEB {lnum_hint})" if vol_id_hint is not None else "")
                    + f" — routed to region {region_index} volumes/")

            found_fs = FoundFS(
                offset_raw=raw_off, offset_clean=clean_off, fs_type=fs_type, endian=entry["endian"],
                size_bytes=size_bytes, size_verified=size_verified, validation=validation,
                magic=entry.get("magic", ""), size_clean=size_bytes, raw_span_size=raw_span_size,
                detected_in=entry["detected_in"],
                region_index=region_index, vol_id_hint=vol_id_hint, lnum_hint=lnum_hint
            )
            found.append(found_fs)

        for fs in found: self._extract_orphan_fs(fs)
        return found

    def _scan_by_magic(self, data: bytes, is_raw: bool) -> List[dict]:
        results: List[dict] = []
        search_limit = min(len(data), 256 * 1024 * 1024)
        if search_limit < len(data):
            log.info("FS magic scan capped at 256 MiB of %d MiB (override: carve.py)",
                     len(data) // 1048576)
        for magic, fs_type, endian, min_size, desc in FS_SCAN_SIGNATURES:
            pos = 0
            while pos < search_limit:
                idx = data.find(magic, pos)
                if idx < 0 or idx >= search_limit: break
                if idx + 96 > len(data): pos = idx + 1; continue

                if is_raw:
                    offset_raw = idx
                    offset_clean = OOBDetector.raw_to_clean_offset(idx, self.geom) if self.geom.has_oob else idx
                    source_space = "raw"
                else:
                    offset_clean = idx
                    offset_raw = OOBDetector.clean_to_raw_offset(idx, self.geom) if self.geom.has_oob else idx
                    source_space = "clean"

                results.append({
                    "offset_raw": offset_raw, "offset_clean": offset_clean, "fs_type": fs_type,
                    "endian": endian, "magic": magic.hex(), "detected_in": [source_space]
                })
                pos = idx + 1

        seen_raw, deduped = set(), []
        for r in results:
            if r["offset_raw"] not in seen_raw:
                seen_raw.add(r["offset_raw"])
                deduped.append(r)
        return deduped

    def _extract_orphan_fs(self, fs: FoundFS) -> None:
        if fs.size_bytes <= 0: return
        # v1.1.2 (Fix 3): an FS embedded inside a UBI region's span is region
        # content — write it under that region's volumes/ dir (with vol/LEB
        # hints in the name), never into the global other_fs/.
        if fs.region_index is not None:
            rdir = self.output_dir / "ubi" / f"region_{fs.region_index}" / "volumes"
            rdir.mkdir(parents=True, exist_ok=True)
            out_dir = rdir
        else:
            out_dir = self.output_dir / "other_fs"
        valid_tag = "VALID" if fs.validation.get("valid") else "INVALID"
        safe_type = fs.fs_type.replace("/", "_")
        name_extra = ""
        if fs.region_index is not None:
            name_extra = f"_emb_r{fs.region_index}"
            if fs.vol_id_hint is not None:
                name_extra += f"_v{fs.vol_id_hint}_l{fs.lnum_hint}"
        out_path = out_dir / f"{safe_type}_{fs.offset_raw:#010x}_{valid_tag}{name_extra}.bin"

        if fs.offset_clean is not None and fs.offset_clean + fs.size_bytes <= len(self.clean_data):
            data = self.clean_data[fs.offset_clean:fs.offset_clean + fs.size_bytes]
        elif fs.raw_span_size > 0 and fs.offset_raw + fs.raw_span_size <= len(self.raw_data):
            raw_chunk = self.raw_data[fs.offset_raw:fs.offset_raw + fs.raw_span_size]
            if self.geom.has_oob:
                clean = bytearray()
                pos = 0
                while pos + self.geom.page_size <= len(raw_chunk):
                    clean.extend(raw_chunk[pos:pos + self.geom.page_size])
                    pos += self.geom.stride
                data = bytes(clean)
            else: data = raw_chunk
        else: return

        out_path.write_bytes(data)
        fs.path = str(out_path)
        # v06: no auto-unsquashfs — user can unpack manually when needed


# ═══════════════════════════════════════════════════════════════════════════
#  REPORTER
# ═══════════════════════════════════════════════════════════════════════════

class Reporter:
    def __init__(self, output_dir: Path): self.output_dir = output_dir

    def write(self, report: FirmwareReport, found_fs_list: Optional[List[FoundFS]] = None) -> None:
        self._write_json(report, found_fs_list)
        self._write_text(report, found_fs_list)

    def _write_json(self, report: FirmwareReport, found_fs_list: Optional[List[FoundFS]] = None) -> None:
        data = asdict(report)
        path = self.output_dir / "report.json"
        path.write_text(json.dumps(data, indent=2, default=str))

    def _write_text(self, report: FirmwareReport, found_fs_list: Optional[List[FoundFS]] = None) -> None:
        lines, sep = [], "=" * 72
        lines += [sep, "  FIRMWARE ANALYSIS REPORT", sep,
                  f"  File       : {report.input_file}",
                  f"  Size       : {report.file_size:,} bytes ({report.file_size / 1024 / 1024:.1f} MiB)",
                  f"  MD5        : {report.md5}", f"  Analysis   : {report.analysis_time_s:.1f}s", ""]

        # Firmware wrapper header section
        if report.firmware_header:
            hdr = report.firmware_header
            lines += ["── FIRMWARE HEADER " + "─" * 53,
                      f"  Type       : {hdr.get('header_type', '?')}",
                      f"  Header size: {hdr.get('header_size', 0):,} bytes (0x{hdr.get('header_size', 0):X})"]
            meta = hdr.get('meta', {})
            if meta:
                for k, v in meta.items():
                    lines.append(f"  {k:<11}: {v}")
            lines.append("")

        if report.oob_geometry:
            g = report.oob_geometry
            lines += ["── NAND / OOB GEOMETRY " + "─" * 50, f"  Has OOB    : {g.get('has_oob')}"]
            if g.get("has_oob"):
                lines += [f"  Page size  : {g['page_size']} bytes", f"  OOB size   : {g['oob_size']} bytes",
                          f"  Stride     : {g['stride']} bytes", f"  Raw EB     : 0x{g['raw_eb_size']:X}",
                          f"  Clean EB   : 0x{g['clean_eb_size']:X}"]
            lines.append("")

        for ri, reg in enumerate(report.ubi_regions):
            lines += [
                f"── UBI REGION {ri} ({reg.get('region_type', 'n/a')}) " + "─" * 35,
                f"  Clean Offset: 0x{reg['start_offset_clean']:X} - 0x{reg['end_offset_clean']:X} (Size: 0x{reg['end_offset_clean'] - reg['start_offset_clean']:X})",
                f"  Raw Offset  : 0x{reg['start_offset_raw']:X} - 0x{reg['end_offset_raw']:X} (Size: 0x{reg['end_offset_raw'] - reg['start_offset_raw']:X})",
                f"  PEB size    : 0x{reg['peb_size_clean']:X} (Clean) / 0x{reg['peb_size_raw']:X} (Raw)",
                f"  LEB size    : 0x{reg['leb_size']:X} ({reg['leb_size']} bytes)",
                f"  PEB count   : {reg['peb_count']}", f"  Image seq   : {reg['image_seq']}", "",
                "  Vol  │ Name                  │ Type    │ LEBs │ FS         │ Valid",
                "  " + "─" * 75,
            ]
            for vid, vol in sorted(reg["volumes"].items(), key=lambda kv: kv[0]):
                if vol is None:
                    lines.append(f"  {int(vid):>4} │ {'(unparsed)':<22} │ {'?':<7} │    ? │ —          │ ?")
                    continue
                tname = VOL_TYPE_NAMES.get(vol["vol_type"], "?")
                fs = vol.get("fs_type") or "—"
                vol_val = vol.get("validation") or {}
                valid_str = "✓" if vol_val.get("valid") else "✗"
                name = vol["name"][:22]
                lines.append(f"  {int(vol['vol_id']):>4} │ {name:<22} │ {tname:<7} │ {vol['leb_count']:>4} │ {fs:<10} │ {valid_str}")
            lines.append("")

        if found_fs_list:
            lines += ["── FILESYSTEMS FOUND OUTSIDE UBI " + "─" * 35,
                      "  Raw Offset  │ Clean Offset │ Type       │ Size        │ Raw Span    │ Valid │ Sources        │ Path",
                      "  " + "─" * 110]
            for fs in found_fs_list:
                valid_str = "✓" if fs.validation.get("valid") else "✗"
                size_str = f"{fs.size_bytes:,}" if fs.size_bytes > 0 else "unknown"
                span_str = f"{fs.raw_span_size:,}" if fs.raw_span_size > 0 else "unknown"
                clean_off_val = fs.offset_clean if fs.offset_clean is not None else 0
                lines.append(f"  0x{fs.offset_raw:08X} │ 0x{clean_off_val:08X} │ {fs.fs_type:<10} │ {size_str:>10} │ {span_str:>10} │  {valid_str}   │ {','.join(fs.detected_in):<14} │ {fs.path or '—'}")
            lines.append("")

        if report.warnings:
            lines += ["── WARNINGS " + "─" * 60]
            for w in report.warnings: lines.append(f"  ⚠  {w}")
            lines.append("")

        lines.append(sep)
        path = self.output_dir / "report.txt"
        path.write_text("\n".join(lines))
        print("\n".join(lines))


# ═══════════════════════════════════════════════════════════════════════════
#  FIRMWARE HEADER DETECTION
# ═══════════════════════════════════════════════════════════════════════════

class FirmwareHeaderDetector:
    """Detects firmware wrapper headers that sit before UBI/flash data.

    Two known types so far:
      1. Big-endian size-prefixed upgrade package — first 4 bytes (BE) = total
         file size, followed by a metadata string like 'fw-type:Cloud'.
         UBI data starts at an offset specified within the header structure.
      2. Legacy bootloader image — magic 0x27051956, 64-byte header with image
         name, load address, entry point, etc. May be followed by bootloader
         and factory/calibration data before UBI.
    """

    U_BOOT_MAGIC = 0x27051956
    BE_SIZE_UPG_MIN_HEADER = 16       # minimum recognizable header size
    BE_SIZE_UPG_MAX_HEADER = 0x20000  # maximum header region to search (128 KB)
    U_BOOT_HEADER_SIZE = 64

    @staticmethod
    def detect(data: bytes) -> FirmwareHeader:
        if len(data) < 16:
            return FirmwareHeader(header_type='none', header_size=0)

        # --- Check legacy bootloader image header ---
        magic_ub = struct.unpack_from('>I', data, 0)[0]
        if magic_ub == FirmwareHeaderDetector.U_BOOT_MAGIC:
            return FirmwareHeaderDetector._parse_u_boot(data)

        # --- Check big-endian size-prefixed upgrade package header ---
        fw_size_be = struct.unpack_from('>I', data, 0)[0]
        if fw_size_be == len(data):
            return FirmwareHeaderDetector._parse_be_size_upg(data)

        return FirmwareHeader(header_type='none', header_size=0)

    @staticmethod
    def _parse_u_boot(data: bytes) -> FirmwareHeader:
        """Parse U-Boot legacy image header (64 bytes)."""
        meta = {}
        try:
            meta['magic'] = '0x27051956 (U-Boot IH_MAGIC)'
            meta['image_name'] = data[32:64].rstrip(b'\x00').decode('ascii', errors='replace')
            meta['data_size'] = struct.unpack_from('>I', data, 12)[0]
            meta['load_addr'] = f"0x{struct.unpack_from('>I', data, 16)[0]:08X}"
            meta['entry_point'] = f"0x{struct.unpack_from('>I', data, 20)[0]:08X}"
            meta['os_type'] = data[28]
            meta['arch'] = data[29]
            meta['image_type'] = data[30]
            meta['compression'] = data[31]
        except struct.error:
            pass

        # U-Boot header is 64 bytes, but UBI data may start much later
        # (after bootloader + factory data). Find first UBI# after header.
        ubi_offset = data.find(UBI_EC_MAGIC, FirmwareHeaderDetector.U_BOOT_HEADER_SIZE)
        if ubi_offset > 0:
            header_size = ubi_offset
        else:
            # No UBI found — entire file may be just the U-Boot image
            header_size = FirmwareHeaderDetector.U_BOOT_HEADER_SIZE

        raw_header = data[:FirmwareHeaderDetector.U_BOOT_HEADER_SIZE]
        log.info("Detected U-Boot legacy image header: '%s', UBI data at 0x%X",
                 meta.get('image_name', '?'), header_size)
        return FirmwareHeader(
            header_type='u_boot_legacy', header_size=header_size,
            raw_header=raw_header, meta=meta
        )

    @staticmethod
    def _parse_be_size_upg(data: bytes) -> FirmwareHeader:
        """Parse big-endian size-prefixed upgrade package header.

        Structure:
          Offset 0: 4-byte BE uint32 = total file size
          Offset 4: metadata (may contain 'fw-type:' string, hashes, etc.)
          The UBI data begins at an offset that can be found by searching
          for the first UBI# magic. The header also contains a 4-byte LE
          offset field near offset 0 that points to the UBI start.
        """
        meta = {}
        meta['file_size_field'] = struct.unpack_from('>I', data, 0)[0]

        # Try to extract fw-type string
        fw_type_match = None
        for start in range(4, min(64, len(data))):
            if data[start:start+8] == b'fw-type:':
                end = data.find(b'\x00', start)
                if end > start:
                    fw_type_match = data[start:end].decode('ascii', errors='replace')
                    break
        if fw_type_match:
            meta['fw_type'] = fw_type_match

        # Extract the first 4 bytes as LE uint32 — this is the UBI offset
        ubi_offset_le = struct.unpack_from('<I', data, 0)[0]
        # Verify: does UBI# actually appear at that offset?
        ubi_offset = -1
        if (ubi_offset_le < len(data) and ubi_offset_le > 16
                and data[ubi_offset_le:ubi_offset_le+4] == UBI_EC_MAGIC):
            ubi_offset = ubi_offset_le
            meta['ubi_offset_field'] = f"0x{ubi_offset_le:X} ({ubi_offset_le})"
        else:
            # Fallback: search for first UBI# after the first 16 bytes
            ubi_offset = data.find(UBI_EC_MAGIC, 16)
            if ubi_offset > 0:
                meta['ubi_offset_searched'] = f"0x{ubi_offset:X} ({ubi_offset})"

        if ubi_offset <= 0:
            ubi_offset = 0  # no header detected, treat entire file as data

        raw_header = data[:ubi_offset] if ubi_offset > 0 else None
        log.info("Detected BE size-prefixed upgrade package header: fw-type='%s', UBI at 0x%X",
                 meta.get('fw_type', '?'), ubi_offset)
        return FirmwareHeader(
            header_type='be_size_upg', header_size=ubi_offset,
            raw_header=raw_header, meta=meta
        )


# ═══════════════════════════════════════════════════════════════════════════
#  FIRMWARE ANALYST
# ═══════════════════════════════════════════════════════════════════════════

class FirmwareAnalyst:
    def __init__(self, firmware_path: str, output_dir: str, page_size: Optional[int] = None, oob_size: Optional[int] = None, peb_size: Optional[int] = None, leb_size: Optional[int] = None, report_only: bool = False, mode: str = "auto"):
        self.firmware_path, self.output_dir = Path(firmware_path), Path(output_dir)
        self.page_size, self.oob_size, self.peb_size, self.leb_size = page_size, oob_size, peb_size, leb_size
        self.report_only, self.mode = report_only, mode

    def run(self) -> FirmwareReport:
        t0 = time.time()
        log.info("Loading: %s", self.firmware_path)
        raw_data = self.firmware_path.read_bytes()
        md5, sha256 = hashlib.md5(raw_data).hexdigest(), hashlib.sha256(raw_data).hexdigest()

        # --- Detect firmware wrapper header (BE size-prefixed upgrade package, legacy bootloader, etc.) ---
        fw_header = FirmwareHeaderDetector.detect(raw_data)
        if fw_header.header_type != 'none' and fw_header.header_size > 0:
            log.info("Firmware header: type='%s', header_size=%d (0x%X) — skipping to UBI data",
                     fw_header.header_type, fw_header.header_size, fw_header.header_size)
            # Extract header blob for the output directory
            if fw_header.raw_header:
                self.output_dir.mkdir(parents=True, exist_ok=True)
                hdr_path = self.output_dir / "firmware_header.bin"
                hdr_path.write_bytes(fw_header.raw_header)
                log.info("Header extracted to: %s", hdr_path)
        else:
            log.info("No firmware wrapper header detected — analyzing entire file")

        # For OOB detection and UBI scanning, work on data after the header
        flash_data = raw_data[fw_header.header_size:] if fw_header.header_size > 0 else raw_data

        detector = OOBDetector(flash_data, self.page_size, self.oob_size)
        if self.mode == "clean_ubi":
            geom = OOBGeometry(0, 0, 0, len(flash_data), len(flash_data), 0, False)
            clean_data = flash_data
        else:
            geom = detector.detect()
            clean_data = detector.strip(geom)

        # Round-trip self-test: clean→raw→clean must be identity for offset
        # classes that survive mapping (multiples of the page size within a
        # raw EB keep clean coordinates). Random-ish probes across the image.
        if geom.has_oob:
            probes = [geom.page_size, geom.page_size * 3,
                      geom.clean_eb_size + geom.page_size,
                      geom.clean_eb_size * 3 + geom.page_size * 5]
            for tc in probes:
                rr = OOBDetector.clean_to_raw_offset(tc, geom)
                if rr is None:
                    raise RuntimeError(f"Offset self-test: clean {tc} unmapped")
                if OOBDetector.raw_to_clean_offset(rr, geom) != tc:
                    raise RuntimeError(
                        f"Offset round-trip failed: clean {tc} -> raw {rr} -> "
                        f"clean {OOBDetector.raw_to_clean_offset(rr, geom)}")
            log.info("Offset round-trip self-tests passed (page=%d, oob=%d).",
                     geom.page_size, geom.oob_size)

        scanner = UBIScanner(clean_data, self.peb_size, self.leb_size)
        scanner._oob_geom = geom  # evidence-sharing: PEB fallback derives
        scanner._peb_hint = geom.raw_eb_size if geom.has_oob else geom.clean_eb_size
        regions = scanner.scan()

        report = FirmwareReport(
            input_file=str(self.firmware_path), file_size=len(raw_data), md5=md5, sha256=sha256,
            oob_geometry=asdict(geom) if geom else None, analysis_time_s=round(time.time() - t0, 2),
            firmware_header=asdict(fw_header) if fw_header.header_type != 'none' else None
        )

        # Map raw offsets and populate region geometry
        for region in regions:
            region.start_offset_raw = OOBDetector.clean_to_raw_offset(region.start_offset_clean, geom)
            region.end_offset_raw = OOBDetector.clean_to_raw_offset(region.end_offset_clean, geom)
            region.peb_size_raw = geom.raw_eb_size if geom.has_oob else region.peb_size_clean
            
            region.geometry = {
                "page_size": geom.page_size, "oob_size": geom.oob_size, "stride": geom.stride,
                "peb_size_clean": region.peb_size_clean, "peb_size_raw": region.peb_size_raw,
                "leb_size": region.leb_size, "vid_hdr_offset": region.vid_hdr_offset,
                "data_offset": region.data_offset, "pages_per_eb": geom.pages_per_eb,
                "ec_magic": "UBI#", "vid_magic": "UBI!",
            }

            for vol_id, vol in region.volumes.items():
                if vol.missing_lnum_count > 0:
                    report.warnings.append(f"Volume {vol_id} ({vol.name}) missing {vol.missing_lnum_count} LNUMs (filled with 0xFF)")

            report.ubi_regions.append({k: v for k, v in asdict(region).items() if k not in ("ec_headers", "vid_headers")})

        extractor = Extractor(self.output_dir, flash_data, clean_data, geom)
        found_fs_list: List[FoundFS] = []

        if not self.report_only:
            for i, region in enumerate(regions):
                extractor.extract_region(region, i, report.warnings)
            found_fs_list = extractor.scan_for_orphan_fs(regions, report.warnings)
            report.other_fs = [asdict(f) for f in found_fs_list]

        Reporter(self.output_dir).write(report, found_fs_list)
        return report


# ═══════════════════════════════════════════════════════════════════════════
#  CLI / GUI
# ═══════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ubi_analyst", description="Firmware analysis and UBI extraction tool")
    p.add_argument("firmware", nargs="?", help="Input firmware binary")
    p.add_argument("-o", "--output", default="output", help="Output directory")
    p.add_argument("--page-size", type=lambda x: int(x, 0), help="NAND page size in bytes")
    p.add_argument("--oob-size", type=lambda x: int(x, 0), help="NAND OOB size in bytes")
    p.add_argument("--peb-size", type=lambda x: int(x, 0), help="Physical Erase Block size")
    p.add_argument("--leb-size", type=lambda x: int(x, 0), help="Logical Erase Block size")
    p.add_argument("--report-only", action="store_true", help="Scan and report only, skip extraction")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--clean-ubi", action="store_true", help="Treat input as already-clean UBI image (no OOB)")
    mode.add_argument("--force-geometry", action="store_true", help="Force provided NAND geometry")
    p.add_argument("--gui", action="store_true", help="Open an option window")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return p

def run_with_options(opts: AnalysisOptions) -> int:
    if opts.verbose: logging.getLogger().setLevel(logging.DEBUG)
    if not opts.firmware or not Path(opts.firmware).exists(): return 1
    analyst = FirmwareAnalyst(opts.firmware, opts.output, opts.page_size, opts.oob_size, opts.peb_size, opts.leb_size, opts.report_only, opts.mode)
    try:
        analyst.run()
        return 0
    except Exception as e:
        log.exception("Analysis failed: %s", e)
        return 1

def main() -> int:
    args = build_parser().parse_args()
    mode = "clean_ubi" if args.clean_ubi else "force_geometry" if args.force_geometry else "auto"
    opts = AnalysisOptions(args.firmware, args.output, mode, args.verbose, args.report_only, args.page_size, args.oob_size, args.peb_size, args.leb_size, args.gui)
    if opts.gui:
        print("error: GUI mode is not available in this build; use CLI mode "
              "(ubipack -x -s <firmware> -o <outdir>)", file=sys.stderr)
        return 2
    if not opts.firmware:
        print("error: no firmware specified; use --help for usage", file=sys.stderr)
        return 2
    return run_with_options(opts)

if __name__ == "__main__":
    sys.exit(main())
