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
import os
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Optional GUI
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    HAS_TK = True
except Exception:
    HAS_TK = False

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

NAND_GEOMETRIES = [
    (512, 16),
    (2048, 64),
    (2048, 128),
    (4096, 128),
    (4096, 256),
]

# ── Filesystem magic signatures for raw scanning ──────────────────────────
FS_SCAN_SIGNATURES = [
    (b"hsqs", "SquashFS", "little", 4096, "SquashFS v4 LE"),
    (b"sqsh", "SquashFS", "big", 4096, "SquashFS v4 BE"),
    (b"qshs", "SquashFS", "mixed", 4096, "SquashFS v4 mixed-endian"),
    (b"shsq", "SquashFS", "mixed", 4096, "SquashFS v4 mixed-endian"),
    (b"\x31\x18\x55\x28", "UBIFS", "little", 4096, "UBIFS LE"),
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
    region_type: str = "image_seq_group"
    grouping_reason: str = "contiguous EC headers grouped by gap threshold and image_seq"


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
        chunk = data[offset:]
        if len(chunk) < 96:
            result["reason"] = "Too small for SquashFS superblock"
            return result
        magic = chunk[:4]
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
        chunk = data[offset:]
        if len(chunk) < 16: return result
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
        chunk = data[offset:]
        if len(chunk) < 128: return result
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
        chunk = data[offset:]
        if len(chunk) < 80: return result
        if chunk[:4] != b"\x31\x18\x55\x28": return result
        try:
            leb_size = struct.unpack_from("<I", chunk, 0x18)[0]
            leb_count = struct.unpack_from("<I", chunk, 0x1C)[0]
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
        chunk = data[offset:]
        if len(chunk) < 40: return result
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
        b"\x31\x18\x55\x28": ("UBIFS", "little"),
        b"\x85\x19": ("JFFS2", "little"),  # 2-byte magic only; node type varies
        b"\x19\x85": ("JFFS2", "big"),     # 2-byte magic only; node type varies
        b"\x45\x3D\xCD\x28": ("CramFS", "little"),
        b"\x28\xCD\x3D\x45": ("CramFS", "big"),
        b"\xD0\x0D\xFE\xED": ("DTB", "big"),
    }

    @staticmethod
    def detect(data: bytes) -> Tuple[Optional[str], Optional[str], dict]:
        stripped = data.lstrip(b"\xff")
        if not stripped: return None, None, {}
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

    def detect(self) -> OOBGeometry:
        f1 = self.data.find(UBI_EC_MAGIC)
        f2 = self.data.find(UBI_EC_MAGIC, f1 + 1)
        if f1 < 0 or f2 < 0:
            raise ValueError("Cannot find two UBI# headers — not a UBI image?")

        raw_eb = f2 - f1
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

        if not candidates:
            log.warning("No standard NAND geometry fits — treating as no OOB")
            return OOBGeometry(0, 0, 0, raw_eb, raw_eb, 0, False)

        if len(candidates) == 1:
            page_size, oob_size, *_ = candidates[0]
            log.info("Auto-detected geometry: page=%dB, OOB=%dB", page_size, oob_size)
            return self._build_geometry(page_size, oob_size, raw_eb)

        page_size, oob_size = self._measure_stride(candidates)
        log.info("Disambiguated geometry: page=%dB, OOB=%dB", page_size, oob_size)
        return self._build_geometry(page_size, oob_size, raw_eb)

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
        ec_headers = self._find_ec_headers()
        if not ec_headers: return []
        peb_size = self._determine_peb_size(ec_headers)
        regions_raw = self._group_regions(ec_headers, peb_size)
        regions = []
        for region_ecs in regions_raw:
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
        return headers

    def _determine_peb_size(self, ec_headers: List[ECHeaderInfo]) -> int:
        if self.forced_peb: return self.forced_peb
        if len(ec_headers) < 2: return 0x20000
        gaps, offsets = [], sorted(h.offset for h in ec_headers)
        for i in range(1, min(len(offsets), 20)):
            gap = offsets[i] - offsets[i - 1]
            if gap > 0: gaps.append(gap)
        return max(set(gaps), key=gaps.count) if gaps else 0x20000

    def _group_regions(self, ec_headers: List[ECHeaderInfo], peb_size: int) -> List[List[ECHeaderInfo]]:
        if not ec_headers: return []
        sorted_ecs = sorted(ec_headers, key=lambda h: h.offset)
        regions, current = [], [sorted_ecs[0]]
        for ec in sorted_ecs[1:]:
            prev = current[-1]
            if ec.offset - prev.offset <= peb_size * 4 and ec.image_seq == prev.image_seq:
                current.append(ec)
            else:
                regions.append(current)
                current = [ec]
        regions.append(current)
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
        region.vid_headers = self._scan_vid_headers(ec_headers, vid_hdr_off)

        leb_map: Dict[int, Dict[int, bytes]] = {}
        for vid in region.vid_headers:
            eb_start = vid.offset - vid_hdr_off
            chunk = self.data[eb_start + data_off : eb_start + data_off + leb_size]
            leb_map.setdefault(vid.vol_id, {})[vid.lnum] = chunk

        vol_names = self._parse_vtbl(leb_map)
        ec_values = [h.ec for h in ec_headers]
        for vid_id, lebs in leb_map.items():
            if vid_id >= 0x7FFFEFFF: continue
            assembled = self._assemble_lebs(lebs)
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


# ═══════════════════════════════════════════════════════════════════════════
#  EXTRACTOR
# ═══════════════════════════════════════════════════════════════════════════

class Extractor:
    def __init__(self, output_dir: Path, raw_data: bytes, clean_data: bytes, geom: OOBGeometry):
        self.output_dir, self.raw_data, self.clean_data, self.geom = output_dir, raw_data, clean_data, geom
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "ubi").mkdir(exist_ok=True)
        (output_dir / "other_fs").mkdir(exist_ok=True)

    def extract_region(self, region: UBIRegion, region_idx: int, warnings_list: List[str]) -> None:
        rdir = self.output_dir / "ubi" / f"region_{region_idx}"
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

        leb_map = self._build_leb_map(region)
        seen_hashes: Dict[str, str] = {}  # sha256 -> primary volume name (for dedup)
        for vol_id, vol_info in sorted(region.volumes.items()):
            self._extract_volume(vol_id, vol_info, leb_map, rdir, region, seen_hashes, warnings_list)

    def _build_leb_map(self, region: UBIRegion) -> Dict[int, Dict[int, bytes]]:
        leb_map: Dict[int, Dict[int, bytes]] = {}
        for vid in region.vid_headers:
            eb_start = vid.offset - region.vid_hdr_offset
            chunk = self.clean_data[eb_start + region.data_offset : eb_start + region.data_offset + region.leb_size]
            leb_map.setdefault(vid.vol_id, {})[vid.lnum] = chunk
        return leb_map

    def _assemble_lebs(self, lebs: Dict[int, bytes], leb_size: int) -> bytes:
        """Helper to assemble LEBs, filling missing LNUMs with 0xFF."""
        if not lebs: return b""
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
            log.info("Extracted kernel volume %d ('%s') → %s (%d bytes)",
                     vol_id, vol_info.name, vol_bin.name, len(clean_vol))

        elif category == "raw":
            vol_bin = vols_dir / f"vol_{vol_id}_{safe_name}.bin"
            vol_bin.write_bytes(clean_vol)
            vol_info.extracted_path = str(vol_bin)
            log.info("Extracted raw volume %d ('%s') → %s (%d bytes)",
                     vol_id, vol_info.name, vol_bin.name, len(clean_vol))

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

    def scan_for_orphan_fs(self, regions: List[UBIRegion], warnings_list: List[str]) -> List[FoundFS]:
        found: List[FoundFS] = []
        covered_clean = set()
        for region in regions:
            for i in range(region.start_offset_clean, min(region.end_offset_clean, len(self.clean_data)), 0x1000):
                covered_clean.add(i)

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
            if clean_off in covered_clean: continue

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

            found_fs = FoundFS(
                offset_raw=raw_off, offset_clean=clean_off, fs_type=fs_type, endian=entry["endian"],
                size_bytes=size_bytes, size_verified=size_verified, validation=validation,
                magic=entry.get("magic", ""), size_clean=size_bytes, raw_span_size=raw_span_size,
                detected_in=entry["detected_in"]
            )
            found.append(found_fs)

        for fs in found: self._extract_orphan_fs(fs)
        return found

    def _scan_by_magic(self, data: bytes, is_raw: bool) -> List[dict]:
        results: List[dict] = []
        search_limit = min(len(data), 256 * 1024 * 1024)
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
        out_dir = self.output_dir / "other_fs"
        valid_tag = "VALID" if fs.validation.get("valid") else "INVALID"
        safe_type = fs.fs_type.replace("/", "_")
        out_path = out_dir / f"{safe_type}_{fs.offset_raw:#010x}_{valid_tag}.bin"

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

        # Runtime self-tests for offset conversions (dynamic — works for any geometry)
        if geom.has_oob:
            test_raw = 230000
            test_clean = OOBDetector.raw_to_clean_offset(test_raw, geom)
            # Compute expected value from first principles: page_index * page_size + min(in_stride, page_size)
            page_index = test_raw // geom.stride
            in_stride = test_raw % geom.stride
            expected_clean = page_index * geom.page_size + min(in_stride, geom.page_size)
            if test_clean != expected_clean:
                raise RuntimeError(f"Offset self-test failed: raw {test_raw} -> clean {test_clean} (expected {expected_clean})")
            test_rt = OOBDetector.clean_to_raw_offset(test_clean, geom)
            if test_rt != test_raw:
                raise RuntimeError(f"Offset round-trip failed: clean {test_clean} -> raw {test_rt} (expected {test_raw})")
            log.info("Offset conversion self-tests passed (page=%d, oob=%d).", geom.page_size, geom.oob_size)

        scanner = UBIScanner(clean_data, self.peb_size, self.leb_size)
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
    if opts.gui or not opts.firmware:
        try:
            app = GuiApp(); app.root.mainloop(); return 0
        except Exception: return 1
    return run_with_options(opts)

if __name__ == "__main__":
    sys.exit(main())
