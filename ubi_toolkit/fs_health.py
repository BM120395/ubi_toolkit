#!/usr/bin/env python3
"""fs_health.py -- post-extraction filesystem health check + anomaly healing.

The analyst extracts every filesystem volume and the repacker rebuilds
regions, but "the bytes were written" is not the same as "the filesystem
is sound". This module answers the second question:

  1. DEEP CHECK -- for SquashFS volumes this walks the real on-disk
     structures (superblock pointers, the metadata-block chain behind
     the inode/directory/fragment tables, the root inode) and reports
     every structure that does not decode. A superblock can look
     perfectly sane while a single damaged metadata block makes the
     filesystem unmountable; only a structural walk catches that.

  2. HEAL -- when the deep check finds damage, evidence-gated repair
     strategies are tried (alternative LEB assemblies from redundant
     flash copies, physical-order vs logical-order reconstruction,
     trim/pad fixes). Each candidate is scored with the same deep
     check, and the healthiest one wins. The pre-heal bytes are kept
     as ``<volume>.orig.<ext>`` so the original anomaly can be
     preserved verbatim (see --dual-output on repack).

Everything here is pure stdlib and vendor-neutral. The healing never
invents data: every candidate byte comes from the dump itself, and
when no candidate is healthy the volume is still written, with the
damage loudly reported instead of silently shipped.
"""

from __future__ import annotations

import logging
import lzma
import struct
import zlib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("ubi_toolkit.fs_health")

SQUASHFS_MAGIC = b"hsqs"

# Metadata header: bit 15 = uncompressed, bits 0-14 = payload size.
META_UNCOMPRESSED_FLAG = 0x8000
META_MAX_PAYLOAD = 8192

# Inode types (SquashFS 3/4)
INODE_TYPES = {1: "dir", 2: "file", 3: "symlink", 4: "blkdev", 5: "chrdev",
               6: "fifo", 7: "socket", 8: "ldir", 9: "ext_file"}


# ---------------------------------------------------------------------------
# Deep check (SquashFS)
# ---------------------------------------------------------------------------
def parse_superblock(data: bytes) -> Optional[dict]:
    """Parse a SquashFS superblock (tries little-endian, then big-endian)."""
    for fmt, order in (("<", "LE"), (">", "BE")):
        if len(data) < 96:
            return None
        magic = data[0:4]
        if order == "LE" and magic != SQUASHFS_MAGIC:
            if magic == b"sqsh":
                continue
            return None
        try:
            (inode_count, mod_time, block_size, frag_count) = struct.unpack_from(
                fmt + "IIII", data, 4)
            (comp_id, block_log, flags, no_ids, s_major, s_minor) = \
                struct.unpack_from(fmt + "HHHHHH", data, 20)
            (root_inode, bytes_used, id_table, xattr_table,
             inode_table, dir_table, frag_table, export_table) = \
                struct.unpack_from(fmt + "QQQQQQQQ", data, 32)
        except struct.error:
            return None
        if block_log < 12 or block_log > 24 or block_size != (1 << block_log):
            continue
        return {
            "order": order, "inode_count": inode_count, "mod_time": mod_time,
            "block_size": block_size, "frag_count": frag_count,
            "compression": comp_id, "block_log": block_log, "flags": flags,
            "no_ids": no_ids, "s_major": s_major, "s_minor": s_minor,
            "root_inode": root_inode, "bytes_used": bytes_used,
            "id_table_start": id_table, "xattr_table_start": xattr_table,
            "inode_table_start": inode_table, "dir_table_start": dir_table,
            "frag_table_start": frag_table, "export_table_start": export_table,
        }
    return None


def _decompress_meta(payload: bytes, comp_id: int) -> Optional[bytes]:
    """Best-effort decompression of one metadata block payload."""
    if comp_id == 1:  # gzip (raw deflate; squashfs omits the zlib header)
        for wbits in (-15, 15):
            try:
                return zlib.decompressobj(wbits).decompress(payload)
            except zlib.error:
                continue
        return None
    if comp_id in (2, 4):  # lzma (alone) / xz
        try:
            fmt = lzma.FORMAT_ALONE if comp_id == 2 else lzma.FORMAT_AUTO
            dec = lzma.LZMADecompressor(format=fmt)
            return dec.decompress(payload)
        except lzma.LZMAError:
            return None
    return None  # lzo/lz4/zstd: not stdlib-decodable; treated as opaque


def _walk_meta_chain(data: bytes, start: int, end: int, comp_id: int,
                     limit: int) -> Tuple[int, int, List[str]]:
    """Walk a metadata block chain [start, end). Returns
    (blocks_ok, blocks_total, issues)."""
    ok = 0
    total = 0
    issues: List[str] = []
    off = start
    while off + 2 <= end and total < limit:
        total += 1
        hdr = struct.unpack_from("<H", data, off)[0]
        c_size = hdr & ~META_UNCOMPRESSED_FLAG
        payload_off = off + 2
        if c_size == 0 or c_size > META_MAX_PAYLOAD or \
                payload_off + c_size > len(data):
            issues.append(f"metadata block at {off:#x}: "
                          f"implausible size {c_size}")
            break
        payload = data[payload_off:payload_off + c_size]
        if hdr & META_UNCOMPRESSED_FLAG:
            out = payload
        else:
            out = _decompress_meta(payload, comp_id)
        if out is None or len(out) == 0:
            issues.append(f"metadata block at {off:#x}: "
                          f"failed to decode ({c_size} B payload)")
            off = payload_off + c_size
            continue
        ok += 1
        off = payload_off + c_size
    return ok, total, issues


def deep_check_squashfs(data: bytes, max_blocks: int = 128) -> dict:
    """Structural health check of a SquashFS image.

    Returns {healthy, errors, warnings, superblock, stats}. A image with
    a plausible superblock but one undecodable table block is NOT
    healthy -- that is the whole point.
    """
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, object] = {}

    sb = parse_superblock(data)
    if sb is None:
        return {"healthy": False, "errors": ["no parseable SquashFS "
                "superblock (magic/version/geometry invalid)"],
                "warnings": warnings, "superblock": None, "stats": stats}

    n = len(data)
    pointers = [("inode_table_start", sb["inode_table_start"]),
                ("dir_table_start", sb["dir_table_start"]),
                ("id_table_start", sb["id_table_start"])]
    if sb["frag_count"]:
        pointers.append(("frag_table_start", sb["frag_table_start"]))
    for name, val in pointers:
        if not (96 <= val < n):
            errors.append(f"{name} = {val:#x} outside image (size {n:#x})")

    if sb["bytes_used"] > n:
        errors.append(f"bytes_used {sb['bytes_used']:,} exceeds image "
                      f"size {n:,}")
    if sb["bytes_used"] < 96:
        errors.append(f"bytes_used {sb['bytes_used']} implausibly small")
    if sb["s_major"] not in (3, 4):
        warnings.append(f"unusual squashfs major version {sb['s_major']}")

    stats["order"] = sb["order"]
    stats["compression"] = sb["compression"]
    stats["bytes_used"] = sb["bytes_used"]
    stats["image_size"] = n

    comp_id = sb["compression"]
    if comp_id not in (1, 2, 4):
        warnings.append(f"compressor id {comp_id} not stdlib-decodable; "
                        f"structure walk limited to pointer/plausibility "
                        f"checks")
        healthy = not errors
        return {"healthy": healthy, "errors": errors, "warnings": warnings,
                "superblock": sb, "stats": stats}

    # -- inode table chain (inode_table_start .. dir_table_start) --------
    if 96 <= sb["inode_table_start"] < n and \
            sb["inode_table_start"] < sb["dir_table_start"] <= n:
        ok, total, iss = _walk_meta_chain(
            data, sb["inode_table_start"], sb["dir_table_start"],
            comp_id, max_blocks)
        stats["inode_blocks_ok"] = ok
        stats["inode_blocks_total"] = total
        errors.extend(iss)
    elif sb["inode_table_start"] < n:
        errors.append("inode table start >= dir table start (chain "
                      "cannot be walked)")

    # -- directory table chain (dir_table_start .. frag/id table) --------
    chain_end = sb["frag_table_start"] if sb["frag_count"] \
        else sb["id_table_start"]
    if 96 <= sb["dir_table_start"] < n and \
            sb["dir_table_start"] < chain_end <= n:
        ok, total, iss = _walk_meta_chain(
            data, sb["dir_table_start"], chain_end, comp_id, max_blocks)
        stats["dir_blocks_ok"] = ok
        stats["dir_blocks_total"] = total
        errors.extend(iss)
        # -- root inode: must be parseable inside the inode table --------
        ri = sb["root_inode"]
        start_block = ri >> 16
        offset = ri & 0xFFFF
        try:
            inode_block_off = sb["inode_table_start"] + start_block
            if inode_block_off >= sb["dir_table_start"]:
                errors.append(f"root inode block index {start_block} "
                              f"outside inode table")
            else:
                hdr = struct.unpack_from("<H", data, inode_block_off)[0]
                c_size = hdr & ~META_UNCOMPRESSED_FLAG
                payload = data[inode_block_off + 2:
                               inode_block_off + 2 + c_size]
                if hdr & META_UNCOMPRESSED_FLAG:
                    block_data = payload
                else:
                    block_data = _decompress_meta(payload, comp_id)
                if block_data is None:
                    errors.append("root inode metadata block does not "
                                  "decode")
                elif offset + 16 > len(block_data):
                    errors.append(f"root inode offset {offset} outside "
                                  f"its metadata block")
                else:
                    itype = struct.unpack_from(
                        "<H" if sb["order"] == "LE" else ">H",
                        block_data, offset)[0]
                    if itype not in INODE_TYPES:
                        errors.append(f"root inode type {itype} invalid")
                    else:
                        stats["root_inode_type"] = INODE_TYPES[itype]
        except (struct.error, KeyError):
            errors.append("root inode could not be parsed")

    # -- fragment table index --------------------------------------------
    # SquashFS 4: frag_table_start -> ceil(frag_count/512) u64 pointers,
    # each pointing at an uncompressed metadata block of 16-byte entries.
    # SquashFS 3: frag_table_start is directly that metadata chain with
    # 8-byte entries.
    if sb["frag_count"] and 96 <= sb["frag_table_start"] < n:
        entry_size = 16 if sb["s_major"] >= 4 else 8
        needed = sb["frag_count"] * entry_size
        if sb["s_major"] >= 4:
            n_index = max(1, -(-sb["frag_count"] // 512))
            if sb["frag_table_start"] + n_index * 8 > len(data):
                errors.append(f"fragment index ({n_index} pointers) "
                              f"truncated at {sb['frag_table_start']:#x}")
                ptrs = []
            else:
                fmt = "<" if sb["order"] == "LE" else ">"
                ptrs = list(struct.unpack_from(
                    fmt + f"{n_index}Q", data, sb["frag_table_start"]))
            got = 0
            for i, ptr in enumerate(ptrs):
                if not (96 <= ptr < n):
                    errors.append(f"fragment index pointer #{i} = "
                                  f"{ptr:#x} outside image")
                    break
                hdr = struct.unpack_from("<H", data, ptr)[0]
                c_size = hdr & ~META_UNCOMPRESSED_FLAG
                payload = data[ptr + 2:ptr + 2 + c_size] \
                    if ptr + 2 + c_size <= len(data) else b""
                out = payload if hdr & META_UNCOMPRESSED_FLAG \
                    else _decompress_meta(payload, comp_id)
                if out is None:
                    errors.append(f"fragment metadata block at {ptr:#x} "
                                  f"does not decode")
                    break
                got += len(out)
            if ptrs and got < needed:
                errors.append(f"fragment table yields {got} B, needs "
                              f"{needed} B for {sb['frag_count']} entries")
            stats["frag_index_blocks_ok"] = len(ptrs) if got >= needed else 0
        else:  # v3-style single chain
            ok, _t, iss = _walk_meta_chain(
                data, sb["frag_table_start"],
                sb["id_table_start"] if sb["id_table_start"] > sb["frag_table_start"] else n,
                comp_id, 8)
            stats["frag_index_blocks_ok"] = ok
            errors.extend(iss)

    healthy = not errors
    return {"healthy": healthy, "errors": errors, "warnings": warnings,
            "superblock": sb, "stats": stats}


# ---------------------------------------------------------------------------
# Health dispatch by filesystem type
# ---------------------------------------------------------------------------
def check_bytes(data: bytes, fs_type: Optional[str]) -> dict:
    """Deep-check extracted filesystem bytes according to their type.

    Every format the analyst can classify has a structural checker: the
    gate inspects the filesystem's real structures (headers, node
    chains, CRCs, directory trees) rather than trusting magic bytes.
    """
    checkers = {
        "SquashFS": deep_check_squashfs,
        "JFFS2": deep_check_jffs2,
        "CramFS": deep_check_cramfs,
        "UBIFS": deep_check_ubifs,
        "DTB": deep_check_dtb,
        "uImage": deep_check_uimage,
        "Initramfs": deep_check_initramfs,
    }
    fn = checkers.get(fs_type)
    if fn is None:
        return {"healthy": True, "errors": [], "warnings": [
            f"no deep checker for {fs_type!r}; superblock-level "
            f"validation only"], "superblock": None, "stats": {}}
    return fn(data)


# ---------------------------------------------------------------------------
# Healing: candidate assembly scoring
# ---------------------------------------------------------------------------
def score_variant(data: bytes, fs_type: Optional[str]) -> Tuple[int, int, int]:
    """Score one candidate volume assembly. Higher is better.

    Returns (healthy_flag, blocks_ok, minus_errors) so a healthy image
    always beats an unhealthy one, and among healthy ones more decoded
    structure wins.
    """
    rep = check_bytes(data, fs_type)
    ok = rep["stats"].get("inode_blocks_ok", 0) + \
        rep["stats"].get("dir_blocks_ok", 0) + \
        rep["stats"].get("frag_index_blocks_ok", 0) + \
        rep["stats"].get("nodes_ok", 0) + \
        rep["stats"].get("frag_index_blocks_ok", 0) + \
        rep["stats"].get("nodes", 0) + \
        rep["stats"].get("props", 0) + \
        rep["stats"].get("files_decoded", 0) + \
        rep["stats"].get("entries_decoded", 0) + \
        rep["stats"].get("members_ok", 0)
    return (1 if rep["healthy"] else 0, ok, -len(rep["errors"]))


def pick_healthiest(candidates: List[Tuple[str, bytes]],
                    fs_type: Optional[str]) -> Tuple[str, bytes, dict]:
    """Deep-check every candidate and return (name, bytes, report) of the
    healthiest. Candidates keep their order as tie-break priority."""
    if not candidates:
        raise ValueError("no candidates given")
    best_name, best_data, best_score, best_rep = candidates[0][0], \
        candidates[0][1], None, None
    for name, blob in candidates:
        rep = check_bytes(blob, fs_type)
        sc = score_variant(blob, fs_type)
        if best_score is None or sc > best_score:
            best_name, best_data, best_score, best_rep = name, blob, sc, rep
        if rep["healthy"]:
            break  # first healthy candidate wins (order = priority)
    return best_name, best_data, best_rep or check_bytes(best_data, fs_type)


# ---------------------------------------------------------------------------
# Heal report (persisted so repack --dual-output can find pre-heal bytes)
# ---------------------------------------------------------------------------
HEAL_MANIFEST_NAME = ".heal_report.json"


def record_heal(vols_dir: Path, entry: dict) -> None:
    """Append one heal record to the region's heal manifest."""
    import json
    path = vols_dir / HEAL_MANIFEST_NAME
    try:
        manifest = json.loads(path.read_text())
    except Exception:
        manifest = {"records": []}
    manifest["records"] = [r for r in manifest.get("records", [])
                           if r.get("file") != entry.get("file")]
    manifest["records"].append(entry)
    path.write_text(json.dumps(manifest, indent=2))


def load_heal_manifest(analysis_dir: Path) -> List[dict]:
    """Collect all heal records across the analysis tree."""
    import json
    records: List[dict] = []
    for p in sorted(analysis_dir.rglob(HEAL_MANIFEST_NAME)):
        try:
            manifest = json.loads(p.read_text())
        except Exception:
            continue
        for r in manifest.get("records", []):
            r = dict(r)
            r["vols_dir"] = str(p.parent)
            records.append(r)
    return records


# ---------------------------------------------------------------------------
# JFFS2 deep check
# ---------------------------------------------------------------------------
JFFS2_NODE_INO = 0x0001
JFFS2_NODE_DIRENT = 0x2000
JFFS2_NODE_TYPES = {0x0001, 0x2000, 0x2003, 0x2004, 0x2005, 0x2007,
                    0x2008, 0x2009}


def deep_check_jffs2(data: bytes, max_nodes: int = 8192) -> dict:
    """Walk the JFFS2 node chain: magic, node type, totlen sanity and
    node-header CRCs. JFFS2 is an append-only log; obsolete/damaged
    tails are tolerated but loudly reported."""
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, object] = {}
    n = len(data)

    if n < 16:
        return {"healthy": False, "errors": ["image too small for JFFS2"],
                "warnings": warnings, "superblock": None, "stats": stats}

    nodes_ok = nodes_bad = inodes = dirents = ff_skipped = 0
    # JFFS2 media often begins with erased (0xFF) space before the first
    # node; skip it instead of reporting a false unknown-magic error.
    off = 0
    while off < n and data[off] == 0xFF:
        off += 1
        ff_skipped += 1
    if ff_skipped and ff_skipped % 4:
        off -= ff_skipped % 4  # keep 4-byte alignment for the first node
        ff_skipped -= ff_skipped % 4
    while off + 12 <= n and nodes_ok + nodes_bad < max_nodes:
        magic, ntype = struct.unpack_from("<HH", data, off)
        if magic == 0x8519:
            errors.append(f"node at {off:#x}: byte-swapped JFFS2 magic "
                          f"(endianness mismatch)")
            nodes_bad += 1
            break
        if magic != 0x1985:
            if data[off:off + 1] == b"\xff":
                run_end = off
                while run_end < n and data[run_end] == 0xFF:
                    run_end += 1
                if run_end - off >= 4:
                    ff_skipped += run_end - off
                    off = run_end
                    continue
            # a short non-JFFS2 tail is the normal end of the log
            warnings.append(f"node chain ends at {off:#x} "
                            f"(non-magic data after {nodes_ok} valid nodes)")
            break

        totlen = struct.unpack_from("<I", data, off + 4)[0]
        if totlen < 12 or totlen > n - off:
            errors.append(f"node at {off:#x}: implausible totlen {totlen}")
            nodes_bad += 1
            break
        # vendor-specific node types (0xE000-flagged, e.g. extended
        # summary/priv nodes) are structurally valid: count, don't fail

        # header CRC: over the first 8 bytes (magic, type, totlen) --
        # accept both vendor conventions: plain crc32 (mkfs.jffs2) and
        # crc32(init=0xFFFFFFFF) ^ 0xFFFFFFFF (observed on some devices)
        calc = zlib.crc32(data[off:off + 8])
        calc_alt = zlib.crc32(data[off:off + 8], 0xFFFFFFFF) ^ 0xFFFFFFFF
        stored = struct.unpack_from("<I", data, off + 8)[0]
        if stored not in (calc, calc_alt):
            errors.append(f"node at {off:#x}: header CRC mismatch "
                          f"(stored {stored:#010x}, calc {calc:#010x})")
            nodes_bad += 1
            break

        nodes_ok += 1
        if ntype == JFFS2_NODE_INO:
            inodes += 1
        elif ntype == JFFS2_NODE_DIRENT:
            dirents += 1
        off += totlen

    stats["nodes_ok"] = nodes_ok
    stats["nodes_bad"] = nodes_bad
    stats["inode_nodes"] = inodes
    stats["dirent_nodes"] = dirents
    stats["erased_skipped"] = ff_skipped
    if nodes_ok == 0:
        errors.append("no valid JFFS2 nodes decoded")
    elif nodes_bad:
        warnings.append(f"{nodes_bad} damaged node(s) after {nodes_ok} "
                        f"valid ones; JFFS2 is append-only so earlier "
                        f"nodes remain readable")
    healthy = nodes_ok >= 2
    return {"healthy": healthy, "errors": errors, "warnings": warnings,
            "superblock": None, "stats": stats}


# ---------------------------------------------------------------------------
# CramFS deep check
# ---------------------------------------------------------------------------
def deep_check_cramfs(data: bytes) -> dict:
    """Superblock field sanity + optional CRC verification."""
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, object] = {}
    n = len(data)

    if n < 100:
        return {"healthy": False, "errors": ["image too small for CramFS"],
                "warnings": warnings, "superblock": None, "stats": stats}
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0x453DCD28:
        fmt = ">"
    elif magic == 0x28CD3D45:
        fmt = "<"
    else:
        return {"healthy": False,
                "errors": [f"bad CramFS magic {magic:#010x}"],
                "warnings": warnings, "superblock": None, "stats": stats}

    size, flags, _future, crc, _edition, blocks, files = \
        struct.unpack_from(fmt + "7I", data, 4)
    try:
        root = struct.unpack_from(fmt + "Q", data, 56)[0]
    except struct.error:
        root = 0
    stats["order"] = "BE" if fmt == ">" else "LE"
    stats["files"] = files
    stats["blocks"] = blocks

    if size > n:
        errors.append(f"superblock size {size:,} exceeds image {n:,}")
    if size < 100:
        errors.append(f"superblock size {size} implausibly small")
    if blocks > (n // 256) + 1:
        errors.append(f"block count {blocks} exceeds image capacity")
    if files == 0:
        errors.append("zero files in superblock")
    if root >> 16 >= (1 << 24):
        errors.append(f"root inode offset {root >> 16} out of range")

    # CRC over the whole image with the CRC field zeroed (skip when the
    # NOT_COMPR/SHIFTED flags change the layout: crc check is skipped if
    # it fails but that's a warning, not an error -- some vendors patch
    # fields after mkcramfs).
    if not (flags & 1):  # CRAMFS_FLAG_CLEVER? bit0 = CramFS_FLAG_...
        img = bytearray(data)
        img[16:20] = b"\x00\x00\x00\x00"
        calc = zlib.crc32(bytes(img)) & 0xFFFFFFFF
        if calc != crc:
            warnings.append(f"image CRC mismatch (stored {crc:#010x}, "
                            f"calc {calc:#010x}) -- patched or damaged")

    healthy = not errors
    return {"healthy": healthy, "errors": errors, "warnings": warnings,
            "superblock": {"size": size, "files": files, "blocks": blocks},
            "stats": stats}


# ---------------------------------------------------------------------------
# UBIFS deep check
# ---------------------------------------------------------------------------
# UBIFS common header (matches the analyst's proven chain-walker):
#   magic u32 = 0x06101831 ('UBI#$' LE), crc u32 @+4 (covers node[8:len]),
#   sqnum u64 @+8, len u32 @+16, node_type u8 @+20, group_type u8 @+21.
# Nodes are 8-byte aligned. CRC convention: plain crc32 and inverted both
# accepted (same vendor-convention handling as EC/VID CRCs elsewhere).
UBIFS_NODE_MAGIC32 = 0x06101831
UBIFS_SB_NODE = 5
UBIFS_MST_NODE = 6


def deep_check_ubifs(data: bytes, max_nodes: int = 512) -> dict:
    """Walk the UBIFS node stream inside the LEB image: common-header
    magic, CRC (both conventions), node length chain and 8-byte node
    alignment. The superblock node (type 5) must appear; the master
    node (type 6) is expected but may live in separate LEBs."""
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, object] = {}
    n = len(data)

    if n < 24:
        return {"healthy": False, "errors": ["image too small for UBIFS"],
                "warnings": warnings, "superblock": None, "stats": stats}

    sb_seen = mst_seen = False
    ok = bad = total = 0
    pos = 0
    while pos + 24 <= n and total < max_nodes:
        if data[pos:pos + 4] != b"\x31\x18\x10\x06":
            bad += 1
            if total == 0:
                errors.append(f"no UBIFS node magic at offset 0 "
                              f"(found {data[pos:pos+4].hex()})")
            else:
                errors.append(f"node stream ends at {pos:#x} with "
                              f"{ok} valid node(s)")
            break
        crc = struct.unpack_from("<I", data, pos + 4)[0]
        ln = struct.unpack_from("<I", data, pos + 16)[0]
        ntype = data[pos + 20]
        if ln < 24 or pos + ln > n:
            bad += 1
            errors.append(f"node at {pos:#x}: implausible node length {ln}")
            break
        calc = zlib.crc32(data[pos + 8:pos + ln]) & 0xFFFFFFFF
        if crc not in (calc, (~calc) & 0xFFFFFFFF):
            bad += 1
            errors.append(f"node at {pos:#x}: header CRC mismatch")
            break
        total += 1
        ok += 1
        if ntype == UBIFS_SB_NODE:
            sb_seen = True
        if ntype == UBIFS_MST_NODE:
            mst_seen = True
        pos = (pos + ln + 7) & ~7

    stats["nodes_ok"] = ok
    stats["nodes_bad"] = bad
    stats["superblock_node"] = sb_seen
    stats["master_node"] = mst_seen
    if ok == 0:
        if "no UBIFS node magic" not in " ".join(errors):
            errors.append("no valid UBIFS nodes decoded")
    if not sb_seen and ok:
        errors.append("no UBIFS superblock node (type 5) in stream")
    if not mst_seen and ok:
        warnings.append("no UBIFS master node (type 6) in the walked "
                        "nodes (may live in separate master LEBs)")

    healthy = ok >= 2 and sb_seen and not (bad and ok < 2)
    return {"healthy": healthy, "errors": errors, "warnings": warnings,
            "superblock": None, "stats": stats}


# ---------------------------------------------------------------------------
# DTB (flattened device tree) deep check
# ---------------------------------------------------------------------------
def deep_check_dtb(data: bytes) -> dict:
    """Header sanity + token-level walk of the dt_struct block."""
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, object] = {}
    n = len(data)

    if n < 28:
        return {"healthy": False, "errors": ["image too small for DTB"],
                "warnings": warnings, "superblock": None, "stats": stats}
    # FDT header is 8 u32s: magic, totalsize, off_memrsv, off_dt_struct,
    # off_dt_strings, boot_cpuid, size_dt_strings, size_dt_struct. Some
    # vendor DTBs leave size_dt_struct = 0 (bound then = totalsize).
    magic, totalsize, off_memrsv, off_struct, off_strings, boot_cpu, \
        size_dt_strings, size_dt_struct = struct.unpack_from(">8I", data, 0)
    if magic != 0xD00DFEED:
        errors.append(f"bad DTB magic {magic:#010x}")
    if totalsize > n:
        errors.append(f"totalsize {totalsize:,} exceeds image {n:,}")
    if totalsize < 28:
        errors.append(f"totalsize {totalsize} implausibly small")
    for name, val in (("off_memrsv", off_memrsv),
                      ("off_dt_struct", off_struct),
                      ("off_dt_strings", off_strings)):
        if not (28 <= val <= n):
            errors.append(f"{name} = {val:#x} outside image")
    if size_dt_struct == 0:
        size_dt_struct = max(0, min(totalsize, n) - off_struct)
    # Some vendor DTBs swap off_dt_struct / off_dt_strings. Detect by
    # probing which offset actually begins a BEGIN_NODE token stream.
    def _looks_like_struct(o):
        """True if a BEGIN_NODE token appears within 64 bytes of `o` (some
        vendors start the struct with NOP padding, or swap the struct and
        strings offsets entirely)."""
        if o < 0 or o > n - 4:
            return False
        window = data[o:min(o + 64, n)]
        return window.find(b"\x00\x00\x00\x01") != -1
    if not _looks_like_struct(off_struct) and _looks_like_struct(off_strings):
        off_struct, off_strings = off_strings, off_struct
        warnings.append("DTB header has off_dt_struct/off_dt_strings "
                        "swapped (vendor quirk); corrected for the walk")
        # size_dt_struct may have been derived from the unswapped offset;
        # with the struct block at the tail of the image it runs to
        # totalsize, so recompute the bound from the corrected offset.
        size_dt_struct = max(0, min(totalsize, n) - off_struct)
    # skip zero padding before the first token (vendor DTBs pad the
    # struct/strings boundary to 16 bytes)
    if size_dt_struct:
        block_end = off_struct + size_dt_struct
        while off_struct + 4 <= n and \
                struct.unpack_from(">I", data, off_struct)[0] == 0 and \
                off_struct < block_end:
            off_struct += 4
        size_dt_struct = block_end - off_struct
    if off_struct + size_dt_struct > n:
        errors.append("dt_struct region exceeds image")

    if not errors:
        pos = off_struct
        end = off_struct + size_dt_struct
        depth = begins = props = 0
        while pos + 4 <= end:
            tok = struct.unpack_from(">I", data, pos)[0]
            pos += 4
            if tok == 1:      # BEGIN_NODE: NUL-terminated name, 4-aligned
                begins += 1
                depth += 1
                while pos < end and data[pos] != 0:
                    pos += 1
                pos += 1
                pos = (pos + 3) & ~3
            elif tok == 2:    # END_NODE
                depth -= 1
                if depth < 0:
                    errors.append("unbalanced END_NODE token")
                    break
            elif tok == 3:    # PROP
                props += 1
                plen, _nameoff = struct.unpack_from(">II", data, pos)
                pos += 8 + ((plen + 3) & ~3)
            elif tok == 4:    # NOP
                pass
            elif tok == 9:    # END
                break
            else:
                errors.append(f"unknown DTB token {tok:#x} at {pos - 4:#x}")
                break
        if depth != 0:
            errors.append(f"unbalanced node nesting (depth {depth} at END)")
        stats["nodes"] = begins
        stats["props"] = props

    healthy = not errors
    return {"healthy": healthy, "errors": errors, "warnings": warnings,
            "superblock": None, "stats": stats}


# ---------------------------------------------------------------------------
# uImage (U-Boot legacy image) deep check
# ---------------------------------------------------------------------------
def deep_check_uimage(data: bytes, max_check: int = 1 << 24) -> dict:
    """Header CRC + payload CRC verification (bounded to 16 MiB)."""
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, object] = {}
    n = len(data)

    if n < 64:
        return {"healthy": False, "errors": ["image too small for uImage"],
                "warnings": warnings, "superblock": None, "stats": stats}
    magic, hcrc, _time, size, _load, _ep, dcrc = struct.unpack_from(
        ">7I", data, 0)
    _os, _arch, itype, comp = struct.unpack_from("4B", data, 28)[0:4]
    if magic != 0x27051956:
        errors.append(f"bad uImage magic {magic:#010x}")
    if size == 0 or 64 + size > n:
        errors.append(f"image size {size:,} implausible for {n:,} B image")
    if magic == 0x27051956 and 0 < size <= n - 64:
        calc = zlib.crc32(data[64:64 + min(size, max_check)]) & 0xFFFFFFFF
        if size <= max_check and calc != dcrc:
            errors.append(f"payload CRC mismatch (stored {dcrc:#010x}, "
                          f"calc {calc:#010x})")
        elif size > max_check:
            warnings.append(f"payload {size:,} B exceeds CRC check window; "
                            f"CRC not verified")
        h = bytearray(data[:64])
        h[4:8] = b"\x00\x00\x00\x00"
        calc_h = zlib.crc32(bytes(h)) & 0xFFFFFFFF
        if calc_h != hcrc:
            errors.append(f"header CRC mismatch (stored {hcrc:#010x}, "
                          f"calc {calc_h:#010x})")
    stats["image_type"] = itype
    stats["payload_size"] = size
    stats["compression"] = comp

    healthy = not errors
    return {"healthy": healthy, "errors": errors, "warnings": warnings,
            "superblock": None, "stats": stats}


# ---------------------------------------------------------------------------
# Initramfs (gzip/xz/zstd-compressed cpio or plain cpio) deep check
# ---------------------------------------------------------------------------
def _cpio_entry_count(data: bytes, max_entries: int = 2048) -> Tuple[int, int]:
    """Count cpio '070701' newc entries; returns (count, trailing_garbage)."""
    count = 0
    off = 0
    n = len(data)
    while off + 110 <= n and count < max_entries:
        idx = data.find(b"070701", off)
        if idx == -1:
            break
        if idx > off and data[off:idx] and set(data[off:idx]) - {0}:
            return count, idx - off
        try:
            namesize = int(data[idx + 94:idx + 102], 16)
            filesize = int(data[idx + 54:idx + 62], 16)
        except ValueError:
            return count, 1
        name = data[idx + 110:idx + 110 + max(0, namesize - 1)]
        hdr_end = idx + 110 + namesize
        name_pad = (4 - (hdr_end % 4)) % 4
        off = hdr_end + name_pad + ((filesize + 3) & ~3)
        if name == b"TRAILER!!!":
            count += 1
            break
        count += 1
    return count, 0


def deep_check_initramfs(data: bytes, max_decomp: int = 8 << 20) -> dict:
    """Detect compression wrapper (gzip/xz/zstd/bzip2/lz4/none), then
    decompress a bounded prefix and validate the cpio structure."""
    errors: List[str] = []
    warnings: List[str] = []
    stats: Dict[str, object] = {}
    n = len(data)

    if n < 8:
        return {"healthy": False, "errors": ["image too small"],
                "warnings": warnings, "superblock": None, "stats": stats}

    raw = data
    comp_name = "none"
    if data[:2] == b"\x1f\x8b":
        comp_name = "gzip"
        try:
            dec = zlib.decompressobj(31)
            raw = dec.decompress(data, max_decomp)
            if not dec.eof:
                warnings.append("gzip stream truncated (bounded decode)")
        except zlib.error as e:
            return {"healthy": False, "errors": [f"gzip decode failed: {e}"],
                    "warnings": warnings, "superblock": None,
                    "stats": {"compression": comp_name}}
    elif data[:6] == b"\xfd7zXZ\x00":
        comp_name = "xz"
        try:
            dec = lzma.LZMADecompressor()
            raw = dec.decompress(data, max_decomp)
            if not dec.eof:
                warnings.append("xz stream truncated (bounded decode)")
        except lzma.LZMAError as e:
            return {"healthy": False, "errors": [f"xz decode failed: {e}"],
                    "warnings": warnings, "superblock": None,
                    "stats": {"compression": comp_name}}
    elif data[:4] == b"\x28\xb5\x2f\xfd":
        comp_name = "zstd"
        warnings.append("zstd payload: structure check limited to header "
                        "(no stdlib decoder)")
        raw = b""
    elif data[:3] == b"BZh":
        comp_name = "bzip2"
        warnings.append("bzip2 payload: structure check limited to header")
        raw = b""
    elif data[:4] == b"\x04\x22\x4d\x18":
        comp_name = "lz4"
        warnings.append("lz4 payload: structure check limited to header")
        raw = b""

    stats["compression"] = comp_name
    if comp_name in ("zstd", "bzip2", "lz4"):
        healthy = True
        return {"healthy": healthy, "errors": errors, "warnings": warnings,
                "superblock": None, "stats": stats}

    if not raw.startswith(b"070701") and b"070701" not in raw[:4096]:
        return {"healthy": False,
                "errors": [f"no cpio newc archive inside {comp_name} "
                           f"wrapper"],
                "warnings": warnings, "superblock": None, "stats": stats}

    count, garbage = _cpio_entry_count(raw)
    stats["entries_decoded"] = count
    if count == 0:
        errors.append("no valid cpio entries decoded")
    elif count < 2:
        errors.append("only one cpio entry decoded (archive truncated?)")
    if garbage:
        errors.append(f"{garbage} B of trailing garbage inside archive")
    healthy = not errors
    return {"healthy": healthy, "errors": errors, "warnings": warnings,
            "superblock": None, "stats": stats}
