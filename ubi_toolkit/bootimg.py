"""bootimg.py — boot-image discovery and extraction for ubipack v1.5.0.

Finds uImage (legacy U-Boot image) headers and FIT (flattened image tree)
blobs in a page-layout-stripped firmware view, verifies their CRCs, and
extracts the payloads. Designed to run on the layout-stripped image
produced when a page layout has been adjudicated; falls back to the raw
image (identity layout) otherwise.

uImage header (64 B, all big-endian):
    0x00 magic 0x27051956, 0x04 hcrc, 0x08 time, 0x0C size,
    0x10 load, 0x14 ep, 0x18 dcrc, 0x1C os, 0x1D arch, 0x1E type,
    0x1F comp, 0x20 name[32]
FIT = FDT container: 0x00 magic 0xD00DFEED, 0x04 totalsize.
"""

import hashlib
import json
import zlib
from typing import Dict, List, Optional

UIMAGE_MAGIC = b"\x27\x05\x19\x56"
FIT_MAGIC = b"\xd0\x0d\xfe\xed"
UIMAGE_HDR = 64

IMAGE_TYPES = {0: "invalid", 1: "standalone", 2: "kernel", 3: "ramdisk",
               4: "multi", 5: "firmware", 6: "script", 7: "filesystem",
               8: "dtb"}
COMP_TYPES = {0: "none", 1: "gzip", 2: "bzip2", 3: "lzma", 4: "lzo",
              5: "lz4", 6: "zstd"}


def _be(buf: bytes, off: int = 0) -> int:
    return int.from_bytes(buf[off:off + 4], "big")


def find_uimages(view: bytes, limit: int = 64) -> List[Dict]:
    """Scan for uImage headers whose header CRC32 verifies. Each hit:
    dict(offset, size, dcrc, load, ep, os, arch, type, comp, name)."""
    out: List[Dict] = []
    pos = 0
    while len(out) < limit:
        pos = view.find(UIMAGE_MAGIC, pos)
        if pos < 0 or pos + UIMAGE_HDR > len(view):
            break
        hdr = bytearray(view[pos:pos + UIMAGE_HDR])
        stored = _be(hdr, 4)
        hdr[4:8] = b"\x00\x00\x00\x00"
        if (zlib.crc32(bytes(hdr)) & 0xFFFFFFFF) == stored:
            size = _be(hdr, 12)
            # plausible payload size: 1 KiB .. 512 MiB and it must fit
            if 0x400 <= size <= (1 << 29) and \
                    pos + UIMAGE_HDR + size <= len(view) + (1 << 20):
                out.append(dict(
                    offset=pos, size=size, dcrc=_be(hdr, 24),
                    load=hex(_be(hdr, 16)), ep=hex(_be(hdr, 20)),
                    itype=IMAGE_TYPES.get(hdr[0x1E], f"unk{hdr[0x1E]}"),
                    comp=COMP_TYPES.get(hdr[0x1F], f"unk{hdr[0x1F]}"),
                    name=hdr[0x20:0x40].rstrip(b"\x00")
                        .decode("latin1", "replace")))
        pos += 1
    # drop nested hits: a header fully inside a previous payload
    kept: List[Dict] = []
    for u in out:
        if kept and u["offset"] < kept[-1]["offset"] + \
                kept[-1]["size"] + UIMAGE_HDR:
            continue
        kept.append(u)
    return kept


def find_fits(view: bytes, limit: int = 16) -> List[Dict]:
    """Best-effort FIT (FDT) container discovery: magic + sane totalsize
    (1 KiB .. 64 MiB, header fields in range)."""
    out: List[Dict] = []
    pos = 0
    while len(out) < limit:
        pos = view.find(FIT_MAGIC, pos)
        if pos < 0:
            break
        if pos + 40 <= len(view):
            ts = _be(view[pos:pos + 8], 4)
            off_struct = _be(view[pos:pos + 40], 8)
            off_strings = _be(view[pos:pos + 40], 12)
            version = _be(view[pos:pos + 40], 16)
            if 0x400 <= ts <= (1 << 26) and \
                    0 < off_struct < ts and off_strings <= ts and \
                    1 <= version <= 20 and \
                    pos + ts <= len(view):
                out.append(dict(offset=pos, size=ts, version=version))
                pos += ts
                continue
        pos += 1
    return out


def _safe_name(name: str, idx: int) -> str:
    keep = "".join(c if c.isalnum() or c in "._-" else "_"
                   for c in name.strip())[:40].strip("._-")
    return f"{keep or 'image'}_{idx}"


def extract_all(view: bytes, out_dir, layout_name: str = "identity",
                log=print) -> List[Dict]:
    """Extract every verified uImage payload and every sane FIT blob from
    the (layout-stripped) view into out_dir. Returns manifest entries."""
    import os
    os.makedirs(out_dir, exist_ok=True)
    manifest: List[Dict] = []
    idx = 0
    for u in find_uimages(view):
        off, size = u["offset"], u["size"]
        payload = view[off + UIMAGE_HDR:off + UIMAGE_HDR + size]
        dcrc_ok = None
        if len(payload) == size:
            c = zlib.crc32(payload) & 0xFFFFFFFF
            dcrc_ok = c == u["dcrc"] or (c ^ 0xFFFFFFFF) == u["dcrc"]
        fname = f"{_safe_name(u['name'], idx)}.uimage.bin"
        (out_dir / fname).write_bytes(payload)
        entry = dict(file=fname, kind="uimage", name=u["name"],
                     itype=u["itype"], comp=u["comp"], load=u["load"],
                     ep=u["ep"], offset_in_view=hex(off), size=size,
                     data_crc_ok=dcrc_ok,
                     sha256=hashlib.sha256(payload).hexdigest())
        manifest.append(entry)
        log(f"[BOOT-IMG] uimage '{u['name']}' type={u['itype']} "
            f"comp={u['comp']} size={size:,} @{off:#x} "
            f"payload_crc={'OK' if dcrc_ok else 'MISMATCH'} -> {fname}")
        idx += 1
    for f in find_fits(view):
        blob = view[f["offset"]:f["offset"] + f["size"]]
        fname = f"{_safe_name('fit_image', idx)}.fit.fdt"
        (out_dir / fname).write_bytes(blob)
        manifest.append(dict(file=fname, kind="fit",
                             offset_in_view=hex(f["offset"]),
                             size=f["size"], fdt_version=f["version"],
                             sha256=hashlib.sha256(blob).hexdigest()))
        log(f"[BOOT-IMG] FIT/FDT container size={f['size']:,} "
            f"@{f['offset']:#x} -> {fname}")
        idx += 1
    if manifest:
        (out_dir / "boot_manifest.json").write_text(
            json.dumps(dict(view=layout_name, images=manifest), indent=2))
    return manifest
