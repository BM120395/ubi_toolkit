"""--restore-reference regression tests (stdlib unittest, temp dirs only).

Reproduces the ECC-interleaved-dump failure mode end-to-end at small scale:
an ECC-interleaved UBI image whose volume, assembled naively (no layout
fix), differs from the donor by long multi-bit runs -- repair_bitrot
rightly refuses, and --restore-reference must restore the donor bytes.

Run from repo root:
    python3 -m unittest tests.test_restore_reference -v
"""
import os
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ubi_toolkit.ubipack import _patch_volumes_with_reference  # noqa: E402
from ubi_toolkit.anomaly import bitrot_signature  # noqa: E402


def _vid(lnum, data_crc, data_size):
    # u64 magic | u8 pad[2] | u8 vid_type | u8 compat | ... big-endian per
    # ubi-media.h; only the fields the scanner reads are populated.
    import struct
    vid = bytearray(64)
    vid[0:4] = b"UBI!"
    struct.pack_into(">I", vid, 0x0C, lnum)        # lnum
    struct.pack_into(">I", vid, 0x14, data_size)   # data_size
    struct.pack_into(">I", vid, 0x20, data_crc)    # data_crc
    struct.pack_into(">H", vid, 0x10, 0)           # vol_id written below
    struct.pack_into(">I", vid, 0x08, 0)           # vol_id
    crc = (zlib.crc32(bytes(vid[:60])) ^ 0xFFFFFFFF) & 0xFFFFFFFF
    struct.pack_into(">I", vid, 0x3C, crc)         # hdr_crc
    return bytes(vid)


def _donor_volume(pages_per_leb=4, page=64, lnum_count=3):
    """Deterministic pseudo-volume with run-heavy structure (simulates
    compressed data, where a layout shift produces long diff runs)."""
    body = b""
    for i in range(pages_per_leb * lnum_count):
        body += bytes((i * 7 + j) & 0xFF for j in range(page))
    return body


class TestRestoreReference(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="ubi-restore-test-")
        self.root = self._tmp.name
        self.vols = os.path.join(self.root, "ubi", "region_0", "volumes")
        os.makedirs(self.vols)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_vol(self, name, data):
        p = os.path.join(self.vols, name)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def _shifted(self, donor, shift=3):
        """Simulate a wrong page layout: drop the first `shift` bytes and
        pad the tail — produces long multi-bit runs vs the donor."""
        out = bytearray(donor[shift:])
        out += bytes(shift)
        return bytes(out)

    def test_shifted_volume_not_patched_without_restore(self):
        donor = _donor_volume()
        shifted = self._shifted(donor)
        sig = bitrot_signature(self._shifted(donor), donor)
        self.assertFalse(sig["is_bitrot"])  # long runs -> not bit rot
        p = self._write_vol("vol_0.bin", shifted := self._shifted(donor))
        _patch_volumes_with_reference(Path(self.root), donor, verbose=False,
                                      restore=False)
        with open(p, "rb") as f:
            self.assertEqual(f.read(), shifted)  # untouched

    def test_restore_reference_restores_donor_bytes(self):
        donor = _donor_volume()
        p = self._write_vol("vol_0.bin", self._shifted(donor))
        _patch_volumes_with_reference(Path(self.root), donor, verbose=False,
                                      restore=True)
        with open(p, "rb") as f:
            self.assertEqual(f.read(), donor)  # donor restored verbatim

    def test_restore_oversized_local_volume_is_size_clamped(self):
        donor = _donor_volume(pages_per_leb=4, page=64, lnum_count=3)
        local = self._shifted(donor) + b"\xAA" * 100  # local grew
        p = self._write_vol("vol_0.bin", local)
        _patch_volumes_with_reference(Path(self.root), donor, verbose=False,
                                      restore=True)
        with open(p, "rb") as f:
            out = f.read()
        self.assertEqual(out[:len(donor)], donor)
        self.assertEqual(out[len(donor):], b"\xAA" * 100)  # tail kept

    def test_bitrot_still_repaired_in_place(self):
        donor = bytearray(_donor_volume())
        donor[10] ^= 0x01                     # single-bit flip
        donor[500] ^= 0x80                    # another, far away
        donor = bytes(donor)
        p = self._write_vol("vol_0.bin", donor)
        _patch_volumes_with_reference(Path(self.root), _donor_volume(),
                                      verbose=False, restore=False)
        with open(p, "rb") as f:
            self.assertEqual(f.read(), _donor_volume())


if __name__ == "__main__":
    unittest.main()
