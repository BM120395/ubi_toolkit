"""Lifecycle round-trip tests (stdlib unittest, temp dirs only).

Run from repo root:
    python3 -m unittest tests.test_lifecycle -v
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ubi_toolkit import lifecycle  # noqa: E402


def _ns(**kw):
    from types import SimpleNamespace
    base = dict(prefix=None, yes=True, force=False, upgrade_url=None,
                clean=None)
    base.update(kw)
    return SimpleNamespace(**base)


class TestLifecycleRoundTrip(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="ubi-lc-test-")
        self.prefix = os.path.join(self.tmpdir(), "prefix")

    def tearDown(self):
        self._tmp.cleanup()

    def tmpdir(self):
        return self._tmp.name

    def test_install_manifest_integrity(self):
        rc = lifecycle.op_install(_ns(prefix=self.prefix))
        self.assertEqual(rc, 0)
        m = lifecycle._read_manifest(self.prefix)
        self.assertIsNotNone(m, "manifest must exist after install")
        assert m is not None  # for type checkers
        self.assertEqual(m["schema"], 1)
        self.assertEqual(m["tool"], "ubi-toolkit")
        self.assertTrue(m["version"].count(".") >= 1)
        self.assertTrue(m["installed_at"])
        self.assertTrue(m["python"])
        for key in ("package_dir", "shims", "created"):
            self.assertTrue(m[key])
        for s in m["shims"]:
            self.assertTrue(os.path.isfile(s))
        # package sentinels present
        for s in lifecycle.SENTINELS:
            self.assertTrue(os.path.isfile(os.path.join(m["package_dir"], s)),
                            f"missing sentinel {s}")

    def test_shim_content_and_marker(self):
        lifecycle.op_install(_ns(prefix=self.prefix))
        shim = os.path.join(self.prefix, "bin", "ubipack")
        self.assertTrue(os.path.isfile(shim))
        body = open(shim, encoding="utf-8").read()
        self.assertIn(lifecycle.SHIM_MARKER, body)
        self.assertIn("-m ubi_toolkit.ubipack", body)
        self.assertTrue(os.access(shim, os.X_OK))

    def test_uninstall_removes_only_managed_paths(self):
        lifecycle.op_install(_ns(prefix=self.prefix))
        foreign = os.path.join(self.prefix, "bin", "unrelated-tool")
        with open(foreign, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        rc = lifecycle.op_uninstall(_ns(prefix=self.prefix))
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(
            os.path.join(self.prefix, "bin", "ubipack")))
        self.assertFalse(os.path.exists(lifecycle._pkg_root(self.prefix)))
        self.assertTrue(os.path.isfile(foreign),
                        "uninstall must not touch non-managed paths")

    def test_uninstall_without_manifest_is_error(self):
        rc = lifecycle.op_uninstall(_ns(prefix=self.prefix))
        self.assertEqual(rc, 2)

    def test_shim_mismatch_kept_without_force(self):
        lifecycle.op_install(_ns(prefix=self.prefix))
        shim = os.path.join(self.prefix, "bin", "ubipack")
        # overwrite with foreign content
        with open(shim, "w") as f:
            f.write("#!/bin/sh\n# someone else's shim\nexit 0\n")
        rc = lifecycle.op_uninstall(_ns(prefix=self.prefix, yes=True,
                                        force=False))
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(shim), "foreign shim must be kept")

    def test_force_removes_foreign_shim(self):
        lifecycle.op_install(_ns(prefix=self.prefix))
        shim = os.path.join(self.prefix, "bin", "ubipack")
        with open(shim, "w") as f:
            f.write("#!/bin/sh\n# someone else's shim\nexit 0\n")
        rc = lifecycle.op_uninstall(_ns(prefix=self.prefix, yes=True,
                                        force=True))
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(shim), "--force must remove it")

    def test_foreign_shim_backed_up_on_install(self):
        bin_dir = os.path.join(self.prefix, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        shim = os.path.join(bin_dir, "ubipack")
        with open(shim, "w") as f:
            f.write("#!/bin/sh\n# uv shim\nexec echo uv\n")
        rc = lifecycle.op_install(_ns(prefix=self.prefix))
        self.assertEqual(rc, 0)
        backups = [p for p in os.listdir(bin_dir)
                   if p.startswith("ubipack.pre-lifecycle")]
        self.assertTrue(backups, "pre-existing shim must be backed up")
        with open(shim, encoding="utf-8") as f:
            self.assertIn(lifecycle.SHIM_MARKER, f.read())

    def test_clean_dry_run_by_default(self):
        # ubipack's own sidecar convention: fw.with_suffix(".autofix.bin")
        fw = os.path.join(self.tmpdir(), "fw.bin")
        with open(fw, "wb") as f:
            f.write(b"\x00" * 16)
        sidecar = os.path.join(self.tmpdir(), "fw.autofix.bin")
        with open(sidecar, "wb") as f:
            f.write(b"x")
        rc = lifecycle.op_clean(_ns(clean=[fw], yes=False))
        self.assertEqual(rc, 0)
        self.assertTrue(os.path.isfile(sidecar),
                        "dry run must not delete")
        rc = lifecycle.op_clean(_ns(clean=[fw], yes=True))
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(sidecar), "--yes must delete")

    def test_self_test_roundtrip(self):
        ok, msg = lifecycle.self_test_roundtrip()
        self.assertTrue(ok, msg)


if __name__ == "__main__":
    unittest.main()
