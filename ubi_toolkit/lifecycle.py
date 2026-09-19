"""Self-managed install / uninstall / clean / upgrade for ubi-toolkit.

v1.6.0. Manifest-driven lifecycle, stdlib-only -- no uv, no pip, no venv,
no sudo for the default user prefix.

  ubipack -I/--install   [--prefix DIR] [--yes] [--force]
  ubipack -U/--uninstall [--prefix DIR] [--yes] [--force]
  ubipack --upgrade      [--upgrade-url URL] [--prefix DIR] [--yes] [--force]
  ubipack -K/--clean PATH... [--yes] [--all]

Layout (default prefix ``~/.local``)::

    <prefix>/share/ubi_toolkit/                  the package dir (pure copies)
    <prefix>/share/ubi_toolkit/.install_manifest.json
    <prefix>/bin/ubipack                         sh shim -> <python> -m ubi_toolkit.ubipack

Uninstall removes exactly the manifest-recorded paths, so shims are
cleaned from ``<prefix>/bin`` without touching anything else there.
A pre-existing (non-managed) shim is backed up, never silently lost.

``--upgrade`` fetches a tarball of the repository default branch
(GitHub codeload by default; any URL or local tarball path via
``--upgrade-url``), sanity-compiles every module, then reinstalls over
the manifest-managed copy and refreshes the shims.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

TOOL_NAME = "ubi-toolkit"
PACKAGE_DIRNAME = "ubi_toolkit"          # python package dir name
ENTRY_MODULE = "ubi_toolkit.ubipack"     # module the shim execs
SHIM_NAMES: Tuple[str, ...] = ("ubipack",)
SENTINELS: Tuple[str, ...] = ("analyst.py", "repacker.py")  # prove a real pkg tree
CLEAN_GLOBS: Tuple[str, ...] = ("*.autofix.bin", "*.layout.bin")
CLEAN_SIDECARS: Tuple[str, ...] = (".autofix.bin", ".layout.bin")
DEFAULT_UPGRADE_URL = ("https://codeload.github.com/BM120395/"
                       "ubi_toolkit_v1.0/tar.gz/HEAD")
MANIFEST_NAME = ".install_manifest.json"
SHIM_MARKER = f"# managed by {TOOL_NAME} lifecycle"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _default_prefix() -> str:
    return os.environ.get("UBITOOLKIT_PREFIX") or os.path.expanduser("~/.local")


def _prefix(args) -> str:
    return os.path.abspath(os.path.expanduser(args.prefix)) \
        if getattr(args, "prefix", None) else _default_prefix()


def _pkg_root(prefix: str):
    from pathlib import Path
    return Path(prefix) / "share" / PACKAGE_DIRNAME


def _manifest_path(prefix: str):
    return _pkg_root(prefix) / MANIFEST_NAME


def _read_manifest(prefix: str) -> Optional[dict]:
    p = _manifest_path(prefix)
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _version() -> str:
    try:
        from ubi_toolkit import __version__  # type: ignore[attr-defined]
        return str(__version__)
    except Exception:
        return "unknown"


def _root_guard(prefix: str, yes: bool) -> bool:
    """Refuse root-installing into a user HOME unless --yes acknowledges."""
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return True
    home = os.path.expanduser("~")
    if prefix.startswith(home + os.sep) or prefix == home:
        print("warning: running as root but the target prefix is inside a "
              "user HOME; installed files would be root-owned", file=sys.stderr)
        if not yes:
            print("re-run with --yes to accept, or choose another --prefix",
                  file=sys.stderr)
            return False
    return True


def _writable_guard(pkg_root) -> bool:
    try:
        pkg_root.mkdir(parents=True, exist_ok=True)
        return True
    except PermissionError:
        print(f"error: cannot write to {pkg_root}", file=sys.stderr)
        print("options: use --prefix DIR for a location you can write, "
              "or run under sudo with --prefix /usr/local for a "
              "system-wide install", file=sys.stderr)
        return False


def _shim_text(pkg_root, python_exe: str) -> str:
    return ("#!/bin/sh\n"
            f"{SHIM_MARKER}\n"
            f"export PYTHONPATH=\"{pkg_root.parent}"
            "${PYTHONPATH:+:$PYTHONPATH}\"\n"
            f"exec \"{python_exe}\" -m {ENTRY_MODULE} \"$@\"\n")


def _write_shims(prefix: str, pkg_root, created: List[str]) -> List[str]:
    from pathlib import Path
    bin_dir = Path(prefix) / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    if str(bin_dir) not in created:
        created.append(str(bin_dir))
    shims: List[str] = []
    text = _shim_text(pkg_root, sys.executable)
    for name in SHIM_NAMES:
        shim = bin_dir / name
        shim.write_text(text, encoding="utf-8")
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP
                   | stat.S_IXOTH)
        if str(shim) not in created:
            created.append(str(shim))
        shims.append(str(shim))
    return shims


def _backup_foreign_shims(prefix: str, backups: List[str]) -> None:
    """Move any non-managed shim aside (e.g. a uv-created one) before we
    replace it, so the user's previous entry point is never lost."""
    from pathlib import Path
    bin_dir = Path(prefix) / "bin"
    for name in SHIM_NAMES:
        shim = bin_dir / name
        if not shim.is_file():
            continue
        try:
            body = shim.read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = ""
        if SHIM_MARKER in body:
            continue  # already ours (upgrade path)
        dst = shim.with_name(shim.name + ".pre-lifecycle")
        n = 1
        while dst.exists():
            dst = shim.with_name(f"{shim.name}.pre-lifecycle-{n}")
            n += 1
        shutil.move(str(shim), str(dst))
        backups.append(str(dst))


# ---------------------------------------------------------------------------
# install / uninstall
# ---------------------------------------------------------------------------
def _copy_package(pkg_root, created: List[str]) -> None:
    src = os.path.dirname(os.path.abspath(__file__))  # .../ubi_toolkit
    pkg_root.mkdir(parents=True, exist_ok=True)
    if str(pkg_root) not in created:
        created.append(str(pkg_root))
    for item in sorted(os.listdir(src)):
        s = os.path.join(src, item)
        d = pkg_root / item
        if os.path.isfile(s) and item.endswith(".py"):
            shutil.copy2(s, d)
            created.append(str(d))
    required = [c for c in created if c.endswith(SENTINELS)]
    if len({os.path.basename(c) for c in required}) < len(SENTINELS):
        raise RuntimeError(f"source package at {src} is missing expected "
                           f"modules {SENTINELS}; refusing to install a "
                           f"broken tree")


def op_install(args) -> int:
    prefix = _prefix(args)
    if not _root_guard(prefix, getattr(args, "yes", False)):
        return 2
    pkg_root = _pkg_root(prefix)
    if not _writable_guard(pkg_root):
        return 2
    old = _read_manifest(prefix)
    created: List[str] = []
    backups: List[str] = list(old.get("backups", [])) if old else []
    _backup_foreign_shims(prefix, backups)
    _copy_package(pkg_root, created)
    shims = _write_shims(prefix, pkg_root, created)
    manifest = {
        "schema": 1,
        "tool": TOOL_NAME,
        "version": _version(),
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.executable,
        "package_dir": str(pkg_root),
        "shims": shims,
        "created": created,
        "backups": backups,
    }
    _manifest_path(prefix).write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    mode = "upgraded" if old else "installed"
    print(f"[INSTALL] {TOOL_NAME} {manifest['version']} {mode}")
    print(f"[INSTALL] package : {pkg_root}")
    for s in shims:
        print(f"[INSTALL] shim    : {s}")
    print(f"[INSTALL] python  : {sys.executable}")
    print(f"verify with: {os.path.basename(shims[0])} --version")
    return 0


def op_uninstall(args) -> int:
    prefix = _prefix(args)
    manifest = _read_manifest(prefix)
    if manifest is None:
        print(f"error: not installed (no manifest at "
              f"{_manifest_path(prefix)})", file=sys.stderr)
        return 2
    if not getattr(args, "yes", False):
        print("will remove:")
        for p in manifest.get("created", []):
            print(f"  {p}")
        for b in manifest.get("backups", []):
            print(f"  (keep backup) {b}")
        try:
            ans = input("Proceed? [y/N] ").strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("y", "yes"):
            print("aborted")
            return 1
    if not _root_guard(prefix, getattr(args, "yes", False)):
        return 2
    force = getattr(args, "force", False)
    removed = missing = kept = 0
    skipped_shims: set = set()
    # shims first (marker-verified unless --force)
    for shim in manifest.get("shims", []):
        p = __import__("pathlib").Path(shim)
        if not p.is_file():
            missing += 1
            continue
        try:
            body = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            body = ""
        if SHIM_MARKER not in body and not force:
            print(f"skip {shim}: not lifecycle-managed (use --force)")
            kept += 1
            skipped_shims.add(str(p))
            continue
        p.unlink()
        removed += 1
    # recorded files, then dirs deepest-first (never re-delete a shim we
    # deliberately kept as foreign-content)
    created = [c for c in manifest.get("created", [])
               if c not in skipped_shims]
    files = [c for c in created if os.path.isfile(c)]
    dirs = sorted((c for c in created if os.path.isdir(c)),
                  key=lambda s: s.count(os.sep), reverse=True)
    for c in files:
        try:
            os.unlink(c)
            removed += 1
        except OSError:
            missing += 1
    for c in dirs:
        try:
            os.rmdir(c)  # only succeeds when empty; pkg_root cleaned via rmdir
            removed += 1
        except OSError:
            pass
    # the package dir itself (may still hold the manifest)
    pkg_root = _pkg_root(prefix)
    if pkg_root.is_dir():
        shutil.rmtree(pkg_root, ignore_errors=True)
        removed += 1
    # prune an emptied bin dir (best effort, never touches other content)
    try:
        ( __import__("pathlib").Path(prefix) / "bin").rmdir()
    except OSError:
        pass
    print(f"[UNINSTALL] {TOOL_NAME}: removed {removed}, "
          f"already-missing {missing}, kept-foreign {kept}")
    return 0


# ---------------------------------------------------------------------------
# upgrade
# ---------------------------------------------------------------------------
def _fetch_tarball(url: str, dest: str) -> None:
    if os.path.exists(url):  # local tarball path (also how tests avoid net)
        shutil.copyfile(url, dest)
        return
    req = urllib.request.Request(
        url, headers={"User-Agent": f"{TOOL_NAME}-lifecycle"})
    with urllib.request.urlopen(req, timeout=60) as r, \
            open(dest, "wb") as f:
        shutil.copyfileobj(r, f)


def _extract_package(tgz: str, tmpdir: str):
    """Return the package dir inside an extracted tool tarball."""
    with tarfile.open(tgz, "r:gz") as t:
        t.extractall(tmpdir)
    for p in sorted(__import__("pathlib").Path(tmpdir).rglob(ENTRY_MODULE
                  .rsplit(".", 1)[-1] + ".py")):
        cand = p.parent
        if cand.name == PACKAGE_DIRNAME and \
                all((cand / s).is_file() for s in SENTINELS):
            return cand
    return None


def _pkg_file_version(pkg_dir, filename: str, pattern: str) -> Optional[str]:
    p = __import__("pathlib").Path(pkg_dir) / filename
    if not p.is_file():
        return None
    m = re.search(pattern, p.read_text(encoding="utf-8", errors="replace"))
    return m.group(1) if m else None


def op_upgrade(args) -> int:
    prefix = _prefix(args)
    url = getattr(args, "upgrade_url", None) or DEFAULT_UPGRADE_URL
    pkg_root = _pkg_root(prefix)
    old = _read_manifest(prefix)
    old_version = old.get("version") if old else None
    tmpdir = __import__("tempfile").mkdtemp(prefix=f"{TOOL_NAME}-upgrade-")
    try:
        tgz = os.path.join(tmpdir, "snapshot.tar.gz")
        print(f"[UPGRADE] fetching {url}")
        try:
            _fetch_tarball(url, tgz)
        except Exception as exc:
            print(f"error: download failed: {exc}", file=sys.stderr)
            print("hint: pass --upgrade-url with a reachable URL or a "
                  "local tarball, or update the repo checkout and run "
                  "install from there", file=sys.stderr)
            return 4
        src_pkg = _extract_package(tgz, tmpdir)
        if src_pkg is None:
            print("error: tarball does not contain a recognizable "
                  f"{PACKAGE_DIRNAME} package", file=sys.stderr)
            return 4
        # sanity: every python file must compile before anything is touched
        for py in sorted(src_pkg.glob("*.py")):
            try:
                compile(py.read_text(encoding="utf-8"), str(py), "exec")
            except SyntaxError as exc:
                print(f"error: fetched tree failed to compile: {exc}",
                      file=sys.stderr)
                return 4
        new_version = (_pkg_file_version(src_pkg, "__init__.py",
                                         r'__version__\s*=\s*"([^"]+)"')
                       or "unknown")
        # install-over: reuse the normal install path from the fetched tree
        args.yes = getattr(args, "yes", False)
        rc = _install_from_tree(src_pkg, prefix, args)
        if rc == 0:
            print(f"[UPGRADE] {old_version or '(not installed)'} -> "
                  f"{new_version}")
        return rc
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _install_from_tree(src_pkg, prefix: str, args) -> int:
    """Install a specific package directory (used by --upgrade)."""
    if not _root_guard(prefix, getattr(args, "yes", False)):
        return 2
    pkg_root = _pkg_root(prefix)
    if not _writable_guard(pkg_root):
        return 2
    old = _read_manifest(prefix)
    created: List[str] = []
    backups: List[str] = list(old.get("backups", [])) if old else []
    _backup_foreign_shims(prefix, backups)
    pkg_root.mkdir(parents=True, exist_ok=True)
    created.append(str(pkg_root))
    for item in sorted(os.listdir(src_pkg)):
        s = os.path.join(str(src_pkg), item)
        if os.path.isfile(s) and item.endswith(".py"):
            shutil.copy2(s, pkg_root / item)
            created.append(str(pkg_root / item))
    shims = _write_shims(prefix, pkg_root, created)
    new_version = (_pkg_file_version(pkg_root, "__init__.py",
                                     r'__version__\s*=\s*"([^"]+)"')
                   or "unknown")
    manifest = {
        "schema": 1,
        "tool": TOOL_NAME,
        "version": new_version,
        "installed_at": datetime.now(timezone.utc).isoformat(),
        "python": sys.executable,
        "package_dir": str(pkg_root),
        "shims": shims,
        "created": created,
        "backups": backups,
    }
    _manifest_path(prefix).write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    print(f"[UPGRADE] package : {pkg_root}")
    for s in shims:
        print(f"[UPGRADE] shim    : {s}")
    return 0


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------
def _sidecars_for_file(p):
    from pathlib import Path
    p = Path(p)
    out = []
    if CLEAN_SIDECARS:
        first = p.with_suffix(CLEAN_SIDECARS[0])
        out.append(first)
        for s in CLEAN_SIDECARS[1:]:
            out.append(p.with_suffix(s))
            out.append(first.with_suffix(s))
    return out


def op_clean(args) -> int:
    from pathlib import Path
    yes = getattr(args, "yes", False)
    do_all = getattr(args, "all", False) or getattr(args, "clean_all", False)
    targets: List[Tuple[str, str]] = []  # (path, reason)
    for raw in (args.clean or []):
        p = Path(raw).expanduser()
        if p.is_dir():
            if do_all:
                targets.append((str(p), "directory (--all)"))
                continue
            found_here = 0
            for pat in CLEAN_GLOBS:
                for hit in sorted(p.rglob(pat)):
                    if hit.is_file() or hit.is_dir():
                        targets.append((str(hit), f"matches {pat}"))
                        found_here += 1
            if not found_here:
                print(f"nothing to clean in {p}")
        elif p.is_file():
            found_here = 0
            for c in _sidecars_for_file(p):
                if c.is_file():
                    targets.append((str(c), "generated sidecar"))
                    found_here += 1
            if not found_here:
                print(f"no generated sidecars for {p}")
        else:
            print(f"skip (not found): {p}")
    if not targets:
        print("nothing to clean")
        return 0
    for t, why in targets:
        print(f"{'removing' if yes else 'would remove'}: {t}  ({why})")
    if not yes:
        print("dry run — re-run with --yes to apply")
        return 0
    n = 0
    for t, _ in targets:
        pp = Path(t)
        try:
            if pp.is_dir():
                shutil.rmtree(pp, ignore_errors=True)
            else:
                pp.unlink()
            n += 1
        except OSError as exc:
            print(f"warning: could not remove {t}: {exc}", file=sys.stderr)
    print(f"[CLEAN] removed {n} item(s)")
    return 0


# ---------------------------------------------------------------------------
# self-test round-trip (invoked from the CLI self-test; temp prefix only)
# ---------------------------------------------------------------------------
def self_test_roundtrip() -> Tuple[bool, str]:
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ubi-lifecycle-test-") as td:
        prefix = os.path.join(td, "prefix")

        def _ns(**kw):
            from types import SimpleNamespace
            base = dict(prefix=prefix, yes=True, force=False,
                        upgrade_url=None, clean=None, all=False)
            base.update(kw)
            return SimpleNamespace(**base)

        rc = op_install(_ns())  # type: ignore[arg-type]
        if rc != 0:
            return False, f"install rc={rc}"
        manifest = _read_manifest(prefix)
        if not manifest or manifest.get("schema") != 1:
            return False, "manifest missing/invalid"
        shims = manifest.get("shims", [])
        if not shims or not all(os.path.isfile(s) for s in shims):
            return False, "shims missing"
        body = open(shims[0], encoding="utf-8").read()
        if SHIM_MARKER not in body or "ubi_toolkit.ubipack" not in body:
            return False, "shim content wrong"
        rc = op_clean(_ns(clean=[prefix]))  # type: ignore[arg-type]
        if rc != 0:
            return False, f"clean rc={rc}"
        rc = op_uninstall(_ns())  # type: ignore[arg-type]
        if rc != 0:
            return False, f"uninstall rc={rc}"
        if os.path.exists(shims[0]) or _pkg_root(prefix).exists():
            return False, "uninstall left files behind"
        return True, f"round-trip OK in temp prefix ({manifest['version']})"
