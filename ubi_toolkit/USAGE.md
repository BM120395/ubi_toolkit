# ubipack — UBI / Flash Image Toolkit — User Guide

Version 1.12.x · Modules: `ubi_toolkit` (analyst, ubipack, carve, anomaly,
fs_health, repacker, splice, bootimg, ecc_runtime)

---

## 1. What it does

`ubipack` analyzes raw NAND/UBI firmware dumps **without any fixed
geometry assumptions**. Every value it uses — page size, OOB size, PEB/EB
size, VID-header offset, LEB size, CRC convention — is:

1. **Derived** from the binary at run time (EC-header lattice, candidate
   geometry decomposition, VID-offset probing), then
2. **Cross-verified** against independent image evidence (EC CRCs, VID
   placement at the declared offset, volume data). A confidence verdict is
   logged; low confidence advises explicit overrides.

Manual overrides (`--page-size`, `--oob-size`, `--peb-size`, `--leb-size`)
remain available as a last-resort escape hatch for pathological images.

## 2. Install / layout

Tools are managed by a lifecycle installer:

    ~/.local/bin/ubipack        # CLI front-end (Python)
    ~/.local/bin/sqpack         # companion SquashFS deterministic repacker
    ~/.local/share/ubi_toolkit/ # library code

Lifecycle: `ubipack -I` (install) · `-U` (uninstall) · `--upgrade` ·
`-K DIR...` (clean outputs).

## 3. Common tasks

### Extract (the usual workflow)

    ubipack -x -s firmware.bin -o out/

Produces:

    out/
      ubi/region_N/            # one dir per detected UBI attach
        clean_ubi.img          # OOB-stripped, EC-consistent image
        raw_ubi.img            # as-is raw slice
        headers/               # ec_headers.json, vid_headers.json,
                               #   crc_convention.json
        volumes/               # assembled volume images (squashfs/ubifs/uImage/DTB...)
      other_fs/                # filesystems found OUTSIDE any UBI region
      boot_images/             # uImage payloads harvested from the dump
      report.json, report.txt  # full forensic report

### Analyze only (no extraction)

    ubipack -a -s firmware.bin -o out/

### Repair flows (ECC-interleaved / bit-rot images)

Some vendors interleave ECC bytes inside the data area. The analyzer detects
this (anomaly `ANOM-1`) and tells you:

    ubipack -a -s firmware.bin -o out/ --auto-fix      # repair + analyze
    ubipack -a -s firmware.bin -o out/ --auto-fix --dry-run   # preview only
    ubipack -a ... --auto-fix --reference good.bin     # byte-exact bit-rot repair

Forced-geometry run (skip detection entirely):

    ubipack -x -s fw.bin -o out/ --page-size 2048 --oob-size 128 [--force-geometry]
    ubipack -x -s fw.bin -o out/ --clean-ubi           # input already OOB-stripped

### Repack (after modifying a volume)

    ubipack -r -n out/ --repacked out_repacked/ \
        --replace region0:squashfs=my_new_rootfs.squashfs

`-n` is the analysis dir containing `ubi/region_N/clean_ubi.img`. Volumes
modified under `out/ubi/region_N/volumes/` are spliced back into the raw
image with correct page/ECC placement.

### Compare / verify

    ubipack -c -n out_a/ -m out_b/     # compare two analysis trees
    ubipack -V -s fw.bin -o out/       # verify existing extraction
    ubipack -t                         # built-in self-test

## 4. Reading the report

- `oob_geometry` — derived page/oob/stride + clean/raw EB sizes.
- `ubi_regions[]` — one entry per attach; each lists volumes with
  `present_leb_count / logical_leb_count` (missing LEBs are 0xFF-filled and
  warned), `fs_type`, and a `validation` verdict.
- Anomalies (`ANOM-n`): `info` = FYI; `repairable` = rerun with `--auto-fix`.

## 5. Exit codes

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | analysis error (see log/traceback) |
| 2 | usage error (e.g. no firmware given; GUI not built) |

## 6. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Empty `volumes/` everywhere | Geometry mismatch — check the
`Geometry cross-verification ... confidence` log line; if `low`, pass
explicit `--page-size/--oob-size`. |
| `repairable` anomaly, no output | Rerun with `--auto-fix`. |
| Truncated SquashFS/UBIFS volume | Missing LEBs (`present < logical` in
report) — flash wear; try the `.orig.` variants or `--reference` repair. |
| Driver claims only 1 region but two banks visible | Banks split by
attach (layout-volume) boundaries; if merged wrongly, file an issue with the
report attached. |
| `sqpack: error: Unknown inode type ...` on a SquashFS extracted by an
older ubipack | Re-extract with the current ubipack — older runs truncated
or OOB-mangled volumes. |

## 7. Performance notes

- EC scan, VID scans and geometry tie-breaks sample bounded windows; large
  dumps (>1 GiB) remain practical.
- FS-magic orphan scan caps at 256 MiB (logged when triggered); use
  `carve.py` modes for full-depth carving of huge dumps.
- Volumes dedupe by SHA-256 — identical A/B banks extract once.
