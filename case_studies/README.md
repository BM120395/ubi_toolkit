# Case study — raw NAND dump recovery (UBI on SPI-NAND)

Real-world recovery that exercised every trap this toolkit is built for.
Firmware: 138,412,032 B raw NAND programmer dump (1024 PEBs x 64 pages x 2112 B),
UBI volume "rootfsa" holding a SquashFS v4.0/xz rootfs (4754 inodes).

See `ubi_dump_recovery.py` for a self-contained, stdlib-only reference
implementation of the techniques below (import it, or run it against a dump).

## Lessons (ordered by how much time each cost)

1. **Page layout is not the data width.** The vendor layout hides ECC bytes
   INSIDE the apparent 2048 B data region: filesystem data per page is
   `P[0:1040] + P[1054:2048] + P[2050:2064]` — a 14 B ECC block inline at data
   offset 1040, and a second 14 B ECC block in the OOB area at offset 16.
   Assuming `P[0:2034]` or `P[0:2048]` shifts every stream after the first page
   and produces mid-payload "corruption" that decoders report as truncated xz
   streams. Probe candidate layouts by scoring total decodable bytes across
   sample pages before blaming compression.

2. **Programmer dumps are uncorrected.** The device controller applies on-die
   ECC on every read; a raw dump carries stable single-bit flips (here: 12,535
   flips, every byte exactly 1 bit, <= 2 flips per 512 B subpage, uniform bit
   planes = retention profile). Two dumps of the same chip taken days apart were
   byte-identical — flips are deterministic, not read noise. xz streams decode
   partially and die mid-payload; container CRCs still validate because the
   container headers/index sit in clean bytes.

3. **CRC-guided metadata repair.** UBI VID headers carry `hdr_crc` over bytes
   0..60. For each VID that fails CRC, try all 480 single-bit flips of the body;
   keep flips that make the CRC validate AND yield a sane lnum. This recovered
   56/104 damaged VIDs and dissolved an entire "stale VID / duplicate lnum"
   mystery that was pure misparse. The repaired lnum map became a bijection
   (104 lnums, each claimed exactly once, gaps = exactly the multi-bit-damaged
   PEBs, whose lnums are position-derived: PEB p holds lnum p-2).

4. **data_crc adjudication.** Once the volume is assembled with the correct page
   layout, plain `zlib.crc32` over `data_size` bytes matched the VID `data_crc`
   for 104/104 usable PEBs. A 0/N pass rate on this check is a layout bug
   signal, not a "vendor convention" signal — re-check geometry first.

5. **Reference-image differential repair.** If a stock/known-good image of the
   same firmware exists, rebuild the volume from the dump, diff, and correct
   flip sites against the reference. Verify end-to-end: UBI hdr_crc (bijective
   map) + UBI data_crc (N/N) + filesystem-level extraction matching the
   superblock inode count.

6. **ECC reversal has limits.** ~900K classical-BCH parameter combinations
   (GF(2^14) t=8, GF(2^8) t=14, all primitive polys, four preimage shapes, both
   14 B code slots, 4 bit orders x endian x bit-reversal) did NOT reproduce the
   stored codes even with corrected preimages. On-die ECC in modern SPI-NAND is
   frequently proprietary. Budget for the differential path instead.

## Geometry quick reference (this device)

    page stride       2112 B (2048 data + 64 OOB)
    PEB stride        0x21000, LEB 0x1F000 (62 data pages)
    EC header         PEB + 0x0000
    VID header        PEB + 0x0840 (BIG-ENDIAN fields)
    fs data per page  P[0:1040] + P[1054:2048] + P[2050:2064]
    volume            bank A PEBs 2..119, bank B PEBs 188..305 (mirror +186)
    lnum map          PEB p -> lnum p-2 (bank A)
