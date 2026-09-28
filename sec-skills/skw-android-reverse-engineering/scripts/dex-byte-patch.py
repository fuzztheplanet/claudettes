#!/usr/bin/env python3
"""dex-byte-patch.py — Equal-length byte patching of a classes.dex, with
automatic DEX header repair (Adler-32 checksum + SHA-1 signature) so the
patched file loads.

Equal-length patching rewrites bytecode in place without rebuilding methods,
which avoids re-running the dex verifier on rebuilt code and produces a minimal,
auditable diff. It is often more reliable on hardened apps than a full smali
rebuild. See references/byte-level-patching.md for technique and the equal-length
instruction swaps this supports.

Modes:
  --find <hex>          Locate a byte sequence; print every offset as
                        MATCH_OFFSET=0x....
  --patch <spec.json>   Apply equal-length patches from a JSON spec (see below),
                        repair the DEX header, and write the output.
  --verify <dex>        Recompute and check the stored checksum + signature.

Spec JSON is a list of objects, each either:
  {"offset": 6703, "from": "0f00", "to": "1200"}   # offset int or "0x..." string
  {"search": "0f00", "replace": "1200"}            # first occurrence

Rules:
  - Replacement length MUST equal the original length (refused otherwise).
  - For "from"/"search" the current bytes are checked before writing.

Machine-readable output:
  MATCH_OFFSET=0x...            (--find)
  PATCH_COUNT=<n>               (--patch)
  BYTES_CHANGED=<n>             (--patch)
  DEX_CHECKSUM_OK=true|false    (--patch, --verify)
  OUTPUT=<path>                 (--patch)
  PATCH_RESULT=success|failed   (--patch, last line)

Exit codes: 0 success, 1 failure. Stdlib only.
"""
import argparse
import hashlib
import json
import sys
import zlib

DEX_MAGIC = b"dex\n"
CHECKSUM_OFF = 8      # u4 (little-endian), Adler-32 over bytes[12:]
SIGNATURE_OFF = 12    # 20-byte SHA-1 over bytes[32:]
FILE_SIZE_OFF = 32    # u4


def log(msg):
    print(f"[INFO] {msg}")


def err(msg):
    print(f"[FAIL] {msg}", file=sys.stderr)


def parse_hex(s):
    """Parse a hex string ('0f00' or '0f 00' or '0x0f00') to bytes."""
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    s = s.replace(" ", "").replace("_", "")
    if len(s) % 2 != 0:
        raise ValueError(f"hex string has odd length: {s!r}")
    return bytes.fromhex(s)


def validate_magic(data):
    if data[:4] != DEX_MAGIC:
        raise ValueError("not a DEX file (bad magic)")
    # version is 3 ASCII digits + NUL at offset 4..8, e.g. b'035\x00'
    ver = data[4:7]
    if not ver.isdigit():
        raise ValueError(f"unrecognized DEX version bytes: {data[4:8]!r}")
    return ver.decode()


def compute_signature(data):
    return hashlib.sha1(data[SIGNATURE_OFF + 20:]).digest()


def compute_checksum(data):
    # Adler-32 over everything after the checksum field (offset 12 onward).
    return zlib.adler32(data[SIGNATURE_OFF:]) & 0xFFFFFFFF


def repair_header(data):
    """Return a bytearray with signature and checksum recomputed."""
    buf = bytearray(data)
    sig = compute_signature(buf)
    buf[SIGNATURE_OFF:SIGNATURE_OFF + 20] = sig
    csum = compute_checksum(buf)
    buf[CHECKSUM_OFF:CHECKSUM_OFF + 4] = csum.to_bytes(4, "little")
    return buf


def read_stored_checksum(data):
    return int.from_bytes(data[CHECKSUM_OFF:CHECKSUM_OFF + 4], "little")


def read_stored_signature(data):
    return bytes(data[SIGNATURE_OFF:SIGNATURE_OFF + 20])


def do_find(path, needle_hex):
    data = open(path, "rb").read()
    needle = parse_hex(needle_hex)
    if not needle:
        err("empty search sequence")
        return 1
    count = 0
    start = 0
    while True:
        idx = data.find(needle, start)
        if idx == -1:
            break
        print(f"MATCH_OFFSET=0x{idx:x}")
        count += 1
        start = idx + 1
    log(f"{count} match(es) for {needle.hex()}")
    return 0


def do_verify(path):
    data = open(path, "rb").read()
    try:
        ver = validate_magic(data)
    except ValueError as e:
        err(str(e))
        print("DEX_CHECKSUM_OK=false")
        return 1
    stored_sum = read_stored_checksum(data)
    stored_sig = read_stored_signature(data)
    calc_sum = compute_checksum(data)
    calc_sig = compute_signature(data)
    sum_ok = stored_sum == calc_sum
    sig_ok = stored_sig == calc_sig
    log(f"DEX version {ver}, file size {len(data)}")
    log(f"checksum stored=0x{stored_sum:08x} computed=0x{calc_sum:08x} {'OK' if sum_ok else 'MISMATCH'}")
    log(f"signature {'OK' if sig_ok else 'MISMATCH'}")
    ok = sum_ok and sig_ok
    print(f"DEX_CHECKSUM_OK={'true' if ok else 'false'}")
    return 0 if ok else 1


def do_patch(path, spec_path, out_path):
    data = bytearray(open(path, "rb").read())
    try:
        validate_magic(data)
    except ValueError as e:
        err(str(e))
        print("PATCH_RESULT=failed")
        return 1

    try:
        spec = json.load(open(spec_path))
    except (OSError, json.JSONDecodeError) as e:
        err(f"cannot read spec: {e}")
        print("PATCH_RESULT=failed")
        return 1
    if not isinstance(spec, list):
        err("spec JSON must be a list of patch objects")
        print("PATCH_RESULT=failed")
        return 1

    bytes_changed = 0
    applied = 0
    for i, item in enumerate(spec):
        try:
            replace = parse_hex(item["to"] if "to" in item else item["replace"])
        except (KeyError, ValueError) as e:
            err(f"patch #{i}: bad/missing 'to'/'replace': {e}")
            print("PATCH_RESULT=failed")
            return 1

        if "offset" in item:
            off = item["offset"]
            if isinstance(off, str):
                off = int(off, 16) if off.lower().startswith("0x") else int(off)
            expect = None
            if "from" in item:
                try:
                    expect = parse_hex(item["from"])
                except ValueError as e:
                    err(f"patch #{i}: bad 'from': {e}")
                    print("PATCH_RESULT=failed")
                    return 1
        elif "search" in item:
            try:
                expect = parse_hex(item["search"])
            except ValueError as e:
                err(f"patch #{i}: bad 'search': {e}")
                print("PATCH_RESULT=failed")
                return 1
            off = data.find(expect)
            if off == -1:
                err(f"patch #{i}: search sequence {expect.hex()} not found")
                print("PATCH_RESULT=failed")
                return 1
            if data.find(expect, off + 1) != -1:
                err(f"patch #{i}: search sequence {expect.hex()} is not unique — "
                    f"use an explicit offset (found first at 0x{off:x})")
                print("PATCH_RESULT=failed")
                return 1
        else:
            err(f"patch #{i}: must have 'offset' or 'search'")
            print("PATCH_RESULT=failed")
            return 1

        orig = bytes(data[off:off + len(replace)])
        if len(replace) != len(orig):
            err(f"patch #{i}: cannot patch past end of file at offset 0x{off:x}")
            print("PATCH_RESULT=failed")
            return 1
        if expect is not None:
            if len(expect) != len(replace):
                err(f"patch #{i}: EQUAL-LENGTH violation — 'from'/'search' is "
                    f"{len(expect)} bytes, 'to'/'replace' is {len(replace)} bytes")
                print("PATCH_RESULT=failed")
                return 1
            if orig != expect:
                err(f"patch #{i}: bytes at offset 0x{off:x} are {orig.hex()}, "
                    f"expected {expect.hex()} — refusing to patch")
                print("PATCH_RESULT=failed")
                return 1

        if orig == replace:
            log(f"patch #{i}: bytes already equal at 0x{off:x}, no change")
        else:
            data[off:off + len(replace)] = replace
            bytes_changed += sum(1 for a, b in zip(orig, replace) if a != b)
            log(f"patch #{i}: 0x{off:x} {orig.hex()} -> {replace.hex()}")
        applied += 1

    data = repair_header(data)
    out = out_path or (path + ".patched")
    with open(out, "wb") as f:
        f.write(data)

    ok = (compute_checksum(data) == read_stored_checksum(data)
          and compute_signature(data) == read_stored_signature(data))
    print(f"PATCH_COUNT={applied}")
    print(f"BYTES_CHANGED={bytes_changed}")
    print(f"DEX_CHECKSUM_OK={'true' if ok else 'false'}")
    print(f"OUTPUT={out}")
    print(f"PATCH_RESULT={'success' if ok else 'failed'}")
    log("Equal-length patch complete — the dex verifier was not asked to "
        "re-verify rebuilt methods (see references/byte-level-patching.md).")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(add_help=True, description="Equal-length DEX byte patcher")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--find", metavar="HEX", help="locate a byte sequence")
    g.add_argument("--patch", metavar="SPEC.JSON", help="apply equal-length patches")
    g.add_argument("--verify", action="store_true", help="verify checksum + signature")
    ap.add_argument("dex", help="path to the classes.dex")
    ap.add_argument("-o", "--output", help="output path (--patch)")
    args = ap.parse_args()

    try:
        if args.find is not None:
            return do_find(args.dex, args.find)
        if args.patch is not None:
            return do_patch(args.dex, args.patch, args.output)
        if args.verify:
            return do_verify(args.dex)
    except FileNotFoundError as e:
        err(f"file not found: {e.filename}")
        return 1
    except OSError as e:
        err(str(e))
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
