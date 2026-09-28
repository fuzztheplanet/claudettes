#!/usr/bin/env python3
"""protobuf-decode.py — schema-free protobuf raw decoder (like `protoc --decode_raw`).

Reverse binary API request/response bodies when there is no .proto available.
Parses the protobuf wire format, prints a field tree (field number, wire type,
decoded value), and recursively decodes length-delimited fields that cleanly
parse as nested messages — falling back to UTF-8 string or hex.

Input sources:
  <file>           read bytes from a file
  --hex <hex>      decode a hex string (whitespace/0x/commas tolerated)
  -                read bytes from stdin

Options:
  --grpc           treat input as gRPC length-prefixed framing:
                   repeating [1-byte compressed flag][4-byte big-endian length][message]
                   (compressed payloads are gunzip/inflate'd via stdlib when possible)
  --raw            print the raw field table only (no nested-message recursion)
  -o, --output F   also write the rendered tree to F
  -h, --help

Machine-readable trailer:
  FIELD_COUNT=<n>          top-level fields decoded (summed across gRPC frames)
  PROTO_DECODE_RESULT=success|failed

Exit codes: 0 success, 1 failure (unparseable / no fields decoded / bad input).

Dependency-free (Python 3 stdlib only). Robust to truncated / non-protobuf input:
reports cleanly instead of raising.
"""
import sys
import struct
import argparse

WIRE_NAMES = {0: "varint", 1: "64-bit", 2: "len-delim", 3: "group-start",
              4: "group-end", 5: "32-bit"}
MAX_DEPTH = 64


class Reader:
    def __init__(self, data):
        self.data = data
        self.pos = 0
        self.n = len(data)

    def eof(self):
        return self.pos >= self.n

    def read_varint(self):
        shift = 0
        result = 0
        start = self.pos
        while True:
            if self.pos >= self.n:
                raise ValueError("truncated varint at offset %d" % start)
            b = self.data[self.pos]
            self.pos += 1
            result |= (b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7
            if shift > 63:
                raise ValueError("varint too long at offset %d" % start)

    def read(self, k):
        if self.pos + k > self.n:
            raise ValueError("truncated field: wanted %d bytes at offset %d" % (k, self.pos))
        chunk = self.data[self.pos:self.pos + k]
        self.pos += k
        return chunk


def zigzag(n):
    return (n >> 1) ^ -(n & 1)


def looks_printable(b):
    if not b:
        return False
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\t\n\r")
    return printable / len(s) >= 0.9


def decode_message(data, depth, recurse, out, strict=False):
    """Decode one protobuf message body, appending rendered lines to `out`.

    strict=True is used for nested-message probing: it raises ValueError on any
    anomaly (truncation, group/unknown wire type, or bytes left unconsumed), so a
    length-delimited field is only treated as a nested message when it parses
    completely and cleanly. Returns the number of fields decoded.
    """
    r = Reader(data)
    count = 0
    indent = "  " * depth
    while not r.eof():
        try:
            tag = r.read_varint()
        except ValueError as e:
            if strict:
                raise
            out.append("%s<trailing/undecodable: %s>" % (indent, e))
            break
        field_no = tag >> 3
        wire = tag & 7
        wname = WIRE_NAMES.get(wire, "unknown(%d)" % wire)

        # Wire types 3/4 (groups, deprecated) and >5 are anomalies for our purposes.
        if wire in (3, 4) or wire > 5:
            if strict:
                raise ValueError("group/unknown wire type %d" % wire)
            out.append("%s#%d (%s): <wire type %d not decoded; stop>"
                       % (indent, field_no, wname, wire))
            break

        try:
            if wire == 0:  # varint
                v = r.read_varint()
                signed = v - (1 << 64) if v >> 63 else v
                out.append("%s#%d (%s): %d   [signed:%d zigzag:%d%s]"
                           % (indent, field_no, wname, v, signed, zigzag(v),
                              " bool:%s" % bool(v) if v in (0, 1) else ""))
                count += 1
            elif wire == 1:  # 64-bit
                raw = r.read(8)
                (u64,) = struct.unpack("<Q", raw)
                (f64,) = struct.unpack("<d", raw)
                out.append("%s#%d (%s): 0x%016x   [double:%r]"
                           % (indent, field_no, wname, u64, f64))
                count += 1
            elif wire == 5:  # 32-bit
                raw = r.read(4)
                (u32,) = struct.unpack("<I", raw)
                (i32,) = struct.unpack("<i", raw)
                (f32,) = struct.unpack("<f", raw)
                out.append("%s#%d (%s): 0x%08x   [int:%d float:%r]"
                           % (indent, field_no, wname, u32, i32, f32))
                count += 1
            elif wire == 2:  # length-delimited
                length = r.read_varint()
                body = r.read(length)
                rendered = False
                if recurse and body and depth < MAX_DEPTH:
                    sub = []
                    try:
                        decode_message(body, depth + 1, recurse, sub, strict=True)
                        out.append("%s#%d (%s): message (%d bytes) {"
                                   % (indent, field_no, wname, length))
                        out.extend(sub)
                        out.append("%s}" % indent)
                        rendered = True
                    except ValueError:
                        rendered = False
                if not rendered:
                    if looks_printable(body):
                        out.append("%s#%d (%s): %r (%d bytes)"
                                   % (indent, field_no, wname,
                                      body.decode("utf-8"), length))
                    else:
                        preview = body[:64].hex()
                        ell = "..." if length > 64 else ""
                        out.append("%s#%d (%s): bytes %s%s (%d bytes)"
                                   % (indent, field_no, wname, preview, ell, length))
                count += 1
        except ValueError as e:
            if strict:
                raise
            out.append("%s#%d (%s): <undecodable: %s>" % (indent, field_no, wname, e))
            break
    return count


def decode_grpc(data, recurse, out):
    """Decode gRPC length-prefixed framing. Returns total field count."""
    import zlib
    import gzip
    r = Reader(data)
    total = 0
    frame = 0
    while not r.eof():
        try:
            flag = r.read(1)[0]
            length = struct.unpack(">I", r.read(4))[0]
            payload = r.read(length)
        except ValueError as e:
            out.append("<gRPC framing error: %s>" % e)
            break
        frame += 1
        if flag == 1:
            decompressed = None
            for name, fn in (("gzip", gzip.decompress), ("deflate", zlib.decompress)):
                try:
                    decompressed = fn(payload)
                    out.append("=== gRPC frame %d (compressed:%s, %d->%d bytes) ==="
                               % (frame, name, length, len(decompressed)))
                    payload = decompressed
                    break
                except Exception:
                    continue
            if decompressed is None:
                out.append("=== gRPC frame %d (compressed, could not inflate; %d bytes) ==="
                           % (frame, length))
                out.append("  raw: %s" % payload[:64].hex())
                continue
        else:
            out.append("=== gRPC frame %d (%d bytes) ===" % (frame, length))
        total += decode_message(payload, 1, recurse, out)
    return total


def read_input(args):
    if args.hex is not None:
        cleaned = args.hex.replace("0x", "").replace(",", " ")
        cleaned = "".join(cleaned.split())
        return bytes.fromhex(cleaned)
    if args.input == "-" or args.input is None:
        return sys.stdin.buffer.read()
    with open(args.input, "rb") as f:
        return f.read()


def main():
    p = argparse.ArgumentParser(add_help=True, description="schema-free protobuf raw decoder")
    p.add_argument("input", nargs="?", help="file path, or - for stdin")
    p.add_argument("--hex", help="decode a hex string instead of a file")
    p.add_argument("--grpc", action="store_true", help="parse gRPC length-prefixed framing")
    p.add_argument("--raw", action="store_true", help="raw field table only, no recursion")
    p.add_argument("-o", "--output", help="also write rendered tree to this file")
    args = p.parse_args()

    try:
        data = read_input(args)
    except (ValueError, OSError) as e:
        print("[FAIL] could not read input: %s" % e, file=sys.stderr)
        print("PROTO_DECODE_RESULT=failed")
        return 1

    if not data:
        print("[FAIL] empty input", file=sys.stderr)
        print("PROTO_DECODE_RESULT=failed")
        return 1

    out = []
    recurse = not args.raw
    try:
        if args.grpc:
            count = decode_grpc(data, recurse, out)
        else:
            count = decode_message(data, 0, recurse, out)
    except Exception as e:  # last-resort guard; never stack-trace on bad input
        print("[FAIL] decode error: %s" % e, file=sys.stderr)
        print("PROTO_DECODE_RESULT=failed")
        return 1

    rendered = "\n".join(out)
    if rendered:
        print(rendered)
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(rendered + "\n")
            print("[OK] wrote %s" % args.output, file=sys.stderr)
        except OSError as e:
            print("[WARN] could not write output file: %s" % e, file=sys.stderr)

    print()
    print("FIELD_COUNT=%d" % count)
    if count == 0:
        print("[FAIL] no protobuf fields decoded — input is not (raw) protobuf?", file=sys.stderr)
        print("PROTO_DECODE_RESULT=failed")
        return 1
    print("PROTO_DECODE_RESULT=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
