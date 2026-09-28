# Protocol Reverse Engineering (non-HTTP / binary bodies)

Phase 5's endpoint extraction assumes REST/GraphQL/WebSocket with readable
bodies. Many apps use binary transports instead — protobuf over HTTP, gRPC,
gRPC-Web, or a custom framing. The symptom is: **the app clearly does network
I/O, but "no endpoints found"** and captured bodies are unreadable bytes. This
reference covers decoding those without the app's schema.

Tie every claim to `verification.md`: a decoded field tree is `OBSERVED`, but a
*reconstructed field meaning* ("field 3 is the user id") is `INFERRED` until you
correlate it with app behavior.

## Protobuf wire format

Protobuf messages are a flat sequence of `(tag, value)` pairs. The tag is a
varint; `field_number = tag >> 3`, `wire_type = tag & 7`.

| Wire type | Name | Encoding | Holds |
|---|---|---|---|
| 0 | varint | LEB128 | int32/64, uint, bool, enum, sint (zigzag) |
| 1 | 64-bit | 8 bytes LE | fixed64, sfixed64, double |
| 2 | length-delimited | varint length + bytes | string, bytes, **nested message**, packed repeated |
| 5 | 32-bit | 4 bytes LE | fixed32, sfixed32, float |
| 3 / 4 | group start/end | deprecated | legacy nested (rare) |

Because the wire format is self-describing for *structure* but not *types*, you
can always recover the shape (field numbers + wire types) even with no `.proto`.
You cannot recover field *names* — those live only in the schema.

## Decode raw bytes with `protobuf-decode.py`

Schema-free decode, equivalent to `protoc --decode_raw`:

```bash
# From a captured body file
python3 <skill-directory>/scripts/protobuf-decode.py body.bin

# From a hex string (e.g. copied from Burp/Frida)
python3 <skill-directory>/scripts/protobuf-decode.py --hex 089601120568656c6c6f

# From stdin
xxd -r -p <<< "089601" | python3 <skill-directory>/scripts/protobuf-decode.py -
```

The decoder prints a field tree, recursively decoding length-delimited fields
that parse cleanly as nested messages and falling back to UTF-8 string or hex.
`FIELD_COUNT=` and `PROTO_DECODE_RESULT=` are emitted for scripting. Use `--raw`
to suppress the nested-message guess when a length-delimited field is really an
opaque blob (e.g. an encrypted payload) that happens to parse by coincidence.

### Reconstructing a usable `.proto`

From the field tree, write a `.proto` you can use with `protoc` to craft
requests. Map wire types to plausible declared types, then refine by observing
values across many captures:

```proto
message Guess {
  int64  field1 = 1;   // wire 0 — could be int/bool/enum
  string field2 = 2;   // wire 2, printable
  Nested field3 = 3;   // wire 2, parsed as a message
}
```

Repeated packed fields appear as a single length-delimited field containing
concatenated varints/fixed values — decode the inner bytes as the element type.

## Find the real schema inside the app

Reconstructing from the wire is a fallback. The actual schema is usually in the
decompiled app — recover names and types directly:

- **Generated protobuf classes.** Search the decompiled tree for the runtime the
  app uses:
  - protobuf-lite: `extends GeneratedMessageLite`, `newMessageInfo`, `PARSER`.
  - protobuf-java (full): `extends GeneratedMessageV3`, `internalGetFieldAccessorTable`.
  - protobuf-nano (older): `extends MessageNano`.
  - Wire (Square): classes with `@WireField` annotations / `ProtoAdapter`.
  ```bash
  grep -rlE 'GeneratedMessageLite|GeneratedMessageV3|MessageNano|ProtoAdapter' <output>/sources/
  grep -rlE 'newMessageInfo|@WireField' <output>/sources/
  ```
  The field numbers and names are embedded in these classes (often in the
  `newMessageInfo` info string / `@WireField(tag = N)`), giving you the schema
  without guessing.
- **Embedded descriptors / `.proto`.** Check `assets/` and resources for
  `*.proto`, `*.desc`, or `FileDescriptorProto` byte blobs.

## gRPC

gRPC = protobuf messages over HTTP/2, with a 5-byte length prefix per message:

```
[1 byte compressed-flag][4 bytes big-endian length][ message bytes ]
```

Decode captured gRPC bodies with the framing parser:

```bash
python3 <skill-directory>/scripts/protobuf-decode.py --grpc frame.bin
```

If the compressed flag is `1`, the payload is gzip/deflate — the script inflates
it with stdlib when possible. Other gRPC specifics:

- **Method routing** is in the HTTP/2 `:path` pseudo-header as
  `/<package>.<Service>/<Method>`. Grep the decompiled app for the service
  interface (`*Grpc`, `MethodDescriptor`, `io.grpc.stub`) to enumerate methods.
- **gRPC-Web** carries the same 5-byte framing over HTTP/1.1, often base64 in the
  body, with a trailing frame (flag `0x80`) holding grpc-status. Base64-decode,
  then feed to `--grpc`.

## QUIC / HTTP/3

A system-proxy MITM (Burp/mitmproxy) **does not see QUIC/HTTP3** — it rides UDP
443 and bypasses the HTTP proxy. Options, in order of preference:

- **Force a downgrade.** Block UDP/443 (firewall/adb) so the client falls back to
  HTTP/2 over TCP, which a normal MITM can decrypt.
- **TLS keylog + Wireshark.** Hook the TLS layer (e.g. `SSL_CTX_set_keylog_callback`
  / BoringSSL) via Frida to dump keys, then decrypt the QUIC capture in Wireshark.
- **Hook below the transport.** Skip the network entirely — hook the app's own
  serializer to read/write the plaintext structure (next section).

## Capture plaintext at runtime (bypasses transport + crypto)

The most reliable route for any binary protocol is to hook the (de)serialization
boundary in the app, where the data is a normal object graph before it is
encoded/encrypted. Cross-reference Phase 7:

- Hook `parseFrom(...)` / `toByteArray()` / `writeTo(...)` on the generated
  message classes to dump inbound/outbound messages as readable objects.
- For custom framing, hook the app's own encode/decode method (found in Phase 4)
  rather than the socket.
- Log the object with the app's own `toString()` where available — generated
  protobuf `toString()` prints field names + values.

This sidesteps pinning, custom framing, and QUIC in one move, and yields
`OBSERVED` evidence of the real request/response contents.

## Symptom cross-reference

See `troubleshooting-index.md` rows: "Response bodies are binary / not JSON" and
"No endpoints found but the app clearly does network I/O".
