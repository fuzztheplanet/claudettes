# Byte-Level DEX Patching

For **authorized** analysis only. Byte patching rewrites Dex bytecode **in place**
without rebuilding the method, then repairs the Dex header so the file still
loads. It produces the smallest possible, fully auditable diff.

Driver script: `<skill-directory>/scripts/dex-byte-patch.py` (stdlib-only Python 3).

## When byte patching beats a smali rebuild

- **Hardened / tamper-checked apps.** A full `apktool b` rebuild renumbers
  offsets, re-encodes the whole Dex, and can perturb structures the app checks.
  An equal-length byte patch changes only the exact bytes you target.
- **Avoiding verifier churn.** Rebuilding a method sends it back through the ART
  dex verifier. A surgical equal-length edit to existing, already-valid bytecode
  keeps the surrounding method structure intact.
- **Minimal, provable diff.** `dex_classdiff`-style before/after byte diffs make
  it trivial to show exactly what changed — good for the verification ladder
  (`verification.md`).
- **No toolchain.** No apktool/aapt needed; works offline with just Python.

Trade-off: you are limited to **equal-length** edits. Anything that changes the
number of bytecode units (adding instructions, changing operand width, editing
the string/type/method pools) needs a rebuild or a dexlib2-level rewrite instead.

## DEX header fields that matter for patching

Offsets from the start of the file:

| Offset | Size | Field | On patch |
|---|---|---|---|
| 0 | 8 | `magic` = `"dex\n0XY\0"` | Validate; never change. |
| 8 | 4 | `checksum` (Adler-32, LE) over `bytes[12:]` | **Must recompute.** |
| 12 | 20 | `signature` (SHA-1) over `bytes[32:]` | **Must recompute.** |
| 32 | 4 | `file_size` (LE) | Unchanged for equal-length edits. |

If you change bytes anywhere from offset 32 onward and **don't** recompute the
signature and checksum, ART rejects the Dex at load (or the packer/loader's own
integrity check trips). `dex-byte-patch.py --patch` recomputes both automatically;
`--verify` checks them on any Dex.

## Locating the bytes to patch

1. Decompile/disassemble to find the method:
   `baksmali disassemble classes.dex -o out/` (or read jadx output for logic).
2. Identify the exact instruction to change and its bytecode encoding. Each Dex
   instruction is a whole number of 16-bit code units; know the encoding of the
   op you're editing (e.g. `if-eqz vAA, +BBBB` is format 21t, 2 code units).
3. Find the byte sequence in the file:
   `dex-byte-patch.py --find <hex> classes.dex` → every `MATCH_OFFSET=0x...`.
   Make the search sequence long enough to be **unique** (include neighbouring
   instructions), or capture the offset from baksmali's `/*offset*/` annotations.

## Equal-length swaps that are commonly useful

All of these keep the byte count identical:

- **Invert a branch.** `if-eqz` (`0x38`) ↔ `if-nez` (`0x39`); `if-eq`↔`if-ne`,
  `if-lt`↔`if-ge`, `if-gt`↔`if-le`. Same format, same size — flip the opcode byte
  to reverse a check without touching its target.
- **Force a boolean return value.** A `const/4 vX, #0` (`0x12`, low nibble = reg,
  high nibble = value) can become `const/4 vX, #1` by changing only the value
  nibble — turn an `isRooted()`/`isEmulator()` result to the safe constant right
  before it's returned.
- **NOP out an instruction.** Overwrite a 1-code-unit instruction with `0000`
  (`nop`). For multi-unit instructions, fill the whole instruction with `nop`s
  (only if the total length matches).
- **Neutralize a call result** by NOPing the `invoke` **and** the paired
  `move-result` (see the adjacency hazard below), or by forcing the moved-in
  register to a constant afterwards.

## The `move-result` adjacency hazard

`move-result*` must **immediately follow** the `invoke*`/`filled-new-array` that
produced the value — it reads an implicit result register. If you NOP an `invoke`
but leave its `move-result`, the `move-result` reads a stale/undefined result and
the verifier rejects the method (or you get garbage at runtime). When patching
around a call:

- NOP the `invoke` **and** its `move-result` together, **or**
- leave the call and instead overwrite the register afterwards with a constant.

Never split an `invoke` / `move-result` pair. If a patched Dex throws
`VerifyError` or won't load, this pairing (or a missed checksum/signature repair)
is the first thing to check — see the symptom row in `troubleshooting-index.md`.

## Workflow with the script

```bash
# 1. Find the (unique) target bytes
dex-byte-patch.py --find 0f0038000700 classes.dex     # -> MATCH_OFFSET=0x1a2f

# 2. Write a spec (equal-length only)
cat > patch.json <<'JSON'
[
  {"offset": "0x1a30", "from": "38", "to": "39"}        # if-eqz -> if-nez
]
JSON

# 3. Apply — header is repaired automatically
dex-byte-patch.py --patch patch.json classes.dex -o classes-patched.dex
#   -> PATCH_COUNT=1  BYTES_CHANGED=1  DEX_CHECKSUM_OK=true  PATCH_RESULT=success

# 4. Verify any dex's integrity
dex-byte-patch.py --verify classes-patched.dex          # -> DEX_CHECKSUM_OK=true
```

`from`/`search` bytes are checked against the file before writing, so a stale
offset fails loudly instead of corrupting the Dex. A non-equal-length `to` is
refused.

## After patching

- Repackage the patched `classes.dex` into the APK (replace the entry, then
  `zipalign` + `apksigner` — see `repack-and-sign.md`), or push it where the
  loader expects it.
- **Prove it landed and runs.** A patched Dex that passes `--verify` is only
  INFERRED to work until you install and observe the changed behavior
  (`verification.md`). Keep the byte diff and the launch result as evidence.
