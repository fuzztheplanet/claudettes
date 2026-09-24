---
name: skw-analyzing-binaries
description: Reverse engineer compiled binaries, firmware, and mobile app packages using triage, static disassembly, decompilation, and dynamic instrumentation. Use when analyzing an executable, ELF/PE/Mach-O file, firmware image, or stripped binary, recovering an algorithm or protocol, or working a CTF reversing challenge.
---

# Analyzing Binaries

Reverse engineering is hypothesis testing against a program you cannot read.
The cost of the job is dominated by how much code you look at, so the whole
discipline is about narrowing: triage first, find the interesting few percent,
then read that carefully.

## When to Use

- Understanding what an unknown or undocumented executable does
- Recovering an algorithm, file format, or wire protocol from a binary
- Locating a vulnerability in a closed-source target
- Firmware analysis for embedded and IoT devices
- Reversing challenges in CTFs

## When NOT to Use

- **Live malware with intent to detonate** — use `analyzing-malware`, which
  covers containment and safe detonation. Come back here for the disassembly.
- **A raw shellcode blob with no headers** (position-independent payload,
  stager, egg-hunter) — use `analyzing-shellcode`
- **Source is available** — use `skw-auditing-code-for-vulnerabilities`
- **Android/iOS app assessment as a whole** — use `skw-testing-mobile-applications`;
  use this skill for the native `.so`/Mach-O components inside it
- **A framework runtime rather than a plain binary** — the toolchain is
  specific and generic RE will not get there: `reversing-flutter-apps` for
  `libapp.so`/Dart snapshots, `reversing-unity-il2cpp` for `libil2cpp.so` plus
  `global-metadata.dat`, `reversing-react-native-apps` for Hermes bytecode
- **A language runtime with its own symbol recovery** — `analyzing-go-binaries`
  (`pclntab` survives stripping), `analyzing-rust-binaries` (panic strings leak
  source paths), `skw-analyzing-dotnet-assemblies` (IL decompiles to C#). Reaching
  for generic RE on these wastes most of the effort
- **A packed or protected executable** — use `skw-unpacking-protected-binaries`
  first; there is nothing to disassemble until it is dumped
- **A whole firmware image to extract before any RE** — use
  `skw-analyzing-firmware-images` for `binwalk`, filesystem carving, and
  cross-architecture emulation; return here for an individual binary inside it

## The Standard of Evidence

_Adapted from REx@Skill (github.com/tihanyin/REx-skill)._

A finding is a **source**, a **sink**, a **missing or broken guard**, and an
**affected principal** — all named, all located. Less than that is a hypothesis.

- **Source** — where attacker-controlled data enters (argv, env, a file, a
  socket, stdin, IPC, or a parsed field inside any of those).
- **Sink** — the operation that goes wrong: an index, pointer arithmetic, a size
  computation, a division, a `free`, a dereference, an `exec`, a format argument,
  a copy.
- **Guard** — the check that should make the sink safe, and *why it does not*:
  absent, on the wrong variable, off-by-one, wrong signedness, applied after the
  first use, present on only one path, or derived from the same input it bounds.
- **Principal** — who is harmed and what they lose. No affected principal is a
  code-quality issue, not a vulnerability.

Grade every non-trivial claim — a false positive costs more than a miss, because
a report that cries wolf is discarded wholesale:

| Rung | You have | Report it? |
| --- | --- | --- |
| `speculative` | a suggestive shape; the guard is unexamined | No — an open question, not a finding |
| `likely` | source, sink, guard and principal all located, the guard shown inadequate | Yes, labelled `likely` |
| `confirmed` | the above **plus an independent observation** — a crash, a sanitizer report, a solver input that behaves as predicted, an emulation fault, an oracle mismatch | Yes, labelled `confirmed` |

**Proof here does not require an exploit or a crash** — the classes missed most
(OOB reads, integer overflows, wrong sizes) do not crash, so a report of
only-crashing bugs lists the easy ones. And a **clean verdict is a named guard,
not a number**: to call a risky operation safe, name the comparison that makes it
so — which variable, against what, signed or unsigned, on every path. If you
cannot, the answer is `unresolved`. Record what you **ruled out**, with the
reason, so "nothing found" is informative rather than silent.

## Triage First — Never Open a Disassembler Cold

Every minute here saves an hour in the decompiler.

```bash
file target && du -h target
# Architecture, endianness, PIE, stripped or not — all decide your tooling
readelf -hSd target        # ELF: headers, sections, dynamic deps
rabin2 -I target           # radare2's normalized summary of any format
objdump -p target          # PE/ELF imports and load config

# Protections tell you what the author expected
checksec --file=target     # NX, canary, RELRO, PIE, Fortify

# Strings, but read them for structure rather than skimming
strings -n 8 -t x target | less        # ASCII with offsets
strings -e l -n 8 target               # UTF-16LE, essential on Windows
```

```bash
# Capability triage before you read any code
capa target        # maps the binary to ATT&CK/MBC behaviours (crypto, C2, injection)
floss target       # recovers stack- and XOR-obfuscated strings plain `strings` misses
```

**What triage should answer before you disassemble:**

| Question | Signal |
| --- | --- |
| What language/toolchain built this? | Rust/Go runtime strings, `libstdc++`, `__gxx_personality`, MSVC RTTI |
| Is it packed? | High entropy, tiny import table, sections named `UPX`, `.themida` |
| What does it talk to? | Imports of socket/HTTP APIs, embedded URLs, cert blobs |
| Where is the interesting logic? | Imports of crypto/file/registry/process APIs |
| Is it stripped? | `nm -D` empty, no `.symtab` |

```bash
# Entropy scan finds packed or embedded-blob regions
binwalk -E target
# Unpack the common case
upx -d target -o target.unpacked
```

Go and Rust binaries are usually not stripped in the ways that matter. Recover
symbols before doing anything else — it changes the job from hours to minutes.

```bash
# Go: recover function names and types
GoReSym -t -p target > syms.json    # or the redress / IDAGolangHelper plugins
# Rust: demangle
nm -C target 2>/dev/null | head
```

## Static Analysis Workflow

Pick one tool and go deep; switching tools mid-analysis loses your annotations.

```bash
# Ghidra headless: batch import, auto-analyze, run a script
analyzeHeadless /proj MyProj -import target -postScript Decompile.java

# radare2 / rizin interactive
r2 -AA target
# aaa            analyze everything
# afl            list functions, sorted by size — big ones first
# axt @ sym.f    cross-references TO a function (who calls this?)
# pdg @ main     decompile with ghidra plugin (r2ghidra)
# iz / izz       strings in data / whole binary
# /x deadbeef    search for a byte pattern

# Binary Ninja / IDA headless equivalents exist; the workflow is identical
```

**Navigate by evidence, not by address order.** The three entry points that
find the interesting code fastest:

1. **Strings → xrefs.** Find a message you saw at runtime, cross-reference it,
   land in the function that produced it.
2. **Imports → xrefs.** Cross-reference `recv`, `CreateProcess`, `fopen`,
   `EVP_EncryptInit` to find the code that does the thing you care about.
3. **Entropy/constants.** Crypto constants (AES S-box, SHA-2 round constants,
   MD5 magic) are recognizable; `binwalk`, `findcrypt`, and YARA rules locate them.

Then read outward from that anchor. Rename every function and variable as you
work out what it does — a decompiler listing you have annotated is a completely
different artifact from a raw one.

## Recognizing Structure in Decompiler Output

The decompiler gives you C-shaped noise. What you are looking for:

- **Loop with an index into a byte array and an XOR** — obfuscation or a
  homebrew cipher. Extract the key, decode offline.
- **A switch on a small integer read from input** — command dispatch. This is
  usually the protocol, and it is the map for everything else.
- **`memcpy` with a length that came from the input** — start of a memory
  safety review; see `skw-auditing-code-for-vulnerabilities`.
- **Repeated `[rax + 8*n]` accesses on the same base** — a struct. Define it in
  the tool; the listing collapses to readable code.
- **A call through a register right after a table load** — vtable or callback
  dispatch. Recover the table to recover the class.

### Read the disassembly, not just the C

The decompiler is a lossy summary; treating its output as source is the most
common source of a wrong finding. Drop to the `.S` in three situations:

- **A `!! LOSSY` marker, or a `printf`/`memcpy` that seems to do too little.** The
  decompiler drops variadic arguments *and the computation behind them* — endemic
  on Mach-O AArch64, where stack-passed varargs get dead-code-eliminated. A
  function whose C is "two prints and a store" can hold the hash, the modulo, and
  the `cbz` guarding a divide in its disassembly. Never conclude "does almost
  nothing" from a short decompilation.
- **Signedness — always.** Whether a bound is a signed or unsigned compare *is*
  frequently the whole bug, and C blurs it. Read the branch: x86 `jl`/`jg`
  (signed) vs `jb`/`ja` (unsigned); AArch64 `b.lt`/`b.gt` vs `b.lo`/`b.hi`; MIPS
  `slt` vs `sltu`. `i <= 3` against a 4-entry table is safe unsigned and
  catastrophic signed — a negative index passes it and lands before the object.
- **When two tools disagree, the bytes win.** Cross-check the decompiler against
  the disassembly, and one decompiler against another (Ghidra vs r2ghidra). A
  `printf` with a missing argument that looks like CWE-134 is almost always
  register reuse (`-fipa-ra`) or the vararg loss above — claim a format-string bug
  only when the format *pointer itself* is attacker-derived.

The class you will miss is not the subtle one: it is an arithmetic relationship
carried **across functions** — a size computed here, bounded there, indexed
somewhere else, where no single line looks wrong. For every buffer, write its
**declared size** next to **every bound** compared against it and check they are
the same number; treat a width or signed/unsigned cast as a sink in its own right.

## Dynamic Analysis

Static tells you what the code can do; dynamic tells you what it does. Run
untrusted binaries only in an isolated VM with no host shares and networking
under your control — see `analyzing-malware` for the containment procedure.

```bash
# Syscall and API-level behaviour
strace -f -e trace=network,file,process -o trace.log ./target
ltrace -f ./target
# Windows equivalents: API Monitor, Procmon, drltrace

# Debugging
gdb -q ./target       # with pwndbg/GEF: `checksec`, `vmmap`, `heap`, `telescope`
lldb ./target         # macOS
x64dbg / WinDbg       # Windows

# Instrumentation — the highest-leverage dynamic technique
frida-trace -f ./target -i 'recv*' -i 'EVP_*'
# then edit the generated JS handlers to dump buffers and patch return values
```

Frida is the fastest route through anti-debugging, custom crypto, and license
checks: hook the function *after* decryption rather than defeating the
obfuscation that protects it.

**Prove a bound, do not argue it.** When you are about to write *bounded*,
*clamped*, *cannot overflow* or *at most N*, stop — each is a decidable question,
and a bound argued in the head is `speculative` however confidently it reads.

```bash
# Emulate ONE function instead of reaching it through the whole program — far
# cheaper, and it turns an argument into an observation. Sweep the length/index/
# count that worries you across 0, 1, the declared bound, the bound ±1, and the
# type max. An unmapped fault is evidence; a clean return in a bare harness is not.
#   Unicorn: map memory, set registers, run the function, read the result
qemu-arm -L /usr/arm-linux-gnueabi ./target      # user-mode, cross-architecture

# Discharge an arithmetic bound with a solver instead of asserting it. z3: can
# 'i <= 3' (signed!) reach a negative index; can off+len wrap past the buffer; can
# n*elem overflow and still pass the check? UNSAT is "safe", with proof behind it.
python3 -c 'import z3; ...'    # model the bitvectors, the guards, and the claim

# angr: find the input that reaches a state ("what reaches this sink at all").
# When a fuzzer plateaus behind a magic/length/checksum, concolic the stuck seeds
# (angr/Driller) and feed the solved inputs back into the corpus. Triton: taint the
# input over one concrete run — an untainted length is a ruled-out with evidence.
```

**Make a silent heap bug loud.** You cannot retrofit AddressSanitizer into a
compiled binary, but you do not need it to make an out-of-bounds access fault: run
the sample under a page-per-allocation allocator (`LD_PRELOAD=libdislocator.so`,
ships with AFL++), under `MALLOC_PERTURB_=165 MALLOC_CHECK_=3`, or under Valgrind
memcheck (`valgrind --track-origins=yes`) — the closest thing to "ASan for a
binary you cannot rebuild". For a foreign architecture, `AFL_USE_QASAN=1` gives
heap checking under `qemu-user`. This is the one place a tool beats another hour
of reading, and it costs one environment variable.

## Firmware

```bash
binwalk -Me firmware.bin        # extract recursively
# Identify the filesystem before extracting: squashfs, jffs2, cramfs, ubifs
unsquashfs -d rootfs squashfs-root.bin

# Then treat the rootfs as a Linux system
rg -n 'password|admin|BEGIN (RSA|OPENSSH) PRIVATE KEY|api[_-]?key' -i rootfs/
find rootfs -name '*.pem' -o -name 'shadow' -o -name '*.conf'
# Web interface and startup scripts are where the bugs are
ls rootfs/etc/init.d rootfs/www rootfs/usr/sbin
```

For a bootloader or bare-metal image with no filesystem, find the load address
(often in the vendor SDK or derivable from absolute-pointer clustering) before
disassembling — a wrong base address makes the whole listing meaningless.

## Anti-Analysis

Recognize it, then decide whether to defeat it or route around it.

| Technique | Recognition | Response |
| --- | --- | --- |
| Packing | High entropy, stub + one big section | Unpack, or dump from memory after the OEP |
| Anti-debug | `IsDebuggerPresent`, `ptrace(PTRACE_TRACEME)`, timing checks | Patch the check, or hook it with Frida |
| VM detection | CPUID checks, MAC OUI, registry artifacts | Harden the VM, or patch the detector |
| String obfuscation | No readable strings but obvious decode loops | Emulate the decoder over all call sites |
| Control-flow flattening | Giant switch on a state variable | Symbolic deobfuscation, or ignore and work dynamically |

Routing around is usually cheaper. If a check is defeating you statically,
hook the function that consumes its result.

## Rationalizations to Reject

- *"I'll read the whole binary."* You will not. Triage and anchor, or you burn
  the engagement on library code.
- *"The decompiler output is wrong, so this is a dead end."* Decompiler output
  is frequently wrong around calling conventions and structs. Check the
  disassembly for the specific instruction before drawing a conclusion.
- *"It's stripped, so symbols are gone."* Library functions are recoverable
  (FLIRT/Sigs, `bindiff` against a compiled reference), and Go/Rust metadata
  usually survives.
- *"I'll just run it to see what it does."* Not before you know whether it is
  hostile and where it is contained.
- *"The strings tell the story."* Strings tell you where to look. Attackers
  plant misleading ones.

## Deliverable

An RE report should let a reader act without repeating your work:

- **Identity** — hashes, file type, architecture, compiler, packer
- **Capability** — what it does, expressed as behaviour, not addresses
- **Key routines** — annotated addresses with a name and a one-line purpose
- **Protocol/format** — field-by-field, with a parser or Kaitai spec if useful
- **Indicators** — network endpoints, file paths, mutexes, keys, constants
- **Open questions** — what you did not resolve, and why

<!-- attack:start -->

## ATT&CK Coverage

_Generated from `secskills-core/ttp-index.json` — edit that file, then run
`python3 scripts/sync_attack.py --write`. Re-verify IDs against the
current ATT&CK release before citing them in a report._

**Defense Evasion** (TA0005)

- [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information — see also `analyzing-malware`, `analyzing-shellcode`
- [T1027.002](https://attack.mitre.org/techniques/T1027/002/) Software Packing — see also `analyzing-malware`
- [T1140](https://attack.mitre.org/techniques/T1140/) Deobfuscate/Decode Files or Information — see also `analyzing-malware`, `analyzing-shellcode`
- [T1497](https://attack.mitre.org/techniques/T1497/) Virtualization/Sandbox Evasion — see also `analyzing-malware`
- [T1622](https://attack.mitre.org/techniques/T1622/) Debugger Evasion — see also `analyzing-malware`

Detection content for any of these: `engineering-detections`. Proactive search: `hunting-threats`. Post-compromise: `responding-to-incidents`.

<!-- attack:end -->

## References

- `analyzing-malware` — containment, detonation, and IOC extraction
- `skw-testing-mobile-applications` — APK/IPA workflows around native components
- Ghidra, rizin/radare2, Binary Ninja, IDA — pick one and learn it deeply
- Frida, angr, Unicorn, QEMU for dynamic and emulated analysis
- z3, Triton, Valgrind, libdislocator (AFL++), capa, floss — solver-discharged
  bounds, taint, and making silent bugs loud on binaries you cannot rebuild
- REx@Skill (github.com/tihanyin/REx-skill) — the evidence-graded RE pipeline
  these techniques are adapted from
