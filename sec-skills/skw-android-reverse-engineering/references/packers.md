# Packers & Protectors

For authorized analysis only (apps you own, signed engagements, CTF).

A **packer** ships the app's real Dex encrypted and only decrypts it in memory
at launch, behind a stub `Application` class that installs a custom
`ClassLoader`. On the shipped APK, jadx sees the stub and little else. The whole
game is: **let the app decrypt itself, then capture the real Dex from memory.**

`detect-packer.sh` fingerprints the packer from native libs, asset blobs, and
the stub application class. Match the family below to pick a recovery approach.

## Family reference

| Family | Identifying artifacts | Protection model | Recovery |
|---|---|---|---|
| **Bangcle / SecShell** | `libsecexe.so`, `libsecmain.so`, `libSecShell*.so`, `libNSaferOnly.so`; `com.secneo.apkwrapper.*` app class | Whole-Dex encryption, native ClassLoader | Runtime memory dump (self-decrypts early) |
| **Qihoo 360 Jiagu** | `libjiagu*.so`, `assets/libjiagu*`; `com.qihoo.util.*` | Dex encryption + native string/API hiding | Memory dump; some builds add VMP on hot methods |
| **Tencent Legu** | `libshell*.so`, `libshella-*.so`, `libtup.so`, `libtxsq*.so`; `com.tencent.StubShell.*` | Dex encryption, anti-debug, sometimes native code virtualization | Memory dump; watch for VMP stubs on protected methods |
| **Alibaba / AliProtect** | `libmobisec.so`, `libsgmain*.so`, `libsgsecuritybody*.so` | Dex encryption + secure-guard SDK | Memory dump |
| **Baidu** | `libbaiduprotect*.so`, `assets/baiduprotect*` | Dex encryption, method-level protection | Memory dump; per-method decrypt may need on-invoke dumping |
| **NetEase** | `libnesec*.so` | Dex encryption | Memory dump |
| **DexProtector** | `libdexprotector*.so`; assets with `.dp` / `.ml` suffixes | Class encryption, string encryption, optional native code hiding, VMP | Memory dump for classes; VMP methods may not dump cleanly |
| **APKProtect** | `libAPKProtect.so` | Dex encryption | Memory dump |
| **Naga / Virbox** | `libvdog*.so`, `libv3*.so` | Strong VMP + native shell | Often resists dumping — expect virtualized stubs; may need dynamic tracing (see `native-and-so.md`) |
| **Kiwi / SecNeo** | `libDexHelper.so`, `libNSaferOnly.so`, `libddog*.so`, `libchaosvmp*.so` | Dex encryption + ChaosVMP code virtualization | Memory dump for non-virtualized code; VMP methods need trace-based recovery |
| **unknown-packer** (heuristic hit) | Stub app class, dex-magic blob under a fake extension, or many `classesN.dex` | Unknown | Confirm by dumping; then identify from the loader `.so` |

## General unpacking loop

1. **Confirm it's really packed.** `detect-packer.sh <apk>`. A high-confidence
   `.so` hit is strong; a heuristic-only hit (stub app / hidden-dex asset) is a
   lead — verify by dumping. Per `verification.md`, "packed" is INFERRED until a
   dump decompiles to real logic.

2. **Run the app on a rooted device/emulator** so it decrypts itself. Pair this
   with Phase 7 — many packers also carry RASP that kills the app on a rooted or
   instrumented device; you may need to bypass anti-debug/anti-root **first** to
   even reach the decrypt.

3. **Dump the real Dex from memory** once the app is live. Options, easiest first:
   - **FRIDA-DEXDump** — scans the process address space for `dex\n` magic and
     dumps every Dex image it finds. Best default; no per-packer knowledge.
   - **FDex2 / Dexdump-via-Xposed** — hooks `ClassLoader.loadClass` /
     `DexFile.openDexFile` / `defineClass` and writes each Dex the loader touches.
     Good when the packer decrypts lazily and DEXDump misses images.
   - **Manual `/proc/<pid>/maps` scan** — locate anonymous RW regions, `dd` them
     out, carve on `dex\n`. Fallback when tooling is blocked.
   - **On-invoke dumping** — for method-level packers (Baidu, some Legu),
     methods decrypt only when first called. Drive the app through the target
     feature while dumping, or hook the method-decrypt trampoline.

4. **Repair the dumped Dex.** Carved images often have a zeroed/short header or
   stale checksum. Fix it so decompilers accept the file:
   ```bash
   python3 <skill-directory>/scripts/dex-byte-patch.py --verify dumped.dex
   ```
   If `DEX_CHECKSUM_OK=false` / `DEX_SIGNATURE_OK=false`, the same script
   recomputes the Adler-32 checksum and SHA-1 signature; some carved images also
   need `header_size`/`file_size` fields corrected before they load.

5. **Re-run detection and decompile the dump.**
   ```bash
   bash <skill-directory>/scripts/detect-packer.sh dumped.dex   # expect: none
   bash <skill-directory>/scripts/decompile.sh dumped.dex
   ```
   If jadx now shows the app's real classes, the unpack worked (OBSERVED). If it
   still shows stubs, you've hit a virtualization boundary — go to the next step.

## VMP / code-virtualization boundaries

DexProtector, ChaosVMP (SecNeo), Naga/Virbox and hardened Legu/Jiagu builds
**virtualize** protected methods: the method body is replaced with a call into a
custom interpreter that executes a private bytecode. Dumping the Dex then yields
a real class list but the hot methods are empty stubs or opaque dispatch loops.
Signs you're here:

- The dump decompiles, but the security-critical method is `return`/a dispatch
  loop calling into a `libX.so` VM.
- `native-and-so.md` shows a large interpreter-shaped native function with a big
  opcode `switch`.

At this boundary, static dumping is exhausted. Recover behavior by **observing
it**, not reading it: Frida-Stalker trace the method, hook its inputs/outputs, or
emulate the VM (see `native-and-so.md` and dynamic-analysis references). Some
methods are also **native-sunk** (Java logic rewritten to C in a `.so`) — treat
those as native analysis targets.

## Anti-analysis note

Packers bundle anti-debug/anti-root/anti-frida. If the app dies on your rooted
device, that's the packer's RASP, not a dump failure — read the crash, bypass
the check (Phase 7 adaptive loop), *then* dump. Two failed dump attempts with
the same crash = two-strike rule: the blocker is the RASP, fix that first.
