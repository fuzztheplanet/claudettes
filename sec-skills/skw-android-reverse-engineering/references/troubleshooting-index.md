# Symptom Index & Two-Strike Rule

This is a **stop signal**, not background reading. When a symptom below matches
what you are seeing, stop and load the referenced material (or run the named
step) **before** continuing. The whole point is to prevent reasoning past a
known failure mode by retrying variations of a broken approach.

## Two-strike rule

If the **same action fails twice with the same error**, the model of the problem
is wrong — do not try it a third time with tweaked parameters. Instead:

1. Re-read the actual error / crash evidence (don't work from memory of it).
2. Find the matching row in the symptom index below and load what it points to.
3. Change **approach**, not parameters — switch tool, switch layer (Java ↔ native
   ↔ server), or switch technique (decompile ↔ dump ↔ dynamic).

Two clean failures is enough signal. A third identical attempt is wasted budget.

## Symptom index

| Symptom | Likely cause | Stop and do this |
|---|---|---|
| jadx output empty, tiny, or only a launcher + one class | App is packed, or logic isn't in Dex (framework runtime) | Run `detect-runtime.sh` and `detect-packer.sh` (Phase 2.5); load `framework-runtimes.md` or `packers.md` |
| `libflutter.so` + `libapp.so`, or `kernel_blob.bin` present | Flutter — Dart AOT, not in Dex | `framework-runtimes.md` → Flutter/Dart AOT toolchain (`dart-aot`) |
| `libil2cpp.so` + `global-metadata.dat` | Unity IL2CPP — logic compiled to native | `framework-runtimes.md` → IL2CPP (Il2CppDumper + Ghidra) |
| `assets/index.android.bundle` / `libhermes.so` | React Native — JS bundle (plain or Hermes) | `framework-runtimes.md` → React Native / Hermes |
| `assemblies/*.dll` / `libmonodroid.so` | Xamarin/.NET — logic in managed DLLs | `framework-runtimes.md` → Xamarin (`skw-analyzing-dotnet-assemblies`) |
| Many `classesN.dex`, or a real dex appears only at runtime | Multidex, or a packer's runtime-decrypted dex | `packers.md` → memory-dump the real dex; then re-decompile |
| App exits immediately, **no crash** in logcat | RASP calling `finish()` / `System.exit()` / `Process.killProcess()` | Phase 7.2/7.3: read launcher `onCreate`; hook `System.exit` and log the stack |
| Native `SIGABRT` shortly after launch | Native anti-tamper (frida/ptrace/integrity) | `native-and-so.md` + `analyze-native.sh`; Phase 7.3 native hooks |
| `SIGSEGV`/`SIGABRT` **right after** a Frida hook attaches | Anti-instrumentation, or a fragile spawn-timing hook | Use `--pause` spawn gating; move the hook earlier; check native frida detection |
| `frida-ps -U` can't see the app / connection fails | frida-server not running, version mismatch, or port detection | Re-run `setup-frida.sh`; try a non-default port (`-l 0.0.0.0:1337`) |
| RegisterNatives hook crashes, or native methods have no `Java_` symbol | JNI bound dynamically via `RegisterNatives` | `native-and-so.md`: hook `art::JNI::RegisterNatives` to dump the mapping |
| Repack installs but won't launch; `INSTALL_PARSE_FAILED` | Bad signature, unaligned zip, or manifest broke during patch | `repack-and-sign.md`: `zipalign` before `apksigner`; verify with `apksigner verify` |
| `adb install` → `INSTALL_FAILED_UPDATE_INCOMPATIBLE` / signature mismatch | Original app still installed with a different signer | Uninstall the original first; keep one consistent debug keystore |
| App runs from Play Store build but your repack is rejected at runtime | Signature-pinned integrity (app checks its own cert) | `signature-derived-keys` / Phase 7 hook the signature check; or module-side delivery |
| SSL/network errors on **some** endpoints only | Per-domain cert pinning or Network Security Config | Phase 6 network-security-config; Phase 7 pin bypass scoped to that domain |
| Response bodies are binary / not JSON | Protobuf, gRPC, or a custom framing | `protocol-reverse.md` + `protobuf-decode.py` |
| "No endpoints found" but the app clearly does network I/O | Obfuscated client, dynamic URLs, or non-HTTP transport | Phase 7 runtime HTTP hook; `protocol-reverse.md`; check native networking |
| Class/method names are single letters | Name obfuscation (R8/ProGuard/DexGuard) | Phase 4: anchor on unobfuscated strings, library APIs, Retrofit annotations |
| A byte patch made the dex fail to load / `VerifyError` | Checksum/signature not fixed, or edit changed instruction length | `byte-level-patching.md`: equal-length only; recompute checksum+signature; verify move-result adjacency |

## When nothing matches

If the symptom isn't listed and two attempts have failed: capture the exact
evidence, drop to the lowest layer you can observe (logcat, `strace`/`ltrace` via
`adb`, native crash tombstone, packet capture), and state the blocker with a
claim-strength label (`verification.md`) rather than guessing forward. A clearly
reported blocker is a valid outcome; a confidently wrong bypass is not.
