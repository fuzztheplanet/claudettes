# Framework Runtimes

For authorized analysis only.

Not every Android app is Java/Kotlin. Cross-platform frameworks keep their real
logic outside the Dex, so jadx returns a thin shell (a launcher activity, a
plugin bridge, and little else). `detect-runtime.sh` tells you which runtime
you're facing; this reference is the toolchain for each. **Detecting the wrong
target early is the single biggest cause of "the app does nothing" mistakes —
match the artifacts before you conclude anything from empty decompiler output.**

## Routing summary

| Runtime | Tell-tale artifacts | Where the logic is | Toolchain |
|---|---|---|---|
| Flutter | `libflutter.so` + `libapp.so`, `kernel_blob.bin`, `*_snapshot_data` | Dart AOT snapshot in `libapp.so` | reFlutter / blutter (Dart SDK version-pinned) |
| React Native | `assets/index.android.bundle`, `libreactnativejni.so` | JS bundle (plain) | pull + beautify the JS bundle |
| RN + Hermes | `libhermes.so`, bundle magic `c61fbc03` | Hermes bytecode | hermes-dec / hbctool disassembly |
| Unity IL2CPP | `libil2cpp.so` + `global-metadata.dat` | Native code + metadata | Il2CppDumper → Ghidra/IDA |
| Unity Mono | `libmono*.so`, `Managed/*.dll` | Managed .NET DLLs | ILSpy / dnSpy |
| Xamarin/.NET | `libmonodroid.so`, `assemblies/*.dll` | Managed .NET DLLs | ILSpy / dnSpy → `skw-analyzing-dotnet-assemblies` |
| Cordova/Ionic/Capacitor | `assets/www/`, `cordova.js`, `capacitor.config.json` | HTML/JS in assets | read `assets/www` directly |
| Native Java/Kotlin | none of the above | Dalvik Dex | normal jadx flow |

## Flutter / Dart AOT

**Why jadx fails:** the Dex is a shim around the Flutter engine. All app logic is
compiled to a **Dart AOT snapshot** embedded in `libapp.so` — machine code plus a
Dart object pool, not Dalvik.

**Approach:**
- **reFlutter** — repackages the APK against a patched Flutter engine that dumps
  the offsets and can route traffic through a proxy. Good for dynamic work.
- **blutter** — static: parses `libapp.so`'s Dart snapshot and reconstructs class
  and function names, producing Frida hook stubs and an IDA/Ghidra script.
- **Dart AOT version pinning (critical):** the snapshot format is tied to an exact
  Dart/Flutter engine version. blutter must be built against the *matching* Dart
  SDK, or it mis-parses. Identify the engine version from the snapshot hash or the
  `flutter` version string in `libflutter.so`, then pin the tool to it.
- `dart_pool_strings` / snapshot string extraction recovers URLs and constants even
  when full reconstruction is hard.

**Network interception caveat:** Flutter uses its own Dart TLS stack and **ignores
the system proxy and user CA store**. A normal MITM (system CA + proxy) sees
nothing. Use reFlutter (bends the engine to the proxy), or Frida-hook the native
`ssl_verify`/BoringSSL functions in `libflutter.so`, or hook the Dart HTTP layer.

## React Native

**Why jadx fails:** the app is a `ReactActivity` host; logic is JavaScript in
`assets/index.android.bundle`.

**Plain JS bundle:** pull it and read/beautify it:
```bash
unzip -p app.apk assets/index.android.bundle > bundle.js
npx prettier --write bundle.js   # or js-beautify
```
It's minified but readable; search for endpoints, keys, and feature flags directly.

**Hermes bytecode:** if `libhermes.so` is present or the bundle starts with magic
`c61fbc03`, the bundle is compiled Hermes bytecode, not JS. Disassemble it:
- **hermes-dec** — disassembles/partially decompiles Hermes bytecode to readable
  pseudo-JS.
- **hbctool** — disassemble/reassemble; supports patching and repacking the bundle.
- Match the Hermes version to the app's RN version; bytecode format changes across
  Hermes releases.

## Unity — IL2CPP

**Why jadx fails:** with IL2CPP, C# is transpiled to C++ and compiled into
`libil2cpp.so`. Type/method metadata lives in `assets/bin/Data/Managed/Metadata/
global-metadata.dat`.

**Approach:**
- **Il2CppDumper** — takes `libil2cpp.so` + `global-metadata.dat` and produces a
  `dummy.dll` (types/signatures), C# stubs, and a **Ghidra/IDA script** that names
  the thousands of otherwise-anonymous functions in the `.so`.
- Load `libil2cpp.so` in Ghidra/IDA, run the generated script, then read the named
  functions.
- **Obfuscation:** `global-metadata.dat` is often encrypted/obfuscated (Beebyte,
  custom loaders) — the magic/version may be mangled. You then need to dump the
  metadata from memory at runtime (after the game decrypts it) or use a patched
  Il2CppDumper fork before it will parse.

## Unity — Mono

If `libmono*.so` and `Managed/*.dll` are present (no `libil2cpp.so`), the game
uses the Mono runtime and C# ships as **managed DLLs**. Decompile the `.dll`s with
ILSpy / dnSpy directly — this is much easier than IL2CPP.

## Xamarin / .NET MAUI

**Why jadx fails:** logic is in managed .NET assemblies under `assemblies/`.
- Extract `assemblies/*.dll`. Modern Xamarin **compresses** them (LZ4 / the
  `XALZ` header, or bundles them into `libassemblies.blob` / `libxamarin-app.so`);
  decompress first (e.g. `xamarin-decompress`) before decompiling.
- Decompile with **ILSpy** or **dnSpy**.
- Hand off to the **`skw-analyzing-dotnet-assemblies`** skill for deeper .NET work.

## Cordova / Ionic / Capacitor

The whole app is a WebView over HTML/JS in `assets/www/`. There's nothing to
decompile — **read the assets directly:**
```bash
unzip app.apk 'assets/www/*' -d www-extracted
```
Look in the JS for endpoints, API keys, and native-bridge plugin calls.
`config.xml` / `capacitor.config.json` list the plugins (i.e. the native surface).

## After routing

Whatever the runtime, still run the Dex-side phases on the shim: the manifest,
exported components (Fragment Injection still applies to the host activities), and
any Firebase/Google config in `res`/`assets` are all in the APK regardless of
runtime. Label reconstructed logic per `verification.md` — decompiled Hermes/IL2CPP
output is INFERRED until you confirm behavior at runtime.
