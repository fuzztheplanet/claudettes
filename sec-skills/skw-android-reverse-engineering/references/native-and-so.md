# Native Libraries (.so) and JNI

The skill's jadx/Fernflower workflow ends at the JNI boundary. Modern Android
apps push their most sensitive logic — RASP, root/frida detection, string and
key decryption, license/signature checks, custom crypto — into native `.so`
libraries precisely because they are harder to decompile. When Phase 7 sees an
immediate `SIGABRT` from `libsomething.so`, or when the interesting method in
Java is just `public native int check();`, the answer is in native code.

Start with `scripts/analyze-native.sh` for triage, then go static (radare2 /
Ghidra) or dynamic (Frida). Everything a symbol name or string tells you is an
**INFERRED** lead until you trace or hook it (see `verification.md`).

```bash
bash <skill-directory>/scripts/analyze-native.sh <apk-or-dir> \
  --report native-report.md --json native.json
```

## The JNI boundary: static vs dynamic binding

A Java `native` method must be connected to a C/C++ function. There are two ways,
and they change how you find the code:

### Static binding (name mangling)
The native function is an **exported symbol** named after the Java method:
`Java_<pkg>_<Class>_<method>`, with `.` → `_` and some escaping (`_1` for a
literal `_`, etc.). These show up directly in the dynamic symbol table:

```bash
readelf -W --dyn-syms libnative.so | grep ' Java_'
nm -D libnative.so | grep ' T Java_'
rabin2 -s libnative.so | grep Java_
```

If you see `Java_com_example_Crypto_decrypt`, that exported function *is* the
implementation of `com.example.Crypto.decrypt()`. Load it in Ghidra and decompile.

### Dynamic binding (RegisterNatives)
The app calls `RegisterNatives(env, clazz, JNINativeMethod[], count)` — usually
from `JNI_OnLoad` — to wire Java methods to arbitrary (often un-exported,
sometimes stripped) native function pointers. **The Java↔native mapping is not in
the export table.** Tell-tale signs from `analyze-native.sh`:

- `JNI_ONLOAD=<lib>` present **and** `JNI_EXPORT` count is 0 → dynamic binding.
- `REGISTER_NATIVES=<lib>` emitted (inference from JNI_OnLoad presence).

You recover the mapping at runtime by hooking the registration itself (below).

## Static workflow

1. **Triage** with `analyze-native.sh` — ABIs, NEEDED deps, JNI exports,
   JNI_OnLoad, anti-tamper indicators, interesting strings. Pick the smallest
   ABI-appropriate library that shows the interesting symbols/strings
   (analyze `arm64-v8a` — real devices — unless you emulate another ABI).
2. **Symbols / imports / strings** with radare2:
   ```bash
   rabin2 -s libnative.so     # symbols (exports)
   rabin2 -i libnative.so     # imports (ptrace, dlopen, pthread_create …)
   rabin2 -z libnative.so     # strings in data sections
   rabin2 -I libnative.so     # header: arch, bits, stripped?, canary, pic
   ```
   `readelf -d` (NEEDED, SONAME), `readelf -h` (machine/ABI), `objdump -T`
   cover the same ground with binutils.
3. **Decompile** the interesting function in **Ghidra** (or IDA). For statically
   bound methods, jump straight to `Java_...`. For dynamically bound ones, get
   the function pointer from the runtime dump first (below), then decompile the
   address.
4. **Map Java → native.** For static binding the name is the map. For dynamic
   binding, the RegisterNatives dump gives `{signature → fnPtr}`; subtract the
   module base to get the file offset Ghidra uses.

## Dynamic workflow with Frida

### Dump the RegisterNatives table
Hook ART's registration to print every dynamically bound method and its native
address. Attach/spawn with `--pause` so the hook is in place before `JNI_OnLoad`
runs:

```javascript
// Hook the libart export that backs RegisterNatives.
var p = Module.findExportByName("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
if (p) {
  Interceptor.attach(p, {
    onEnter: function (args) {
      var methods = args[2];       // const JNINativeMethod*
      var count   = args[3].toInt32();
      for (var i = 0; i < count; i++) {
        var m    = methods.add(i * Process.pointerSize * 3);
        var name = m.readPointer().readCString();
        var sig  = m.add(Process.pointerSize).readPointer().readCString();
        var fnPtr= m.add(Process.pointerSize * 2).readPointer();
        var mod  = Process.findModuleByAddress(fnPtr);
        console.log("[RN] " + name + sig + " -> " + fnPtr +
                    (mod ? "  (" + mod.name + "+0x" + fnPtr.sub(mod.base).toString(16) + ")" : ""));
      }
    }
  });
}
```

The mangled symbol can vary across Android/ART versions — if the export isn't
found, resolve it from `rabin2 -s libart.so | grep RegisterNatives` on the
device's own libart, or hook the caller.

### Attach to a resolved native function
```javascript
var addr = Module.findExportByName("libnative.so", "Java_com_example_Crypto_decrypt");
// or use the fnPtr from the RegisterNatives dump for dynamically bound methods
Interceptor.attach(addr, {
  onEnter: function (args) { /* args[0]=JNIEnv, args[1]=this/clazz, args[2..]=params */ },
  onLeave: function (ret) { console.log("ret=" + ret); }
});
```

### Neutralize a native check
Return the safe value with `Interceptor.replace` + `NativeCallback`:
```javascript
Interceptor.replace(addr, new NativeCallback(function () {
  return 0;               // e.g. "not tampered" / "not rooted"
}, 'int', []));
```
**Return, do not spin or hang.** An infinite loop or a swallowed exit freezes the
app with no crash record and destroys your evidence trail (this mirrors the
Phase 7 rule and the `native-tamper` guidance).

## Common native anti-tamper mechanisms → where they show up → hook point

| Mechanism | Static indicator | Runtime symptom | Neutralize |
|---|---|---|---|
| `ptrace(PTRACE_TRACEME)` anti-debug | `ptrace` import | Debugger/Frida attach fails; SIGTRAP | Hook `ptrace`, return 0 |
| TracerPid check | string `/proc/self/status`, `TracerPid` | Exits when traced | Hook `fopen`/`read` of that path, or the comparison |
| Frida scan (ports/threads/maps) | strings `frida`, `gum-js-loop`, `/proc/self/maps`, `27042` | SIGABRT / exit shortly after inject | Rename frida-server, non-default port; hook the scan fn |
| APK signature check in native | strings `GetApkSignature`, `getPackageInfo`, `checkSignature` | Repacked/resigned build dies | Hook the check to return the original hash (see `repack-and-sign.md`) |
| Self-CRC of the .so / dex | string `CRC32`, custom checksum consts | Dies after any byte patch | Prefer equal-length dex byte patch, or hook the verify fn |
| Emulator/root detection | strings `/system/bin/su`, `magisk`, `goldfish`, `ro.kernel.qemu` | Refuses to run on emulator/root | Hook the detector; spoof properties |

`analyze-native.sh` emits `NATIVE_ANTITAMPER=<lib>:<indicator>` for these — treat
each as a lead to the function that owns the string/import.

## Native crypto

Look for `AES`, `RSA`, `EVP_`, `CCCrypt`, `mbedtls_`, `BEGIN … PRIVATE KEY`, or a
custom cipher. Keys are frequently derived or decrypted at runtime, so the
fastest path is to hook the crypto entry point (or the JNI method that calls it)
and read the key/IV/plaintext from arguments — a runtime capture is OBSERVED
evidence, whereas a hardcoded-looking constant in `.rodata` is only INFERRED to
be the live key until you confirm it is used.

## Handoff

This reference covers native triage *in the Android context* — finding the code,
mapping JNI, and neutralizing checks enough to continue app analysis. For deep
native reverse engineering (full decompilation, VM/obfuscator lifting, exploiting
memory-corruption in the native layer), hand off to the **skw-analyzing-binaries**
and **skw-exploiting-memory-corruption** skills with the specific library and the
function address you isolated here.

## Related

- `troubleshooting-index.md` — rows for `SIGABRT native`, `RegisterNatives hook
  crashes`, `native methods have no Java_ symbol`.
- `verification.md` — symbol-name and string matches are INFERRED until traced or
  hooked; a recovered key is OBSERVED only when captured in use.
- Phase 7 (Frida) for the spawn-gating and iteration loop this plugs into.
