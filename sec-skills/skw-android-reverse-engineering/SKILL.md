---
name: skw-android-reverse-engineering
description: Decompile Android APK, XAPK, AAB, DEX, JAR, and AAR files using jadx or Fernflower/Vineflower. Reverse engineer Android apps, extract HTTP API endpoints (Retrofit, OkHttp, Volley, GraphQL, WebSocket), trace call flows from UI to network layer, analyze security patterns (cert pinning, exposed secrets, Android Fragment Injection via exported PreferenceActivity), perform dynamic analysis with Frida (adaptive bypass generation, crash analysis, runtime hooking), and — only when the decompiled app contains Google API keys or Firebase configuration — run a conditional Firebase & Google API testing phase (Auth, Realtime DB, Firestore, Remote Config, Storage, Dynamic Links, FCM, Gemini, Maps). Use when the user wants to decompile, analyze, or reverse engineer Android packages, find API endpoints, follow call flows, audit app security, bypass runtime protections, test exposed Google/Firebase credentials, check for Fragment Injection exposure, identify packers and app runtimes (Flutter, React Native, Unity/IL2CPP, Xamarin, Cordova), analyze native .so/JNI libraries, decode protobuf/gRPC traffic, merge split APKs, or patch, repack, and re-sign an APK on authorized targets.
---

# Android Reverse Engineering

Decompile Android APK, XAPK, AAB, DEX, JAR, and AAR files using jadx and Fernflower/Vineflower, trace call flows through application code and libraries, analyze security patterns, produce structured documentation of extracted APIs, and perform adaptive dynamic analysis with Frida — generating custom bypass scripts based on what the static analysis finds, iterating through crash logs to refine hooks until protections are bypassed. Two decompiler engines are supported — jadx for broad Android coverage and Fernflower for higher-quality output on complex Java code — and can be used together for comparison.

## Operating rules

Read these before starting. They override default reasoning until evidence proves otherwise.

**Evidence and claim strength.** Every statement this skill emits carries a claim-strength label — OBSERVED, MEASURED, INFERRED, or UNVERIFIED. A grep or tool hit is a *lead*, not a finding, until you read the code or observe the behavior. Never state a claim stronger than its evidence; "vulnerable" and "bypassed" require OBSERVED or MEASURED proof. See `<skill-directory>/references/verification.md` for the ladder and the rules.

**Decision gates.** Phases are gated. Before moving on, confirm the phase's pass criterion actually holds — e.g. decompilation produced real Java (not an empty tree from a packed app or a non-Java runtime), the app actually runs before you credit a bypass, a patch actually landed. A failed gate routes you to the triage gate (Phase 2.5) or a reference, not forward.

**Symptom index — stop signals.** When you hit a failure mode (empty decompile, immediate exit, `SIGABRT`, frida can't connect, repack won't install, binary response bodies, …), match it in `<skill-directory>/references/troubleshooting-index.md` and load what it points to *before* continuing.

**Two-strike rule.** If the same action fails twice with the same error, the approach is wrong — do not retry a third time with tweaked parameters. Re-read the evidence, consult the symptom index, and change tool or layer (Java ↔ native ↔ server; static ↔ dump ↔ dynamic).

**Definition of done.** "Scripts ran cleanly" is not done. A task is complete only when every hit is confirmed by reading code, every endpoint traced to an entry point, every bypass reproduced from a clean start, every finding labeled with its strength, every modification proven landed and the app verified to still run, output desensitized, and negatives stated. The full checklist is in `<skill-directory>/references/verification.md`.

**Authorized use only.** This skill operates on apps you own, targets you are contracted or permitted to test, public CTF material, or controlled sandboxes. Confirm scope before any modification (patch/repack), device action, or credential probe.

## Project-local path portability

Before running a command, resolve `<skill-directory>` to the absolute directory containing this
`SKILL.md`. Never pass the literal placeholder to the shell.

## Operating rules

These govern every phase. They exist to stop confident, unverified conclusions —
the main failure mode of automated reverse engineering.

- **Evidence & claim strength.** Label every finding with a strength —
  `OBSERVED`, `MEASURED`, `INFERRED`, or `UNVERIFIED` — and never state one
  higher than the evidence supports. A grep/tool hit is a *lead*, not a finding,
  until you read the code behind it. "Vulnerable" and "bypassed" require
  `OBSERVED`/`MEASURED` proof. See `<skill-directory>/references/verification.md`
  for the full ladder. (In a bug-bounty context, theoretical "could allow…"
  impact is `UNVERIFIED` and must not be written as a finding.)

- **Decision gates.** Several phases below are **gates**: they have an explicit
  pass criterion, and a fail routes you elsewhere before you waste effort. Do not
  push past a gate on assumption — e.g. do not analyze "empty" jadx output as if
  the app had no logic before the Phase 2.5 triage gate has ruled out packing and
  non-Java runtimes.

- **Symptom index / two-strike rule.** When something fails or looks wrong, check
  `<skill-directory>/references/troubleshooting-index.md` — a matching symptom row
  is a stop signal to load the referenced material. If the **same action fails
  twice with the same error, stop**: the hypothesis is wrong. Change approach
  (tool, layer, or technique), not parameters. A third identical retry is wasted.

- **Definition of done.** "Scripts ran cleanly" is not done. A task is done only
  when every hit is confirmed, every endpoint is traced, every bypass is
  reproduced from a clean start, every finding is labeled with its strength and
  evidence, every modification is proven landed **and** launch-verified, output is
  desensitized, and checked-and-clean negatives are stated — not just positives.
  The full checklist is in `<skill-directory>/references/verification.md`.

## Prerequisites

This skill requires **Java JDK 17+** and **jadx** to be installed. **Fernflower/Vineflower** and **dex2jar** are optional but recommended for better decompilation quality. **bundletool** is required for AAB (App Bundle) files. For dynamic analysis (Phase 7), **Python 3.8+**, **adb**, and a device/emulator with **frida-server** are needed — the `setup-frida.sh` script handles the full setup. Run the dependency checker to verify:

```bash
bash <skill-directory>/scripts/check-deps.sh
```

If anything is missing, follow the installation instructions in `<skill-directory>/references/setup-guide.md`.

## Workflow

### Phase 1: Verify and Install Dependencies

Before decompiling, confirm that the required tools are available — and install any that are missing.

**Action**: Run the dependency check script.

```bash
bash <skill-directory>/scripts/check-deps.sh
```

The output contains machine-readable lines:
- `INSTALL_REQUIRED:<dep>` — must be installed before proceeding
- `INSTALL_OPTIONAL:<dep>` — recommended but not blocking

**If required dependencies are missing** (exit code 1), install them automatically:

```bash
bash <skill-directory>/scripts/install-dep.sh <dep>
```

The install script detects the OS and package manager, then:
- Installs without sudo when possible (downloads to `~/.local/share/`, symlinks in `~/.local/bin/`)
- Uses sudo and the system package manager when necessary (apt, dnf, pacman)
- If sudo is needed but unavailable or the user declines, it prints the exact manual command and exits with code 2 — show these instructions to the user

**For optional dependencies**, ask the user if they want to install them. Vineflower and dex2jar are recommended for best results.

After installation, re-run `check-deps.sh` to confirm everything is in place. Do not proceed to Phase 2 until all required dependencies are OK.

### Phase 2: Decompile

**Split-APK sets first.** If the target is an installed app or a split set
(`base.apk` + `split_config.*.apk` / feature splits), or an `.apks`/`.apkm`
archive, merge it into one APK before decompiling — decompiling only `base.apk`
misses code that lives in feature splits.

```bash
# From a directory of splits, an .apks/.xapk archive, or a connected device
bash <skill-directory>/scripts/merge-splits.sh <dir|archive>
bash <skill-directory>/scripts/merge-splits.sh --device -p <package>
```

Read `MERGE_RESULT`: `success` (decompile `MERGED_APK`), `not-needed` (only
config splits — `base.apk` alone is fine for code analysis), or `failed`. `.xapk`
bundles are also handled directly by `decompile.sh`.

Use the decompile wrapper script to process the target file. The script supports three engines: `jadx`, `fernflower`, and `both`.

**Action**: Choose the engine and run the decompile script. The script handles APK, XAPK, AAB, DEX, JAR, and AAR files.

```bash
bash <skill-directory>/scripts/decompile.sh [OPTIONS] <file>
```

For **XAPK** files (ZIP bundles containing multiple APKs, used by APKPure and similar stores): the script automatically extracts the archive, identifies all APK files inside (base + split APKs), and decompiles each one into a separate subdirectory. The XAPK manifest is copied to the output for reference.

For **AAB** files (Android App Bundles): the script uses bundletool to generate a universal APK from the bundle, then decompiles it. bundletool must be installed (run `install-dep.sh bundletool`).

For **DEX** files: jadx handles them natively. For Fernflower, dex2jar is used as an intermediate step (same as APK files).

Options:
- `-o <dir>` — Custom output directory (default: `<filename>-decompiled`)
- `--deobf` — Enable deobfuscation (recommended for obfuscated apps)
- `--no-res` — Skip resources, decompile code only (faster)
- `--engine ENGINE` — `jadx` (default), `fernflower`, or `both`

**Engine selection strategy**:

| Situation | Engine |
|---|---|
| First pass on any APK/AAB | `jadx` (fastest, handles resources) |
| JAR/AAR library analysis | `fernflower` (better Java output) |
| jadx output has warnings/broken code | `both` (compare and pick best per class) |
| Complex lambdas, generics, streams | `fernflower` |
| Quick overview of a large APK | `jadx --no-res` |
| DEX file analysis | `jadx` (native support) or `fernflower` (via dex2jar) |

When using `--engine both`, the outputs go into `<output>/jadx/` and `<output>/fernflower/` respectively, with a comparison summary at the end showing file counts and jadx warning counts. Review classes with jadx warnings in the Fernflower output for better code.

For APK files with Fernflower, the script automatically uses dex2jar as an intermediate step. dex2jar must be installed for this to work.

See `<skill-directory>/references/jadx-usage.md` and `<skill-directory>/references/fernflower-usage.md` for the full CLI references.

### Phase 2.5: Target Triage Gate (runtime + packer)

**This is a gate.** Before analyzing the decompiled output as normal Java/Kotlin,
confirm it actually *is*. Two conditions make jadx output empty or misleading — a
non-JVM runtime and a packer — and both reroute you. Check them now.

**Runtime check** — where does the app's logic actually live?

```bash
bash <skill-directory>/scripts/detect-runtime.sh <apk-or-output-dir> --report <output>/runtime.md
```

- Exit 2 / `RUNTIME_DETECTED=native-java` → normal flow, continue to Phase 3.
- Exit 0 with `RUNTIME_DETECTED=flutter|react-native|unity-il2cpp|unity-mono|xamarin|cordova`
  → the Dex holds little logic. Follow the emitted `RUNTIME_TOOL` and switch
  toolchains per `<skill-directory>/references/framework-runtimes.md` (e.g. blutter
  for Flutter, Il2CppDumper for Unity, the JS bundle for React Native) **before**
  spending time in the decompiled Java.

**Packer check** — is the real Dex encrypted/hidden behind a loader?

```bash
bash <skill-directory>/scripts/detect-packer.sh <apk-or-output-dir> --report <output>/packer.md
```

- Exit 2 / `PACKER_DETECTED=none` → continue.
- Exit 0 with `PACKER_DETECTED=<family>` → the decompiled classes are likely a
  stub loader, not the app. Recover the real Dex first (let the app decrypt itself
  and dump from memory) per `<skill-directory>/references/packers.md`, repair the
  dumped Dex header (`dex-byte-patch.py --verify`), then re-run this gate and
  Phase 2 on the recovered Dex.

Detection is signature/heuristic based, so a clean result is `INFERRED`, not proof
of "no packer / plain runtime" — label it that way (`references/verification.md`).

### Phase 3: Analyze Structure

Navigate the decompiled output to understand the app's architecture.

**Actions**:

1. **Read AndroidManifest.xml** from `<output>/resources/AndroidManifest.xml`:
   - Identify the main launcher Activity
   - List all Activities, Services, BroadcastReceivers, ContentProviders
   - Note permissions (especially `INTERNET`, `ACCESS_NETWORK_STATE`)
   - Find the application class (`android:name` on `<application>`)

2. **Survey the package structure** under `<output>/sources/`:
   - Identify the main app package and sub-packages
   - Distinguish app code from third-party libraries
   - Look for packages named `api`, `network`, `data`, `repository`, `service`, `retrofit`, `http` — these are where API calls live

3. **Identify the architecture pattern**:
   - MVP: look for `Presenter` classes
   - MVVM: look for `ViewModel` classes and `LiveData`/`StateFlow`
   - Clean Architecture: look for `domain`, `data`, `presentation` packages
   - This informs where to look for network calls in the next phases

### Phase 4: Trace Call Flows

Follow execution paths from user-facing entry points down to network calls.

**Actions**:

1. **Start from entry points**: Read the main Activity or Application class identified in Phase 3.

2. **Follow the initialization chain**: Application.onCreate() often sets up the HTTP client, base URL, and DI framework. Read this first.

3. **Trace user actions**: From an Activity, follow:
   - `onCreate()` → view setup → click listeners
   - Click handler → ViewModel/Presenter method
   - ViewModel → Repository → API service interface
   - API service → actual HTTP call

4. **Map DI bindings** (if Dagger/Hilt is used): Find `@Module` classes to understand which implementations are provided for which interfaces.

5. **Handle obfuscated code**: When class names are mangled, use string literals and library API calls as anchors. Retrofit annotations and URL strings are never obfuscated.

See `<skill-directory>/references/call-flow-analysis.md` for detailed techniques and grep commands.

### Phase 5: Extract and Document APIs

Find all API endpoints and produce structured documentation.

**Action**: Run the API search script for a broad sweep.

```bash
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/
```

Additional options:
- `--context N` — Show N lines of context around each match (recommended: `--context 3`)
- `--report FILE` — Export results as a structured Markdown report
- `--dedup` — Deduplicate results by endpoint/URL

Targeted searches:
```bash
# Only Retrofit
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --retrofit

# Only hardcoded URLs
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --urls

# Only auth patterns
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --auth

# Only Kotlin coroutines/Flow patterns
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --kotlin

# Only RxJava patterns
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --rxjava

# Only GraphQL patterns
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --graphql

# Only WebSocket patterns
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --websocket

# Only security patterns (cert pinning, exposed secrets, debug flags)
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --security

# Full analysis with context and Markdown report
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --context 3 --dedup --report report.md
```

Then, for each discovered endpoint, read the surrounding source code to extract:
- HTTP method and path
- Base URL
- Path parameters, query parameters, request body
- Headers (especially authentication)
- Response type
- Where it's called from (the call chain from Phase 4)

**Document each endpoint** using this format:

```markdown
### `METHOD /path`

- **Source**: `com.example.api.ApiService` (ApiService.java:42)
- **Base URL**: `https://api.example.com/v1`
- **Path params**: `id` (String)
- **Query params**: `page` (int), `limit` (int)
- **Headers**: `Authorization: Bearer <token>`
- **Request body**: `{ "email": "string", "password": "string" }`
- **Response**: `ApiResponse<User>`
- **Called from**: `LoginActivity → LoginViewModel → UserRepository → ApiService`
```

**Binary / non-HTTP bodies.** If endpoints exist but request/response bodies are
not readable JSON — or the app clearly does network I/O yet the sweep finds "no
endpoints" — the transport is likely protobuf, gRPC, or a custom framing. Decode
captured bodies schema-free:

```bash
python3 <skill-directory>/scripts/protobuf-decode.py <body.bin>       # or --hex / stdin
python3 <skill-directory>/scripts/protobuf-decode.py --grpc <frame.bin>
```

Recover the real schema from the app's generated protobuf classes, and for
QUIC/HTTP3 (invisible to a proxy MITM) hook the serializer at runtime — see
`<skill-directory>/references/protocol-reverse.md`.

See `<skill-directory>/references/api-extraction-patterns.md` for library-specific search patterns and the full documentation template.

### Phase 6: Security Patterns Scan

Run the automated security sweep over the decompiled source to surface security-relevant patterns. This is the static baseline that Phase 8 (Security Analysis & Vulnerability Audit) later synthesizes together with the runtime findings from Phase 7.

**Action**: Run the security-focused search:

```bash
bash <skill-directory>/scripts/find-api-calls.sh <output>/sources/ --security --context 3
```

Look for and flag:
- **Disabled certificate pinning** — custom `TrustManager` that trusts all certs, `ALLOW_ALL_HOSTNAME_VERIFIER`
- **Exposed secrets** — hardcoded passwords, API keys, encryption keys in source code
- **Debug flags left on** — `BuildConfig.DEBUG` checks, staging URLs, verbose logging
- **Weak crypto** — MD5 hashing, ECB mode encryption, hardcoded IVs/salts
- **Network Security Config** — check `res/xml/network_security_config.xml` for `cleartextTrafficPermitted="true"` or overly broad trust anchors

These raw findings feed Phase 8. Targeted vulnerability hunting (e.g. Fragment Injection) and the RASP/anti-tamper synthesis from Phase 7's dynamic analysis happen in Phase 8.

### Phase 6.5: Native Library Analysis

Java/Kotlin analysis stops at the JNI boundary, but RASP, crypto, and string
protection increasingly live in `.so` code. Triage the native libraries so
Phase 7 (and any `SIGABRT` / native-crash cases) has a map to work from.

```bash
bash <skill-directory>/scripts/analyze-native.sh <apk-or-output-dir> --report <output>/native.md
```

It enumerates `.so` per ABI and emits `SO=`, `NEEDED=`,
`JNI_EXPORT=<lib>:<Java_symbol>`, `JNI_ONLOAD=`/`REGISTER_NATIVES=`,
`NATIVE_ANTITAMPER=<lib>:<indicator>` (ptrace, TracerPid, frida/maps scans, native
signature checks), and `NATIVE_STRING=` leads (URLs, key material).

Key point: **no `Java_*` exports plus a `JNI_OnLoad`/`RegisterNatives` hit means
JNI is bound dynamically** — the static export table hides the mapping; dump it at
runtime by hooking `art::JNI::RegisterNatives`. The anti-tamper indicators here
explain crashes you'll hit in Phase 7 and point to the function to hook. Full
static + dynamic workflow, and handoff to the `skw-analyzing-binaries` /
`skw-exploiting-memory-corruption` skills for deep native RE, is in
`<skill-directory>/references/native-and-so.md`.

### Phase 7: Dynamic Analysis with Frida (Adaptive Loop)

Use Frida to observe and modify app behavior at runtime. **Do not use pre-built generic bypass scripts.** Instead, generate custom Frida scripts based on what the static analysis (Phases 3–6) revealed in the decompiled code, then iterate based on crash logs and runtime behavior.

This phase requires a connected device/emulator. The user likely already has frida-server on their device — detect it first before offering to install anything.

#### Step 7.1: Setup Frida Environment

**Action**: Run the Frida setup script. It detects the existing environment before changing anything.

```bash
bash <skill-directory>/scripts/setup-frida.sh
```

The script performs these checks in order:
1. **adb connectivity** — is a device/emulator connected?
2. **frida-server on device** — checks common paths (`/data/local/tmp/frida-server`, etc.) and running processes
3. **frida-server version** — extracts version from the binary on device
4. **Python 3 + venv module** — required for frida-tools
5. **Creates/reuses venv** — at `~/.local/share/frida-re/venv`, installs `frida-tools` matching the device's frida-server version
6. **Version match validation** — warns if client/server versions diverge
7. **Connectivity test** — runs `frida-ps -U` to verify end-to-end

If frida-server is missing from the device, the script prints instructions. To auto-install:
```bash
bash <skill-directory>/scripts/setup-frida.sh --install-server
```

**Important**: The venv ensures frida-tools never pollutes the global Python environment. The version matching ensures client and server are compatible. If the user already has a working frida-server, the script adapts to their version instead of forcing an upgrade.

Read the machine-readable output lines (`FRIDA_VENV=`, `FRIDA_SERVER_VERSION=`, `FRIDA_DEVICE=`, `FRIDA_STATUS=`) to configure subsequent steps.

#### Step 7.2: Baseline Crash Check (Before Any Hooks)

Before writing any Frida script, check if the app even runs on this device. Many apps with RASP will crash immediately on rooted devices/emulators.

**Action**: Launch the app and capture crash diagnostics.

```bash
bash <skill-directory>/scripts/adb-crash-capture.sh -p <package>
```

Options:
- `-t <seconds>` — monitoring window (default: 10)
- `-a <activity>` — launch specific activity instead of auto-detect
- `-o <dir>` — save logcat/crash logs to directory
- `-v` — include full logcat in output

Read the machine-readable output:
- `APP_STATUS=running` — app is fine, proceed to runtime analysis
- `APP_STATUS=crashed` — check `CRASH_SIGNAL`, `CRASH_EXCEPTION`, `CRASH_MESSAGE`
- `APP_STATUS=exited` — app quit without a visible crash (common RASP pattern: `System.exit()` or `Process.killProcess()`)

The script also outputs:
- **JAVA CRASH** section — full stack trace from `FATAL EXCEPTION`
- **NATIVE CRASH** section — signal info and native backtrace
- **RASP/SECURITY INDICATORS** — log lines mentioning security, root, frida, tamper, integrity, debug, hook
- **APP LOG** — last 50 lines from the app's PID

If the app runs fine (status=running), skip to Step 7.4 for runtime analysis.
If the app crashes or exits, proceed to Step 7.3.

#### Step 7.3: Adaptive Bypass Loop

This is the core of dynamic analysis. Use the decompiled code from previous phases combined with crash logs to understand WHY the app is dying, then generate a targeted Frida script to bypass that specific check.

**The loop**:

```
1. Read crash output from Step 7.2 (or previous iteration)
2. Identify the protection mechanism:
   - Cross-reference crash class/method with decompiled code
   - Follow the stack trace back to the triggering check
   - Look for the RASP/security indicators in logs
3. Read the relevant decompiled source to understand the check logic
4. Generate a Frida script that specifically disables that check
5. Run the script and capture new crash output
6. If still crashing: repeat from step 1 (new crash = new check to bypass)
7. If running: proceed to Step 7.4
```

**How to identify protection mechanisms from crash data**:

| Crash Pattern | Likely Cause | Where to Look in Decompiled Code |
|---|---|---|
| `System.exit(0)` in stack trace | RASP calling `System.exit()` | Search for `System.exit` and `Process.killProcess` calls |
| `SecurityException` | Permission or integrity check | Search for the exception class in decompiled code |
| `SIGABRT` from native code | Native anti-tamper (frida detection, lib integrity) | Check `.so` libraries loaded by the app, search for `dlopen`, `ptrace`, `frida` strings |
| App starts then immediately closes (no crash) | `finish()` called on Activity, or `System.exit()` in `onCreate` | Read the launcher Activity's `onCreate()`, look for conditional `finish()` calls |
| `RootBeer`, `SafetyNet`, `Play Integrity` in logs | Root/integrity detection SDK | Search for the SDK's package in decompiled code |
| `ssl`, `certificate`, `pin` in crash | SSL pinning preventing traffic inspection | Search for `CertificatePinner`, `TrustManager`, network security config |
| `frida`, `xposed`, `substrate` in logs | Instrumentation framework detection | Search for string constants checking process names, ports, or loaded modules |

**How to generate the bypass script**:

Read the decompiled source of the method that performs the check. Understand:
- What does the method return? (boolean, int, void)
- Is it Java or native?
- Does it run once (in `onCreate`) or continuously (background thread)?
- What is the expected "safe" return value?

Then write a Frida script that hooks that specific method. Examples of patterns (adapt to actual code):

For a Java method returning boolean:
```javascript
Java.perform(function() {
    var cls = Java.use('com.example.security.RootChecker');
    cls.isDeviceRooted.implementation = function() {
        console.log('[bypass] RootChecker.isDeviceRooted() called, returning false');
        return false;
    };
});
```

For a native function:
```javascript
var funcAddr = Module.findExportByName("libsecurity.so", "Java_com_example_NativeCheck_verify");
if (funcAddr) {
    Interceptor.replace(funcAddr, new NativeCallback(function() {
        console.log('[bypass] native verify() called, returning 0');
        return 0;
    }, 'int', []));
}
```

For `System.exit()` prevention (when you don't know the exact check yet):
```javascript
Java.perform(function() {
    var System = Java.use('java.lang.System');
    System.exit.implementation = function(code) {
        console.log('[bypass] System.exit(' + code + ') blocked');
        // Don't call the original — app stays alive
        // Check the stack trace to find who's calling this:
        console.log(Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Throwable").$new()
        ));
    };
});
```

**Action**: Save the generated script to a temp file and run it:

```bash
bash <skill-directory>/scripts/frida-run.sh \
  -p <package> -l /tmp/bypass.js -t 15
```

Options:
- `-t <seconds>` — timeout (default: 30)
- `--pause` — suspend app on spawn, useful for early hooks before any app code runs
- `--attach` — attach to running process instead of spawning
- `-e "<code>"` — inline JavaScript instead of a file
- `--output-dir <dir>` — save stdout/stderr/crash to files

Read the output:
- `FRIDA_RESULT=success` — bypass worked, app is running
- `FRIDA_RESULT=crash` — check the CRASH LOG section, identify the next check to bypass
- `FRIDA_RESULT=connection_failed` — frida-server issue, re-run setup-frida.sh
- `FRIDA_RESULT=timeout` — app ran for the full timeout window (usually means success)

**If the app crashes again**: read the new crash log, cross-reference with decompiled code, identify the NEXT protection check, add another hook to the script, and run again. Each iteration should bypass one more check. Common pattern: apps have 3–5 layered checks.

**Important considerations**:
- Use `--pause` (spawn gating) when the check runs in `Application.onCreate()` — this ensures hooks are in place before any app code executes
- If the app uses a background thread for continuous checks, hook `Thread.start()` or the specific `Runnable` to neutralize it
- If native checks use `ptrace(PTRACE_TRACEME)`, hook `ptrace` via `Interceptor.replace`
- If the app checks for frida-server's default port (27042), the frida-server can be started on a different port: `frida-server -l 0.0.0.0:1337`
- Log stack traces in your hooks — they reveal the call chain leading to the check, which helps find related checks

#### Step 7.4: Runtime Analysis

Once the app is running (with or without bypass scripts), use Frida for the actual analysis goals.

**Generate analysis scripts based on what static analysis found.** Do not use generic scripts — target the specific classes, methods, and patterns identified in Phases 3–6.

Common analysis patterns (adapt to the actual code found):

**Intercept HTTP traffic** — hook the specific HTTP client the app uses (identified in Phase 5):
```javascript
// Example: if static analysis found OkHttp usage
Java.perform(function() {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var RealCall = Java.use('okhttp3.internal.connection.RealCall');
    // Hook based on actual classes found in the decompiled code
});
```

**Monitor crypto operations** — hook the specific encryption methods found in Phase 6:
```javascript
// Example: if static analysis found AES usage in com.example.crypto.CryptoHelper
Java.perform(function() {
    var helper = Java.use('com.example.crypto.CryptoHelper');
    // Hook the specific encrypt/decrypt methods found
});
```

**Trace method calls** — when static analysis shows a call flow but you need to verify it at runtime:
```bash
# Use frida-trace for quick method tracing (uses the venv)
$FRIDA_VENV/bin/frida-trace -U -f <package> -j 'com.example.api.*!*'
```

**Action**: Write the analysis script, run it, and interpret results:

```bash
bash <skill-directory>/scripts/frida-run.sh \
  -p <package> -l /tmp/analysis.js -t 60 --output-dir ./frida-output/
```

If bypass hooks are needed alongside analysis hooks, combine them in a single script — bypass hooks first, then analysis hooks.

#### Step 7.5: Iterate and Document

After each Frida run, document:
- What protection was found and how it was bypassed
- What runtime behavior was observed that static analysis couldn't show
- Any new endpoints, keys, or tokens discovered at runtime

Feed runtime findings back into the API documentation from Phase 5 — runtime analysis often reveals:
- Dynamically constructed URLs that don't appear in static code
- Encryption keys loaded from server responses
- Token refresh flows that are only triggered under specific conditions
- Feature flags that change API behavior

### Phase 8: Security Analysis & Vulnerability Audit

Synthesize the automated sweep from Phase 6 with the runtime findings from Phase 7, then run targeted vulnerability detectors for issues the generic sweep does not catch.

**Carry forward from Phase 6**: review every flag the `find-api-calls.sh --security` sweep produced (disabled certificate pinning, exposed secrets, debug flags, weak crypto, Network Security Config) and confirm each by reading the surrounding decompiled code — raw grep hits are leads, not findings, until you read the code.

**Carry forward from Phase 7**:
- **RASP/Anti-tamper** — document what protections were found, how robust they are, and what was needed to bypass them

**Targeted vulnerability hunting**: run the issue-specific detectors that the generic sweep does not cover. Each has its own playbook in `references/`.

#### Fragment Injection (exported PreferenceActivity)

Android `PreferenceActivity` honours an Intent extra (`:android:show_fragment`) that selects which Fragment class to instantiate. An exported (or launchable) activity that does this without a restrictive `isValidFragment()` override lets an attacker instantiate arbitrary internal fragments inside the victim's process/UID — bypassing UI gating and access controls.

**Action**: Run the detector against the decompiled output.

```bash
bash <skill-directory>/scripts/find-fragment-injection.sh \
  <output>/ --report <output>/fragment-injection-report.md --json <output>/fragment-injection.json
```

Read the machine-readable output:
- `TARGET_SDK_VERSION=<n>` — drives the `isValidFragment` gate (see below).
- `FRAG_INJECTION_CANDIDATE=<class>` — an exported/launchable `PreferenceActivity` that is injectable: `always_true` override, OR `missing` override with `targetSdk < 19` (or unknown). Exit 0 if any candidate exists, exit 2 if none.
- `FRAG_INJECTION_BROKEN=<class>` — `missing` override with `targetSdk ≥ 19`: the app crashes on injection instead of being exploited. Broken, not vulnerable — report as a robustness issue.
- `IS_VALID_FRAGMENT=<class>:<status>` — `missing`, `always_true`, or `whitelist` (only `whitelist` is safe).
- `SHOW_FRAGMENT_READER` / `DYNAMIC_FRAGMENT_LOAD` — code that reads the extra or does `Fragment.instantiate`/`FragmentFactory`/`Class.forName` from Intent extras. `DYNAMIC_FRAGMENT_LOAD` is the relevant surface for modern AndroidX apps (which don't use `PreferenceActivity`); `ANDROIDX_PREFERENCE` flags when the modern preference API is in use.

For each candidate, confirm dynamically: launch the activity via adb with the `:android:show_fragment` extra set to an internal fragment, and observe logcat/Frida for the fragment instantiating (lifecycle logs or a fragment-stack crash). Use `--pause` Frida spawn gating to hook the **candidate subclass's** `isValidFragment`/`Fragment.instantiate` before `onCreate`.

See `<skill-directory>/references/android-fragment-injection.md` for the full detection-→-exploitation-→-classification playbook, adb and Frida commands, and remediation guidance.

### Phase 9: Firebase & Google API Testing (Conditional)

**Only run this phase if the decompiled app contains Google API keys or Firebase configuration.** If none are present, skip it entirely — do not invent keys, do not hit Google endpoints speculatively.

This phase is strictly for apps the user is authorized to test (their own apps, signed engagements, or bug-bounty programs that explicitly permit it). Confirm authorization before running write/create probes (Realtime DB `PUT`, Dynamic Links creation, FCM send) or billable probes (Maps, Vision, Translate, etc.).

#### Step 9.1: Detect Firebase/Google configuration (gatekeeper)

**Action**: Run the detection script against the decompiled output. Its exit code drives the rest of the phase.

```bash
bash <skill-directory>/scripts/find-firebase-config.sh \
  <output>/ --env /tmp/fb-env.sh --json /tmp/fb-env.json
```

The script scans `res/values/strings.xml`, `AndroidManifest.xml`, `assets/google-services.json`, `assets/appsettings.json`, and the full decompiled tree for values matching `AIza[0-9A-Za-z_\-]{35}` and known Firebase keys (`google_api_key`, `project_id`, `firebase_database_url`, `gcm_defaultSenderId`, `google_app_id`, `google_storage_bucket`, `default_web_client_id`).

Read the machine-readable output:
- `FIREBASE_FOUND=true` or `GOOGLE_API_KEY_FOUND=true` (exit 0) → proceed to Step 9.2.
- Both `false` (exit 2) → **skip the rest of Phase 9 entirely** and move on to the final deliverables.

The `--env` file produced on success is ready to `source` before running any Firebase/Google request (`API_KEY`, `PROJECT_ID`, `DB_URL`, `APP_ID`, `GCM_SENDER_ID`, `PACKAGE`, `OAUTH_CLIENT_ID`, `STORAGE_BUCKET`, plus an `API_KEYS` array for apps that ship multiple keys).

#### Step 9.2: Confirm authorization

Before running any probe, confirm with the user that the app is in scope for Firebase/Google API testing. If the user has not authorized this, stop and report the configuration findings only. Do not proceed to Step 9.3.

#### Step 9.3: Run the test matrix

**Action**: Run the automated matrix against the extracted configuration.

```bash
bash <skill-directory>/scripts/test-firebase-google.sh \
  --env /tmp/fb-env.sh --report <output>/firebase-google-report.md
```

Useful flags:
- `--skip-billable` — skip Section 9 (Maps/AI/YouTube) to avoid billable calls on the target project.
- `--skip-writes` — skip Realtime DB `PUT`, Dynamic Links creation, and FCM `send` (use when authorization covers reads only).
- `--only auth,rtdb,firestore` — restrict to specific sections (`auth`, `rtdb`, `firestore`, `remoteconfig`, `storage`, `dynamiclinks`, `fcm`, `gemini`, `billable`).
- `--api-key <KEY>` — override the key (useful when iterating through multiple keys from `API_KEYS`).

The script runs the full playbook in `<skill-directory>/references/firebase-google-api-testing.md` — Firebase Auth (signup, signin, OIDC providers, phone, OOB codes, enumeration), Realtime DB (unauth and authenticated reads, rules, write test), Firestore (list root, common collections, authenticated Bearer), Remote Config (`firebase:fetch`), Cloud Storage (both bucket conventions), Dynamic Links (open redirect / phishing check), FCM legacy send, Gemini (`/files`, `/models`, `/cachedContents`, `gemini-pro:generateContent` — TruffleSecurity vector), and billable Maps/AI/YouTube/Cloud Functions probes.

Each probe is classified as `VULNERABLE`, `SAFE`, `BLOCKED`, `NOT_FOUND`, `OK`, `ERROR-200`, `INFO`, or `NETWORK_ERROR`. When Firebase Auth returns an `idToken` (anonymous or email signup open), the script captures it and reuses it as `$JWT` for the authenticated Realtime DB / Firestore / lookup probes in the same run.

Read the final machine-readable output:
- `PROBE_COUNT=<n>` — how many endpoints were exercised.
- `VULN_COUNT=<n>` — how many returned exploitable data.
- `REPORT_FILE=<path>` — Markdown report with per-probe status, verdict, and response excerpt.

#### Step 9.4: Iterate across multiple keys

If `find-firebase-config.sh` reported `API_KEY_COUNT > 1`, re-run `test-firebase-google.sh` with each additional key (`source /tmp/fb-env.sh && test-firebase-google.sh --api-key "${API_KEYS[1]}" --report <output>/firebase-google-report-key2.md`). Different keys often belong to different GCP projects with different APIs enabled — a key that looks safe on project A may be wide open on project B.

#### Interpreting results

See `<skill-directory>/references/firebase-google-api-testing.md` for the full response-interpretation table (`SERVICE_DISABLED`, `PERMISSION_DENIED`, `ADMIN_ONLY_OPERATION`, `OPERATION_NOT_ALLOWED`, `NO_TEMPLATE`, etc.) and for the raw curl commands to re-run any single probe manually.

### Phase 10: Patch, Repack & Verify (authorized modification)

Run this phase only to modify an app you are **authorized** to modify (your own
app, a signed engagement, CTF, or a sandbox). Modification changes the app's
signature and can trip integrity checks — confirm scope before starting.

Two patch layers, cheapest-safe first:

1. **Byte-level (equal-length) Dex patch** — best on hardened apps: it avoids
   rebuilding/re-verifying methods and keeps the change surgical.
   ```bash
   python3 <skill-directory>/scripts/dex-byte-patch.py classes.dex --find <hex>
   python3 <skill-directory>/scripts/dex-byte-patch.py classes.dex --patch spec.json -o patched.dex
   python3 <skill-directory>/scripts/dex-byte-patch.py patched.dex --verify
   ```
   Equal-length only; the script recomputes the Dex Adler-32 checksum and SHA-1
   signature so the result loads. Mind the `move-result` adjacency hazard. See
   `<skill-directory>/references/byte-level-patching.md`.

2. **Smali rebuild + repack** — when the edit changes instruction length or spans
   methods:
   ```bash
   bash <skill-directory>/scripts/repack.sh --decode app.apk        # -> DECODED_DIR
   # edit the smali under the decoded dir
   bash <skill-directory>/scripts/repack.sh --all <decoded-dir>     # build -> align -> sign -> install -> verify
   ```
   `repack.sh` enforces `zipalign` before `apksigner`, auto-creates a debug
   keystore, and runs an install + launch health check (`INSTALL_STATUS`,
   `LAUNCH_STATUS`). See `<skill-directory>/references/repack-and-sign.md` for
   signing schemes and the signature-pinning / LSPosed-module fallbacks when a
   resign is rejected.

**Verification is mandatory (definition of done).** A patch is `INFERRED` until
you prove it landed (a Dex/class diff or `--verify`) **and** the app installs and
launches (`INSTALL_STATUS=ok`, `LAUNCH_STATUS=running`). Save the diff and the
health-check output as evidence. See `<skill-directory>/references/verification.md`.

---

At the end of the workflow, deliver:

1. **Decompiled source** in the output directory
2. **Architecture summary** — app structure, main packages, pattern used
3. **API documentation** — all discovered endpoints in the format above
4. **Call flow map** — key paths from UI to network (especially authentication and main features)
5. **Security findings** — certificate pinning status, exposed secrets, debug flags, crypto issues, Fragment Injection exposure (candidates, `isValidFragment` status, adb/Frida confirmation)
6. **Dynamic analysis results** (if Phase 7 was performed):
   - Protection mechanisms found and bypass scripts generated
   - Runtime-only discoveries (dynamic URLs, keys, tokens, feature flags)
   - Frida scripts used (saved in the output directory for reproducibility)
7. **Firebase & Google API findings** (if Phase 9 was performed):
   - Extracted configuration values (`find-firebase-config.sh` output / env file)
   - Per-probe verdicts from `test-firebase-google.sh` (the Markdown report)
   - Highlighted `VULNERABLE` findings with the response excerpt and impact
   - Any additional keys tested and their separate reports
8. **Target triage** (Phase 2.5) — the detected runtime and packer, and the toolchain used if a non-Java runtime or packer was found
9. **Native analysis** (Phase 6.5, if native libs present) — JNI bindings, native anti-tamper mechanisms, and any native-only secrets/URLs
10. **Modifications** (Phase 10, if performed) — the patch layer used, the before/after diff proving the patch landed, and the install+launch verification result

Every finding above carries a claim-strength label (`references/verification.md`); state what was checked-and-clean, not only what was found.

Use `--report report.md` on find-api-calls.sh to generate a structured Markdown report automatically.

## References

- `<skill-directory>/references/setup-guide.md` — Installing Java, jadx, Fernflower/Vineflower, dex2jar, and optional tools
- `<skill-directory>/references/jadx-usage.md` — jadx CLI options and workflows
- `<skill-directory>/references/fernflower-usage.md` — Fernflower/Vineflower CLI options, when to use, APK workflow
- `<skill-directory>/references/api-extraction-patterns.md` — Library-specific search patterns and documentation template
- `<skill-directory>/references/call-flow-analysis.md` — Techniques for tracing call flows in decompiled code
- `<skill-directory>/references/firebase-google-api-testing.md` — Phase 9 playbook: Firebase Auth, Realtime DB, Firestore, Remote Config, Storage, Dynamic Links, FCM, Gemini, billable Maps/AI probes
- `<skill-directory>/references/android-fragment-injection.md` — Phase 8 playbook: detecting and exploiting Fragment Injection via exported PreferenceActivity, adb/Frida confirmation, result classification, remediation
- `<skill-directory>/references/setup-guide.md` — Frida setup section covers Python venv, frida-server, and version matching
- `<skill-directory>/references/verification.md` — Operating rules: claim-strength ladder (OBSERVED/MEASURED/INFERRED/UNVERIFIED) and the definition-of-done checklist (applies to every phase)
- `<skill-directory>/references/troubleshooting-index.md` — Operating rules: symptom→action index and the two-strike rule
- `<skill-directory>/references/framework-runtimes.md` — Phase 2.5: Flutter/Dart-AOT, React Native/Hermes, Unity IL2CPP/Mono, Xamarin, Cordova toolchains and routing
- `<skill-directory>/references/packers.md` — Phase 2.5: packer/protector families and the dump → repair → re-decompile recovery loop
- `<skill-directory>/references/protocol-reverse.md` — Phase 5: protobuf/gRPC/gRPC-Web decoding, schema recovery, QUIC/HTTP3 notes
- `<skill-directory>/references/native-and-so.md` — Phase 6.5: JNI static vs dynamic (RegisterNatives) binding, native anti-tamper, radare2/Ghidra + Frida workflow
- `<skill-directory>/references/byte-level-patching.md` — Phase 10: equal-length Dex byte patching, header/checksum repair, move-result hazard
- `<skill-directory>/references/repack-and-sign.md` — Phase 10: apktool decode/build, zipalign + apksigner, signing schemes, post-install hazards
