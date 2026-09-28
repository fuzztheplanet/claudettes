# Repack & Sign: the patch → build → sign → install → verify loop

For **authorized** analysis only (apps you own, signed engagements, CTF,
sandboxes). Repacking produces a modified, re-signed copy of someone's app;
treat the output like any other test artifact.

Driver script: `<skill-directory>/scripts/repack.sh`. It wraps apktool +
Android SDK build-tools (`zipalign`, `apksigner`) + `adb`.

A patch is **INFERRED** until it is (a) proven to have landed by a diff and
(b) proven not to have broken the app by an install + launch health check. See
`verification.md` for the claim-strength ladder — do not report "patched" from a
clean build alone.

## The loop

```
1. decode      repack.sh --decode app.apk -o app-src
2. edit        edit smali under app-src/smali*/...   (or resources)
3. build       repack.sh --build app-src -o app-unsigned.apk
4. align+sign  repack.sh --sign app-unsigned.apk -o app-signed.apk
5. install     repack.sh --install app-signed.apk -p com.example.app
6. verify      diff the smali / confirm behavior; confirm LAUNCH_STATUS=running
```

`repack.sh --all app-src -p <pkg>` chains steps 3→5.

## Decode strategies

`apktool d` disassembles Dex to smali and decodes resources. Choose scope:

- **Full decode (default)** — smali + decoded resources. Needed when you must
  edit resources (strings, layouts, `network_security_config.xml`) or the
  manifest. Slowest; most likely to hit resource-rebuild issues.
- **`-r` / `--no-res`** — skip resource decoding; resources are copied back
  verbatim on build. Use when you only touch smali. Avoids a whole class of
  rebuild failures around resource IDs and is usually the right choice for a
  code-only patch.
- **`-s` / `--no-src`** — skip smali (resources only). Rare for RE.
- **`-b` (default keeps debug info)** — fine to leave as is.

Rule of thumb: **smali-only patch → decode with `-r`.** Only full-decode when the
edit genuinely requires resources or the manifest.

## The smali edit loop

- Locate the method in `app-src/smali*/` (`smali/`, `smali_classes2/`, …).
- Make the smallest edit that achieves the goal — flip a branch, force a return,
  neutralize a check. Large rewrites raise the odds of a build/verify failure.
- For a **binary/equal-length** change to bytecode, consider byte patching the
  Dex directly instead (`byte-level-patching.md`) — no rebuild, minimal diff.
- Keep a copy of the original method body so you can produce a diff for the
  verification step.

## Build pitfalls

- **Missing framework resources** — `apktool b` fails referencing framework
  resource IDs (common with vendor-themed apps). Install the framework once:
  `apktool if <framework-res.apk>` (pull `/system/framework/framework-res.apk`
  and any vendor overlay from the device), then rebuild.
- **`aapt`/`aapt2` mismatch** — some apps only build with `--use-aapt2`; others
  break with it. If a resource build fails, try toggling aapt version.
- **Resource ID drift** — full resource re-encoding can renumber IDs; prefer
  `-r` decode to avoid this entirely on code-only patches.
- **`res/raw` / unknown assets** — apktool copies these verbatim; don't expect it
  to touch them.

## Aligning and signing (order matters)

**`zipalign` MUST run before `apksigner`.** apksigner preserves zip alignment;
running zipalign after signing invalidates the signature. `repack.sh --sign`
enforces this order (`zipalign -p -f 4` then `apksigner sign`).

Android signing schemes:

| Scheme | What it is | Notes |
|---|---|---|
| **v1 (JAR)** | Signed entries in `META-INF/` | Required for install on API < 24; weak, per-file. |
| **v2** | Whole-APK signature (APK Signing Block) | API ≥ 24. Default with apksigner. |
| **v3** | v2 + key-rotation lineage | API ≥ 28. |
| **v4** | Out-of-band `.apk.idsig` for incremental install | API ≥ 30; needed for `adb install --incremental`. |

Default guidance: let `apksigner` apply **v1+v2+v3** (its default). For a target
running a specific minSdk, that default is fine. Only force flags
(`--v1-signing-enabled`, `--v2-…`) if an install error points at a scheme.

### Debug keystore

`repack.sh --sign` auto-creates one at
`~/.local/share/skw-android-re/debug.keystore` if you don't pass `--keystore`:

```
alias=androiddebugkey  storepass=android  keypass=android
```

Reuse the **same** keystore across a project so re-installs don't hit signature
mismatches. `repack.sh` prints `SIGNER_CERT_SHA256=<hash>` — record it; some apps
compare their own signing cert against a known value (see below).

## Install hazards

- **`INSTALL_FAILED_UPDATE_INCOMPATIBLE` / "signatures do not match"** — the
  original app is installed and signed by a different key. Uninstall it first:
  `adb uninstall <pkg>`. (Loses app data.)
- **`INSTALL_PARSE_FAILED_NO_CERTIFICATES` / `_UNEXPECTED_EXCEPTION`** — the APK
  was not aligned/signed correctly, or the zip is malformed. Re-run
  `--sign`; confirm `apksigner verify` passes.
- **`INSTALL_FAILED_INVALID_APK`** — often a v2+ signature over a zip that was
  modified after signing (e.g. zipalign run last). Fix the order.
- **Split APKs** — you can't `adb install` a bare `base.apk` for an app shipped
  as splits; merge first (`merge-splits.sh`) or `adb install-multiple`.

## Post-install: when the app detects the repack

A resigned APK has a different signing certificate than the store build. Apps
increasingly check this at runtime:

- **Signature / integrity pinning** — the app reads its own
  `PackageInfo.signatures` / `signingInfo` (or a native equivalent) and compares
  a hash against a baked-in value; on mismatch it exits or degrades. Your
  `SIGNER_CERT_SHA256` won't match. Options: hook the signature-check method at
  runtime (Phase 7) rather than repacking, or forge the returned cert bytes in
  the hook. If the app derives crypto **keys** from the signing cert, see
  `signature-derived-keys` (a hook must return the *original* cert bytes, not
  yours).
- **Play Integrity / attestation** — server-side; repacking won't pass it.
  Client-side gating on the verdict can be hooked; the server verdict cannot.
- **When repack is blocked entirely** (hardened, can't rebuild, tamper-proofed):
  deliver the change as an **LSPosed/Xposed module** or a **Frida script**
  instead of a patched APK — you modify behavior in-process without altering the
  installed package or its signature. (`lsposed-and-modules` / Phase 7.)

## Verification checklist (Definition of Done for a repack)

- [ ] The intended smali/resource change is present in `app-src` (keep the diff).
- [ ] `apksigner verify` passes on the signed APK.
- [ ] `INSTALL_STATUS=ok`.
- [ ] `LAUNCH_STATUS=running` (not `crashed`/`exited`) — the app survived launch.
- [ ] The targeted behavior actually changed at runtime (OBSERVED), not just
      "it built and installed" (which is only INFERRED).
- [ ] The saved patched APK and the smali diff are in the output directory.

If `LAUNCH_STATUS=exited` with no crash, suspect a tamper/self-signature check
(above) — cross-ref `troubleshooting-index.md`.
