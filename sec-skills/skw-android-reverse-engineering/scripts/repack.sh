#!/usr/bin/env bash
# repack.sh — Decode / build / align / sign / install / verify workflow for APKs
#
# Wraps apktool + Android build-tools (zipalign, apksigner) + adb to support the
# patch loop: decode an APK to smali, edit it, rebuild, align, sign with a debug
# keystore, install, and health-check that the repacked app still launches.
#
# For AUTHORIZED analysis only (apps you own, signed engagements, CTF, sandboxes).
#
# Machine-readable output lines:
#   DECODED_DIR=<dir>          (--decode)
#   BUILT_APK=<path>           (--build / --all)
#   SIGNED_APK=<path>          (--sign / --all)
#   SIGNER_CERT_SHA256=<hash>  (--sign / --all)
#   INSTALL_STATUS=ok|failed   (--install / --all)
#   LAUNCH_STATUS=running|crashed|exited|unknown  (--install / --all)
#   REPACK_RESULT=success|failed   (always, last line)
#
# Exit codes:
#   0  requested action(s) succeeded
#   1  action failed (build/sign/install error, bad input)
#   2  a required tool is missing / manual action needed
set -euo pipefail

echo "[NOTICE] repack.sh modifies an app and may touch a device — use only on targets you are authorized to analyze." >&2

usage() {
  cat <<EOF
Usage: repack.sh <ACTION> [OPTIONS]

Decode, rebuild, sign, and install an Android APK for the patch/repack loop.

Actions (choose one):
  --decode <apk>          Decode APK to a smali+resources dir (apktool d).
  --build <decoded-dir>   Rebuild an unsigned APK from a decoded dir (apktool b).
  --sign <apk>            zipalign + sign an APK with a debug keystore.
  --install <apk>         adb install -r, launch, and health-check the app.
  --all <decoded-dir>     build -> sign -> install -> verify, in sequence.

Options:
  -o, --output <path>     Output APK (build/sign) or dir (decode). Sensible default otherwise.
  --keystore <path>       Keystore for signing (default: auto debug keystore, see below).
  --ks-pass <pass>        Keystore/key password (default: android).
  -p, --package <pkg>     Package name (install health-check; else auto-detected via aapt).
  -a, --activity <act>    Launcher activity for install (else auto-resolved).
  -h, --help              Show this help.

Debug keystore:
  Auto-created at ~/.local/share/skw-android-re/debug.keystore if absent.
  alias=androiddebugkey  storepass=android  keypass=android

Tool discovery order: PATH, then env vars (APKTOOL_JAR, BUILD_TOOLS), then common
Android SDK build-tools locations. zipalign MUST run before apksigner.

Examples:
  repack.sh --decode app.apk -o app-src
  # ... edit smali under app-src/ ...
  repack.sh --all app-src -p com.example.app
  repack.sh --sign app-unsigned.apk -o app-signed.apk
EOF
  exit 0
}

# --- Logging helpers ---
info()  { echo "[INFO] $*"; }
ok()    { echo "[OK] $*"; }
warn()  { echo "[WARN] $*" >&2; }
fail()  { echo "[FAIL] $*" >&2; }

finish_fail() { echo "REPACK_RESULT=failed"; exit "${1:-1}"; }

# --- Parse arguments ---
ACTION=""
TARGET=""
OUTPUT=""
KEYSTORE=""
KS_PASS="android"
PKG=""
ACTIVITY=""

set_action() {
  if [[ -n "$ACTION" ]]; then
    fail "Only one action may be specified (got --$ACTION and $1)."
    finish_fail 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --decode)   set_action "$1"; ACTION="decode";  TARGET="${2:-}"; shift; shift 2>/dev/null || true ;;
    --build)    set_action "$1"; ACTION="build";   TARGET="${2:-}"; shift; shift 2>/dev/null || true ;;
    --sign)     set_action "$1"; ACTION="sign";    TARGET="${2:-}"; shift; shift 2>/dev/null || true ;;
    --install)  set_action "$1"; ACTION="install"; TARGET="${2:-}"; shift; shift 2>/dev/null || true ;;
    --all)      set_action "$1"; ACTION="all";     TARGET="${2:-}"; shift; shift 2>/dev/null || true ;;
    -o|--output)   OUTPUT="${2:-}"; shift; shift 2>/dev/null || true ;;
    --keystore)    KEYSTORE="${2:-}"; shift; shift 2>/dev/null || true ;;
    --ks-pass)     KS_PASS="${2:-}"; shift; shift 2>/dev/null || true ;;
    -p|--package)  PKG="${2:-}"; shift; shift 2>/dev/null || true ;;
    -a|--activity) ACTIVITY="${2:-}"; shift; shift 2>/dev/null || true ;;
    -h|--help)     usage ;;
    -*)            fail "Unknown option $1"; usage ;;
    *)             fail "Unexpected argument $1"; usage ;;
  esac
done

if [[ -z "$ACTION" ]]; then
  fail "No action specified."
  usage
fi
if [[ -z "$TARGET" ]]; then
  fail "Action --$ACTION requires a target argument."
  finish_fail 1
fi

# --- Tool discovery ---
APKTOOL_CMD=""
find_apktool() {
  if command -v apktool &>/dev/null; then
    APKTOOL_CMD="apktool"; return 0
  fi
  if [[ -n "${APKTOOL_JAR:-}" && -f "${APKTOOL_JAR:-}" ]]; then
    APKTOOL_CMD="java -jar $APKTOOL_JAR"; return 0
  fi
  for c in "$HOME/.local/share/apktool/apktool.jar" "$HOME/apktool/apktool.jar" \
           /usr/local/bin/apktool.jar; do
    if [[ -f "$c" ]]; then APKTOOL_CMD="java -jar $c"; return 0; fi
  done
  return 1
}

# Locate a build-tool binary (zipalign/apksigner/aapt/aapt2) via PATH, BUILD_TOOLS
# env dir, or the newest build-tools dir under a discovered Android SDK.
find_build_tool() {
  local name="$1"
  if command -v "$name" &>/dev/null; then command -v "$name"; return 0; fi
  if [[ -n "${BUILD_TOOLS:-}" && -x "${BUILD_TOOLS%/}/$name" ]]; then
    echo "${BUILD_TOOLS%/}/$name"; return 0
  fi
  local sdk
  for sdk in "${ANDROID_SDK_ROOT:-}" "${ANDROID_HOME:-}" \
             "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" \
             "/usr/lib/android-sdk" "/opt/android-sdk"; do
    [[ -n "$sdk" && -d "$sdk/build-tools" ]] || continue
    local bt
    bt=$(ls -1 "$sdk/build-tools" 2>/dev/null | sort -V | tail -n1)
    if [[ -n "$bt" && -x "$sdk/build-tools/$bt/$name" ]]; then
      echo "$sdk/build-tools/$bt/$name"; return 0
    fi
  done
  return 1
}

need_tool_hint() {
  case "$1" in
    apktool)   echo "Install apktool (https://apktool.org) or set APKTOOL_JAR=/path/to/apktool.jar" ;;
    zipalign|apksigner)
               echo "Install Android SDK build-tools and set BUILD_TOOLS=<sdk>/build-tools/<ver>, or add it to PATH" ;;
    adb)       echo "Install platform-tools (adb) and connect a device/emulator" ;;
    keytool)   echo "Install a JDK (keytool ships with it)" ;;
  esac
}

# --- Debug keystore ---
ensure_keystore() {
  if [[ -n "$KEYSTORE" ]]; then
    [[ -f "$KEYSTORE" ]] || { fail "Keystore not found: $KEYSTORE"; finish_fail 1; }
    return 0
  fi
  KEYSTORE="$HOME/.local/share/skw-android-re/debug.keystore"
  if [[ -f "$KEYSTORE" ]]; then
    info "Using debug keystore: $KEYSTORE"
    return 0
  fi
  if ! command -v keytool &>/dev/null; then
    fail "keytool not found — cannot create debug keystore. $(need_tool_hint keytool)"
    finish_fail 2
  fi
  mkdir -p "$(dirname "$KEYSTORE")"
  info "Creating debug keystore at $KEYSTORE (alias=androiddebugkey)"
  keytool -genkeypair -v \
    -keystore "$KEYSTORE" -alias androiddebugkey \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -storepass "$KS_PASS" -keypass "$KS_PASS" \
    -dname "CN=Android Debug,O=Android,C=US" >/dev/null 2>&1 \
    || { fail "keytool failed to create debug keystore"; finish_fail 1; }
  ok "Debug keystore created"
}

# --- Actions ---
do_decode() {
  local apk="$1"
  [[ -f "$apk" ]] || { fail "APK not found: $apk"; finish_fail 1; }
  find_apktool || { fail "apktool not available. $(need_tool_hint apktool)"; finish_fail 2; }
  local out="$OUTPUT"
  [[ -n "$out" ]] || out="$(basename "$apk" .apk)-src"
  info "Decoding $apk -> $out"
  # shellcheck disable=SC2086
  $APKTOOL_CMD d -f -o "$out" "$apk" || { fail "apktool decode failed"; finish_fail 1; }
  ok "Decoded to $out"
  echo "DECODED_DIR=$out"
}

do_build() {
  local src="$1"
  [[ -d "$src" ]] || { fail "Decoded dir not found: $src"; finish_fail 1; }
  find_apktool || { fail "apktool not available. $(need_tool_hint apktool)"; finish_fail 2; }
  local out="$OUTPUT"
  [[ -n "$out" ]] || out="${src%/}-unsigned.apk"
  info "Building $src -> $out"
  # shellcheck disable=SC2086
  $APKTOOL_CMD b -o "$out" "$src" || {
    fail "apktool build failed. If it complains about framework resources, run: $APKTOOL_CMD if <framework.apk>"
    finish_fail 1
  }
  [[ -f "$out" ]] || { fail "Build produced no APK"; finish_fail 1; }
  ok "Built $out"
  echo "BUILT_APK=$out"
  BUILT_APK="$out"
}

do_sign() {
  local apk="$1"
  [[ -f "$apk" ]] || { fail "APK not found: $apk"; finish_fail 1; }
  local zipalign apksigner
  zipalign="$(find_build_tool zipalign)" || { fail "zipalign not found. $(need_tool_hint zipalign)"; finish_fail 2; }
  apksigner="$(find_build_tool apksigner)" || { fail "apksigner not found. $(need_tool_hint apksigner)"; finish_fail 2; }
  ensure_keystore

  local out="$OUTPUT"
  [[ -n "$out" ]] || out="$(basename "$apk" .apk)-signed.apk"
  local aligned
  aligned="$(dirname "$out")/.$(basename "$out" .apk)-aligned.apk"

  # zipalign MUST run before apksigner (apksigner preserves alignment; the
  # reverse order would invalidate the signature).
  info "Aligning (zipalign -p 4) -> $aligned"
  rm -f "$aligned"
  "$zipalign" -p -f 4 "$apk" "$aligned" || { fail "zipalign failed"; finish_fail 1; }

  info "Signing with $KEYSTORE"
  "$apksigner" sign \
    --ks "$KEYSTORE" --ks-key-alias androiddebugkey \
    --ks-pass "pass:$KS_PASS" --key-pass "pass:$KS_PASS" \
    --out "$out" "$aligned" || { fail "apksigner sign failed"; finish_fail 1; }
  rm -f "$aligned"

  "$apksigner" verify "$out" >/dev/null 2>&1 \
    && ok "Signature verifies" || warn "apksigner verify reported issues on $out"

  local sha
  sha="$("$apksigner" verify --print-certs "$out" 2>/dev/null \
        | grep -iE 'SHA-256 digest' | head -n1 | grep -oE '[0-9a-f]{64}' | head -n1 || true)"
  [[ -n "$sha" ]] || sha="unknown"
  ok "Signed -> $out"
  echo "SIGNED_APK=$out"
  echo "SIGNER_CERT_SHA256=$sha"
  SIGNED_APK="$out"
}

do_install() {
  local apk="$1"
  [[ -f "$apk" ]] || { fail "APK not found: $apk"; finish_fail 1; }
  command -v adb &>/dev/null || { fail "adb not found. $(need_tool_hint adb)"; finish_fail 2; }

  # Resolve package if not provided (needs aapt/aapt2).
  if [[ -z "$PKG" ]]; then
    local aapt
    if aapt="$(find_build_tool aapt2)" || aapt="$(find_build_tool aapt)"; then
      PKG="$("$aapt" dump badging "$apk" 2>/dev/null | sed -n "s/.*package: name='\([^']*\)'.*/\1/p" | head -n1 || true)"
      if [[ -z "$ACTIVITY" ]]; then
        ACTIVITY="$("$aapt" dump badging "$apk" 2>/dev/null | sed -n "s/.*launchable-activity: name='\([^']*\)'.*/\1/p" | head -n1 || true)"
      fi
    fi
  fi

  info "Installing $apk (adb install -r)"
  local install_out
  if install_out="$(adb install -r "$apk" 2>&1)"; then
    echo "INSTALL_STATUS=ok"
  else
    fail "adb install failed:"
    echo "$install_out" >&2
    if echo "$install_out" | grep -qi 'INSTALL_FAILED_UPDATE_INCOMPATIBLE\|signatures do not match'; then
      warn "Signature mismatch with the installed app. Uninstall the original first: adb uninstall ${PKG:-<pkg>}"
    fi
    echo "INSTALL_STATUS=failed"
    echo "LAUNCH_STATUS=unknown"
    finish_fail 1
  fi

  if [[ -z "$PKG" ]]; then
    warn "Package unknown (no aapt) — skipping launch health-check. Re-run with -p <pkg>."
    echo "LAUNCH_STATUS=unknown"
    return 0
  fi

  info "Launching $PKG and watching for 5s"
  adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
  adb logcat -c >/dev/null 2>&1 || true
  if [[ -n "$ACTIVITY" ]]; then
    adb shell am start -n "$PKG/$ACTIVITY" >/dev/null 2>&1 || true
  else
    adb shell monkey -p "$PKG" -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 || true
  fi
  sleep 5

  local crash pid
  crash="$(adb logcat -d 2>/dev/null | grep -iE 'FATAL EXCEPTION|beginning of crash' | head -n1 || true)"
  pid="$(adb shell pidof "$PKG" 2>/dev/null | tr -d '\r' || true)"

  if [[ -n "$crash" ]]; then
    warn "Crash detected in logcat: $crash"
    echo "LAUNCH_STATUS=crashed"
    finish_fail 1
  elif [[ -n "$pid" ]]; then
    ok "App running (pid $pid)"
    echo "LAUNCH_STATUS=running"
  else
    warn "App is not running after launch (exited or never started — possible RASP self-exit)."
    echo "LAUNCH_STATUS=exited"
    finish_fail 1
  fi
}

# --- Dispatch ---
case "$ACTION" in
  decode)  do_decode "$TARGET" ;;
  build)   do_build  "$TARGET" ;;
  sign)    do_sign   "$TARGET" ;;
  install) do_install "$TARGET" ;;
  all)
    do_build "$TARGET"
    OUTPUT=""            # let sign pick its default name from the built apk
    do_sign "$BUILT_APK"
    OUTPUT=""
    do_install "$SIGNED_APK"
    ;;
esac

echo "REPACK_RESULT=success"
exit 0
