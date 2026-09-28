#!/usr/bin/env bash
# detect-runtime.sh — Identify the app's UI/logic runtime.
#
# jadx only sees Dalvik bytecode. Apps built on Flutter, React Native, Unity,
# Xamarin, or Cordova keep their real logic in a Dart AOT snapshot, a JS bundle,
# native IL2CPP code, managed .NET DLLs, or HTML/JS assets — decompiling the Dex
# then yields a thin shell. Detecting the runtime first routes analysis to the
# correct toolchain (see references/framework-runtimes.md) instead of concluding
# "the app does nothing" from empty decompiler output.
set -euo pipefail

usage() {
  cat <<EOF
Usage: detect-runtime.sh <apk-or-dir> [OPTIONS]

Detect the framework/runtime an Android app is built on.

Arguments:
  <apk-or-dir>   An .apk/.xapk file, OR an extracted/decompiled directory
                 (one containing lib/<abi>/*.so, assets/, etc.).

Options:
  --report FILE  Write a Markdown report to FILE.
  --json FILE    Write findings as JSON to FILE.
  -h, --help     Show this help message.

Machine-readable output (printed to stdout):
  RUNTIME_HIT=<runtime>:<path>     (one line per matched artifact)
  RUNTIME_DETECTED=<flutter|react-native|unity-il2cpp|unity-mono|xamarin|cordova|native-java|multiple>
  RUNTIME_EVIDENCE=<path>
  RUNTIME_TOOL=<blutter|hermes-dec|il2cppdumper|ilspy|read-assets-www|jadx>

Exit codes:
  0  a non-standard runtime was detected -> load references/framework-runtimes.md
  2  plain native Java/Kotlin            -> proceed with the normal jadx flow
  1  usage / input error
EOF
  exit 0
}

TARGET=""
REPORT_FILE=""
JSON_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report) REPORT_FILE="$2"; shift 2 ;;
    --json)   JSON_FILE="$2"; shift 2 ;;
    -h|--help) usage ;;
    -*)       echo "Error: Unknown option $1" >&2; exit 1 ;;
    *)        TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Error: No target specified." >&2
  exit 1
fi
if [[ ! -e "$TARGET" ]]; then
  echo "Error: Not found: $TARGET" >&2
  exit 1
fi

# --- Resolve target to a directory ROOT --------------------------------------
ROOT=""
TMP_DIR=""
cleanup() { [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT

if [[ -d "$TARGET" ]]; then
  ROOT="$TARGET"
else
  ext_lower=$(echo "${TARGET##*.}" | tr '[:upper:]' '[:lower:]')
  case "$ext_lower" in
    apk|xapk|zip|aab) ;;
    *) echo "Error: Unsupported file '.$ext_lower' (want a dir or .apk/.xapk)." >&2; exit 1 ;;
  esac
  if ! command -v unzip &>/dev/null; then
    echo "[MISSING] unzip is required to inspect an APK archive." >&2
    exit 2
  fi
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/runtime-scan-XXXXXX")
  echo "[INFO] Extracting $(basename "$TARGET") for inspection..."
  unzip -qo "$TARGET" -d "$TMP_DIR" 2>/dev/null || true
  if [[ "$ext_lower" == "xapk" ]]; then
    inner_apk=$(find "$TMP_DIR" -maxdepth 2 -name '*.apk' | head -1 || true)
    [[ -n "$inner_apk" ]] && unzip -qo "$inner_apk" -d "$TMP_DIR/_base" 2>/dev/null || true
  fi
  ROOT="$TMP_DIR"
fi

# Search roots: ROOT, plus the unpacked XAPK base if present. Only include
# directories that exist, so `find` never errors under `set -o pipefail`.
SEARCH_ROOTS=("$ROOT")
[[ -d "$ROOT/_base" ]] && SEARCH_ROOTS+=("$ROOT/_base")

# --- Detection state ---------------------------------------------------------
HITS=()                    # "runtime|path"
declare -A RT_SEEN=()
FIRST_EVIDENCE=""

rel() { echo "${1#"$ROOT"/}"; }

exists_any() {
  # exists_any <find-args...> : print first matching path or empty
  { find "${SEARCH_ROOTS[@]}" "$@" 2>/dev/null || true; } | head -1
}

add_hit() {
  local rt="$1" path="$2"
  HITS+=("$rt|$path")
  RT_SEEN["$rt"]=1
  [[ -z "$FIRST_EVIDENCE" ]] && FIRST_EVIDENCE="$path"
  return 0
}

# --- Flutter -----------------------------------------------------------------
for p in \
  "$(exists_any -type f -name 'libflutter.so')" \
  "$(exists_any -type f -name 'libapp.so')" \
  "$(exists_any -type f -name 'kernel_blob.bin')" \
  "$(exists_any -type f -name 'isolate_snapshot_data')" \
  "$(exists_any -type f -name 'vm_snapshot_data')"; do
  [[ -n "$p" ]] && add_hit "flutter" "$(rel "$p")"
done

# --- React Native ------------------------------------------------------------
for p in \
  "$(exists_any -type f -name 'index.android.bundle')" \
  "$(exists_any -type f -name 'libreactnativejni.so')" \
  "$(exists_any -type f -name 'libhermes.so')" \
  "$(exists_any -type f -name 'libjsc.so')"; do
  [[ -n "$p" ]] && add_hit "react-native" "$(rel "$p")"
done
# Hermes bytecode bundle magic (0xC61FBC03, little-endian) at the start of the bundle.
rn_bundle=$(exists_any -type f -name 'index.android.bundle')
if [[ -n "$rn_bundle" && -r "$rn_bundle" ]]; then
  magic=$(head -c4 "$rn_bundle" 2>/dev/null | od -An -tx1 2>/dev/null | tr -d ' \n')
  if [[ "$magic" == "c61fbc03" ]]; then
    add_hit "react-native-hermes" "$(rel "$rn_bundle")"
  fi
fi

# --- Unity (IL2CPP vs Mono) --------------------------------------------------
il2cpp_so=$(exists_any -type f -name 'libil2cpp.so')
metadata=$(exists_any -type f -name 'global-metadata.dat')
if [[ -n "$il2cpp_so" || -n "$metadata" ]]; then
  [[ -n "$il2cpp_so" ]] && add_hit "unity-il2cpp" "$(rel "$il2cpp_so")"
  [[ -n "$metadata" ]]  && add_hit "unity-il2cpp" "$(rel "$metadata")"
fi
mono_so=$(exists_any -type f -name 'libmono*.so')
unity_so=$(exists_any -type f -name 'libunity.so')
if [[ -n "$mono_so" && -z "$il2cpp_so" ]]; then
  add_hit "unity-mono" "$(rel "$mono_so")"
elif [[ -n "$unity_so" && -z "$il2cpp_so" && -z "$metadata" ]]; then
  add_hit "unity-mono" "$(rel "$unity_so")"
fi

# --- Xamarin / .NET ----------------------------------------------------------
for p in \
  "$(exists_any -type f -name 'libmonodroid.so')" \
  "$(exists_any -type f -name 'libmonosgen*.so')" \
  "$(exists_any -type f -path '*/assemblies/*.dll')" \
  "$(exists_any -type f -name 'libxamarin-app.so')"; do
  [[ -n "$p" ]] && add_hit "xamarin" "$(rel "$p")"
done

# --- Cordova / Ionic / Capacitor ---------------------------------------------
for p in \
  "$(exists_any -type f -name 'cordova.js')" \
  "$(exists_any -type f -name 'capacitor.config.json')" \
  "$(exists_any -type d -path '*/assets/www')" \
  "$(exists_any -type f -name 'cordova_plugins.js')"; do
  [[ -n "$p" ]] && add_hit "cordova" "$(rel "$p")"
done

# --- Classify ----------------------------------------------------------------
# Collapse hermes into react-native for the top-level verdict but keep the tool hint.
declare -A NORM=()
for rt in "${!RT_SEEN[@]}"; do
  case "$rt" in
    react-native-hermes) NORM["react-native"]=1 ;;
    *) NORM["$rt"]=1 ;;
  esac
done

runtimes=("${!NORM[@]}")
DETECTED="native-java"
TOOL="jadx"

pick_tool() {
  case "$1" in
    flutter)        echo "blutter" ;;
    react-native)   [[ -n "${RT_SEEN[react-native-hermes]:-}" ]] && echo "hermes-dec" || echo "read-assets-www" ;;
    unity-il2cpp)   echo "il2cppdumper" ;;
    unity-mono)     echo "ilspy" ;;
    xamarin)        echo "ilspy" ;;
    cordova)        echo "read-assets-www" ;;
    *)              echo "jadx" ;;
  esac
}

if [[ ${#runtimes[@]} -eq 1 ]]; then
  DETECTED="${runtimes[0]}"
  TOOL=$(pick_tool "$DETECTED")
elif [[ ${#runtimes[@]} -gt 1 ]]; then
  DETECTED="multiple"
  # Tool hint follows the first (highest-signal) evidence's runtime.
  first_rt="${HITS[0]%%|*}"
  case "$first_rt" in react-native-hermes) first_rt="react-native" ;; esac
  TOOL=$(pick_tool "$first_rt")
fi

# --- Summary -----------------------------------------------------------------
echo
echo "=== Runtime Detection ==="
if [[ ${#HITS[@]} -eq 0 ]]; then
  echo "[OK] No cross-platform runtime markers found — looks like native Java/Kotlin."
else
  for h in "${HITS[@]}"; do
    IFS='|' read -r rt path <<<"$h"
    echo "RUNTIME_HIT=${rt}:${path}"
  done
fi
echo
echo "RUNTIME_DETECTED=${DETECTED}"
[[ -n "$FIRST_EVIDENCE" ]] && echo "RUNTIME_EVIDENCE=${FIRST_EVIDENCE}"
echo "RUNTIME_TOOL=${TOOL}"

# --- Markdown report ---------------------------------------------------------
if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# Runtime Detection Report"
    echo
    echo "- Target: \`$TARGET\`"
    echo "- Detected runtime: **${DETECTED}**"
    echo "- Suggested tool: \`${TOOL}\`"
    echo
    if [[ ${#HITS[@]} -gt 0 ]]; then
      echo "| Runtime | Artifact |"
      echo "|---|---|"
      for h in "${HITS[@]}"; do
        IFS='|' read -r rt path <<<"$h"
        echo "| ${rt} | \`${path}\` |"
      done
    else
      echo "No cross-platform runtime markers — proceed with jadx."
    fi
    echo
    echo "See \`references/framework-runtimes.md\` for the per-runtime toolchain."
  } > "$REPORT_FILE"
  echo "REPORT_FILE=${REPORT_FILE}"
fi

# --- JSON --------------------------------------------------------------------
if [[ -n "$JSON_FILE" ]]; then
  {
    printf '{\n'
    printf '  "target": "%s",\n' "$TARGET"
    printf '  "detected": "%s",\n' "$DETECTED"
    printf '  "tool": "%s",\n' "$TOOL"
    printf '  "evidence": "%s",\n' "$FIRST_EVIDENCE"
    printf '  "hits": ['
    for i in "${!HITS[@]}"; do
      IFS='|' read -r rt path <<<"${HITS[$i]}"
      [[ "$i" -gt 0 ]] && printf ','
      printf '{"runtime":"%s","artifact":"%s"}' "$rt" "$path"
    done
    printf ']\n'
    printf '}\n'
  } > "$JSON_FILE"
  echo "JSON_FILE=${JSON_FILE}"
fi

# --- Exit code ---------------------------------------------------------------
if [[ "$DETECTED" == "native-java" ]]; then
  exit 2
else
  exit 0
fi
