#!/usr/bin/env bash
# analyze-native.sh — Static triage of native .so libraries in an Android app.
#
# The skill's Java/Kotlin analysis stops at the JNI boundary. RASP, crypto, and
# string protection increasingly live in native code, and the Frida phase often
# trips over SIGABRT / libsecurity.so crashes it cannot investigate. This script
# enumerates the .so libraries per ABI and surfaces, for each one: ELF deps,
# exported JNI functions (static binding), JNI_OnLoad presence (dynamic binding
# via RegisterNatives), native anti-tamper / anti-analysis indicators, and a
# short sample of interesting strings (URLs, crypto, su/root paths).
#
# It is a triage tool, not a decompiler: symbol-name and string matches are
# INFERRED leads (see references/verification.md), to be confirmed by loading the
# library into radare2/Ghidra or by hooking with Frida. See
# references/native-and-so.md for the full playbook.
#
# Machine-readable output (stdout):
#   NATIVE_SCAN=true
#   ABI_LIST=<abi,abi,...>
#   SO=<name>:<abi>
#   NEEDED=<name>:<dep>
#   JNI_EXPORT=<lib>:<Java_symbol>
#   JNI_ONLOAD=<lib>
#   REGISTER_NATIVES=<lib>            (inferred: JNI_OnLoad present)
#   NATIVE_ANTITAMPER=<lib>:<indicator>
#   NATIVE_STRING=<lib>:<kind>:<short excerpt>
#   SO_COUNT=<n>
#   JNI_EXPORT_COUNT=<n>
#   ANTITAMPER_COUNT=<n>
#   REPORT_FILE=<path>   (if --report)
#   JSON_FILE=<path>     (if --json)
#
# Exit codes:
#   0  scan completed (with or without findings)
#   1  usage / input error
set -euo pipefail

usage() {
  cat <<EOF
Usage: analyze-native.sh <target> [OPTIONS]

Statically triage the native .so libraries bundled in an Android app.

Arguments:
  <target>          An .apk/.xapk file, an extracted APK directory, a decompile
                    output directory, or a lib/ directory. The script finds
                    lib/<abi>/*.so beneath it (or treats *.so directly).

Options:
  --abi ABI         Restrict to one ABI (arm64-v8a, armeabi-v7a, x86, x86_64).
  --strings-min N   Minimum string length to extract (default: 6).
  --report FILE     Write a structured Markdown report to FILE.
  --json FILE       Write findings as JSON to FILE.
  -h, --help        Show this help.

Tools used when present (degrades gracefully if missing):
  readelf, nm, objdump  — ELF symbols / dynamic section
  rabin2 (radare2)      — fallback symbol/import/string extraction
  strings, file, unzip

Next steps after this triage:
  - Load a flagged library into radare2/Ghidra (references/native-and-so.md).
  - If a native method has no Java_* export, it is bound dynamically via
    RegisterNatives — dump the mapping at runtime by hooking
    art::JNI::RegisterNatives with Frida (Phase 7).
  - Hand deep native RE to the skw-analyzing-binaries /
    skw-exploiting-memory-corruption skills.
EOF
  exit 0
}

TARGET=""
ABI_FILTER=""
STRINGS_MIN=6
REPORT_FILE=""
JSON_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --abi)         ABI_FILTER="$2"; shift 2 ;;
    --strings-min) STRINGS_MIN="$2"; shift 2 ;;
    --report)      REPORT_FILE="$2"; shift 2 ;;
    --json)        JSON_FILE="$2"; shift 2 ;;
    -h|--help)     usage ;;
    -*)            echo "Error: Unknown option $1" >&2; exit 1 ;;
    *)             TARGET="$1"; shift ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "Error: No target specified." >&2
  exit 1
fi
if [[ ! -e "$TARGET" ]]; then
  echo "Error: Target not found: $TARGET" >&2
  exit 1
fi

# --- Tool discovery ----------------------------------------------------------
HAVE_READELF=false; command -v readelf &>/dev/null && HAVE_READELF=true
HAVE_NM=false;      command -v nm      &>/dev/null && HAVE_NM=true
HAVE_OBJDUMP=false; command -v objdump &>/dev/null && HAVE_OBJDUMP=true
HAVE_RABIN2=false;  command -v rabin2  &>/dev/null && HAVE_RABIN2=true
HAVE_STRINGS=false; command -v strings &>/dev/null && HAVE_STRINGS=true

if ! $HAVE_READELF && ! $HAVE_NM && ! $HAVE_OBJDUMP && ! $HAVE_RABIN2; then
  echo "[WARN] No symbol tools found (readelf/nm/objdump/rabin2)." >&2
  echo "[WARN] Falling back to strings-only analysis. Install binutils or radare2 for symbols." >&2
fi
if ! $HAVE_STRINGS; then
  echo "[INFO] 'strings' not found — using a grep-based fallback for string extraction." >&2
fi

# --- Resolve the set of .so files to inspect ---------------------------------
TMP_EXTRACT=""
cleanup() { [[ -n "$TMP_EXTRACT" && -d "$TMP_EXTRACT" ]] && rm -rf "$TMP_EXTRACT"; return 0; }
trap cleanup EXIT

SEARCH_ROOT=""
ext_lower=""
if [[ -f "$TARGET" ]]; then
  ext_lower="$(echo "${TARGET##*.}" | tr '[:upper:]' '[:lower:]')"
fi

if [[ -f "$TARGET" && ( "$ext_lower" == "apk" || "$ext_lower" == "xapk" || "$ext_lower" == "zip" ) ]]; then
  if ! command -v unzip &>/dev/null; then
    echo "Error: unzip is required to inspect an .$ext_lower file." >&2
    exit 1
  fi
  TMP_EXTRACT="$(mktemp -d "${TMPDIR:-/tmp}/native-scan-XXXXXX")"
  echo "[INFO] Extracting $(basename "$TARGET") to inspect native libraries..." >&2
  # Only extract lib/ to stay fast on large APKs; fall back to full extract.
  unzip -qo "$TARGET" 'lib/*' -d "$TMP_EXTRACT" 2>/dev/null || unzip -qo "$TARGET" -d "$TMP_EXTRACT" 2>/dev/null || true
  # XAPK: also unpack any inner APKs' lib/ dirs.
  while IFS= read -r -d '' inner; do
    unzip -qo "$inner" 'lib/*' -d "$TMP_EXTRACT" 2>/dev/null || true
  done < <(find "$TMP_EXTRACT" -name '*.apk' -print0 2>/dev/null)
  SEARCH_ROOT="$TMP_EXTRACT"
elif [[ -f "$TARGET" && "$ext_lower" == "so" ]]; then
  SEARCH_ROOT=""   # single-file mode handled below
else
  SEARCH_ROOT="$TARGET"
fi

SO_FILES=()
if [[ -f "$TARGET" && "$ext_lower" == "so" ]]; then
  SO_FILES+=("$TARGET")
else
  while IFS= read -r -d '' so; do
    SO_FILES+=("$so")
  done < <(find "$SEARCH_ROOT" -type f -name '*.so' -print0 2>/dev/null | sort -z)
fi

echo "NATIVE_SCAN=true"

if [[ ${#SO_FILES[@]} -eq 0 ]]; then
  echo "[INFO] No .so libraries found under: $TARGET"
  echo "SO_COUNT=0"
  echo "JNI_EXPORT_COUNT=0"
  echo "ANTITAMPER_COUNT=0"
  echo "[INFO] App may be pure Java/Kotlin, or native code is delivered another way."
  exit 0
fi

# --- Helpers -----------------------------------------------------------------
abi_of() {
  # Derive ABI from the lib/<abi>/ path component; fall back to ELF machine.
  local path="$1" abi=""
  abi="$(echo "$path" | sed -nE 's#.*/lib/([^/]+)/[^/]+\.so$#\1#p')"
  if [[ -z "$abi" && "$HAVE_READELF" == true ]]; then
    local machine
    machine="$(readelf -h "$path" 2>/dev/null | sed -nE 's/.*Machine:[[:space:]]*(.*)/\1/p' | head -n1)"
    case "$machine" in
      *AArch64*) abi="arm64-v8a" ;;
      *ARM*)     abi="armeabi-v7a" ;;
      *X86-64*|*x86-64*) abi="x86_64" ;;
      *80386*|*Intel*)   abi="x86" ;;
      *) abi="unknown" ;;
    esac
  fi
  [[ -z "$abi" ]] && abi="unknown"
  echo "$abi"
}

dyn_syms() {
  # Emit dynamic symbol names, one per line, best available tool.
  local so="$1"
  if $HAVE_READELF; then
    readelf -W --dyn-syms "$so" 2>/dev/null | awk '{print $NF}'
  elif $HAVE_NM; then
    nm -D --defined-only "$so" 2>/dev/null | awk '{print $NF}'
  elif $HAVE_RABIN2; then
    rabin2 -qs "$so" 2>/dev/null | awk '{print $NF}'
  fi
}

needed_libs() {
  local so="$1"
  if $HAVE_READELF; then
    readelf -d "$so" 2>/dev/null | sed -nE 's/.*\(NEEDED\).*\[(.*)\]/\1/p'
  elif $HAVE_OBJDUMP; then
    objdump -p "$so" 2>/dev/null | sed -nE 's/^[[:space:]]*NEEDED[[:space:]]+(.*)/\1/p'
  elif $HAVE_RABIN2; then
    rabin2 -ql "$so" 2>/dev/null
  fi
}

extract_strings() {
  local so="$1"
  if $HAVE_STRINGS; then
    strings -n "$STRINGS_MIN" "$so" 2>/dev/null
  else
    LC_ALL=C grep -aoE "[[:print:]]{$STRINGS_MIN,}" "$so" 2>/dev/null
  fi
}

# --- Accumulators for report/JSON --------------------------------------------
declare -A ABIS_SEEN=()
SO_COUNT=0
JNI_EXPORT_COUNT=0
ANTITAMPER_COUNT=0
REPORT_LIBS=()          # "name|abi|jniexports|antitamper|needed"

# Anti-tamper / anti-analysis indicator strings to flag.
ANTITAMPER_PATTERNS='ptrace|PTRACE_TRACEME|TracerPid|/proc/self/status|/proc/self/maps|/proc/net/tcp|frida|gum-js-loop|gmain|linjector|re\.frida|xposed|substrate|LD_PRELOAD|dladdr|inotify_init|/proc/self/task|magisk|/sbin/su|which su|/system/bin/su|GetApkSignature|getPackageInfo|checkSignature|CRC32'

echo "[INFO] Found ${#SO_FILES[@]} native library file(s). Analyzing..." >&2

for so in "${SO_FILES[@]}"; do
  name="$(basename "$so")"
  abi="$(abi_of "$so")"
  [[ -n "$ABI_FILTER" && "$abi" != "$ABI_FILTER" ]] && continue

  SO_COUNT=$((SO_COUNT + 1))
  ABIS_SEEN["$abi"]=1
  echo "SO=${name}:${abi}"

  # NEEDED deps
  while IFS= read -r dep; do
    [[ -z "$dep" ]] && continue
    echo "NEEDED=${name}:${dep}"
  done < <(needed_libs "$so")

  # Dynamic symbols → JNI exports + JNI_OnLoad
  syms="$(dyn_syms "$so" || true)"
  jni_here=0
  while IFS= read -r sym; do
    [[ "$sym" == Java_* ]] || continue
    echo "JNI_EXPORT=${name}:${sym}"
    jni_here=$((jni_here + 1))
    JNI_EXPORT_COUNT=$((JNI_EXPORT_COUNT + 1))
  done < <(printf '%s\n' "$syms")

  has_onload=false
  if printf '%s\n' "$syms" | grep -q '^JNI_OnLoad$'; then
    has_onload=true
    echo "JNI_ONLOAD=${name}"
    # JNI_OnLoad present is the strongest static signal of dynamic binding.
    echo "REGISTER_NATIVES=${name}"
  fi
  if [[ "$jni_here" -eq 0 && "$has_onload" == false ]]; then
    # No Java_* exports and no JNI_OnLoad symbol: could be a helper lib, or
    # symbols are stripped. Still flag if JNI_OnLoad appears as a string.
    if extract_strings "$so" | grep -q 'JNI_OnLoad'; then
      echo "JNI_ONLOAD=${name}"
      echo "REGISTER_NATIVES=${name}"
      has_onload=true
    fi
  fi

  # Anti-tamper indicators (strings + undefined imports)
  at_hits=""
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    ind="$(echo "$hit" | grep -oiE "$ANTITAMPER_PATTERNS" | head -n1)"
    [[ -z "$ind" ]] && continue
    case " $at_hits " in *" $ind "*) ;; *)
      at_hits="$at_hits $ind"
      echo "NATIVE_ANTITAMPER=${name}:${ind}"
      ANTITAMPER_COUNT=$((ANTITAMPER_COUNT + 1))
    ;; esac
  done < <(extract_strings "$so" | grep -iE "$ANTITAMPER_PATTERNS" | head -n 200)

  # Interesting strings, classified, capped and truncated.
  # (|| true on each pipeline: a no-match grep exits 1, which would otherwise
  #  abort the whole scan under set -e + pipefail.)
  # URLs
  while IFS= read -r u; do
    [[ -z "$u" ]] && continue
    echo "NATIVE_STRING=${name}:url:${u:0:120}"
  done < <(extract_strings "$so" | grep -aoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' | sort -u | head -n 10 || true)
  # Crypto hints
  while IFS= read -r c; do
    [[ -z "$c" ]] && continue
    echo "NATIVE_STRING=${name}:crypto:${c:0:60}"
  done < <(extract_strings "$so" | grep -aoiE 'AES(/[A-Z0-9]+)?|RSA|DES|ECB|CBC|GCM|PKCS[0-9]|HmacSHA[0-9]+|BEGIN (RSA |EC |)PRIVATE KEY' | sort -u | head -n 8 || true)
  # Root/su/system hints
  if extract_strings "$so" | grep -qaE '/system/bin/su|/sbin/su|which su|magisk'; then
    echo "NATIVE_STRING=${name}:root-check:present"
  fi

  needed_join="$(needed_libs "$so" | tr '\n' ',' | sed 's/,$//' || true)"
  REPORT_LIBS+=("${name}|${abi}|${jni_here}|$(echo "$at_hits" | sed 's/^ //;s/ /,/g')|${needed_join}")
done

ABI_LIST="$(printf '%s\n' "${!ABIS_SEEN[@]}" | sort | tr '\n' ',' | sed 's/,$//')"
echo "ABI_LIST=${ABI_LIST}"
echo "SO_COUNT=${SO_COUNT}"
echo "JNI_EXPORT_COUNT=${JNI_EXPORT_COUNT}"
echo "ANTITAMPER_COUNT=${ANTITAMPER_COUNT}"

# --- Optional Markdown report ------------------------------------------------
if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# Native library triage"
    echo
    echo "- Target: \`${TARGET}\`"
    echo "- ABIs: \`${ABI_LIST}\`"
    echo "- Libraries: ${SO_COUNT} · JNI exports: ${JNI_EXPORT_COUNT} · anti-tamper indicators: ${ANTITAMPER_COUNT}"
    echo
    echo "> Findings below are INFERRED leads (symbol/string matches). Confirm by"
    echo "> loading the library into radare2/Ghidra or hooking with Frida. See"
    echo "> references/native-and-so.md and references/verification.md."
    echo
    echo "| Library | ABI | Java_* exports | Anti-tamper indicators | NEEDED |"
    echo "|---|---|---|---|---|"
    for row in "${REPORT_LIBS[@]}"; do
      IFS='|' read -r n a j at nd <<< "$row"
      [[ -z "$at" ]] && at="—"
      [[ -z "$nd" ]] && nd="—"
      echo "| \`${n}\` | ${a} | ${j} | ${at} | ${nd} |"
    done
    echo
    echo "## Interpretation"
    echo
    echo "- A library with **JNI_OnLoad but zero \`Java_*\` exports** binds its"
    echo "  native methods dynamically via RegisterNatives — dump the mapping at"
    echo "  runtime (hook \`art::JNI::RegisterNatives\`)."
    echo "- Anti-tamper indicators (ptrace, TracerPid, frida, signature/CRC checks)"
    echo "  are where the Frida phase's SIGABRT/immediate-exit crashes originate."
    echo "  Map each to a hook point per references/native-and-so.md."
  } > "$REPORT_FILE"
  echo "REPORT_FILE=${REPORT_FILE}"
fi

# --- Optional JSON report ----------------------------------------------------
if [[ -n "$JSON_FILE" ]]; then
  {
    echo "{"
    echo "  \"target\": \"${TARGET}\","
    echo "  \"abis\": \"${ABI_LIST}\","
    echo "  \"so_count\": ${SO_COUNT},"
    echo "  \"jni_export_count\": ${JNI_EXPORT_COUNT},"
    echo "  \"antitamper_count\": ${ANTITAMPER_COUNT},"
    printf '  "libraries": ['
    for i in "${!REPORT_LIBS[@]}"; do
      [[ "$i" -gt 0 ]] && printf ','
      IFS='|' read -r n a j at nd <<< "${REPORT_LIBS[$i]}"
      printf '{"name":"%s","abi":"%s","jni_exports":%s,"antitamper":"%s","needed":"%s"}' \
        "$n" "$a" "${j:-0}" "$at" "$nd"
    done
    echo "]"
    echo "}"
  } > "$JSON_FILE"
  echo "JSON_FILE=${JSON_FILE}"
fi

exit 0
