#!/usr/bin/env bash
# detect-packer.sh — Fingerprint common Android packers/protectors.
#
# Scans an APK/XAPK file or an already-extracted/decompiled directory for the
# native libraries, asset blobs, and stub application classes that identify a
# commercial packer. A packed app decrypts its real Dex only at runtime, so
# jadx on the shipped APK yields little — detecting the packer first tells you
# to switch to a runtime-dump workflow (see references/packers.md) instead of
# reasoning past empty decompiler output.
set -euo pipefail

usage() {
  cat <<EOF
Usage: detect-packer.sh <apk-or-dir> [OPTIONS]

Fingerprint the packer/protector used by an Android app.

Arguments:
  <apk-or-dir>   An .apk/.xapk file, OR an extracted/decompiled directory
                 (one containing lib/<abi>/*.so, assets/, AndroidManifest.xml).

Options:
  --report FILE  Write a Markdown report to FILE.
  --json FILE    Write findings as JSON to FILE.
  -h, --help     Show this help message.

Machine-readable output (printed to stdout):
  PACKER_HIT=<family>:<path>     (one line per matched artifact)
  PACKER_DETECTED=<family|none>  (best guess; "unknown-packer" for heuristic-only)
  PACKER_CONFIDENCE=high|medium|low
  PACKER_EVIDENCE=<path>         (the strongest single artifact, if any)

Exit codes:
  0  a packer/protector was detected   -> load references/packers.md, dump at runtime
  2  no packer signatures found        -> proceed with normal decompilation
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
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/packer-scan-XXXXXX")
  echo "[INFO] Extracting $(basename "$TARGET") for inspection..."
  unzip -qo "$TARGET" -d "$TMP_DIR" 2>/dev/null || true
  # XAPK: unpack the inner base APK too so lib/ and assets/ are visible.
  if [[ "$ext_lower" == "xapk" ]]; then
    inner_apk=$(find "$TMP_DIR" -maxdepth 2 -name '*.apk' | head -1 || true)
    if [[ -n "$inner_apk" ]]; then
      unzip -qo "$inner_apk" -d "$TMP_DIR/_base" 2>/dev/null || true
    fi
  fi
  ROOT="$TMP_DIR"
fi

# Search roots: ROOT, plus the unpacked XAPK base if present. Only include
# directories that exist, so `find` never errors under `set -o pipefail`.
SEARCH_ROOTS=("$ROOT")
[[ -d "$ROOT/_base" ]] && SEARCH_ROOTS+=("$ROOT/_base")

shopt -s nullglob

# --- Detection state ---------------------------------------------------------
HITS=()                    # "family|path|confidence"
declare -A FAMILY_SEEN=()
BEST_CONF="none"
BEST_FAMILY="none"
BEST_EVIDENCE=""

conf_rank() { case "$1" in high) echo 3 ;; medium) echo 2 ;; low) echo 1 ;; *) echo 0 ;; esac; }

add_hit() {
  local family="$1" path="$2" conf="$3"
  HITS+=("$family|$path|$conf")
  FAMILY_SEEN["$family"]=1
  if (( $(conf_rank "$conf") > $(conf_rank "$BEST_CONF") )); then
    BEST_CONF="$conf"; BEST_FAMILY="$family"; BEST_EVIDENCE="$path"
  fi
}

rel() { echo "${1#"$ROOT"/}"; }

# --- 1. Native library signatures (highest confidence) -----------------------
while IFS= read -r -d '' so; do
  b=$(basename "$so"); lb=${b,,}
  case "$lb" in
    libsecexe.so|libsecmain.so|libsecshell*.so|libnsaferonly*.so)
      add_hit "Bangcle/SecShell" "$(rel "$so")" high ;;
    libjiagu*.so)
      add_hit "Qihoo360-Jiagu" "$(rel "$so")" high ;;
    libshell*.so|libshella*.so|libshellx*.so|libtup.so|libtxsq*.so|libtmsdual*.so|libtprt.so)
      add_hit "Tencent-Legu" "$(rel "$so")" high ;;
    libmobisec.so|libsgmain*.so|libsgsecuritybody*.so|libaliprotect*.so)
      add_hit "Alibaba/AliProtect" "$(rel "$so")" high ;;
    libbaiduprotect*.so)
      add_hit "Baidu" "$(rel "$so")" high ;;
    libnesec*.so|libnepub*.so)
      add_hit "NetEase" "$(rel "$so")" high ;;
    libdexprotector*.so|libdexpro*.so)
      add_hit "DexProtector" "$(rel "$so")" high ;;
    libapkprotect*.so)
      add_hit "APKProtect" "$(rel "$so")" high ;;
    libvdog*.so|libv3*.so|libvirbox*.so)
      add_hit "Naga/Virbox" "$(rel "$so")" high ;;
    libdexhelper*.so|libnqshield*.so|libddog*.so|libchaosvmp*.so|libddjvm*.so)
      add_hit "Kiwi/SecNeo" "$(rel "$so")" high ;;
    libmogosec*.so|libpreverify*.so)
      add_hit "Mogo/generic-protector" "$(rel "$so")" medium ;;
  esac
done < <(find "${SEARCH_ROOTS[@]}" -type f -name '*.so' -print0 2>/dev/null)

# --- 2. Asset blobs: encrypted / hidden dex payloads -------------------------
# A dex file begins with the magic bytes "dex\n" (64 65 78 0a).
is_dex_magic() {
  local f="$1"
  [[ -r "$f" ]] || return 1
  local magic
  magic=$(head -c4 "$f" 2>/dev/null | tr -d '\0')
  [[ "$magic" == dex* ]]
}

for cand in \
  "$ROOT"/assets/* "$ROOT"/_base/assets/* \
  "$ROOT"/assets/**/* "$ROOT"/_base/assets/**/*; do
  [[ -f "$cand" ]] || continue
  cb=$(basename "$cand"); lcb=${cb,,}
  case "$lcb" in
    classes0.dex|*.dp|*.ml|dhconfig*|libjiagu*|baiduprotect*|*sec*.dat|*.mp3.dex)
      add_hit "packed-asset" "$(rel "$cand")" medium ;;
  esac
  # A dex-format blob hiding under a non-.dex extension is a strong packer tell.
  case "$lcb" in
    *.dat|*.bin|*.jar|*.mp3|*.png|*.dex0)
      if is_dex_magic "$cand"; then
        add_hit "hidden-dex-asset" "$(rel "$cand")" high
      fi ;;
  esac
done

# --- 3. Stub application class in the manifest -------------------------------
# Works on both binary AXML (raw APK) and text manifests (decompiled dir).
MANIFEST=""
for m in "$ROOT/AndroidManifest.xml" "$ROOT/resources/AndroidManifest.xml" "$ROOT/_base/AndroidManifest.xml"; do
  [[ -f "$m" ]] && { MANIFEST="$m"; break; }
done
if [[ -n "$MANIFEST" ]]; then
  stub=$(strings -a "$MANIFEST" 2>/dev/null | grep -ioE \
    'com\.(secneo|stub|tencent\.StubShell|qihoo|ali\.mobisecenhance|baidu\.protect|netease)[.A-Za-z0-9]*|(^|\.)StubApp|StubApplication|ProxyApplication|AppWrapper|s\.h\.e\.l\.l[.A-Za-z0-9]*' \
    | head -1 || true)
  if [[ -n "$stub" ]]; then
    add_hit "stub-application:$stub" "$(rel "$MANIFEST")" medium
  fi
fi

# --- 4. Multiple root classesN.dex (weak signal on its own) ------------------
dex_count=$( { find "${SEARCH_ROOTS[@]}" -maxdepth 1 -name 'classes*.dex' 2>/dev/null || true; } | wc -l | tr -d ' ')
if (( dex_count > 3 )); then
  add_hit "multi-dex(${dex_count})" "$(rel "$ROOT")" low
fi

# --- Summary -----------------------------------------------------------------
echo
echo "=== Packer Detection ==="
if [[ ${#HITS[@]} -eq 0 ]]; then
  echo "[OK] No known packer/protector signatures found."
else
  for h in "${HITS[@]}"; do
    IFS='|' read -r fam path conf <<<"$h"
    echo "PACKER_HIT=${fam}:${path}"
  done
fi
echo

# If only heuristic (medium/low) hits, report unknown-packer rather than a name.
DETECTED="none"
if [[ ${#HITS[@]} -gt 0 ]]; then
  if [[ "$BEST_CONF" == "high" ]]; then
    DETECTED="$BEST_FAMILY"
  else
    # Prefer a concrete family name if any family was named, else unknown.
    DETECTED="${BEST_FAMILY:-unknown-packer}"
    [[ "$DETECTED" == "none" ]] && DETECTED="unknown-packer"
  fi
fi

echo "PACKER_DETECTED=${DETECTED}"
echo "PACKER_CONFIDENCE=${BEST_CONF}"
[[ -n "$BEST_EVIDENCE" ]] && echo "PACKER_EVIDENCE=${BEST_EVIDENCE}"

# --- Markdown report ---------------------------------------------------------
if [[ -n "$REPORT_FILE" ]]; then
  {
    echo "# Packer Detection Report"
    echo
    echo "- Target: \`$TARGET\`"
    echo "- Detected: **${DETECTED}** (confidence: ${BEST_CONF})"
    echo
    if [[ ${#HITS[@]} -gt 0 ]]; then
      echo "| Family | Artifact | Confidence |"
      echo "|---|---|---|"
      for h in "${HITS[@]}"; do
        IFS='|' read -r fam path conf <<<"$h"
        echo "| ${fam} | \`${path}\` | ${conf} |"
      done
    else
      echo "No known packer signatures found."
    fi
    echo
    echo "Next step: if a packer is detected, see \`references/packers.md\` — the"
    echo "real Dex must be dumped from memory at runtime, then re-validated with"
    echo "\`dex-byte-patch.py --verify\` and re-decompiled."
  } > "$REPORT_FILE"
  echo "REPORT_FILE=${REPORT_FILE}"
fi

# --- JSON --------------------------------------------------------------------
if [[ -n "$JSON_FILE" ]]; then
  {
    printf '{\n'
    printf '  "target": "%s",\n' "$TARGET"
    printf '  "detected": "%s",\n' "$DETECTED"
    printf '  "confidence": "%s",\n' "$BEST_CONF"
    printf '  "evidence": "%s",\n' "$BEST_EVIDENCE"
    printf '  "hits": ['
    for i in "${!HITS[@]}"; do
      IFS='|' read -r fam path conf <<<"${HITS[$i]}"
      [[ "$i" -gt 0 ]] && printf ','
      printf '{"family":"%s","artifact":"%s","confidence":"%s"}' "$fam" "$path" "$conf"
    done
    printf ']\n'
    printf '}\n'
  } > "$JSON_FILE"
  echo "JSON_FILE=${JSON_FILE}"
fi

# --- Exit code ---------------------------------------------------------------
if [[ ${#HITS[@]} -gt 0 ]]; then
  exit 0
else
  exit 2
fi
