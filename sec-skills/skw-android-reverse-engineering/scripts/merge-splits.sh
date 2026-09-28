#!/usr/bin/env bash
# merge-splits.sh — Merge a split-APK set (base.apk + split_config.*.apk / feature
# splits) into a single APK so the normal decompile flow can process it.
#
# Modern apps ship as split APKs (App Bundle output). Decompiling only base.apk
# misses code that lives in feature splits. Density/language config splits carry
# no code, so when only those are present, base.apk alone is sufficient.
#
# Input modes:
#   <dir>                     directory containing multiple .apk files → merge all
#   <archive.apks|.xapk>      extract, then merge the APKs inside
#   --device -p <package>     `adb shell pm path <package>`, pull every apk, merge
#
# Merge engine: APKEditor (java -jar APKEditor.jar m -i <dir> -o <out.apk>).
# Locate via APKEDITOR_JAR env, PATH (`apkeditor`), or common ~/.local paths.
#
# Machine-readable output:
#   SPLIT_COUNT=<n>           number of APKs in the set
#   CODE_SPLITS=<n>           how many contain a classes*.dex
#   MERGED_APK=<path>         path to the merged APK (on success)
#   MERGE_RESULT=success|failed|not-needed
#
# Exit codes: 0 success or not-needed, 1 failure, 2 tool missing / manual action.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: merge-splits.sh [OPTIONS] [<dir>|<archive.apks|.xapk>]

Merge a split-APK set into one APK for analysis.

Modes:
  merge-splits.sh <dir>                 Merge all .apk files in a directory
  merge-splits.sh <archive.apks|.xapk>  Extract archive, then merge
  merge-splits.sh --device -p <pkg>     Pull the installed split set, then merge

Options:
  -o, --output FILE   Output merged APK path (default: <name>-merged.apk)
  --device            Pull the split set from a connected device via adb
  -p, --package PKG   Package name (required with --device)
  -h, --help          Show this help

Environment:
  APKEDITOR_JAR       Path to APKEditor.jar

Notes:
  Requires APKEditor (https://github.com/REAndroid/APKEditor) and a JRE.
  If only density/language config splits are present (no feature-split code),
  base.apk alone is enough — the script reports MERGE_RESULT=not-needed.
EOF
  exit 0
}

OUTPUT=""
FROM_DEVICE=false
PACKAGE=""
TARGET=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output)  OUTPUT="$2"; shift 2 ;;
    --device)     FROM_DEVICE=true; shift ;;
    -p|--package) PACKAGE="$2"; shift 2 ;;
    -h|--help)    usage ;;
    -*)           echo "Error: unknown option $1" >&2; usage ;;
    *)            TARGET="$1"; shift ;;
  esac
done

info()  { echo "[INFO] $*"; }
ok()    { echo "[OK] $*"; }
warn()  { echo "[WARN] $*" >&2; }
fail()  { echo "[FAIL] $*" >&2; }

# --- Locate APKEditor ---
find_apkeditor() {
  if command -v apkeditor &>/dev/null; then
    echo "apkeditor"; return 0
  fi
  for candidate in \
    "${APKEDITOR_JAR:-}" \
    "$HOME/.local/share/apkeditor/APKEditor.jar" \
    "$HOME/.local/share/skw-android-re/APKEditor.jar" \
    "$HOME/APKEditor.jar"; do
    if [[ -n "$candidate" ]] && [[ -f "$candidate" ]]; then
      echo "java -jar $candidate"; return 0
    fi
  done
  return 1
}

TMPDIRS=()
cleanup() { for d in "${TMPDIRS[@]:-}"; do [[ -n "$d" && -d "$d" ]] && rm -rf "$d"; done; }
trap cleanup EXIT

# --- Resolve the directory of APKs to merge ---
WORK_DIR=""

if [[ "$FROM_DEVICE" == true ]]; then
  echo "NOTE: authorized-use only — pull apps only from devices/apps you are permitted to analyze." >&2
  if [[ -z "$PACKAGE" ]]; then
    fail "--device requires -p <package>"; echo "MERGE_RESULT=failed"; exit 1
  fi
  if ! command -v adb &>/dev/null; then
    fail "adb not found (needed for --device)"; echo "MERGE_RESULT=failed"; exit 2
  fi
  WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/splits-pull-XXXXXX"); TMPDIRS+=("$WORK_DIR")
  info "Querying split paths for $PACKAGE..."
  mapfile -t paths < <(adb shell pm path "$PACKAGE" 2>/dev/null | tr -d '\r' | sed 's/^package://')
  if [[ ${#paths[@]} -eq 0 ]]; then
    fail "no paths returned — is $PACKAGE installed on the connected device?"
    echo "MERGE_RESULT=failed"; exit 1
  fi
  for pth in "${paths[@]}"; do
    [[ -z "$pth" ]] && continue
    info "pulling $pth"
    adb pull "$pth" "$WORK_DIR/" >/dev/null 2>&1 || warn "failed to pull $pth"
  done
elif [[ -n "$TARGET" && -d "$TARGET" ]]; then
  WORK_DIR="$TARGET"
elif [[ -n "$TARGET" && -f "$TARGET" ]]; then
  ext_lower=$(echo "${TARGET##*.}" | tr '[:upper:]' '[:lower:]')
  case "$ext_lower" in
    apks|xapk|zip|apkm)
      WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/splits-extract-XXXXXX"); TMPDIRS+=("$WORK_DIR")
      info "extracting $TARGET ..."
      unzip -qo "$TARGET" -d "$WORK_DIR"
      ;;
    *)
      fail "single file '$TARGET' is not a split archive (.apks/.xapk/.apkm)"
      echo "MERGE_RESULT=failed"; exit 1 ;;
  esac
else
  fail "no target given"; usage
fi

# --- Enumerate APKs ---
mapfile -t APKS < <(find "$WORK_DIR" -maxdepth 2 -name '*.apk' | sort)
SPLIT_COUNT=${#APKS[@]}
echo "SPLIT_COUNT=$SPLIT_COUNT"

if [[ "$SPLIT_COUNT" -eq 0 ]]; then
  fail "no .apk files found under $WORK_DIR"; echo "MERGE_RESULT=failed"; exit 1
fi

# --- Count code-bearing splits (contain classes*.dex) ---
CODE_SPLITS=0
for apk in "${APKS[@]}"; do
  if unzip -l "$apk" 2>/dev/null | grep -qE 'classes[0-9]*\.dex'; then
    CODE_SPLITS=$((CODE_SPLITS + 1))
  fi
done
echo "CODE_SPLITS=$CODE_SPLITS"

for apk in "${APKS[@]}"; do
  info "  split: $(basename "$apk")"
done

# --- One apk, or only base carries code → merge not needed for code analysis ---
if [[ "$SPLIT_COUNT" -eq 1 ]]; then
  ok "single APK — nothing to merge."
  echo "MERGED_APK=${APKS[0]}"
  echo "MERGE_RESULT=not-needed"
  exit 0
fi
if [[ "$CODE_SPLITS" -le 1 ]]; then
  base=""
  for apk in "${APKS[@]}"; do
    if [[ "$(basename "$apk")" == "base.apk" ]] || unzip -l "$apk" 2>/dev/null | grep -qE 'classes[0-9]*\.dex'; then
      base="$apk"; break
    fi
  done
  if [[ -n "$base" ]]; then
    ok "only config splits carry no code — base APK alone is sufficient for code analysis."
    info "decompile: $base   (merge only if you need the split resources)"
    echo "MERGED_APK=$base"
    echo "MERGE_RESULT=not-needed"
    exit 0
  fi
fi

# --- Merge with APKEditor ---
if ! MERGE_CMD=$(find_apkeditor); then
  fail "APKEditor not found — cannot merge feature splits automatically."
  echo "         Install: download APKEditor.jar from https://github.com/REAndroid/APKEditor/releases" >&2
  echo "         then set APKEDITOR_JAR=/path/to/APKEditor.jar and re-run." >&2
  echo "         Manual alternative: java -jar APKEditor.jar m -i <dir-of-apks> -o merged.apk" >&2
  echo "MERGE_RESULT=failed"
  exit 2
fi

if [[ -z "$OUTPUT" ]]; then
  base_name=$(basename "${TARGET:-$PACKAGE}")
  base_name="${base_name%.*}"
  OUTPUT="${base_name:-app}-merged.apk"
fi

# APKEditor merges from a directory of splits.
MERGE_INPUT="$WORK_DIR"
info "merging $SPLIT_COUNT splits with APKEditor → $OUTPUT"
if $MERGE_CMD m -i "$MERGE_INPUT" -o "$OUTPUT" 2>&1; then
  if [[ -f "$OUTPUT" ]]; then
    ok "merged APK: $OUTPUT"
    echo "MERGED_APK=$OUTPUT"
    echo "MERGE_RESULT=success"
    exit 0
  fi
fi
fail "APKEditor merge failed"
echo "MERGE_RESULT=failed"
exit 1
