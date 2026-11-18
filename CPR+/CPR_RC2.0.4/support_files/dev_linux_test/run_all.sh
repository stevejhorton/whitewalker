#!/bin/bash
# Runs every *.Tests.ps1 in the release (tests/ and the release root), 4 at a time, one pwsh per file, 280s cap each.
# Usage:  bash run_all.sh [release_root]      default release_root = the CPR folder this kit lives in
#         OUT=/some/dir bash run_all.sh        (default: $CPR_DEV_HOME/results)
# Prints one line per file that has failures, then TOTAL.  Per-file detail: $OUT/<name>.txt
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${1:-$HERE/../..}" && pwd)"
HOME_DIR="${CPR_DEV_HOME:-$HOME/.cpr-dev}"
OUT="${OUT:-$HOME_DIR/results}"
[ -x "$HOME_DIR/ps/pwsh" ] || bash "$HERE/bootstrap.sh"
rm -rf "$OUT"; mkdir -p "$OUT"
export PSModulePath="$HOME_DIR/mods"
run() { f="$1"; n="$(echo "${f#$ROOT/}" | tr '/' '_' | sed 's/\.ps1$//')"
  ( cd "$ROOT" && timeout 280 "$HOME_DIR/ps/pwsh" -NoProfile -File "$HERE/run_one.ps1" -Path "$f" > "$OUT/$n.txt" 2>&1; echo "rc=$?" >> "$OUT/$n.txt" ); }
export -f run; export ROOT HERE HOME_DIR OUT
( cd "$ROOT" && { ls tests/*.Tests.ps1 2>/dev/null; ls ./*.Tests.ps1 2>/dev/null | sed 's#^\./##'; } | sort -u | xargs -P 4 -I{} bash -c 'run "$ROOT/{}"' )
tp=0; tf=0
for f in "$OUT"/*.txt; do
  l=$(grep '^SUMMARY' "$f" | head -1); p=$(echo "$l" | cut -d'|' -f2); fl=$(echo "$l" | cut -d'|' -f3)
  [ -z "$l" ] && { echo "$(basename "$f" .txt): NO SUMMARY (timeout/crash) - see $f"; tf=$((tf+1)); continue; }
  tp=$((tp+p)); tf=$((tf+fl)); [ "$fl" != "0" ] && echo "$(basename "$f" .txt): pass=$p fail=$fl"
done
echo "TOTAL pass=$tp fail=$tf   (details: $OUT)"
