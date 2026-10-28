#!/usr/bin/env bash
#
# roll_cpr_package.sh
# 28sep26
# steve.horton@optum.com
#
# Pulls the latest slo_jam repo content, lists CPR_* version dirs, stages the
# chosen version's contents, and produces two release zips (cpr_current.zip +
# versioned zip) under CPR_release/<version>/. If running under WSL, also
# copies both zips to /mnt/c/temp/ for easy access from Windows.
#
# Location: tools/automation/win_ise_rescanner/
set -euo pipefail

# --- Resolve script root (dir this script lives in) -------------------------
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_ROOT"

echo "Script root: $SCRIPT_ROOT"

# --- -1. OS detection -> portable command variables --------------------------
# macOS ships BSD find/sed/stat; Linux (incl. WSL) ships GNU find/sed/stat.
# GNU find supports `-printf`; BSD find does not (errors with
# "find: -printf: unknown primary or operator"). Detect the platform once up
# top and build OS-appropriate command invocations instead of relying on
# flags that only exist on one flavor.
OS_NAME="$(uname -s)"
case "$OS_NAME" in
    Darwin)
        PLATFORM="macos"
        ;;
    Linux)
        PLATFORM="linux"
        ;;
    *)
        PLATFORM="unknown"
        ;;
esac

echo "Detected platform: $PLATFORM ($OS_NAME)"

# Portable "list immediate CPR_* subdirectory names" helper.
# Avoids GNU-only `find -printf` entirely - works identically on
# macOS (BSD find) and Linux (GNU find) via `-exec basename`.
list_cpr_dirs() {
    find . -maxdepth 1 -type d -name 'CPR_*' -exec basename {} \; | sort
}

# --- 0. git pull the repo (CPR_* dirs are plain subdirs, not their own repos)
REPO_ROOT="$(git -C "$SCRIPT_ROOT" rev-parse --show-toplevel 2>/dev/null || true)"

if [ -z "$REPO_ROOT" ]; then
    echo "Warning: $SCRIPT_ROOT is not inside a git repo. Skipping git pull." >&2
else
    echo "Running git pull in repo root: $REPO_ROOT ..."
    (cd "$REPO_ROOT" && git pull)
fi

# --- 1. Discover CPR_* version dirs (post-pull, so listing is current) ------
mapfile -t CPR_DIRS < <(list_cpr_dirs)

if [ "${#CPR_DIRS[@]}" -eq 0 ]; then
    echo "No CPR_* directories found in $SCRIPT_ROOT" >&2
    exit 1
fi

echo
echo "Available CPR versions:"
for i in "${!CPR_DIRS[@]}"; do
    printf "  [%d] %s\n" "$((i+1))" "${CPR_DIRS[$i]}"
done
echo

read -rp "Select a version by number or name: " SELECTION

VERSION=""

if [[ "$SELECTION" =~ ^[0-9]+$ ]]; then
    # Numeric selection -> index into list
    if [ "$SELECTION" -ge 1 ] && [ "$SELECTION" -le "${#CPR_DIRS[@]}" ]; then
        VERSION="${CPR_DIRS[$((SELECTION-1))]}"
    fi
else
    # Name-based selection -> exact match first, then unique partial match
    for d in "${CPR_DIRS[@]}"; do
        if [ "$d" == "$SELECTION" ]; then
            VERSION="$d"
            break
        fi
    done

    if [ -z "$VERSION" ]; then
        mapfile -t MATCHES < <(printf '%s\n' "${CPR_DIRS[@]}" | grep -F -- "$SELECTION" || true)
        if [ "${#MATCHES[@]}" -eq 1 ]; then
            VERSION="${MATCHES[0]}"
        elif [ "${#MATCHES[@]}" -gt 1 ]; then
            echo "Ambiguous selection '$SELECTION' matches multiple versions:" >&2
            printf '  %s\n' "${MATCHES[@]}" >&2
        fi
    fi
fi

if [ -z "$VERSION" ]; then
    echo "Invalid selection: $SELECTION" >&2
    exit 1
fi

VERSION_DIR="$SCRIPT_ROOT/$VERSION"

echo "Selected version: $VERSION"

# --- 2. Determine staging dir (CPR or .tmp/CPR) ------------------------------
STAGE_DIR="$SCRIPT_ROOT/CPR"

if [ -d "$STAGE_DIR" ]; then
    if [ -n "$(ls -A "$STAGE_DIR" 2>/dev/null)" ]; then
        echo "$STAGE_DIR exists and is not empty; using $SCRIPT_ROOT/.tmp/CPR instead."
        STAGE_DIR="$SCRIPT_ROOT/.tmp/CPR"
        rm -rf "$STAGE_DIR"
        mkdir -p "$STAGE_DIR"
    else
        echo "$STAGE_DIR exists and is empty; using it."
    fi
else
    echo "Creating $STAGE_DIR"
    mkdir -p "$STAGE_DIR"
fi

# --- 3. Copy selected version's content into staging dir --------------------
echo "Copying contents of $VERSION_DIR to $STAGE_DIR ..."
rsync -a --exclude='.git' "$VERSION_DIR"/ "$STAGE_DIR"/ 2>/dev/null || {
    # Fallback if rsync isn't available
    find "$VERSION_DIR" -mindepth 1 -maxdepth 1 ! -name '.git' -exec cp -r {} "$STAGE_DIR"/ \;
}

# --- 3b. Prune repo-only material from the staged package ---------------------
# install.ps1 mirrors docs\ to EVERY endpoint (C:\ProgramData\WhiteWalker\docs) and the zip is
# pulled from the share, so ship only the docs that runtime code reads: the toast logo,
# the user guide (+ its logo) and the VPN blackhole page. Everything else in docs\
# (reports, diagrams, test plans, steve_to_review) stays in the repo only.
# archive\ is a dev artifact the installer never deploys; logs\ is created by the installer.
# To ship another doc, add its file name to DOCS_SHIP.
DOCS_SHIP="CPR_Logo.jpeg CPR_Logo.png cpr_user_guide.html vpn_blackhole_info.html"
if [ -d "$STAGE_DIR/docs" ]; then
    for f in "$STAGE_DIR"/docs/* "$STAGE_DIR"/docs/.[!.]*; do
        [ -e "$f" ] || continue
        keep=0
        for k in $DOCS_SHIP; do
            [ "$(basename "$f")" = "$k" ] && keep=1
        done
        [ "$keep" -eq 1 ] || rm -rf "$f"
    done
fi
rm -rf "$STAGE_DIR/archive" "$STAGE_DIR/logs" "$STAGE_DIR/support_files/dev_linux_test"   # dev-only Linux test kit: never shipped

# --- 4 & 5. Zip staging contents as cpr_current.zip and CPR_<version>.zip ----
CURRENT_ZIP="$SCRIPT_ROOT/cpr_current.zip"
VERSION_ZIP="$SCRIPT_ROOT/${VERSION}.zip"

rm -f "$CURRENT_ZIP" "$VERSION_ZIP"

echo "Creating $CURRENT_ZIP ..."
(cd "$STAGE_DIR" && zip -r -q "$CURRENT_ZIP" .)

echo "Creating $VERSION_ZIP ..."
(cd "$STAGE_DIR" && zip -r -q "$VERSION_ZIP" .)

# --- 6. Place both zips into CPR_release/<version>/ --------------------------
RELEASE_DIR="$SCRIPT_ROOT/CPR_release/$VERSION"
mkdir -p "$RELEASE_DIR"

cp "$CURRENT_ZIP" "$RELEASE_DIR"/
cp "$VERSION_ZIP" "$RELEASE_DIR"/

echo
echo "Done. Release artifacts:"
echo "  $RELEASE_DIR/$(basename "$CURRENT_ZIP")"
echo "  $RELEASE_DIR/$(basename "$VERSION_ZIP")"

# --- 7. If running under WSL, also copy zips to /mnt/c/temp/ for Windows ----
IS_WSL=false
if [ "$PLATFORM" = "linux" ]; then
    if grep -qi microsoft /proc/version 2>/dev/null; then
        IS_WSL=true
    elif [ -n "${WSL_DISTRO_NAME:-}" ]; then
        IS_WSL=true
    fi
fi

if [ "$IS_WSL" = true ]; then
    WIN_TEMP="/mnt/c/temp"
    echo
    echo "WSL detected. Copying zips to $WIN_TEMP ..."
    mkdir -p "$WIN_TEMP"
    cp "$CURRENT_ZIP" "$WIN_TEMP"/
    cp "$VERSION_ZIP" "$WIN_TEMP"/
    echo "  $WIN_TEMP/$(basename "$CURRENT_ZIP")"
    echo "  $WIN_TEMP/$(basename "$VERSION_ZIP")"
fi

echo
echo "Drop those two zip files on the domain share at \\\\DSADCWPFP001A06.ms.ds.uhc.com\NETLOGON\UHG\Scripts\AOVPN\CPR."
