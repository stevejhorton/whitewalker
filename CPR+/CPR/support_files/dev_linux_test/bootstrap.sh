#!/bin/bash
# Installs PowerShell 7 + Pester 5 (built from source) into $CPR_DEV_HOME so the Pester suite can run on Linux.
# Dev/CI tooling only. Nothing here is deployed to endpoints (the installer copies named files from support_files).
# Usage:  bash bootstrap.sh            (idempotent; re-run is a no-op once installed)
# Needs:  curl, tar, git, outbound HTTPS to github.com (a Claude Code session: call add_repo for pester/Pester first).
set -euo pipefail
PWSH_VER="${PWSH_VER:-7.5.4}"
PESTER_VER="${PESTER_VER:-5.6.1}"
HOME_DIR="${CPR_DEV_HOME:-$HOME/.cpr-dev}"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HOME_DIR"

if [ ! -x "$HOME_DIR/ps/pwsh" ]; then
  echo "[bootstrap] downloading PowerShell $PWSH_VER"
  curl -fsSL -o "$HOME_DIR/pwsh.tgz" "https://github.com/PowerShell/PowerShell/releases/download/v${PWSH_VER}/powershell-${PWSH_VER}-linux-x64.tar.gz"
  mkdir -p "$HOME_DIR/ps" && tar xzf "$HOME_DIR/pwsh.tgz" -C "$HOME_DIR/ps" && chmod +x "$HOME_DIR/ps/pwsh" && rm -f "$HOME_DIR/pwsh.tgz"
fi

if [ ! -d "$HOME_DIR/pester-src/.git" ]; then
  echo "[bootstrap] cloning Pester $PESTER_VER (source; PSGallery/NuGet/dotnet are usually blocked)"
  GIT_LFS_SKIP_SMUDGE=1 git clone -q --depth 1 --branch "$PESTER_VER" https://github.com/pester/pester "$HOME_DIR/pester-src"
fi

if [ ! -f "$HOME_DIR/mods/Pester/$PESTER_VER/Pester.psm1" ]; then
  echo "[bootstrap] building the Pester module (C# is compiled in-session by Add-Type; no dotnet SDK needed)"
  CPR_DEV_HOME="$HOME_DIR" PESTER_VER="$PESTER_VER" "$HOME_DIR/ps/pwsh" -NoProfile -File "$HERE/build_pester.ps1"
fi
echo "[bootstrap] ready: $HOME_DIR  (pwsh $("$HOME_DIR/ps/pwsh" -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'), Pester $PESTER_VER)"
