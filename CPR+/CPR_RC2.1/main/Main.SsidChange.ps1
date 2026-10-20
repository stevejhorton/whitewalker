# CPR RC2 trusted SSID, cache, notification, and SSID-change helpers.
# Depends on: Main.Network.ps1, Main.VpnState.ps1, Main.FlareGun.ps1, and Main.Logging.ps1.

function Test-ShareReachableFast {
    <#
    .SYNOPSIS
    Fast, hard-timeout TCP connect check to SMB port 445 on the target host.
    Avoids slow UNC Test-Path negotiation (can hang 10-20s+ when off-network,
    e.g. home WiFi with no route to the corp share) and avoids ICMP-block
    false negatives from ping/Test-Connection (many DCs silently drop ICMP,
    which would make Test-Connection time out the FULL timeout anyway - a
    false negative indistinguishable from "actually unreachable").

    Returns $true only if a TCP handshake to port 445 completes within
    $TimeoutMs. Returns $false on any failure, timeout, or exception -
    never throws. Worst-case blocking time is bounded by $TimeoutMs.
    #>
    param(
        [string]$HostName,
        [int]$TimeoutMs = 300
    )
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcp.BeginConnect($HostName, 445, $null, $null)
        $success = $connectTask.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($success -and $tcp.Connected) {
            $tcp.EndConnect($connectTask)
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

function Sync-TrustedSsidFile {
    <#
    .SYNOPSIS
    Syncs trusted_ssids.cfg from NETLOGON share using version+hash check.
    Respects $TrustedSsidSyncCooldownHours to prevent thrashing.
    Falls back to local copy silently if share is unreachable.
    Only called when current SSID is NOT in $HardcodedTrustedSsids.
    #>

    if (-not $TrustedSsidSyncEnabled) {
        Write-Log "TrustedSsid: sync disabled - using local cache only" "DEBUG"
        return
    }

    # Cooldown check - don't hammer the share on every CPR run
    if (Test-Path $TrustedSsidSyncFlag) {
        try {
            $lastSync = [datetime]::Parse((Get-Content $TrustedSsidSyncFlag -Raw).Trim())
            $ageHours = ((Get-Date) - $lastSync).TotalHours
            if ($ageHours -lt $TrustedSsidSyncCooldownHours) {
                Write-Log "TrustedSsid: cache fresh ($([math]::Round($ageHours,1))h old) - skipping sync" "DEBUG"
                return
            }
            Write-Log "TrustedSsid: cache stale ($([math]::Round($ageHours,1))h old) - syncing from share" "INFO"
        } catch {
            Write-Log "TrustedSsid: could not read sync flag - forcing sync" "WARN"
        }
    } else {
        Write-Log "TrustedSsid: no sync flag - first run, syncing from share" "INFO"
    }

    # Fast bounded reachability check BEFORE any UNC Test-Path/Copy-Item.
    # Prevents multi-second hangs when off-VPN/off-prem (e.g. home WiFi) -
    # UNC negotiation against an unreachable host can block far longer than
    # this 300ms TCP probe. Fails closed: if unreachable, Test-SsidTrusted
    # falls back to the local cached trusted_ssids.cfg (if any), or returns
    # "not trusted" if no local cache exists - both are safe outcomes since
    # being unable to reach the corp share means we're almost certainly not
    # on-prem anyway.
    $shareHost = ([uri]("file:" + ($RemoteTrustedSsidFile -replace '\\','/'))).Host
    if (-not (Test-ShareReachableFast -HostName $shareHost -TimeoutMs 300)) {
        Write-Log "TrustedSsid: fast reachability check failed ($shareHost:445 unreachable in 300ms) - using local cache" "DEBUG"
        return
    }

    # Share reachability check (now only reached if fast check passed)
    if (-not (Test-Path -LiteralPath (Split-Path $RemoteTrustedSsidFile -Parent) -ErrorAction SilentlyContinue)) {
        Write-Log "TrustedSsid: share unreachable - using local cache" "WARN"
        return
    }

    if (-not (Test-Path -LiteralPath $RemoteTrustedSsidFile)) {
        Write-Log "TrustedSsid: remote file not found at $RemoteTrustedSsidFile - using local cache" "WARN"
        return
    }

    # Version check (fast path)
    try {
        $remoteVer = (Get-Content $RemoteTrustedSsidFile -TotalCount 1 -ErrorAction Stop).Trim()
        $localVer  = if (Test-Path $TrustedSsidFile) { (Get-Content $TrustedSsidFile -TotalCount 1 -ErrorAction SilentlyContinue).Trim() } else { "" }
        if ($remoteVer -and $localVer -and ($remoteVer -eq $localVer)) {
            Write-Log "TrustedSsid: version match ($remoteVer) - no pull needed" "DEBUG"
            (Get-Date -Format "o") | Set-Content $TrustedSsidSyncFlag -Encoding UTF8 -Force
            return
        }
    } catch { }

    # Pull from share
    try {
        Copy-Item -LiteralPath $RemoteTrustedSsidFile -Destination $TrustedSsidFile -Force -ErrorAction Stop
        (Get-Date -Format "o") | Set-Content $TrustedSsidSyncFlag -Encoding UTF8 -Force
        Write-Log "TrustedSsid: updated from share" "INFO"
    } catch {
        Write-Log "TrustedSsid: failed to pull from share: $_ - using local cache" "WARN"
    }
}

function Test-SsidTrusted {
    <#
    .SYNOPSIS
    Returns $true if the current SSID is trusted (on-prem confirmed).
    Wired (Ethernet) connections always return $true - SSID is irrelevant.
    Checks Tier 1 (hardcoded array) first - zero I/O, instant.
    Falls through to Tier 2 (trusted_ssids.cfg) only on a miss.
    Returns $true if check is disabled via $TrustedSsidEnabled = $false.
    #>
    param(
        [object]$NetworkInfo
    )

    # Feature gate
    if (-not $TrustedSsidEnabled) {
        Write-Log "TrustedSsid: check disabled - skipping" "DEBUG"
        return $true
    }

    # Wired - SSID is meaningless, skip check entirely
    if ($NetworkInfo.ConnectionType -eq "Ethernet") {
        Write-Log "TrustedSsid: wired connection - SSID check skipped" "DEBUG"
        return $true
    }

    $currentSsid = $NetworkInfo.SSID

    if ([string]::IsNullOrWhiteSpace($currentSsid) -or $currentSsid -eq "N/A") {
        Write-Log "TrustedSsid: no SSID detected - cannot confirm trusted" "WARN"
        return $false
    }

    # Tier 1: hardcoded fast path - zero I/O
    if ($HardcodedTrustedSsids -contains $currentSsid) {
        Write-Log "TrustedSsid: '$currentSsid' matched hardcoded list - trusted (fast path)" "DEBUG"
        return $true
    }

    Write-Log "TrustedSsid: '$currentSsid' not in hardcoded list - checking trusted_ssids.cfg" "DEBUG"

    # Tier 2: sync + check cfg file
    Sync-TrustedSsidFile

    if (-not (Test-Path $TrustedSsidFile)) {
        Write-Log "TrustedSsid: no local trusted_ssids.cfg found - SSID not trusted" "WARN"
        return $false
    }

    try {
        $trustedSsids = Get-Content $TrustedSsidFile -ErrorAction Stop |
            Where-Object { $_ -notmatch '^\s*#' -and $_ -notmatch '^\s*version:' -and $_.Trim() -ne '' } |
            ForEach-Object { $_.Trim() }

        if ($trustedSsids -contains $currentSsid) {
            Write-Log "TrustedSsid: '$currentSsid' matched trusted_ssids.cfg - trusted" "INFO"
            return $true
        } else {
            Write-Log "TrustedSsid: '$currentSsid' NOT in trusted_ssids.cfg - SSID not trusted" "WARN"
            return $false
        }
    } catch {
        Write-Log "TrustedSsid: error reading trusted_ssids.cfg: $_ - SSID not trusted" "WARN"
        return $false
    }
}
# ------------------------------- ISE Rescan ----------------------------------
function Set-RescanStamp {
    $global:_state.lastRescan = (Get-Date).ToString('o')
    Save-State $global:_state
}

function Invoke-PostureRescan {
  if (Rescan-InCooldown) { Write-Log "Rescan suppressed (cooldown ${RescanCooldownMinutes}m)"; return }

  # CRITICAL: Check posture service state BEFORE attempting CLI operations
  # This prevents IPC errors and service crashes
  $postureService = Get-PostureService
  if (-not $postureService) {
    Write-Log "Posture service not found; skipping rescan."
    Write-Log "Searched for: csc_iseagent, ciscod.exe, csc_posture, csc_vpn_posture" "DEBUG"
    return
  }
  
  Write-Log "Using posture service: $($postureService.Name) ($($postureService.DisplayName))" "INFO"
  
  if ($postureService.Status -ne "Running") {
    Write-Log "Posture service not running (Status: $($postureService.Status)). Attempting to start..."
    try {
      Start-Service -Name $postureService.Name -ErrorAction Stop
      Write-Log "Posture service started. Waiting 10 seconds for stabilization..."
      Start-Sleep -Seconds 10
    } catch {
      Write-Log "Failed to start posture service: $_"
      return
    }
  } else {
    Write-Log "Posture service already running (Status: $($postureService.Status))"
  }

  # Execute direct rescan using variable path
  # Steve's proven method: simple, direct, no fancy redirection
  try {
    Write-Log "Executing ISE rescan: & '$ise_cmd' rescan"
    if (-not $WhatIf) {
      $output = & $ise_cmd rescan 2>&1
      Write-Log "ISE rescan command executed. Output: $output"
    } else {
      Write-Log "WHATIF: Would execute ISE rescan" "INFO"
    }
    Set-RescanStamp
    
    # CRITICAL: Allow 30 seconds for posture module recovery
    # ISE client is brittle and needs time to stabilize after rescan
    Write-Log "Sleeping 30 seconds post-rescan to allow posture module recovery..."
    if (-not $WhatIf) {
      Start-Sleep -Seconds 30
    }
    
    Write-Log "ISE rescan completed successfully"
  } catch {
    Write-Log "Error executing ISE rescan: $_"
    # Don't try fallback methods - they're more likely to break things
    # If direct method fails, log it and move on
  }
}
    
function Send-WwNotification {
    param([string]$Title, [string]$Body, [int]$Duration = 10, [string]$Type = "toast")
    $payload = "NOTIFY:$Type|title=$Title|body=$Body|duration=$Duration"
    Write-Log "Queuing user notification: $payload" "INFO"
    if (-not $WhatIf) {
        try {
            $proc = Start-Process -FilePath "eventcreate.exe" `
                -ArgumentList "/T INFORMATION /ID 800 /L APPLICATION /SO WhiteWalkerFlareGun /D `"$payload`"" `
                -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
            if ($proc.ExitCode -eq 0) {
                Write-Log "Notification event written successfully (ID 800)" "INFO"
            } else {
                Write-Log "Notification event FAILED (ExitCode: $($proc.ExitCode)) - payload: $payload" "WARN"
            }
        } catch {
            Write-Log "Failed to write notification event: $_" "WARN"
        }
    } else {
        Write-Log "WHATIF: Would send notification - $payload" "INFO"
    }
}
function Update-SsidCache {
    # Written at end of EVERY run - not just after nwcheck 200.
    # Critical: VPN-connected runs must write cache or SSID change detection
    # silently skips on the next network change (no cache = no comparison).
    param([string]$Ssid)
    if ([string]::IsNullOrEmpty($Ssid) -or $Ssid -eq 'N/A') { return }
    try {
        Set-Content -Path $SsidCacheFile -Value $Ssid -Encoding UTF8 -Force
        Write-Log "SSID cache updated: $Ssid" "DEBUG"
        if (Test-Path $SsidChangedFlag) {
            Remove-Item $SsidChangedFlag -Force -ErrorAction SilentlyContinue
            Write-Log "SSID changed flag cleared" "DEBUG"
        }
    } catch { Write-Log "Could not update SSID cache: $_" "WARN" }
}

function Test-OnPremBySuffix {
    <#
    .SYNOPSIS
    Lightweight on-prem detection via DNS suffix inspection only - no network required.
    Returns $true if ONLY corporate suffixes present (on-prem).
    Returns $false if any non-corp suffix present (off-prem or VPN from home).
    Reuses same corp suffix list as Test-DC. Called by Invoke-SsidChangeCheck
    to determine whether a Connected VPN should be kicked on network change.
    #>
    $corpSuffixes = @('ms.ds.uhc.com', 'ds.uhc.com', 'uhc.com')
    try {
        $foundSuffixes = @()
        try {
            $dnsGlobal = Get-DnsClientGlobalSetting -ErrorAction Stop
            if ($dnsGlobal.SuffixSearchList) {
                $foundSuffixes += $dnsGlobal.SuffixSearchList | ForEach-Object { $_.ToLower().Trim() }
            }
        } catch { }
        try {
            $primary = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
            if (-not [string]::IsNullOrWhiteSpace($primary)) {
                $cleanPrimary = $primary.ToLower().Trim()
                if ($cleanPrimary -notin @('(none)', 'none')) { $foundSuffixes += $cleanPrimary }
            }
        } catch { }

        $foundSuffixes = $foundSuffixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
        if (-not $foundSuffixes) { return $false }  # no suffixes - can't confirm on-prem

        foreach ($found in $foundSuffixes) {
            $isCorp = $false
            foreach ($corp in $corpSuffixes) {
                if ($found -eq $corp -or $found -like "*.$corp") { $isCorp = $true; break }
            }
            if (-not $isCorp) {
                Write-Log "OnPremSuffix: non-corp suffix '$found' present - off-prem" "DEBUG"
                return $false
            }
        }
        Write-Log "OnPremSuffix: only corp suffixes present - on-prem confirmed" "DEBUG"
        return $true
    } catch {
        Write-Log "OnPremSuffix: check failed: $_" "DEBUG"
        return $false  # safe default - don't disconnect VPN if unsure
    }
}

function Invoke-SsidChangeCheck {
    param([string]$CurrentSsid)
    if ([string]::IsNullOrEmpty($CurrentSsid) -or $CurrentSsid -eq 'N/A') { return }

    $cachedSsid = $null
    if (Test-Path $SsidCacheFile) {
        try { $cachedSsid = (Get-Content $SsidCacheFile -Raw -ErrorAction Stop).Trim() } catch { }
    }

    if ([string]::IsNullOrEmpty($cachedSsid)) {
        Write-Log "No cached SSID - first run, writing cache now" "DEBUG"
        Update-SsidCache -Ssid $CurrentSsid
        return
    }

    if ($CurrentSsid -eq $cachedSsid) { Write-Log "SSID unchanged: $CurrentSsid" "DEBUG"; return }

    Write-Log "SSID CHANGED: '$cachedSsid' -> '$CurrentSsid'" "INFO"
    $vpnState = Get-VpnState
    Write-Log "VPN state on SSID change: $vpnState" "INFO"

    if ($vpnState -eq "Disconnected") {
        Write-Log "VPN already disconnected on SSID change - no intervention" "INFO"
        return
    }

    # Transitional blocking states (Reconnecting/Connecting) - VPN is blocking
    # 802.1x and ISE posture on the new network. Disconnect immediately regardless
    # of SSID - AnyConnect has no awareness of time passed since original disconnect.
    if ($vpnState -in @('Reconnecting', 'Connecting')) {
        Write-Log "VPN in blocking state '$vpnState' on SSID change - disconnecting immediately" "WARN"
        try {
            & $vpn_cmd disconnect | Out-Null
            Start-Sleep -Seconds 2
            Write-Log "VPN cleared from blocking state" "INFO"
        } catch { Write-Log "Error disconnecting VPN in blocking state: $_" "WARN" }
        return
    }

    # VPN is Connected - check if we're actually on-prem via DNS suffixes (no network needed).
    # On-prem = only corp suffixes present. Off-prem = foreign suffixes in the list.
    # This works regardless of SSID name - Ed can rename WLANi03 and it still works.
    if ($vpnState -eq 'Connected') {
        if (Test-OnPremBySuffix) {
            Write-Log "VPN Connected but on-prem confirmed by DNS suffixes - disconnecting" "WARN"
            try {
                & $vpn_cmd disconnect | Out-Null
                Start-Sleep -Seconds 2
                Write-Log "VPN disconnected - on-prem confirmed" "INFO"
            } catch { Write-Log "Error disconnecting VPN on on-prem detection: $_" "WARN" }
            if ($BlackholeEnabled) {
                Send-WwNotification -Title "VPN Disabled On This Network" `
                    -Body "You are connected directly to the corporate network. VPN is not required here and has been disabled to improve performance and battery life." `
                    -Duration 10
            } else {
                Write-Log "VPN disconnect notification suppressed (BlackholeEnabled=false)" "DEBUG"
            }
        } else {
            Write-Log "VPN Connected, off-prem confirmed by DNS suffixes - leaving VPN alone" "INFO"
        }
        return
    }

    # Remaining transitional states between off-prem networks: grace window
    Write-Log "VPN is '$vpnState' on SSID change - grace window ${VpnSsidChangeGraceSec}s" "INFO"
    $elapsed = 0; $resolved = $false

    while ($elapsed -lt $VpnSsidChangeGraceSec) {
        Start-Sleep -Seconds $VpnSsidChangePollSec
        $elapsed += $VpnSsidChangePollSec
        $vpnState = Get-VpnState
        Write-Log "SSID change grace: ${elapsed}s/${VpnSsidChangeGraceSec}s - VPN: $vpnState" "DEBUG"
        if ($vpnState -eq "Disconnected") {
            Write-Log "VPN disconnected within grace window" "INFO"
            $resolved = $true; break
        }
    }

    if (-not $resolved) {
        Write-Log "VPN stuck in '$vpnState' after ${VpnSsidChangeGraceSec}s - forcing disconnect" "WARN"
        try {
            & $vpn_cmd disconnect | Out-Null
            Start-Sleep -Seconds 2
            Write-Log "VPN force disconnected due to SSID change" "INFO"
            Write-TeeLog 'vpn_disconnect_forced' @{ reason = "ssid_change_stuck"; vpn_state_was = $vpnState }
        } catch { Write-Log "Error disconnecting VPN on SSID change: $_" "WARN" }
        
        # Notify user why VPN dropped
        if ($BlackholeEnabled) {
            Send-WwNotification -Title "VPN Disconnected" `
                -Body "A network change was detected. VPN has been disconnected to allow connection to the new network. It will reconnect automatically." `
                -Duration 10
        } else {
            Write-Log "VPN disconnect notification suppressed (BlackholeEnabled=false)" "DEBUG"
        }
        
        try {
            Set-Content -Path $SsidChangedFlag -Value (Get-Date).ToString('o') -Encoding UTF8 -Force
        } catch { }
    }
}

