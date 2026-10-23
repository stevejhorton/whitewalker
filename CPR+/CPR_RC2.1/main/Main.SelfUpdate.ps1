# CPR RC2 self-update helper.
# Depends on: Main.Logging.ps1 and Main.Configuration.ps1.

# =============================================================================
# Self-Update
# =============================================================================
function Invoke-SelfUpdate {
    <#
    .SYNOPSIS
    Checks for cpr_update_<dev|prod>[_tee_<1-5>[_keep]].flag in C:\Windows\Temp. The optional _tee_ part
    sets the tee level after a successful update (via the normal cpr_tee_* flag handler).
    If found and network state allows, pulls cpr_current.zip from NETLOGON
    bin/DEV or bin/PROD channel, extracts to $env:TEMP, and runs install.ps1.
    On failure the attempt count is written into the flag and the next run retries;
    after $SelfUpdateMaxAttempts failures the flag is renamed .failed so techs can see it.
    Never touches logs.
    Gated by $SelfUpdateEnabled.
    #>

    function Get-SelfUpdateNetworkState {
        $state = ""
        try {
            if (Test-Path $StateFile) {
                $s = Get-Content $StateFile -Raw | ConvertFrom-Json
                $state = $s.currentState
            }
        } catch { }

        if ([string]::IsNullOrWhiteSpace($state)) { return "unknown" }
        return $state
    }

    $selfUpdateStartedAt = Get-Date

    # Find the update flag: cpr_update_<dev|prod>[_tee_<1-5>[_keep]].flag. The optional tee part is only
    # requested AFTER the update succeeds (success branch drops the matching cpr_tee_* flag for the normal
    # tee handler, cooldown and all). DEV wins over PROD; within a channel the highest tee level wins,
    # _keep before plain. Anything else named cpr_update_*.flag is renamed .failed, like invalid cpr_tee_* flags.
    $updFlags = @()
    foreach ($uf in @(Get-ChildItem -LiteralPath $TeeFlagDir -Filter 'cpr_update_*' -File -ErrorAction SilentlyContinue)) {
        if ($uf.Extension -ne '.flag') { continue }
        if (-not ($uf.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -and
            $uf.Name -match '^cpr_update_(dev|prod)(_tee_([1-5])(_keep)?)?\.flag$') {
            $updFlags += [pscustomobject]@{
                File    = $uf
                Channel = $Matches[1].ToUpper()
                Tee     = $(if ($Matches[3]) { [int]$Matches[3] } else { 0 })
                Keep    = [bool]$Matches[4]
            }
        } else {
            Write-Log "SelfUpdate: ignoring invalid flag name '$($uf.Name)' (expected cpr_update_<dev|prod>[_tee_<1-5>[_keep]].flag)" "WARN"
            try { Rename-Item -LiteralPath $uf.FullName -NewName ($uf.Name -replace '\.flag$', '.failed') -Force -ErrorAction Stop } catch { }
            Write-TeeLog 'cpr_self_update_failed' @{
                channel = ''; status = 'rejected'; network_state = ''; reason = 'invalid_flag_name'; exit_code = ''
            }
        }
    }
    if ($updFlags.Count -eq 0) { return }  # no flag, nothing to do

    $pickFlag = $updFlags | Sort-Object @{ Expression = { $_.Channel -eq 'DEV' }; Descending = $true },
        @{ Expression = 'Tee'; Descending = $true }, @{ Expression = 'Keep'; Descending = $true } | Select-Object -First 1
    $channel  = $pickFlag.Channel
    $flagFile = $pickFlag.File.FullName
    $teeLevel = [int]$pickFlag.Tee
    $teeKeep  = [bool]$pickFlag.Keep
    if ($teeLevel -gt 0) {
        Write-Log "SelfUpdate: flag also requests tee level $teeLevel$(if ($teeKeep) { ' (keep)' }) after a successful update" "INFO"
    }

    # Failed attempts so far live in the flag itself (an empty/legacy flag = 0). The flag sits in a
    # user-writable folder, so anything that is not a positive integer counts as 0 and the value is capped.
    $maxAttempts = [math]::Max(1, [int]$SelfUpdateMaxAttempts)
    $priorFailures = 0
    try {
        $rawCount = [string](Get-Content -LiteralPath $flagFile -Raw -ErrorAction Stop)
        $parsedCount = 0
        if ([int]::TryParse($rawCount.Trim(), [ref]$parsedCount) -and $parsedCount -gt 0) {
            $priorFailures = [math]::Min($parsedCount, $maxAttempts)
        }
    } catch { }

    $telemetryNetworkState = Get-SelfUpdateNetworkState
    Write-TeeLog 'cpr_self_update_triggered' @{
        channel       = $channel
        status        = 'detected'
        network_state = $telemetryNetworkState
        reason        = 'flag_detected'
        attempt       = [string]($priorFailures + 1)
    }

    if (-not $SelfUpdateEnabled) {
        Write-Log "SelfUpdate: $channel flag found at $flagFile but SelfUpdateEnabled=false - skipping (flag left in place)" "WARN"
        Write-TeeLog 'cpr_self_update_failed' @{
            channel       = $channel
            status        = 'skipped'
            network_state = $telemetryNetworkState
            reason        = 'self_update_disabled'
            exit_code     = ''
        }
        return
    }

    Write-Log "SelfUpdate: $channel flag detected - checking eligibility" "INFO"

    # Cooldown check - prevent re-trigger loop
    if (Test-Path $SelfUpdateCooldownFlag) {
        try {
            $lastRan  = [datetime]::Parse((Get-Content $SelfUpdateCooldownFlag -Raw).Trim())
            $ageMin   = ((Get-Date) - $lastRan).TotalMinutes
            if ($ageMin -lt $SelfUpdateCooldownMinutes) {
                Write-Log "SelfUpdate: cooldown active ($([math]::Round($ageMin,1))m ago) - skipping" "WARN"
                Write-TeeLog 'cpr_self_update_failed' @{
                    channel       = $channel
                    status        = 'skipped'
                    network_state = $telemetryNetworkState
                    reason        = 'cooldown_active'
                    exit_code     = ''
                }
                return
            }
        } catch { }
    }

    # Network state check - only proceed if we can reach the share
    $lastState = $telemetryNetworkState

    $goodStates = @("on_prem","user_tun","mgmt_tun")
    if ($goodStates -notcontains $lastState) {
        Write-Log "SelfUpdate: $channel flag found but network state is '$lastState' - share likely unreachable. Will retry when on-prem or VPN." "WARN"
        Write-TeeLog 'cpr_self_update_failed' @{
            channel       = $channel
            status        = 'skipped'
            network_state = $lastState
            reason        = 'network_state_not_eligible'
            exit_code     = ''
        }
        return
    }

    Write-Log "SelfUpdate: proceeding - channel=$channel state=$lastState" "INFO"

    $remoteZip = "\\ms.ds.uhc.com\netlogon\UHG\Scripts\AOVPN\CPR\bin\$channel\$SelfUpdateZipName"
    $localZip  = Join-Path $env:TEMP "cpr_update_$channel.zip"
    $extractDir= Join-Path $env:TEMP "cpr_update_$channel"
    $failureReason = "unexpected_exception"
    $installerExitCode = $null

    try {
        # Verify share is reachable
        if (-not (Test-Path -LiteralPath $remoteZip)) {
            # Test-Path is $false for "not there" AND for "could not reach it" (slow SMB/DNS on a busy box).
            # Probe the parent folder to tell them apart so Splunk shows the real cause.
            if (Test-Path -LiteralPath $SelfUpdateRemoteBase) {
                $failureReason = "remote_zip_missing"
                throw "Remote zip not found (share reachable): $remoteZip"
            }
            $failureReason = "share_unreachable"
            throw "Share not reachable (neither the zip nor $SelfUpdateRemoteBase could be seen): $remoteZip"
        }

        # Pull zip
        Write-Log "SelfUpdate: pulling $remoteZip -> $localZip" "INFO"
        $phaseStartedAt = Get-Date
        try {
            Copy-Item -LiteralPath $remoteZip -Destination $localZip -Force -ErrorAction Stop
        } catch {
            $failureReason = "zip_copy_failed"
            throw
        }
        Write-Log ("self_update_phase phase='download' elapsed_ms={0}" -f `
            [math]::Round(((Get-Date) - $phaseStartedAt).TotalMilliseconds)) "INFO"

        # Clean and extract
        if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue }
        Write-Log "SelfUpdate: extracting to $extractDir" "INFO"
        $phaseStartedAt = Get-Date
        try {
            Expand-Archive -LiteralPath $localZip -DestinationPath $extractDir -Force -ErrorAction Stop
        } catch {
            $failureReason = "zip_extract_failed"
            throw
        }
        Write-Log ("self_update_phase phase='extract' elapsed_ms={0}" -f `
            [math]::Round(((Get-Date) - $phaseStartedAt).TotalMilliseconds)) "INFO"

        # Find and run install.ps1
        $installScript = Get-ChildItem -Path $extractDir -Filter $SelfUpdateInstallScript -Recurse | Select-Object -First 1
        if (-not $installScript) {
            $failureReason = "install_script_missing"
            throw "install.ps1 not found in extracted zip at $extractDir"
        }

        Write-Log "SelfUpdate: running $($installScript.FullName)" "INFO"
        $phaseStartedAt = Get-Date
        $script:NetworkSnapshotInvalidated = $true
        try {
            $proc = Start-Process "powershell.exe" `
                -ArgumentList "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$($installScript.FullName)`"" `
                -WindowStyle Hidden -Wait -PassThru -ErrorAction Stop
        } catch {
            $failureReason = "installer_launch_failed"
            throw
        }
        Write-Log ("self_update_phase phase='installer_maintenance' elapsed_ms={0} exit_code={1}" -f `
            [math]::Round(((Get-Date) - $phaseStartedAt).TotalMilliseconds), $proc.ExitCode) "INFO"

        if ($proc.ExitCode -ne 0) {
            $failureReason = "installer_nonzero_exit"
            $installerExitCode = $proc.ExitCode
            throw "install.ps1 exited with code $($proc.ExitCode)"
        }

        # Success - clean up and stamp cooldown
        Remove-Item $flagFile -Force -ErrorAction SilentlyContinue
        # Other flags of this channel asked for the same update - drop them so it does not run twice.
        foreach ($o in $updFlags) {
            if ($o.Channel -eq $channel -and $o.File.FullName -ne $flagFile) {
                Remove-Item -LiteralPath $o.File.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        # Combined flag: hand the tee level to the normal cpr_tee_<N>[_keep].flag handler (runs later this
        # run; its cooldown, keep, revert and events apply unchanged). Never fails the update.
        if ($teeLevel -gt 0) {
            try {
                $teeFlagPath = Join-Path $TeeFlagDir ("cpr_tee_{0}{1}.flag" -f $teeLevel, $(if ($teeKeep) { '_keep' } else { '' }))
                New-Item -ItemType File -Path $teeFlagPath -Force -ErrorAction Stop | Out-Null
                Write-Log "SelfUpdate: update succeeded - dropped $(Split-Path $teeFlagPath -Leaf) for the tee flag handler" "INFO"
            } catch {
                Write-Log "SelfUpdate: update succeeded but the tee flag could not be created: $_" "WARN"
            }
        }
        Remove-Item $localZip -Force -ErrorAction SilentlyContinue
        (Get-Date).ToString("o") | Set-Content $SelfUpdateCooldownFlag -Encoding UTF8 -Force
        Write-Log "SelfUpdate: $channel install completed successfully - flag removed" "INFO"
        Write-TeeLog 'cpr_self_update_passed' @{
            channel       = $channel
            status        = 'completed'
            network_state = $lastState
            reason        = 'install_completed'
            exit_code     = if ($null -ne $proc.ExitCode) { [string]$proc.ExitCode } else { '' }
            attempt       = [string]($priorFailures + 1)
        }
        Write-Log ("phase_timing phase='self_update_maintenance' elapsed_ms={0} status='completed'" -f `
            [math]::Round(((Get-Date) - $selfUpdateStartedAt).TotalMilliseconds)) "INFO"

    } catch {
        $failedFlag   = $flagFile -replace '\.(flag)$', '.failed'
        $errorSummary = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        $failedCount  = $priorFailures + 1
        $gaveUp       = ($failedCount -ge $maxAttempts)
        Write-TeeLog 'cpr_self_update_failed' @{
            channel       = $channel
            status        = if ($gaveUp) { 'gave_up' } else { 'retry_pending' }
            network_state = $lastState
            reason        = $failureReason
            exit_code     = if ($null -ne $installerExitCode) { [string]$installerExitCode } else { '' }
            attempt       = [string]$failedCount
        }
        Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
        Write-Log "[!!] SELF-UPDATE FAILED - channel=$channel attempt $failedCount of $maxAttempts" "ERROR"
        Write-Log "[!!] Error category: $failureReason" "ERROR"
        Write-Log "[!!] Error: $errorSummary" "ERROR"
        if ($gaveUp) {
            Write-Log "[!!] Giving up - flag renamed to: $failedFlag" "ERROR"
        } else {
            Write-Log "[!!] Flag kept (count=$failedCount); the next run will retry" "ERROR"
        }
        Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
        try {
            if ($gaveUp) {
                Rename-Item -Path $flagFile -NewName (Split-Path $failedFlag -Leaf) -Force -ErrorAction Stop
            } else {
                Set-Content -LiteralPath $flagFile -Value ([string]$failedCount) -Encoding ASCII -Force -ErrorAction Stop
            }
        } catch {
            Write-Log "SelfUpdate: could not update flag file: $_" "WARN"
        }
        Remove-Item $localZip -Force -ErrorAction SilentlyContinue
        Write-Log ("phase_timing phase='self_update_maintenance' elapsed_ms={0} status='failed' reason='{1}'" -f `
            [math]::Round(((Get-Date) - $selfUpdateStartedAt).TotalMilliseconds), $failureReason) "WARN"
    }
}
