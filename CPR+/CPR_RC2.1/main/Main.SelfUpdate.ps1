# CPR RC2 self-update helper.
# Depends on: Main.Logging.ps1 and Main.Configuration.ps1.

# =============================================================================
# Self-Update
# =============================================================================
function Invoke-SelfUpdate {
    <#
    .SYNOPSIS
    Checks for cpr_update_dev.flag or cpr_update_prod.flag in C:\Windows\Temp.
    If found and network state allows, pulls cpr_current.zip from NETLOGON
    bin/DEV or bin/PROD channel, extracts to $env:TEMP, and runs install.ps1.
    Renames flag to .failed on error so techs can see it. Never touches logs.
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

    # Determine which flag (if any) is present. DEV wins if both present.
    $channel  = $null
    $flagFile = $null
    if (Test-Path $SelfUpdateDevFlag)  { $channel = "DEV";  $flagFile = $SelfUpdateDevFlag }
    elseif (Test-Path $SelfUpdateProdFlag) { $channel = "PROD"; $flagFile = $SelfUpdateProdFlag }

    if (-not $channel) { return }  # no flag, nothing to do

    $telemetryNetworkState = Get-SelfUpdateNetworkState
    Write-TeeLog 'cpr_self_update_triggered' @{
        channel       = $channel
        status        = 'detected'
        network_state = $telemetryNetworkState
        reason        = 'flag_detected'
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
        if (-not (Test-Path $remoteZip)) {
            $failureReason = "remote_zip_missing"
            throw "Remote zip not found: $remoteZip"
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
        Remove-Item $localZip -Force -ErrorAction SilentlyContinue
        (Get-Date).ToString("o") | Set-Content $SelfUpdateCooldownFlag -Encoding UTF8 -Force
        Write-Log "SelfUpdate: $channel install completed successfully - flag removed" "INFO"
        Write-TeeLog 'cpr_self_update_passed' @{
            channel       = $channel
            status        = 'completed'
            network_state = $lastState
            reason        = 'install_completed'
            exit_code     = if ($null -ne $proc.ExitCode) { [string]$proc.ExitCode } else { '' }
        }
        Write-Log ("phase_timing phase='self_update_maintenance' elapsed_ms={0} status='completed'" -f `
            [math]::Round(((Get-Date) - $selfUpdateStartedAt).TotalMilliseconds)) "INFO"

    } catch {
        $failedFlag = $flagFile -replace '\.(flag)$', '.failed'
        $errorSummary = if ($_.Exception -and $_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
        Write-TeeLog 'cpr_self_update_failed' @{
            channel       = $channel
            status        = 'failed'
            network_state = $lastState
            reason        = $failureReason
            exit_code     = if ($null -ne $installerExitCode) { [string]$installerExitCode } else { '' }
        }
        Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
        Write-Log "[!!] SELF-UPDATE FAILED - channel=$channel" "ERROR"
        Write-Log "[!!] Error category: $failureReason" "ERROR"
        Write-Log "[!!] Error: $errorSummary" "ERROR"
        Write-Log "[!!] Flag renamed to: $failedFlag" "ERROR"
        Write-Log "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" "ERROR"
        try {
            Rename-Item -Path $flagFile -NewName (Split-Path $failedFlag -Leaf) -Force -ErrorAction Stop
        } catch {
            Write-Log "SelfUpdate: could not rename flag file: $_" "WARN"
        }
        Remove-Item $localZip -Force -ErrorAction SilentlyContinue
        Write-Log ("phase_timing phase='self_update_maintenance' elapsed_ms={0} status='failed' reason='{1}'" -f `
            [math]::Round(((Get-Date) - $selfUpdateStartedAt).TotalMilliseconds), $failureReason) "WARN"
    }
}
