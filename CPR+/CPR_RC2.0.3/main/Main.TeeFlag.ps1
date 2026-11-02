# Main.TeeFlag.ps1 - user-touchable tee level flag + automatic revert.
#
# A user without admin rights can create  C:\Windows\Temp\cpr_tee_<1-5>.flag  or  cpr_tee_<1-5>_keep.flag.
# The next WW_main run (running as SYSTEM) applies that level through WW_set_tee_level.ps1 - the same
# lever the admin console and the installer use. The flag is NAME ONLY: its content is never read.
# On success the flag is deleted; on any failure it is renamed *.failed (swept after
# $TeeFlagFailedMaxAgeDays).
#   cpr_tee_<N>.flag       -> level N, reverts to the previous level after $TeeFlagRevertHours (14 days)
#   cpr_tee_<N>_keep.flag  -> level N, sticks (cancels any pending revert) until someone changes it

function Read-TeeRevertState {
    if (-not (Test-Path -LiteralPath $TeeRevertStateFile)) { return $null }
    try { return (Get-Content -LiteralPath $TeeRevertStateFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop) }
    catch {
        Write-Log "TeeFlag: revert state unreadable - discarding ($_)" "WARN"
        Remove-Item -LiteralPath $TeeRevertStateFile -Force -ErrorAction SilentlyContinue
        return $null
    }
}

function Send-TeeLevelSetEvent {
    param($Level, $PreviousLevel, [string]$Source, [string]$Result, [string]$Reason = '')
    try {
        Write-TeeLog 'tee_level_set' @{
            level          = "$Level"
            previous_level = $(if ($null -ne $PreviousLevel) { "$PreviousLevel" } else { '' })
            source         = $Source
            result         = $Result
            reason         = $Reason
        }
    } catch { }
}

function Send-TeeLevelInfoIfDue {
    <#
    Reports the EFFECTIVE tee level and why, at every level (tee_level_info lives in master L0, so even
    level 0 reports). Sent when the active profile file changed or $TeeLevelInfoHours have passed.
    The cheap check (file stamp vs. active file timestamp) runs first; the profile is only parsed when due.
    #>
    try {
        if (-not (Test-Path -LiteralPath $TeeEventsFile)) { Write-Log "TeeLevelInfo: skipped - active profile missing ($TeeEventsFile)" "DEBUG"; return }
        $f = Get-Item -LiteralPath $TeeEventsFile -ErrorAction Stop
        $sig = "$($f.LastWriteTimeUtc.Ticks)|$($f.Length)"
        if (Test-Path -LiteralPath $TeeLevelInfoStampFile) {
            try {
                $stamp = Get-Content -LiteralPath $TeeLevelInfoStampFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $at = [datetime]::MinValue
                if ($stamp.signature -eq $sig -and [datetime]::TryParse([string]$stamp.sent_at, [ref]$at) -and
                    ((Get-Date) - $at).TotalHours -lt $TeeLevelInfoHours) {
                    Write-Log ("TeeLevelInfo: not due (sent {0:N1}h ago, profile unchanged)" -f ((Get-Date) - $at).TotalHours) "DEBUG"
                    return
                }
            } catch { }
        }
        $info = Get-CprActiveTeeLevelInfo -ActivePath $TeeEventsFile
        if (-not $info.Readable -or $null -eq $info.Level) { Write-Log "TeeLevelInfo: skipped - active profile unreadable or has no Level (readable=$($info.Readable) level=$($info.Level))" "WARN"; return }
        $st = Read-TeeRevertState
        $revertAt = if ($st -and $st.expires_at) { [string]$st.expires_at } else { '' }
        $r = Write-TeeLog 'tee_level_info' @{
            level           = "$($info.Level)"
            reason          = $(if ($info.Reason) { "$($info.Reason)" } else { 'unknown_legacy' })
            source          = $(if ($info.GeneratedBy) { "$($info.GeneratedBy)" } else { 'unknown' })
            generated       = $(if ($info.Generated) { "$($info.Generated)" } else { '' })
            profile_version = $(if ($info.ProfileVersion) { "$($info.ProfileVersion)" } else { '' })
            revert_at       = $revertAt
            tag_count       = "$($info.TagCount)"
        } -PassThru
        if ($r) { Write-Log "TeeLevelInfo: level=$($info.Level) reason=$($info.Reason) queued=$($r.Queued) result=$($r.Reason)" "DEBUG" }
        if ($r -and $r.Queued) {
            @{ sent_at = (Get-Date).ToString('o'); signature = $sig } | ConvertTo-Json |
                Set-Content -LiteralPath $TeeLevelInfoStampFile -Encoding UTF8 -Force -ErrorAction SilentlyContinue
        }
    } catch { Write-Log "TeeLevelInfo: error (ignored): $_" "WARN" }
}

function Move-TeeFlagToFailed {
    param([string]$Path)
    try {
        $failed = [System.IO.Path]::ChangeExtension($Path, '.failed')
        Move-Item -LiteralPath $Path -Destination $failed -Force -ErrorAction Stop
    } catch {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-TeeLevelFlagCheck {
    <# Cheap when idle: one filtered directory listing and one Test-Path. Never throws. #>
    if (-not $TeeFlagEnabled) { return }
    try {
        if (-not (Test-Path -LiteralPath $TeeSetScript) -or -not (Test-Path -LiteralPath $TeeMasterFile)) {
            Write-Log "TeeFlag: skipped - tee tool or master missing (tool=$(Test-Path -LiteralPath $TeeSetScript) master=$(Test-Path -LiteralPath $TeeMasterFile)) - reinstall needed" "WARN"
            return
        }

        # Dot-sourced INSIDE this function so the tool's parameters never leak into the main scope.
        . $TeeSetScript

        $now   = Get-Date
        $state = Read-TeeRevertState

        # ---- 1. automatic revert of a flag-set level -------------------------------------------
        if ($state -and $state.expires_at) {
            $expires = [datetime]::MinValue
            if ([datetime]::TryParse([string]$state.expires_at, [ref]$expires) -and $now -ge $expires) {
                $info = Get-CprActiveTeeLevelInfo -ActivePath $TeeEventsFile
                if ($null -ne $info.Level -and [int]$info.Level -eq [int]$state.set_level) {
                    if ($WhatIf) { Write-Log "WHATIF: would revert tee level $($state.set_level) -> $($state.previous_level)" "INFO" }
                    else {
                        $r = Set-CprTeeLevel -Level ([int]$state.previous_level) -MasterPath $TeeMasterFile -ActivePath $TeeEventsFile -GeneratedBy 'cpr_tee_revert' -Reason 'revert_expired'
                        if ($r.Success) {
                            Write-Log "TeeFlag: reverted tee level $($state.set_level) -> $($state.previous_level) (flag level expired)" "INFO"
                            Send-TeeLevelSetEvent -Level $state.previous_level -PreviousLevel $state.set_level -Source 'revert' -Result 'reverted' -Reason 'expired'
                            Remove-Item -LiteralPath $TeeRevertStateFile -Force -ErrorAction SilentlyContinue
                            $state = $null
                        } else {
                            Write-Log "TeeFlag: revert failed, will retry next run: $($r.Error)" "WARN"
                        }
                    }
                } else {
                    Write-Log "TeeFlag: level was changed by someone else since the flag - not reverting" "INFO"
                    Remove-Item -LiteralPath $TeeRevertStateFile -Force -ErrorAction SilentlyContinue
                    $state = $null
                }
            }
        }

        # ---- 2. flags ----------------------------------------------------------------------------
        $teeFiles = @(Get-ChildItem -LiteralPath $TeeFlagDir -Filter 'cpr_tee_*' -File -ErrorAction SilentlyContinue)
        $valid = @(); $invalid = @()
        foreach ($f in $teeFiles) {
            if ($f.Extension -ne '.flag') { continue }
            if ($f.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { $invalid += $f; continue }
            if ($f.Name -match '^cpr_tee_([1-5])(_keep)?\.flag$') { $valid += [pscustomobject]@{ File = $f; Level = [int]$Matches[1]; Keep = [bool]$Matches[2] } }
            else { $invalid += $f }
        }
        foreach ($f in $invalid) {
            Write-Log "TeeFlag: ignoring invalid flag name '$($f.Name)' (expected cpr_tee_<1-5>.flag or cpr_tee_<1-5>_keep.flag)" "WARN"
            if (-not $WhatIf) { Move-TeeFlagToFailed -Path $f.FullName }
            Send-TeeLevelSetEvent -Level '' -PreviousLevel $null -Source 'flag' -Result 'rejected' -Reason 'invalid_name'
        }

        if ($valid.Count -gt 0) {
            $last = $null
            if ($state -and $state.applied_at) {
                $t = [datetime]::MinValue
                if ([datetime]::TryParse([string]$state.applied_at, [ref]$t)) { $last = $t }
            }
            if ($last -and ($now - $last).TotalMinutes -lt $TeeFlagCooldownMinutes) {
                Write-Log "TeeFlag: cooldown ($TeeFlagCooldownMinutes min) - flag left in place for a later run" "DEBUG"
            } else {
                # Highest level wins; at the same level the sticky (_keep) flag wins.
                $pick = $valid | Sort-Object @{ Expression = 'Level'; Descending = $true }, @{ Expression = 'Keep'; Descending = $true } | Select-Object -First 1
                foreach ($v in $valid) {
                    if ($v.File.FullName -ne $pick.File.FullName -and -not $WhatIf) {
                        Remove-Item -LiteralPath $v.File.FullName -Force -ErrorAction SilentlyContinue
                    }
                }
                $info = Get-CprActiveTeeLevelInfo -ActivePath $TeeEventsFile
                # A PENDING revert keeps its original previous level (flags don't chain); otherwise
                # the level to return to is whatever is active right now.
                $previous = if ($state -and $state.expires_at -and $null -ne $state.previous_level) { [int]$state.previous_level }
                            elseif ($null -ne $info.Level) { [int]$info.Level }
                            else { [int]$TeeDefaultLevel }
                if ($WhatIf) {
                    Write-Log "WHATIF: would set tee level $($pick.Level) from $($pick.File.Name)" "INFO"
                } else {
                    $r = Set-CprTeeLevel -Level $pick.Level -MasterPath $TeeMasterFile -ActivePath $TeeEventsFile -GeneratedBy 'cpr_tee_flag' -Reason $(if ($pick.Keep) { 'flag_keep' } else { 'flag' })
                    if ($r.Success) {
                        Remove-Item -LiteralPath $pick.File.FullName -Force -ErrorAction SilentlyContinue
                        $stateOut = [ordered]@{
                            previous_level = $previous
                            set_level      = $pick.Level
                            applied_at     = $now.ToString('o')
                            expires_at     = $(if (-not $pick.Keep -and $TeeFlagRevertHours -gt 0) { $now.AddHours($TeeFlagRevertHours).ToString('o') } else { $null })
                            keep           = $pick.Keep
                        }
                        try { ($stateOut | ConvertTo-Json) | Set-Content -LiteralPath $TeeRevertStateFile -Encoding UTF8 -Force -ErrorAction Stop }
                        catch { Write-Log "TeeFlag: could not write revert state: $_" "WARN" }
                        Write-Log "TeeFlag: tee level set to $($pick.Level) by $($pick.File.Name) (previous=$previous, $(if ($pick.Keep) { 'keep - no revert' } else { "revert after ${TeeFlagRevertHours}h" }))" "INFO"
                        Send-TeeLevelSetEvent -Level $pick.Level -PreviousLevel $previous -Source 'flag' -Result 'applied' -Reason $(if ($pick.Keep) { 'keep' } else { "revert_hours=$TeeFlagRevertHours" })
                    } else {
                        Write-Log "TeeFlag: could not set tee level $($pick.Level): $($r.Error)" "WARN"
                        Move-TeeFlagToFailed -Path $pick.File.FullName
                        Send-TeeLevelSetEvent -Level $pick.Level -PreviousLevel $previous -Source 'flag' -Result 'failed' -Reason "$($r.Error)"
                    }
                }
            }
        }

        # ---- 2b. effective level report (always-on, level 0 and up) ------------------------------
        if (-not $WhatIf) { Send-TeeLevelInfoIfDue }

        # ---- 3. sweep stale *.failed -------------------------------------------------------------
        if (-not $WhatIf) {
            $cut = $now.AddDays(-[math]::Abs($TeeFlagFailedMaxAgeDays))
            foreach ($pat in @('cpr_tee_*.failed', 'cpr_update_*.failed')) {
                Get-ChildItem -LiteralPath $TeeFlagDir -Filter $pat -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt $cut } |
                    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue }
            }
        }
    } catch {
        Write-Log "TeeFlag: unexpected error (ignored): $_" "WARN"
    }
}
