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

function Get-TeeAssignLevelFromLines {
    <# Pure parser. [tee1]..[tee5] sections; one host name (or -like wildcard) per line; '#' comments; the
       highest matching section wins. Returns an int, or $null when the host is not listed. #>
    param([string[]]$Lines, [string]$ComputerName)
    $best = $null; $section = $null
    foreach ($raw in @($Lines)) {
        $l = ("$raw" -replace '\s+#.*$', '').Trim()
        if (-not $l -or $l.StartsWith('#') -or $l -match '^version\s*:') { continue }
        if ($l -match '^\[tee([1-5])\]$') { $section = [int]$Matches[1]; continue }
        if ($l.StartsWith('[')) { $section = $null; continue }
        if ($null -eq $section) { continue }
        if ($ComputerName -like $l) { if ($null -eq $best -or $section -gt $best) { $best = $section } }
    }
    return $best
}

function Sync-TeeAssignFile {
    <# Reads tee_assign.cfg from the share when due. Returns $true when the share was read OK within
       $TeeAssignFreshHours (this run or a recent one). Bounded: one 300 ms TCP probe, failures back off. #>
    $now = Get-Date
    $lastOk = $null
    if (Test-Path -LiteralPath $TeeAssignSyncFlag) {
        try { $lastOk = [datetime]::Parse((Get-Content -LiteralPath $TeeAssignSyncFlag -Raw -ErrorAction Stop).Trim()) } catch { $lastOk = $null }
    }
    if ($lastOk -and ($now - $lastOk).TotalHours -lt $TeeAssignSyncCooldownHours) { return $true }
    if (Test-Path -LiteralPath $TeeAssignTryFlag) {
        $tried = (Get-Item -LiteralPath $TeeAssignTryFlag -ErrorAction SilentlyContinue).LastWriteTime
        if ($tried -and ($now - $tried).TotalMinutes -lt $TeeAssignRetryMinutes) {
            return [bool]($lastOk -and ($now - $lastOk).TotalHours -lt $TeeAssignFreshHours)
        }
    }
    $ok = $false
    try {
        (Get-Date -Format 'o') | Set-Content -LiteralPath $TeeAssignTryFlag -Encoding UTF8 -Force -ErrorAction SilentlyContinue
        $shareHost = ([uri]("file:" + ($TeeAssignRemoteFile -replace '\\', '/'))).Host
        if ((Test-ShareReachableFast -HostName $shareHost -TimeoutMs 300) -and (Test-Path -LiteralPath $TeeAssignRemoteFile)) {
            $remote = Get-Content -LiteralPath $TeeAssignRemoteFile -Raw -ErrorAction Stop
            $local  = if (Test-Path -LiteralPath $TeeAssignFile) { Get-Content -LiteralPath $TeeAssignFile -Raw -ErrorAction SilentlyContinue } else { $null }
            if ($remote -ne $local) {
                Set-Content -LiteralPath $TeeAssignFile -Value $remote -Encoding UTF8 -Force -NoNewline -ErrorAction Stop
                Write-Log "TeeAssign: tee_assign.cfg updated from share" "INFO"
            }
            (Get-Date -Format 'o') | Set-Content -LiteralPath $TeeAssignSyncFlag -Encoding UTF8 -Force -ErrorAction Stop
            $ok = $true
        } else {
            Write-Log "TeeAssign: share not reachable - using the local copy, no extend/apply" "DEBUG"
        }
    } catch { Write-Log "TeeAssign: sync error (ignored): $_" "WARN" }
    if ($ok) { return $true }
    return [bool]($lastOk -and ($now - $lastOk).TotalHours -lt $TeeAssignFreshHours)
}

function Get-TeeAssignment {
    <# Returns @{ Level = <1-5 or $null>; Fresh = <share read OK recently> }. Never throws. #>
    $res = [pscustomobject]@{ Level = $null; Fresh = $false }
    try {
        if (-not $TeeAssignEnabled) { return $res }
        $res.Fresh = [bool](Sync-TeeAssignFile)
        if ($res.Fresh -and (Test-Path -LiteralPath $TeeAssignFile)) {
            $res.Level = Get-TeeAssignLevelFromLines -Lines (Get-Content -LiteralPath $TeeAssignFile -ErrorAction Stop) -ComputerName $env:COMPUTERNAME
        }
    } catch { Write-Log "TeeAssign: error (ignored): $_" "WARN" }
    return $res
}

function Write-TeeRevertState {
    param($Obj)
    try { ($Obj | ConvertTo-Json) | Set-Content -LiteralPath $TeeRevertStateFile -Encoding UTF8 -Force -ErrorAction Stop; return $true }
    catch { Write-Log "TeeFlag: could not write revert state: $_" "WARN"; return $false }
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

        # ---- 0. share-assigned level: push the revert time out while the host stays listed ----------
        $assign = Get-TeeAssignment
        if ($assign.Fresh -and $null -ne $assign.Level -and $state -and $state.source -eq 'manifest' -and $state.expires_at -and
            [int]$state.set_level -eq [int]$assign.Level -and $TeeFlagRevertHours -gt 0) {
            $exp0 = [datetime]::MinValue
            if ([datetime]::TryParse([string]$state.expires_at, [ref]$exp0) -and ($exp0 - $now).TotalHours -lt ($TeeFlagRevertHours - $TeeAssignExtendMinGapHours)) {
                $act0 = Get-CprActiveTeeLevelInfo -ActivePath $TeeEventsFile
                if ($null -ne $act0.Level -and [int]$act0.Level -eq [int]$state.set_level) {
                    $newExp = $now.AddHours($TeeFlagRevertHours)
                    if ($WhatIf) { Write-Log "WHATIF: would extend tee level $($state.set_level) revert to $($newExp.ToString('o'))" "INFO" }
                    else {
                        $state.expires_at = $newExp.ToString('o')
                        if (Write-TeeRevertState -Obj $state) {
                            Write-Log "TeeAssign: host still listed in tee$($assign.Level) - revert time extended to $($newExp.ToString('s')) (was $($exp0.ToString('s')))" "INFO"
                            Send-TeeLevelSetEvent -Level $state.set_level -PreviousLevel $state.previous_level -Source 'manifest' -Result 'extended' -Reason "revert_hours=$TeeFlagRevertHours"
                        }
                    }
                }
            }
        }

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

        # ---- 2a. share-assigned level: apply it (manual flags and manual stamps take precedence) ---
        if ($assign.Fresh -and $null -ne $assign.Level -and -not $WhatIf) {
            $state = Read-TeeRevertState
            $info  = Get-CprActiveTeeLevelInfo -ActivePath $TeeEventsFile
            $cur   = if ($null -ne $info.Level) { [int]$info.Level } else { [int]$TeeDefaultLevel }
            $go = $false; $previousA = $cur
            if (-not $state) {
                if ($cur -ge [int]$assign.Level) { Write-Log "TeeAssign: listed in tee$($assign.Level) but already at level $cur - nothing to do" "DEBUG" }
                else { $go = $true }
            } elseif ($state.source -eq 'manifest' -and [int]$state.set_level -ne [int]$assign.Level -and $cur -eq [int]$state.set_level) {
                $go = $true; $previousA = [int]$state.previous_level      # the list moved this host to another level
            } elseif ($state.source -ne 'manifest') {
                Write-Log "TeeAssign: listed in tee$($assign.Level) but a manual tee state is active - left alone" "DEBUG"
            }
            if ($go) {
                $r = Set-CprTeeLevel -Level ([int]$assign.Level) -MasterPath $TeeMasterFile -ActivePath $TeeEventsFile -GeneratedBy 'cpr_tee_assign' -Reason 'manifest'
                if ($r.Success) {
                    $stateOut = [ordered]@{
                        previous_level = $previousA
                        set_level      = [int]$assign.Level
                        applied_at     = $now.ToString('o')
                        expires_at     = $(if ($TeeFlagRevertHours -gt 0) { $now.AddHours($TeeFlagRevertHours).ToString('o') } else { $null })
                        keep           = $false
                        source         = 'manifest'
                    }
                    [void](Write-TeeRevertState -Obj $stateOut)
                    Write-Log "TeeAssign: tee level set to $($assign.Level) from tee_assign.cfg (previous=$previousA, revert after ${TeeFlagRevertHours}h unless still listed)" "INFO"
                    Send-TeeLevelSetEvent -Level $assign.Level -PreviousLevel $previousA -Source 'manifest' -Result 'applied' -Reason "revert_hours=$TeeFlagRevertHours"
                } else {
                    Write-Log "TeeAssign: could not set tee level $($assign.Level): $($r.Error)" "WARN"
                    Send-TeeLevelSetEvent -Level $assign.Level -PreviousLevel $previousA -Source 'manifest' -Result 'failed' -Reason "$($r.Error)"
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
