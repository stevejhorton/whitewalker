<#
.SYNOPSIS
    Menu-driven viewer for CPR RC2 runtime logs.

.DESCRIPTION
    Uses only Windows PowerShell built-ins.  With no parameters it presents a
    numbered menu; parameters are intended for scripted and remote use.
#>
[CmdletBinding()]
param(
    [ValidateSet('Main','Installer','CapPortal','CapPortalBase','Haystack','SyslogQueue',
        'FlareGunSystem','FlareGunUser','XmlVault','VpnHosts','Notify','Diagnostics','BrowserTest',
        'AdminActions')]
    [string]$Stream,
    [ValidateRange(1, 1000000)]
    [int]$Last = 200,
    [switch]$Wait,
    [string]$Filter,
    [switch]$All
)

$script:WhiteWalkerLogRoot = 'C:\ProgramData\WhiteWalker\logs'
$script:WhiteWalkerLogInventory = @(
    [pscustomobject]@{ Name='Main';           File='white_walker.main.log';             Description='Main WhiteWalker orchestration';              Json=$false }
    [pscustomobject]@{ Name='Installer';      File='white_walker_install.log';          Description='Installer execution and validation';           Json=$false }
    [pscustomobject]@{ Name='CapPortal';     File='white_walker.cap_portal.log';       Description='Full captive-portal runner';                  Json=$false }
    [pscustomobject]@{ Name='CapPortalBase'; File='white_walker.cap_portal_base.log';  Description='Base captive-portal runner';                   Json=$false }
    [pscustomobject]@{ Name='Haystack';      File='haystack.log';                      Description='HayStack event monitoring and queue draining'; Json=$false }
    [pscustomobject]@{ Name='SyslogQueue';   File='haystack_syslog_queue.jsonl';       Description='HayStack and tee telemetry queue (JSONL)';    Json=$true  }
    [pscustomobject]@{ Name='FlareGunSystem';File='white_walker.flaregun_system.log';  Description='SYSTEM flare processing';                     Json=$false }
    [pscustomobject]@{ Name='FlareGunUser';  File='white_walker.flaregun_user.log';    Description='User-context flare processing';              Json=$false }
    [pscustomobject]@{ Name='XmlVault';      File='white_walker.xml_vault.log';        Description='VPN XML vault operations';                    Json=$false }
    [pscustomobject]@{ Name='VpnHosts';      File='Set-VpnHostsEntry.log';             Description='VPN blackhole hosts-file changes';            Json=$false }
    [pscustomobject]@{ Name='Notify';        File='WW_notify.log';                     Description='User notifications';                         Json=$false }
    [pscustomobject]@{ Name='Diagnostics';   File='diag_yyyyMMdd_HHmmss.log';           Description='On-demand diagnostic reports';                Json=$false }
    [pscustomobject]@{ Name='BrowserTest';   File='white_walker.browser_test.log';     Description='Browser diagnostic test output';              Json=$false }
    [pscustomobject]@{ Name='AdminActions';  File='white_walker.admin_actions.log';    Description='Admin action console audit trail';            Json=$false }
)

function Get-WWLogInventory {
    return $script:WhiteWalkerLogInventory
}

function Get-WWLogDefinition {
    param([Parameter(Mandatory)][string]$Name)
    $definition = $script:WhiteWalkerLogInventory | Where-Object Name -eq $Name
    if (-not $definition) { throw "Unknown WhiteWalker log stream: $Name" }
    return $definition
}

function Get-WWLogPath {
    param([Parameter(Mandatory)][psobject]$Definition)
    if ($Definition.Name -eq 'Diagnostics') {
        $latest = Get-ChildItem -LiteralPath $script:WhiteWalkerLogRoot -Filter 'diag_*.log' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($latest) { return $latest.FullName }
        return Join-Path $script:WhiteWalkerLogRoot 'diag_yyyyMMdd_HHmmss.log'
    }
    return ($script:WhiteWalkerLogRoot + '\' + $Definition.File)
}

function Get-WWLogSeverity {
    param([AllowEmptyString()][string]$Line)
    if ($Line -match '(?i)\[(ERROR|FATAL)\]|\b(ERROR|FATAL)\b') { return 'Error' }
    if ($Line -match '(?i)\[(WARN|WARNING)\]|\b(WARN|WARNING)\b') { return 'Warning' }
    if ($Line -match '(?i)\[DEBUG\]|\bDEBUG\b') { return 'Debug' }
    if ($Line -match '(?i)\[INFO\]|\bINFO\b') { return 'Info' }
    return 'Plain'
}

function Get-WWSeverityColor {
    param([Parameter(Mandatory)][ValidateSet('Error','Warning','Debug','Info','Plain')][string]$Severity)
    switch ($Severity) {
        'Error'   { return 'Red' }
        'Warning' { return 'Yellow' }
        'Debug'   { return 'DarkGray' }
        'Info'    { return 'Gray' }
        default   { return 'White' }
    }
}

function ConvertFrom-WWJsonLine {
    param([Parameter(Mandatory)][string]$Line)
    try {
        $item = $Line | ConvertFrom-Json -ErrorAction Stop
        $timestamp = $null
        foreach ($field in @('EvtTime','timestamp','time','ts')) {
            if ($item.PSObject.Properties.Name -contains $field) {
                $timestamp = $item.$field
                if ($timestamp -is [datetime]) {
                    $timestamp = $timestamp.ToString('yyyy-MM-ddTHH:mm:ss.fffK',
                        [Globalization.CultureInfo]::InvariantCulture)
                }
                break
            }
        }
        $parts = @()
        if ($timestamp) { $parts += [string]$timestamp }
        foreach ($field in @('action','machine','user','status','reason')) {
            if ($item.PSObject.Properties.Name -contains $field -and $null -ne $item.$field -and "$($item.$field)" -ne '') {
                $parts += "$field=$($item.$field)"
            }
        }
        if ($parts.Count -gt 0) { return ($parts -join ' ') }
    } catch { }
    return $Line
}

function Get-WWTimestamp {
    param([AllowEmptyString()][string]$Line)
    $match = [regex]::Match($Line, '\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?')
    $value = [datetime]::MinValue
    if ($match.Success) {
        [datetime]::TryParse($match.Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeLocal, [ref]$value) | Out-Null
    }
    return $value
}

function Test-WWLogFilter {
    param([AllowEmptyString()][string]$Line, [AllowEmptyString()][string]$Filter)
    return [string]::IsNullOrEmpty($Filter) -or $Line.IndexOf($Filter, [StringComparison]::OrdinalIgnoreCase) -ge 0
}

function Write-WWLogLine {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Line,
        [string]$Source,
        [switch]$Json
    )
    if ([string]::IsNullOrWhiteSpace($Line)) { return }
    $display = if ($Json) { ConvertFrom-WWJsonLine $Line } else { $Line }
    $severity = Get-WWLogSeverity $display
    $prefix = if ($Source) { "[$Source] " } else { '' }
    Write-Host ($prefix + $display) -ForegroundColor (Get-WWSeverityColor $severity)
}

function Get-WWLogLines {
    param([Parameter(Mandatory)][psobject]$Definition, [int]$Count = 200)
    $path = Get-WWLogPath $Definition
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Host "Log not found (it may not have been created yet): $path" -ForegroundColor DarkYellow
        return @()
    }
    return @(Get-Content -LiteralPath $path -Tail $Count -ErrorAction SilentlyContinue)
}

function Get-WWFileLength {
    # Current byte length, or -1 when the file does not exist / is unreadable.
    param([Parameter(Mandatory)][string]$Path)
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        return [int64]$item.Length
    } catch {
        return [int64](-1)
    }
}

function Read-WWLogTail {
    <#
    .SYNOPSIS
    Byte-offset tail reader (RC2.2).

    .DESCRIPTION
    The previous tailer tracked position by LINE COUNT via repeated
    Get-Content, so every rotation (Invoke-LogRotation renames the live log to
    `.1` at 1MB and the SYSTEM writer recreates it) or truncation made the
    count invalid and the whole log was re-spooled from the top - the defect
    the owner saw on screen.

    Position is now tracked by BYTE OFFSET:

      current length  > offset  -> append:    read only the new bytes
      current length  < offset  -> rotated or truncated: reset to 0 deliberately
                                   and read the new file from its start
      current length == offset  -> nothing new

    The file is opened Read with FileShare::ReadWrite|Delete on every poll so a
    SYSTEM-context writer can keep writing, rotating and recreating it while we
    read. Returns @{ Offset; Lines; Event } where Event is
    'append' | 'rotated' | 'truncated' | 'none' | 'missing'.
    #>
    param(
        [Parameter(Mandatory)][string]$Path,
        [int64]$Offset = 0
    )

    $result = @{ Offset = $Offset; Lines = @(); Event = 'none' }

    $length = Get-WWFileLength $Path
    if ($length -lt 0) {
        # Writer may be mid-rotation; keep the offset so an unchanged file is
        # not replayed when it reappears.
        $result.Event = 'missing'
        return $result
    }

    if ($length -eq $Offset) { return $result }

    if ($length -lt $Offset) {
        # Rotated (renamed to .1 and recreated) or truncated in place. Either
        # way the stored offset no longer addresses this file: reset to 0 and
        # read the new content deliberately, exactly once.
        $result.Event = if (Test-Path -LiteralPath ($Path + '.1') -PathType Leaf) { 'rotated' } else { 'truncated' }
        $Offset = 0
    } else {
        $result.Event = 'append'
    }

    $stream = $null
    $reader = $null
    try {
        $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
            ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        [void]$stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
        $reader = New-Object System.IO.StreamReader($stream)
        $text = $reader.ReadToEnd()
        $result.Offset = $stream.Position
        if ($text) {
            $result.Lines = @($text -split "`r?`n")
            # A trailing newline produces a final empty element; a partially
            # written last line is kept (the next poll re-reads from here).
            if ($result.Lines.Count -gt 0 -and [string]::IsNullOrEmpty($result.Lines[-1])) {
                $result.Lines = @($result.Lines[0..($result.Lines.Count - 2)])
            }
        }
    } catch {
        # Transient sharing/rotation error - keep the previous offset and retry.
        $result.Offset = $Offset
        $result.Lines = @()
    } finally {
        if ($reader) { try { $reader.Dispose() } catch { } }
        if ($stream) { try { $stream.Dispose() } catch { } }
    }

    return $result
}

function Test-WWExitKeyPressed {
    <#
    NON-BLOCKING key check so a tail loop hosted inside
    admin\Invoke-WhiteWalkerAction.ps1 can return to the menu on Q or Esc
    without exiting the console. Returns $false in any host without an
    interactive key-available API (ISE, remoting, Pester).
    #>
    try {
        if (-not $Host.UI.RawUI) { return $false }
        if (-not [console]::KeyAvailable) { return $false }
        $key = [console]::ReadKey($true)
        return ($key.Key -eq [ConsoleKey]::Escape -or $key.Key -eq [ConsoleKey]::Q)
    } catch {
        return $false
    }
}

function Show-WWLogStream {
    param(
        [Parameter(Mandatory)][psobject]$Definition,
        [int]$Count,
        [string]$Match,
        [switch]$Follow,
        [switch]$AllowExitKey,
        [int]$MaxIterations = 0
    )
    $path = Get-WWLogPath $Definition
    $lines = @(Get-WWLogLines $Definition $Count)
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if (Test-WWLogFilter $line $Match) { Write-WWLogLine $line -Source $Definition.Name -Json:$Definition.Json }
    }
    if (-not $Follow -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return }

    if ($AllowExitKey) {
        Write-Host "`n-- live tail: press Q or Esc to return to the menu --" -ForegroundColor DarkCyan
    }

    # Start at the CURRENT end of file: the backlog above was already printed.
    $offset = Get-WWFileLength $path
    if ($offset -lt 0) { $offset = 0 }
    $iterations = 0
    while ($true) {
        Start-Sleep -Milliseconds 500
        if ($AllowExitKey -and (Test-WWExitKeyPressed)) {
            Write-Host "Stopped tailing $($Definition.Name)." -ForegroundColor Yellow
            return
        }

        $tail = Read-WWLogTail -Path $path -Offset $offset
        $offset = $tail.Offset
        if ($tail.Event -eq 'rotated' -or $tail.Event -eq 'truncated') {
            Write-Host "-- log $($tail.Event); re-opened $path from the start --" -ForegroundColor DarkYellow
        }
        foreach ($line in $tail.Lines) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if (Test-WWLogFilter $line $Match) { Write-WWLogLine $line -Source $Definition.Name -Json:$Definition.Json }
        }

        $iterations++
        if ($MaxIterations -gt 0 -and $iterations -ge $MaxIterations) { return }
    }
}

function Show-WWCombinedLogs {
    param([int]$Count, [string]$Match, [switch]$Follow)
    $definitions = Get-WWLogInventory
    $seen = @{}
    $reportedMissing = @{}
    do {
        $batch = @()
        foreach ($definition in $definitions) {
            $path = Get-WWLogPath $definition
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                if (-not $reportedMissing.ContainsKey($definition.Name)) {
                    Write-Host "[$($definition.Name)] Log not found (it may not have been created yet): $path" -ForegroundColor DarkYellow
                    $reportedMissing[$definition.Name] = $true
                }
                continue
            }
            $allLines = if ($Follow) {
                @(Get-Content -LiteralPath $path -ErrorAction SilentlyContinue)
            } else {
                @(Get-Content -LiteralPath $path -Tail $Count -ErrorAction SilentlyContinue)
            }
            $lines = $allLines
            $start = if ($seen.ContainsKey($definition.Name)) {
                [int]$seen[$definition.Name]
            } elseif ($Follow) {
                [Math]::Max(0, $allLines.Count - $Count)
            } else {
                0
            }
            if ($lines.Count -lt $start) { $start = 0 }
            if ($lines.Count -gt $start) {
                foreach ($line in $lines[$start..($lines.Count - 1)]) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    if (Test-WWLogFilter $line $Match) {
                        $batch += [pscustomobject]@{ Definition=$definition; Line=$line; Time=(Get-WWTimestamp $line) }
                    }
                }
            }
            $seen[$definition.Name] = $allLines.Count
        }
        foreach ($entry in ($batch | Sort-Object Time)) {
            Write-WWLogLine $entry.Line -Source $entry.Definition.Name -Json:$entry.Definition.Json
        }
        if ($Follow) { Start-Sleep -Milliseconds 500 }
    } while ($Follow)
}

function Start-WWLogMenu {
    $definitions = Get-WWLogInventory
    Write-Host "`nWhiteWalker log viewer" -ForegroundColor Cyan
    for ($i = 0; $i -lt $definitions.Count; $i++) {
        Write-Host ("{0,2}. {1,-15} {2}" -f ($i + 1), $definitions[$i].Name, $definitions[$i].Description)
    }
    Write-Host ("{0,2}. {1}" -f ($definitions.Count + 1), 'Everything')
    $selection = [int](Read-Host 'Select a stream')
    if ($selection -eq $definitions.Count + 1) {
        Show-WWCombinedLogs -Count $Last -Match $Filter -Follow:$Wait
        return
    }
    if ($selection -lt 1 -or $selection -gt $definitions.Count) { throw 'Invalid stream selection.' }
    $definition = $definitions[$selection - 1]
    $action = Read-Host '1=live tail, 2=last lines, 3=filter'
    if ($action -eq '3') { $Filter = Read-Host 'Keyword' }
    Show-WWLogStream -Definition $definition -Count $Last -Match $Filter -Follow:($action -eq '1')
}

if (-not ($MyInvocation.InvocationName -eq '.')) {
    if ($PSBoundParameters.Count -eq 0) {
        Start-WWLogMenu
    } elseif ($All) {
        Show-WWCombinedLogs -Count $Last -Match $Filter -Follow:$Wait
    } elseif ($Stream) {
        Show-WWLogStream -Definition (Get-WWLogDefinition $Stream) -Count $Last -Match $Filter -Follow:$Wait
    } else {
        throw 'Specify -Stream <name> or -All.'
    }
}
