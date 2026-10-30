# CPR RC2 logging, run headers, and system-context utilities.
# Depends on: WW_csc_client_info.ps1 and WW_tee.ps1 loaded by WW_main.ps1.

function Invoke-LogRotation {
    # Size-based rotation. Runs before logger opens the file.
    # Keeps last $LogRotationKeep files as .1 .2 ... .5
    if (-not (Test-Path $LogPath)) { return }
    
    $size = (Get-Item $LogPath -ErrorAction SilentlyContinue).Length
    if ($size -lt $LogRotationMaxBytes) { return }
    
    Write-Host "Log rotation triggered: $LogPath ($([math]::Round($size/1KB))KB)"
    
    # Drop oldest if already at limit
    $oldest = "$LogPath.$LogRotationKeep"
    if (Test-Path $oldest) { Remove-Item $oldest -Force -ErrorAction SilentlyContinue }
    
    # Shift .1-.4 down to .2-.5
    for ($i = ($LogRotationKeep - 1); $i -ge 1; $i--) {
        $src = "$LogPath.$i"
        $dst = "$LogPath.$($i + 1)"
        if (Test-Path $src) { Rename-Item $src $dst -Force -ErrorAction SilentlyContinue }
    }
    
    # Rotate current log to .1
    Rename-Item $LogPath "$LogPath.1" -Force -ErrorAction SilentlyContinue
}

function Initialize-Logger {
  Invoke-LogRotation
  $dir = Split-Path -Parent $LogPath
  if (-not (Test-Path $dir)) { 
    try {
      New-Item -Path $dir -ItemType Directory -Force | Out-Null 
    } catch {
      Write-Host "WARNING: Cannot create log directory $dir - $_"
    }
  }
  if (-not (Test-Path $LogPath)) { 
    try {
      New-Item -Path $LogPath -ItemType File -Force | Out-Null 
    } catch {
      Write-Host "WARNING: Cannot create log file $LogPath - $_"
    }
  }
}

function Add-LogLine([string]$line) {
  # Retry through a transient lock (AV scan, a tail or editor holding the file): 6 tries, ~1s of backoff.
  # If the line still cannot be written, leave a trace in log_write_failures.txt instead of dropping it silently.
  $lastErr = ''
  for ($i=1; $i -le 6; $i++) {
    try   { Add-Content -Path $LogPath -Value $line -Encoding UTF8 -ErrorAction Stop; return }
    catch { $lastErr = $_.Exception.Message; Start-Sleep -Milliseconds (50 * $i) }
  }
  Write-Host "LOG WRITE FAILED: $lastErr"
  try {
    $failFile = Join-Path (Split-Path -Parent $LogPath) 'log_write_failures.txt'
    Add-Content -LiteralPath $failFile -Value ("{0} run={1} err={2} line={3}" -f (Get-Date -Format 'o'), $RunId, $lastErr, $line) -ErrorAction Stop
  } catch { }
}
# TEST-ONLY timing suffix. On when WW_main.ps1 is run with -WWTiming, or when the flag file
# C:\Windows\Temp\cpr_logtiming.flag exists. Appends " [+<ms since previous line>ms | <s since run start>s]".
# Off by default: the log text is then identical to what it always was.
$script:WWTimingFlagPath = 'C:\Windows\Temp\cpr_logtiming.flag'
$script:WWLogTiming = $false
try {
  $swSwitch = Get-Variable -Name WWTiming -ValueOnly -ErrorAction SilentlyContinue
  $script:WWLogTiming = ([bool]$swSwitch) -or (Test-Path -LiteralPath $script:WWTimingFlagPath)
} catch { $script:WWLogTiming = $false }
$script:WWLogClock = [System.Diagnostics.Stopwatch]::StartNew()
$script:WWLogLastMs = 0
function Get-LogTimingSuffix {
  $now = $script:WWLogClock.ElapsedMilliseconds
  $delta = $now - $script:WWLogLastMs
  $script:WWLogLastMs = $now
  return (" [+{0}ms | {1}s]" -f $delta, ([math]::Round($now / 1000.0, 2)).ToString([System.Globalization.CultureInfo]::InvariantCulture))
}
function Write-Log { param([Parameter(Mandatory=$true)][string]$Message, [string]$Level = "INFO")
  $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
  $logLine = "$ts [WW] [$Level] $Message"
  if ($script:WWLogTiming) { $logLine += (Get-LogTimingSuffix) }
  Add-LogLine $logLine
}
function Write-DebugBlock {
  param([Parameter(Mandatory=$true)][string]$Label,[Parameter(Mandatory=$true)][string]$Text)
  if (-not $WWTrace) { return }
  $flat = $Text.Replace("`r","").Replace("`n","[NL]")
  Write-Log ("DEBUG {0}:`n{1}" -f $Label, $flat)
}

# Run header/trailer with enhanced context
$RunId  = "{0}-{1}" -f (Get-Date -Format "yyyyMMddHHmmssfff"), $PID
$HostNm = $env:COMPUTERNAME
$UserNm = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

function Get-SystemContext {
    # Gather system info without slowing down execution
    $ctx = @{
        OS = "Unknown"
        Model = "Unknown"
        SerialNumber = "Unknown"
        LastBootTime = "Unknown"
    }
    
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($cs) {
            $ctx.Model = "$($cs.Manufacturer) $($cs.Model)"
        }
        
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            $ctx.OS = "$($os.Caption) $($os.Version)"
            $ctx.LastBootTime = $os.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
        if ($bios) {
            $ctx.SerialNumber = $bios.SerialNumber
        }
    } catch {
        Write-Log "Could not gather full system context: $_" "DEBUG"
    }
    
    return $ctx
}

# -----------------------------------------------------------------------------
# HEADER needle support - consolidated run-header field cache
# -----------------------------------------------------------------------------
# Write-RunHeader already computes this context for the free-text header lines
# in white_walker.main.log. These helpers additionally persist those values -
# unchanged - into a single header_cache.json so HayStack can ship opted-in
# fields as structured telemetry without anyone editing PowerShell. The
# free-text header output is untouched; this is a purely additive side channel.
#
# Fast path philosophy mirrors WW_csc_client_info.ps1: read the small cache,
# skip anything whose RefreshHours has not elapsed, and write the file at most
# once per run (all due fields in a single write - never one write per field).
#
# Keep $HeaderCacheFieldNames in sync with $HaystackHeaderFields in
# haystack.ps1 and haystack_action.ps1.
# -----------------------------------------------------------------------------
$HeaderCacheFieldNames = @(
    'ww_version'
    'os'
    'model'
    'serial'
    'last_boot'
    'csc_version'
    'csc_source'
    'vpn_profile'
)

function ConvertTo-HeaderCacheStamp {
    # ConvertFrom-Json rehydrates ISO-8601 strings as [datetime]. Normalize any
    # timestamp back to a round-trip ISO string so the cache stays stable and
    # culture-independent across reads/writes.
    param([object]$Value)

    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value.ToString('o') }
    if ($Value -is [datetime])       { return ([datetimeoffset]$Value).ToString('o') }
    return [string]$Value
}

function ConvertTo-HeaderCacheTable {
    # Normalizes deserialized header_cache.json into a mutable ordered hashtable.
    param([object]$Raw)

    $table = [ordered]@{
        SchemaVersion = 1
        UpdatedAt     = $null
        Fields        = [ordered]@{}
        Bundles       = [ordered]@{}
    }
    if ($null -eq $Raw) { return $table }

    if ($Raw.PSObject.Properties.Name -contains 'UpdatedAt') { $table.UpdatedAt = ConvertTo-HeaderCacheStamp -Value $Raw.UpdatedAt }
    if ($Raw.PSObject.Properties.Name -contains 'Fields' -and $Raw.Fields) {
        foreach ($prop in $Raw.Fields.PSObject.Properties) {
            $table.Fields[$prop.Name] = [ordered]@{
                value        = $prop.Value.value
                collected_at = ConvertTo-HeaderCacheStamp -Value $prop.Value.collected_at
                last_sent_at = ConvertTo-HeaderCacheStamp -Value $prop.Value.last_sent_at
            }
        }
    }
    if ($Raw.PSObject.Properties.Name -contains 'Bundles' -and $Raw.Bundles) {
        foreach ($prop in $Raw.Bundles.PSObject.Properties) {
            $table.Bundles[$prop.Name] = [ordered]@{ last_sent_at = ConvertTo-HeaderCacheStamp -Value $prop.Value.last_sent_at }
        }
    }
    return $table
}

function Read-HeaderCache {
    if (-not (Test-Path -LiteralPath $HeaderCacheFile)) { return $null }
    try {
        $raw = Get-Content -LiteralPath $HeaderCacheFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        return (ConvertTo-HeaderCacheTable -Raw $raw)
    } catch {
        Write-Log "HeaderCache: cache read/parse failed, rebuilding: $_" "DEBUG"
        return $null
    }
}

function Get-HeaderFieldRefreshHours {
    <#
    .SYNOPSIS
    Returns a field -> RefreshHours map derived from the active HEADER needles.

    Every known field starts at the global default. A HEADER needle naming a
    field (or '*' for all) lowers that field's interval when it asks for a
    shorter one, so no field goes staler than the most demanding consumer
    expects. Parsing here is deliberately permissive/best-effort - haystack.ps1
    owns directive validation and WARN logging.
    #>
    $hours = @{}
    foreach ($field in $HeaderCacheFieldNames) { $hours[$field] = $HeaderCacheDefaultRefreshHours }

    foreach ($file in $HeaderNeedleFiles) {
        if (-not (Test-Path -LiteralPath $file)) { continue }
        try {
            $lines = Get-Content -LiteralPath $file -ErrorAction Stop
        } catch {
            Write-Log "HeaderCache: could not read needle file '$file': $_" "DEBUG"
            continue
        }

        foreach ($line in $lines) {
            $trimmed = ([string]$line).Trim()
            if ($trimmed -notmatch '^HEADER\|') { continue }

            $parts = $trimmed -split '\|'
            if ($parts.Count -lt 3) { continue }

            $fieldName = $parts[1].Trim().ToLowerInvariant()
            $refresh   = $null
            for ($i = 3; $i -lt $parts.Count; $i++) {
                $token = $parts[$i].Trim()
                if ($token -match '^(?i)RefreshHours\s*=\s*(\d+)$') {
                    $candidate = [int]$matches[1]
                    if ($candidate -gt 0) { $refresh = $candidate }
                }
            }
            if ($null -eq $refresh) { continue }

            $targets = if ($fieldName -eq '*') {
                $HeaderCacheFieldNames
            } elseif ($HeaderCacheFieldNames -contains $fieldName) {
                @($fieldName)
            } else {
                @()
            }

            foreach ($target in $targets) {
                if ($refresh -lt $hours[$target]) { $hours[$target] = $refresh }
            }
        }
    }

    return $hours
}

function Update-HeaderCacheFields {
    <#
    .SYNOPSIS
    Refreshes due fields in header_cache.json from values already in hand.

    $Fields is field-name -> current value, computed by Write-RunHeader for its
    normal log lines. A field is rewritten only when it is missing from the
    cache, unparseable, or older than its effective RefreshHours. Returns $true
    when the cache file was written.
    #>
    param([Parameter(Mandatory=$true)][hashtable]$Fields)

    $cache = Read-HeaderCache
    if ($null -eq $cache) { $cache = ConvertTo-HeaderCacheTable -Raw $null }

    $refreshHours = Get-HeaderFieldRefreshHours
    $now          = [datetimeoffset]::Now
    $dirty        = $false

    foreach ($field in $HeaderCacheFieldNames) {
        if (-not $Fields.ContainsKey($field)) { continue }

        $due = $true
        if ($cache.Fields.Contains($field)) {
            $entry = $cache.Fields[$field]
            $effectiveHours = if ($refreshHours.ContainsKey($field)) { $refreshHours[$field] } else { $HeaderCacheDefaultRefreshHours }
            if (-not [string]::IsNullOrWhiteSpace([string]$entry.collected_at)) {
                try {
                    $collected = [datetimeoffset]::Parse([string]$entry.collected_at)
                    $due = ($collected.AddHours($effectiveHours) -le $now)
                } catch {
                    $due = $true
                }
            }
        }

        if (-not $due) { continue }

        $lastSent = if ($cache.Fields.Contains($field)) { $cache.Fields[$field].last_sent_at } else { $null }
        $cache.Fields[$field] = [ordered]@{
            value        = [string]$Fields[$field]
            collected_at = $now.ToString('o')
            last_sent_at = $lastSent
        }
        $dirty = $true
    }

    if (-not $dirty) { return $false }

    try {
        $cacheDir = Split-Path -Parent $HeaderCacheFile
        if ($cacheDir -and -not (Test-Path -LiteralPath $cacheDir)) {
            New-Item -Path $cacheDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $cache.UpdatedAt = $now.ToString('o')
        $cache | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $HeaderCacheFile -Encoding UTF8 -Force -ErrorAction Stop
        return $true
    } catch {
        Write-Log "HeaderCache: could not write $HeaderCacheFile : $_" "DEBUG"
        return $false
    }
}

function Get-CprBuildFingerprint {
    # Short hash over WW_main.ps1 + every main\*.ps1, so the log states exactly which
    # code ran (a leftover or mixed file set changes the hash). Computed once per run.
    param([string]$MainDir = $PSScriptRoot)
    if ($script:CprBuildFingerprint) { return $script:CprBuildFingerprint }
    try {
        $files = @(Get-ChildItem -LiteralPath $MainDir -Filter '*.ps1' -File | Sort-Object Name)
        $top = Join-Path (Split-Path -Parent $MainDir) 'WW_main.ps1'
        if (Test-Path -LiteralPath $top) { $files = @(Get-Item -LiteralPath $top) + $files }
        $ms = New-Object System.IO.MemoryStream
        foreach ($f in $files) {
            $n = [System.Text.Encoding]::ASCII.GetBytes($f.Name)
            $b = [System.IO.File]::ReadAllBytes($f.FullName)
            $ms.Write($n, 0, $n.Length); $ms.Write($b, 0, $b.Length)
        }
        $ms.Position = 0
        $hash = (([System.Security.Cryptography.SHA256]::Create()).ComputeHash($ms) | ForEach-Object { $_.ToString('x2') }) -join ''
        $script:CprBuildFingerprint = ('{0} files={1}' -f $hash.Substring(0, 12), $files.Count)
    } catch { $script:CprBuildFingerprint = 'unknown' }
    return $script:CprBuildFingerprint
}

function Write-RunHeader {
  $utc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff 'UTC'")
  $loc = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
  $bar = ('=' * 80)
  Add-LogLine $bar
  Add-LogLine ("RUN START  White Walker v{0}" -f $ver)
  Add-LogLine ("run_id={0} host={1} user={2}" -f $RunId, $HostNm, $UserNm)
  $buildFp = try { Get-CprBuildFingerprint } catch { 'unknown' }
  Add-LogLine ("build={0}" -f $buildFp)
  Add-LogLine ("ts_local={0}  ts_utc={1}" -f $loc, $utc)
  Add-LogLine ("log_path={0}" -f $LogPath)
  
  # Add system context
  $sysCtx = Get-SystemContext
  Add-LogLine ("system={0}" -f $sysCtx.OS)
  Add-LogLine ("model={0}" -f $sysCtx.Model)
  Add-LogLine ("serial={0}" -f $sysCtx.SerialNumber)
  Add-LogLine ("last_boot={0}" -f $sysCtx.LastBootTime)

  # Cisco Secure Client version + module inventory (cached, change-detected -
  # zero manifest I/O on the fast path; see WW_csc_client_info.ps1 header)
  $cscVersion = "Unknown"
  $cscSource  = "Unknown"
  try {
    $cscInfo = Get-CiscoSecureClientInfo
    $cscVersion = [string]$cscInfo.CoreVersion
    $cscSource  = [string]$cscInfo.Source
    Add-LogLine ("csc_version={0}  source={1}" -f $cscInfo.CoreVersion, $cscInfo.Source)
    if ($global:CscInfoLogModulesAlways -or $WWDebug -or $WWTrace) {
      $moduleSummary = ($cscInfo.Modules | ForEach-Object { "$($_.Module)=$($_.Version)" }) -join ', '
      Add-LogLine ("csc_modules={0}" -f $moduleSummary)
    }
  } catch {
    $cscSource = "error: $_"
    Add-LogLine ("csc_version=Unknown  source=error: {0}" -f $_)
  }

  Add-LogLine ("preflight_mode=RC1.6 gateway.optum.com (https, 200/404=online, 3xx=route-to-workflow)")
  Add-LogLine ("blackhole_enabled={0}  script={1}" -f $BlackholeEnabled, $BlackholeScriptPath)
  Add-LogLine ("blackhole_flag_present={0}" -f (Test-Path $BlackholeFlagFile))
  Add-LogLine ("haystack_enabled={0}  script={1}" -f $HaystackEnabled, $HaystackScriptPath)
  Add-LogLine ("tee_enabled={0}  events_file={1}" -f $TeeEnabled, $TeeEventsFile)
  Add-LogLine ("xml_vault_enabled={0}  script={1}" -f $XmlVaultEnabled, $XmlVaultScriptPath)
  Add-LogLine ("cap_portal_runner_mode={0}  base_script={1}" -f $CapPortalRunnerMode, $CapPortalBaseScriptPath)
  $vpnProfile = (Get-ItemProperty -Path "HKLM:\SYSTEM\UHG\DSM" -ErrorAction SilentlyContinue).VPN
  if ($vpnProfile) {
      Add-LogLine ("vpn_profile={0}" -f $vpnProfile)
  } else {
      Add-LogLine "vpn_profile=NOT_SET ***ALERT***"
      Write-TeeLog 'vpn_profile_missing' @{}
  }

  # Additive structured side channel for HEADER needles. Uses only values this
  # function already computed above - no extra probes, no change to any of the
  # free-text lines, and never allowed to break the header if it fails.
  try {
      Update-HeaderCacheFields -Fields @{
          ww_version  = $ver
          os          = $sysCtx.OS
          model       = $sysCtx.Model
          serial      = $sysCtx.SerialNumber
          last_boot   = $sysCtx.LastBootTime
          csc_version = $cscVersion
          csc_source  = $cscSource
          vpn_profile = if ($vpnProfile) { $vpnProfile } else { 'NOT_SET' }
      } | Out-Null
  } catch {
      Write-Log "HeaderCache: refresh skipped - $_" "DEBUG"
  }

  Add-LogLine $bar
}

function Write-RunEnd([string]$Reason='') {
  # Update SSID cache on every run regardless of exit reason.
  # CRITICAL: must happen here not just on nwcheck 200 - VPN-connected runs
  # would never write the cache otherwise, breaking SSID change detection.
  if ($script:currentSsid) {
      Update-SsidCache -Ssid $script:currentSsid
  }
  if ($script:endNetworkSsid -and $script:endNetworkSsid -ne $script:currentSsid) {
      Add-LogLine ("network_now ssid=""{0}"" (run handled ssid=""{1}"")" -f $script:endNetworkSsid, $script:currentSsid)
  }
  $bar = ('-' * 80)
  Add-LogLine $bar
  Add-LogLine ("RUN END    run_id={0} exit_reason=""{1}""" -f $RunId, $Reason)
  Add-LogLine ""
}

