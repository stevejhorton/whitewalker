<#
.SYNOPSIS
  Test-CprSyslogPath - can this box actually get a syslog packet to the CPR VIP right now?

.DESCRIPTION
  Syslog is plain UDP (no acknowledgement), so "Syslog fired" in haystack.log only means the packet
  was handed to the network. This tool checks everything on the box that decides whether it can arrive:

    1. currentState   what WW_main last wrote to C:\Windows\UHGLogs\state.json, and whether haystack
                      treats it as reachable (on_prem / user_tun / mgmt_tun = send live, otherwise cache)
    2. DNS            does cpr-syslog.uhc.com resolve from here
    3. Route          which adapter / next hop the OS would use to reach the resolved address, and (when
                      the state says tunnel) whether that adapter looks like the VPN adapter
    4. Queue          how many hits are cached waiting to ship, how old the oldest is, last drain line

  With -Send it also sends ONE test message so you can look for it in Splunk:
      machine="CPR_TESTER" Label="cpr_syslog_path_test" token="<yyyyMMddHHmmss>"

  Read-only without -Send. Safe to run any time (admin console: Quick Actions, WW_diagnostics.ps1 -Syslog).

.PARAMETER Send
  Also send one UDP test message through WW_syslog.ps1.

.PARAMETER MachineName
  Value of machine= in the test message. Default CPR_TESTER (easy to find, never a real host).

.EXAMPLE
  .\Test-CprSyslogPath.ps1
  .\Test-CprSyslogPath.ps1 -Send
#>
[CmdletBinding()]
param(
    [switch]$Send,
    [string]$MachineName = 'CPR_TESTER',
    [string]$Server      = 'cpr-syslog.uhc.com',
    [int]   $Port        = 514
)

$root      = Split-Path -Parent $PSScriptRoot          # ...\WhiteWalker (diagnostics\ lives one level down)
$syslog    = Join-Path $root 'WW_syslog.ps1'
$stateFile = 'C:\Windows\UHGLogs\state.json'            # same file haystack_action.ps1 reads ($WwStateFile)
$queueFile = Join-Path $root 'logs\haystack_syslog_queue.jsonl'
$hsLog     = Join-Path $root 'logs\haystack.log'
$reachableStates = @('on_prem', 'user_tun', 'mgmt_tun')  # same list as haystack_action.ps1 Test-SyslogReachable
$problems  = New-Object System.Collections.Generic.List[string]

function Write-PathLine {
    param([string]$Tag, [string]$Text, [string]$Color = 'White')
    Write-Host ("[{0}] {1}" -f $Tag, $Text) -ForegroundColor $Color
}

Write-Host ""
Write-Host "CPR syslog path check -> ${Server}:${Port}   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan

# ---- 1. currentState -------------------------------------------------------------------------------------
$state = ''
try {
    if (Test-Path -LiteralPath $stateFile) {
        $state = [string](Get-Content -LiteralPath $stateFile -Raw -ErrorAction Stop | ConvertFrom-Json).currentState
    }
} catch { }
if ([string]::IsNullOrWhiteSpace($state)) {
    Write-PathLine 'WARN' "currentState unknown ($stateFile missing or empty) - haystack treats that as NOT reachable and caches every hit" 'Yellow'
    $problems.Add('currentState unknown')
} elseif ($reachableStates -contains $state) {
    Write-PathLine 'OK' "currentState = $state  (haystack sends live)" 'Green'
} else {
    Write-PathLine 'INFO' "currentState = $state  (haystack CACHES hits until the state is on_prem / user_tun / mgmt_tun)" 'Cyan'
}

# ---- 2. DNS ----------------------------------------------------------------------------------------------
$ips = @()
try {
    $ips = @(Resolve-DnsName -Name $Server -Type A -ErrorAction Stop |
        Where-Object { $_.IPAddress } | ForEach-Object { [string]$_.IPAddress })
} catch { }
if ($ips.Count -eq 0) {
    Write-PathLine 'FAIL' "$Server does not resolve from here - nothing can be delivered" 'Red'
    $problems.Add('DNS does not resolve')
} else {
    Write-PathLine 'OK' "$Server -> $($ips -join ', ')" 'Green'
}

# ---- 3. Route --------------------------------------------------------------------------------------------
$ifAlias = ''
if ($ips.Count -gt 0) {
    try {
        $target = [string]$ips[0]                       # first ADDRESS (not the first character of a string)
        $route  = @(Find-NetRoute -RemoteIPAddress $target -ErrorAction Stop |
            Where-Object { $_.PSObject.Properties['NextHop'] }) | Select-Object -First 1
        if ($route) {
            $ifAlias = [string]$route.InterfaceAlias
            $ifDesc  = ''
            try { $ifDesc = [string](Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop).InterfaceDescription } catch { }
            $looksVpn = ("$ifAlias $ifDesc") -match 'Cisco|AnyConnect|Secure Client|VPN'
            Write-PathLine 'INFO' "route to $target : interface '$ifAlias' ($ifDesc) next hop $($route.NextHop)" 'Cyan'
            if (@('user_tun', 'mgmt_tun') -contains $state -and -not $looksVpn) {
                Write-PathLine 'WARN' "state says tunnel, but this route leaves via a NON-VPN adapter - packets go to the local network, not the VPN" 'Yellow'
                $problems.Add('route bypasses the tunnel')
            } elseif (@('user_tun', 'mgmt_tun') -contains $state) {
                Write-PathLine 'OK' "route goes through the VPN adapter" 'Green'
            }
        } else {
            Write-PathLine 'WARN' "no route returned for $target" 'Yellow'
            $problems.Add('no route')
        }
    } catch {
        Write-PathLine 'WARN' "route lookup failed: $($_.Exception.Message)" 'Yellow'
        $problems.Add('route lookup failed')
    }
}

# ---- 4. Queue --------------------------------------------------------------------------------------------
if (Test-Path -LiteralPath $queueFile) {
    $q = @(Get-Content -LiteralPath $queueFile -ErrorAction SilentlyContinue | Where-Object { $_ -and $_.Trim() })
    $oldest = ''
    try { $oldest = ([datetime]::Parse(($q[0] | ConvertFrom-Json).ts)).ToString('yyyy-MM-dd HH:mm:ss') } catch { }
    if ($q.Count -gt 0 -and $reachableStates -contains $state) {
        Write-PathLine 'WARN' "queue: $($q.Count) cached hit(s), oldest $oldest - state is reachable, so the next HayStack_Monitor run should drain them" 'Yellow'
    } else {
        Write-PathLine 'INFO' "queue: $($q.Count) cached hit(s) waiting, oldest $oldest" 'Cyan'
    }
} else {
    Write-PathLine 'OK' "queue: empty (nothing waiting to ship)" 'Green'
}
if (Test-Path -LiteralPath $hsLog) {
    $d = Select-String -LiteralPath $hsLog -Pattern 'SyslogQueue: drained' | Select-Object -Last 1
    if ($d) {
        $line = $d.Line.Trim()
        Write-PathLine 'INFO' ("last drain: " + $line.Substring(0, [Math]::Min(150, $line.Length))) 'Cyan'
    }
}

# ---- 5. Optional test send -------------------------------------------------------------------------------
if ($Send) {
    if (-not (Test-Path -LiteralPath $syslog)) {
        Write-PathLine 'FAIL' "WW_syslog.ps1 not found at $syslog" 'Red'
        $problems.Add('WW_syslog.ps1 missing')
    } else {
        # Same conventions as production emitters (WW_tee.ps1 Write-TeeLog): action, machine, user, EvtTime
        # first, then schema-known fields only (Label, vpn_state, note). machine= is the test name by request;
        # the real host goes in note= so it is still traceable.
        $helper = Join-Path $root 'WW_haystack_schema.ps1'
        if (Test-Path -LiteralPath $helper) { try { . $helper } catch { } }
        $user = ''
        if (Get-Command Get-HaystackUserContext -ErrorAction SilentlyContinue) {
            try { $user = [string](Get-HaystackUserContext) } catch { }
        }
        if ([string]::IsNullOrWhiteSpace($user)) { $user = 'USER_UNKNOWN' }
        $token = (Get-Date).ToString('yyyyMMddHHmmss')
        $msg = 'action="needle_hit" machine="{0}" user="{1}" EvtTime="{2}" Label="cpr_syslog_path_test" vpn_state="{3}" note="token={4} src_host={5} route_if={6}"' -f `
            $MachineName, $user, (Get-Date -Format 'o'), $state, $token, $env:COMPUTERNAME, $ifAlias
        if (Get-Command Test-HaystackMsgSchema -ErrorAction SilentlyContinue) {
            $chk = Test-HaystackMsgSchema -Payload $msg
            if ($chk.IsValid -and $chk.UnknownFields.Count -eq 0) {
                Write-PathLine 'OK' "payload passes the haystack schema (mandatory fields present, no unknown fields)" 'Green'
            } else {
                Write-PathLine 'WARN' "payload schema check: missing=[$($chk.MissingFields -join ',')] unknown=[$($chk.UnknownFields -join ',')]" 'Yellow'
                $problems.Add('payload fails schema check')
            }
        }
        & $syslog -Message $msg -SyslogServer $Server -Port $Port
        if ($LASTEXITCODE -eq 0) {
            Write-PathLine 'OK' "sent 1 UDP test message to ${Server}:${Port}" 'Green'
            Write-Host "       Splunk search:  index=cba_cpr_logging machine=""$MachineName"" Label=""cpr_syslog_path_test"" | table EvtTime,action,machine,user,vpn_state,note | sort 0 - EvtTime" -ForegroundColor White
            Write-Host "       (this send: note contains token=$token)" -ForegroundColor White
        } else {
            Write-PathLine 'FAIL' "WW_syslog.ps1 returned exit code $LASTEXITCODE" 'Red'
            $problems.Add('send failed')
        }
    }
}

Write-Host ""
if ($problems.Count -eq 0) {
    Write-Host "No problems found on this box." -ForegroundColor Green
} else {
    Write-Host ("Problems: " + ($problems -join '; ')) -ForegroundColor Yellow
}
Write-Host "Note: syslog is UDP with no acknowledgement. Only Splunk can confirm arrival." -ForegroundColor DarkGray
Write-Host ""
if ($problems.Count -eq 0) { exit 0 } else { exit 1 }
