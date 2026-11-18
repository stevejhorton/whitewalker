# End-of-run EventID 301 sweep (RC2.0.3): every NEW navigation 301 since the last sweep becomes one
# cap_portal_webhelper_navigation row, whatever exit path the run took. Watermark = last record scanned.

function global:Get-CprFunctionSource {
    param([string]$Path, [string[]]$Names)
    $errors = $null; $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Failed to parse $Path" }
    $found = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Names -contains $node.Name }, $true)
    return (($found | ForEach-Object { $_.Extent.Text }) -join "`n`n")
}

BeforeAll {
    $script:root = Split-Path $PSScriptRoot -Parent
    $script:capPath = Join-Path $script:root 'main/Main.CaptivePortal.ps1'
    $script:entrySource = Get-Content (Join-Path $script:root 'main/Main.Entry.ps1') -Raw
    $script:configSource = Get-Content (Join-Path $script:root 'main/Main.Configuration.ps1') -Raw

    function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') }
    function global:Write-TeeLog { param([string]$Tag, [hashtable]$Data) }
    function global:Get-WinEvent { param($FilterHashtable, $MaxEvents, [switch]$Oldest, $ErrorAction) }
    function global:Get-CaptivePortalNetworkContext { return @{ ssid = 'xfinitywifi'; ip = '172.20.20.20'; gw = '172.20.20.1'; dns = '8.8.8.8' } }

    Invoke-Expression (Get-CprFunctionSource -Path $script:capPath -Names @(
        'Get-CprCiscoWebHelperQueryParameter', 'Get-CprCiscoWebHelperQueryParameterAny',
        'ConvertFrom-CprCiscoWebHelperEventText', 'Get-CprCiscoWebHelperUrlFromText',
        'Get-CprCiscoWebHelperUrlDetails', 'ConvertFrom-CprCiscoWebHelperNavigationBody',
        'Get-CprCiscoWebHelperDedupeKey', 'New-CprCiscoWebHelperEvidenceResult',
        'Write-CprCiscoWebHelper301Evidence', 'Read-CprWebHelper301Watermark', 'Save-CprWebHelper301Watermark',
        'Get-CprCiscoWebHelper301SweepEvidence', 'Invoke-CprWebHelper301Sweep'
    ))

    function script:New-NavBody {
        param([string]$Fqdn = 'cp-app.example.com', [string]$Trace = 'trace-1', [string]$Path = '/welcome')
        "[TID=1 PID=2] primary control navigated successfully to URL 'https://${Fqdn}${Path}?traceId=${Trace}&cp_da_osname=Windows'. Final URL 'http://www.msftconnecttest.com:80/connecttest.txt'."
    }
    function script:New-TestEvent {
        param([int64]$Id, [datetime]$Time, [string]$Message)
        [pscustomobject]@{ ProviderName = 'csc_webhelper'; Id = 301; RecordId = $Id; TimeCreated = $Time; Message = $Message }
    }
}

AfterAll {
    foreach ($v in 'CapPortalWebHelper301SweepEnabled', 'CapPortalWebHelper301SweepWatermarkFile', 'CapPortalWebHelper301SweepFirstLookbackSec',
        'CapPortalWebHelper301SweepMaxAgeSec', 'CapPortalWebHelper301SweepMaxScan', 'CapPortalWebHelper301SweepMaxRows',
        'CapPortalWebHelper301LogName', 'CapPortalWebHelper301ProviderName', 'CapPortalWebHelper301EventId', 'CapPortalWebHelper301MaxAgeSec') {
        Remove-Variable -Name $v -Scope Global -ErrorAction SilentlyContinue
    }
}

Describe 'Get-CprCiscoWebHelper301SweepEvidence' {
    BeforeEach {
        $script:now = Get-Date
        $script:logs = @()
        function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') $script:logs += "$Level $Message" }
    }

    It 'returns one row per distinct attempt (traceId), the newest event of an attempt wins, and the watermark is the last record scanned' {
        $t = $script:now.AddSeconds(-60)
        $evs = @(
            (New-TestEvent 100 $t.AddSeconds(0)  (New-NavBody -Trace 'A' -Path '/one')),
            (New-TestEvent 101 $t.AddSeconds(1)  '[TID=1 PID=2] Engineering debug: control created'),
            (New-TestEvent 102 $t.AddSeconds(2)  (New-NavBody -Trace 'A' -Path '/two')),
            (New-TestEvent 103 $t.AddSeconds(20) (New-NavBody -Trace 'B' -Fqdn 'portal-b.example.com')),
            (New-TestEvent 104 $t.AddSeconds(21) '[TID=1 PID=2] Engineering debug: closed')
        )
        Mock Get-WinEvent { $evs }
        $r = Get-CprCiscoWebHelper301SweepEvidence -Since $t.AddSeconds(-5) -Now $script:now
        $r.ReadFailed | Should -BeFalse
        $r.Scanned | Should -Be 5
        $r.Navigations | Should -Be 2
        $r.Evidence.Count | Should -Be 2
        $r.Evidence[0].TraceId | Should -Be 'A'
        $r.Evidence[0].EventRecordId | Should -Be '102'
        $r.Evidence[0].NavigatedUrl | Should -Match '/two'
        $r.Evidence[1].Fqdn | Should -Be 'portal-b.example.com'
        $r.Evidence[1].Port | Should -Be '443'
        $r.Evidence[1].Source | Should -Be 'cisco_webhelper_301_sweep'
        $r.Evidence[1].Status | Should -Be 'observed'
        $r.LastRecordId | Should -Be 104
        $r.LastTime | Should -Be $t.AddSeconds(21)
    }

    It 'collapses by host+path when an attempt carries no traceId' {
        $t = $script:now.AddSeconds(-30)
        $body = "[TID=1 PID=2] primary control navigated successfully to URL 'https://portal.example.com/login?x=1'. Final URL 'http://a.example.com:80/x'."
        Mock Get-WinEvent { @((New-TestEvent 1 $t $body), (New-TestEvent 2 $t.AddSeconds(1) $body)) }
        $r = Get-CprCiscoWebHelper301SweepEvidence -Since $t.AddSeconds(-5) -Now $script:now
        $r.Evidence.Count | Should -Be 1
        $r.Evidence[0].EventRecordId | Should -Be '2'
    }

    It 'skips records at or below the watermark and records this run already wrote' {
        $t = $script:now.AddSeconds(-60)
        $evs = @(
            (New-TestEvent 10 $t                  (New-NavBody -Trace 'old')),
            (New-TestEvent 11 $t.AddSeconds(5)    (New-NavBody -Trace 'wm')),
            (New-TestEvent 12 $t.AddSeconds(10)   (New-NavBody -Trace 'written')),
            (New-TestEvent 13 $t.AddSeconds(15)   (New-NavBody -Trace 'new'))
        )
        Mock Get-WinEvent { $evs }
        $wm = [pscustomobject]@{ RecordId = [int64]11; Time = $t.AddSeconds(5) }
        $r = Get-CprCiscoWebHelper301SweepEvidence -Since $wm.Time -Now $script:now -Watermark $wm -AlreadyEmitted @{ '12' = $true }
        $r.Scanned | Should -Be 2
        @($r.Evidence).Count | Should -Be 1
        $r.Evidence[0].TraceId | Should -Be 'new'
        $r.LastRecordId | Should -Be 13
    }

    It 'keeps the newest MaxRows attempts and counts the rest as dropped' {
        $t = $script:now.AddSeconds(-60)
        $evs = 1..8 | ForEach-Object { New-TestEvent (200 + $_) $t.AddSeconds($_) (New-NavBody -Trace "t$_") }
        Mock Get-WinEvent { $evs }
        $r = Get-CprCiscoWebHelper301SweepEvidence -Since $t -Now $script:now -MaxRows 3
        $r.Navigations | Should -Be 8
        $r.Dropped | Should -Be 5
        ($r.Evidence | ForEach-Object { $_.TraceId }) -join ',' | Should -Be 't6,t7,t8'
        $r.LastRecordId | Should -Be 208
    }

    It 'flags a full batch so the next sweep continues from the watermark' {
        $t = $script:now.AddSeconds(-60)
        $evs = 1..4 | ForEach-Object { New-TestEvent (300 + $_) $t.AddSeconds($_) 'noise' }
        Mock Get-WinEvent { $evs }
        (Get-CprCiscoWebHelper301SweepEvidence -Since $t -Now $script:now -MaxScan 4).BatchFull | Should -BeTrue
        (Get-CprCiscoWebHelper301SweepEvidence -Since $t -Now $script:now -MaxScan 5).BatchFull | Should -BeFalse
    }

    It 'marks an event older than the context window as late' {
        $old = $script:now.AddSeconds(-1000)
        Mock Get-WinEvent { @((New-TestEvent 400 $old (New-NavBody -Trace 'late'))) }
        $r = Get-CprCiscoWebHelper301SweepEvidence -Since $old.AddSeconds(-5) -Now $script:now -ContextWindowSec 330
        $r.Evidence[0].Reason | Should -Be 'swept_navigation_late'
    }

    It 'treats NoMatchingEventsFound as an empty result and any other error as a read failure' {
        Mock Get-WinEvent {
            $ex = New-Object System.Exception 'No events were found that match the specified selection criteria.'
            $er = New-Object System.Management.Automation.ErrorRecord $ex, 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', ([System.Management.Automation.ErrorCategory]::ObjectNotFound), $null
            throw $er
        }
        $r = Get-CprCiscoWebHelper301SweepEvidence -Since $script:now.AddSeconds(-60) -Now $script:now
        $r.ReadFailed | Should -BeFalse
        $r.Scanned | Should -Be 0

        Mock Get-WinEvent { throw 'RPC server unavailable' }
        $r2 = Get-CprCiscoWebHelper301SweepEvidence -Since $script:now.AddSeconds(-60) -Now $script:now
        $r2.ReadFailed | Should -BeTrue
        $r2.Error | Should -Match 'RPC'
    }

    It 'treats a box with no Cisco log at all (NoMatchingLogsFound) as nothing to report, not a read failure' {
        Mock Get-WinEvent {
            $ex = New-Object System.Exception 'There is not an event log on the localhost computer that matches "Cisco Secure Client".'
            $er = New-Object System.Management.Automation.ErrorRecord $ex, 'NoMatchingLogsFound,Microsoft.PowerShell.Commands.GetWinEventCommand', ([System.Management.Automation.ErrorCategory]::ObjectNotFound), $null
            throw $er
        }
        $r = Get-CprCiscoWebHelper301SweepEvidence -Since $script:now.AddSeconds(-60) -Now $script:now
        $r.ReadFailed | Should -BeFalse
        $r.Scanned | Should -Be 0
    }
}

Describe 'webhelper 301 watermark file' {
    It 'round-trips the record id and time, leaves no temp file, and returns $null for a missing or unreadable file' {
        $p = Join-Path $TestDrive 'wm\webhelper_301_watermark.json'
        Read-CprWebHelper301Watermark -Path $p | Should -BeNullOrEmpty
        $t = Get-Date
        Save-CprWebHelper301Watermark -Path $p -RecordId 4242 -Time $t | Should -BeTrue
        $wm = Read-CprWebHelper301Watermark -Path $p
        $wm.RecordId | Should -Be 4242
        [math]::Abs(($wm.Time - $t).TotalSeconds) | Should -BeLessThan 1
        Test-Path -LiteralPath "$p.tmp" | Should -BeFalse
        Set-Content -LiteralPath $p -Value 'not json'
        Read-CprWebHelper301Watermark -Path $p | Should -BeNullOrEmpty
    }
}

Describe 'Invoke-CprWebHelper301Sweep' {
    BeforeEach {
        $global:CapPortalWebHelper301SweepEnabled = $true
        $global:CapPortalWebHelper301SweepWatermarkFile = Join-Path $TestDrive ("wm_{0}.json" -f [guid]::NewGuid().ToString('N'))
        $global:CapPortalWebHelper301SweepFirstLookbackSec = 330
        $global:CapPortalWebHelper301SweepMaxAgeSec = 86400
        $global:CapPortalWebHelper301SweepMaxScan = 300
        $global:CapPortalWebHelper301SweepMaxRows = 5
        $global:CapPortalWebHelper301LogName = 'Cisco Secure Client'
        $global:CapPortalWebHelper301ProviderName = 'csc_webhelper'
        $global:CapPortalWebHelper301EventId = 301
        $global:CapPortalWebHelper301MaxAgeSec = 330
        $script:WebHelper301EmittedIds = @{}
        $script:logs = @(); $script:tee = @()
        $script:now = Get-Date
        function global:Write-Log { param([string]$Message, [string]$Level = 'INFO') $script:logs += "$Level $Message" }
        function global:Write-TeeLog { param([string]$Tag, [hashtable]$Data) $script:tee += [pscustomobject]@{ Tag = $Tag; Data = $Data } }
    }

    It 'writes one row per new attempt with the run context, advances the watermark, and writes nothing twice' {
        $t = $script:now.AddSeconds(-90)
        $evs = @((New-TestEvent 500 $t (New-NavBody -Trace 'A')), (New-TestEvent 501 $t.AddSeconds(3) '[TID=1 PID=2] noise'), (New-TestEvent 502 $t.AddSeconds(40) (New-NavBody -Trace 'B' -Fqdn 'b.example.com')))
        Mock Get-WinEvent { $evs }
        Invoke-CprWebHelper301Sweep -ExitReason 'vpn_connecting_exit:vpn_connecting'
        $rows = @($script:tee | Where-Object { $_.Tag -eq 'cap_portal_webhelper_navigation' })
        $rows.Count | Should -Be 2
        $rows[0].Data.trace_id | Should -Be 'A'
        $rows[0].Data.detection_source | Should -Be 'cisco_webhelper_301_sweep'
        $rows[0].Data.reason | Should -Be 'swept_navigation'
        $rows[0].Data.fqdn | Should -Be 'cp-app.example.com'
        $rows[0].Data.port | Should -Be '443'
        $rows[0].Data.ssid | Should -Be 'xfinitywifi'
        $rows[0].Data.ip | Should -Be '172.20.20.20'
        $rows[0].Data.event_record_id | Should -Be '500'
        $rows[1].Data.fqdn | Should -Be 'b.example.com'
        (Read-CprWebHelper301Watermark -Path $global:CapPortalWebHelper301SweepWatermarkFile).RecordId | Should -Be 502

        # Same events again (a later run): everything is at or below the watermark, so no new rows.
        $script:tee = @(); $script:WebHelper301EmittedIds = @{}
        Invoke-CprWebHelper301Sweep
        @($script:tee).Count | Should -Be 0
    }

    It 'attaches no ip/gw/dns to a late event and uses the SSID named in the event when it differs from the run' {
        $old = $script:now.AddSeconds(-2000)
        $ssidBody = "[TID=1 PID=2] primary control navigated successfully to URL 'https://s.example.com/p?ssid=OtherNet&traceId=S'. Final URL 'http://x.example.com:80/'."
        $evs = @((New-TestEvent 600 $old (New-NavBody -Trace 'L')), (New-TestEvent 601 $script:now.AddSeconds(-20) $ssidBody))
        Mock Get-WinEvent { $evs }
        Invoke-CprWebHelper301Sweep
        $late = $script:tee | Where-Object { $_.Data.trace_id -eq 'L' }
        $late.Data.reason | Should -Be 'swept_navigation_late'
        $late.Data.ssid | Should -BeNullOrEmpty
        $late.Data.ip | Should -BeNullOrEmpty
        $other = $script:tee | Where-Object { $_.Data.trace_id -eq 'S' }
        $other.Data.ssid | Should -Be 'OtherNet'
        $other.Data.ip | Should -BeNullOrEmpty
    }

    It 'does not write a record this run already wrote in-line' {
        $t = $script:now.AddSeconds(-30)
        $evs = @((New-TestEvent 700 $t (New-NavBody -Trace 'inline')), (New-TestEvent 701 $t.AddSeconds(5) (New-NavBody -Trace 'extra')))
        Mock Get-WinEvent { $evs }
        $inline = New-CprCiscoWebHelperEvidenceResult
        $inline.EventRecordId = '700'; $inline.Status = 'observed'; $inline.UsableNavigation = $true
        Write-CprCiscoWebHelper301Evidence -Evidence $inline -NetworkContext @{ ssid = 'x'; ip = ''; gw = ''; dns = '' }
        $script:tee = @()
        Invoke-CprWebHelper301Sweep
        @($script:tee).Count | Should -Be 1
        $script:tee[0].Data.trace_id | Should -Be 'extra'
    }

    It 'leaves the watermark alone when the read fails, and does not create one when nothing matched' {
        Mock Get-WinEvent { throw 'RPC server unavailable' }
        Invoke-CprWebHelper301Sweep
        Test-Path -LiteralPath $global:CapPortalWebHelper301SweepWatermarkFile | Should -BeFalse
        @($script:logs | Where-Object { $_ -match 'webhelper_301_sweep read failed' }).Count | Should -Be 1

        Mock Get-WinEvent { @() }
        Invoke-CprWebHelper301Sweep
        Test-Path -LiteralPath $global:CapPortalWebHelper301SweepWatermarkFile | Should -BeFalse
    }

    It 'continues from the watermark when the first batch was full' {
        $t = $script:now.AddSeconds(-120)
        $global:CapPortalWebHelper301SweepMaxScan = 3
        $all = 1..6 | ForEach-Object { New-TestEvent (800 + $_) $t.AddSeconds($_) (New-NavBody -Trace "n$_") }
        Mock Get-WinEvent { param($FilterHashtable) @($all | Where-Object { $_.TimeCreated -ge $FilterHashtable.StartTime } | Select-Object -First 3) }
        Invoke-CprWebHelper301Sweep
        @($script:tee).Count | Should -Be 3
        (Read-CprWebHelper301Watermark -Path $global:CapPortalWebHelper301SweepWatermarkFile).RecordId | Should -Be 803
        # The query restarts AT the watermark time, so its own record takes one slot of the next batch.
        $script:tee = @(); $script:WebHelper301EmittedIds = @{}
        Invoke-CprWebHelper301Sweep
        ($script:tee | ForEach-Object { $_.Data.trace_id }) -join ',' | Should -Be 'n4,n5'
        $script:tee = @(); $script:WebHelper301EmittedIds = @{}
        Invoke-CprWebHelper301Sweep
        ($script:tee | ForEach-Object { $_.Data.trace_id }) -join ',' | Should -Be 'n6'
    }

    It 'does not stall when a same-timestamp burst at or below the watermark fills a whole batch' {
        $t = $script:now.AddSeconds(-60)
        $global:CapPortalWebHelper301SweepMaxScan = 3
        $burst = 1..5 | ForEach-Object { New-TestEvent (900 + $_) $t (New-NavBody -Trace "b$_" -Path "/p$_") }
        Mock Get-WinEvent { param($FilterHashtable, $MaxEvents) @($burst | Where-Object { $_.TimeCreated -ge $FilterHashtable.StartTime } | Select-Object -First $MaxEvents) }
        [void](Save-CprWebHelper301Watermark -Path $global:CapPortalWebHelper301SweepWatermarkFile -RecordId 903 -Time $t)
        Invoke-CprWebHelper301Sweep
        ($script:tee | ForEach-Object { $_.Data.trace_id }) -join ',' | Should -Be 'b4,b5'
        (Read-CprWebHelper301Watermark -Path $global:CapPortalWebHelper301SweepWatermarkFile).RecordId | Should -Be 905
    }

    It 'does nothing when skipped or disabled' {
        Mock Get-WinEvent { throw 'must not be called' }
        Invoke-CprWebHelper301Sweep -Skip $true
        $global:CapPortalWebHelper301SweepEnabled = $false
        Invoke-CprWebHelper301Sweep
        @($script:tee).Count | Should -Be 0
        Should -Invoke Get-WinEvent -Times 0 -Exactly
    }
}

Describe 'sweep wiring' {
    It 'runs in the finally block, after the exit flare and before the maintenance stage, on EVERY exit including VPN-connected and online fast-path ones' {
        $i = $script:entrySource.IndexOf('Send-CprExitFlare $script:exitReason')
        $j = $script:entrySource.IndexOf('Invoke-CprWebHelper301Sweep -ExitReason')
        $k = $script:entrySource.IndexOf('# Maintenance stage: last')
        $i | Should -BeGreaterThan 0
        $j | Should -BeGreaterThan $i
        $k | Should -BeGreaterThan $j
        $call = $script:entrySource.Substring($j, 120)
        $call | Should -Not -Match '-Skip'
        $script:entrySource.Substring($i, $j - $i) | Should -Not -Match "vpn_connected:\*"
        $script:entrySource.Substring($i, $j - $i) | Should -Not -Match 'onlineFastPathSelected\)\s*-or'
    }
    It 'defines each sweep setting as a literal in the configuration' {
        foreach ($n in 'CapPortalWebHelper301SweepEnabled', 'CapPortalWebHelper301SweepWatermarkFile', 'CapPortalWebHelper301SweepFirstLookbackSec',
            'CapPortalWebHelper301SweepMaxAgeSec', 'CapPortalWebHelper301SweepMaxScan', 'CapPortalWebHelper301SweepMaxRows') {
            $script:configSource | Should -Match ('(?m)^\$' + $n + '\s*=')
        }
    }
}
